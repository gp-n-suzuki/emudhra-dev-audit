"""Local-only smoke test: HTTPS 404 accepted vs untrusted local CA rejected.
Creates disposable test keys in an OS temporary directory, not in this package.
Does not validate eMudhra patch coverage or every OS/runtime configuration.
"""
import http.server, importlib.util, json, os, pathlib, shutil, ssl, sys, tempfile, threading
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import audit
from fixture_safety import safe_chain_active

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404); self.send_header('Content-Length','0'); self.end_headers()
    def log_message(self,*args): pass
    def handle(self):
        try: super().handle()
        except (ConnectionResetError, BrokenPipeError): pass

def create_certificates(base, san='DNS:localhost,IP:127.0.0.1', purpose='serverAuth', ca_name='eMudhra audit local test CA'):
    """Keep the CA and TLS server roles separate for native trust stores."""
    ca=base/'ca.pem'; ca_key=base/'ca-key.pem'
    cert=base/'server.pem'; key=base/'server-key.pem'; csr=base/'server.csr'
    extensions=base/'server.ext'
    extensions.write_text(
        'basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\n'
        'extendedKeyUsage='+purpose+'\n'
        'subjectAltName='+san+'\n'
        'subjectKeyIdentifier=hash\n'
        'authorityKeyIdentifier=keyid,issuer\n', encoding='utf-8')
    commands=[
        ['req','-x509','-newkey','rsa:2048','-nodes','-sha256',
         '-keyout',str(ca_key),'-out',str(ca),'-days','1',
         '-subj','/CN='+ca_name,
         '-addext','basicConstraints=critical,CA:TRUE,pathlen:0',
         '-addext','keyUsage=critical,keyCertSign,cRLSign',
         '-addext','subjectKeyIdentifier=hash'],
        ['req','-new','-newkey','rsa:2048','-nodes','-sha256',
         '-keyout',str(key),'-out',str(csr),'-subj','/CN=localhost'],
        ['x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),
         '-set_serial','2','-out',str(cert),'-days','1','-sha256',
         '-extfile',str(extensions)],
    ]
    for command in commands:
        rc,out,err=audit.run(['openssl']+command,timeout=15)
        if rc: raise RuntimeError(audit.redact(err))
    return ca,cert,key

def main():
    results=[]
    skipped=[]
    protected=safe_chain_active()
    with tempfile.TemporaryDirectory(prefix='emudhra-fixture-') as tmp:
        base=pathlib.Path(tmp)
        ca,cert,key=create_certificates(base)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cert),str(key))
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        url='https://localhost:'+str(server.server_port)+'/'
        clean={'HTTPS_PROXY':'','https_proxy':'','HTTP_PROXY':'','http_proxy':'','ALL_PROXY':'','all_proxy':'','NO_PROXY':'localhost,127.0.0.1','no_proxy':'localhost,127.0.0.1'}
        # Only the loopback fixture bypasses environmental proxies; public probes do not.
        def check(name,cmd,env,expected,git=False):
            rc,out,err=audit.run(cmd,timeout=12,env=dict(clean,**env))
            data=audit.git_result(err+'\n'+out,rc) if git else audit.parse_probe(out,err,rc)
            state=audit.classify(data)[0]
            if expected == 'ACTION':
                if data.get('state') != 'accepted': raise AssertionError(name+': origin HTTPS was not accepted')
                expected = 'UNKNOWN'  # Local fixture is not an eMudhra certificate.
            results.append({'probe':name,'result':state,'expected':expected,'detail':data.get('detail','')})
            if state!=expected: raise AssertionError(name+': '+json.dumps(data)+'\n'+audit.redact(err[-5000:]))
        try:
            py=(audit.PROBES/'python_probe.py').read_text(encoding='utf-8')
            for mode in ('urllib','requests','httpx','pip'):
                if mode == 'pip' and protected:
                    for case in ('unknown CA','trusted local CA'):
                        skipped.append({'probe':'Python pip / '+case,'reason':'Safe Chain integration may be active'})
                    continue
                if importlib.util.find_spec(mode) is None:
                    for case in ('unknown CA','trusted local CA'):
                        skipped.append({'probe':'Python '+mode+' / '+case,'reason':'module unavailable: '+mode})
                    continue
                cmd=[sys.executable,'-B','-c',py,mode,url,'4']
                check('Python '+mode+' / unknown CA',cmd,{},'REJECTED')
                check('Python '+mode+' / trusted local CA',cmd,{'SSL_CERT_FILE':str(ca),'REQUESTS_CA_BUNDLE':str(ca),'PIP_CERT':str(ca)},'ACTION')
            node=shutil.which('node')
            if node:
                src=(audit.PROBES/'node_probe.cjs').read_text(encoding='utf-8')
                for mode in ('https','fetch'):
                    check('Node '+mode+' / unknown CA',[node,'-e',src,mode,url,'4'],{},'REJECTED')
                    check('Node '+mode+' / trusted local CA',[node,'-e',src,mode,url,'4'],{'NODE_EXTRA_CA_CERTS':str(ca)},'ACTION')
            java=shutil.which('java');javac=shutil.which('javac')
            if java and javac:
                rc,out,err=audit.run([javac,'-d',str(base),str(audit.PROBES/'TLSProbe.java')],timeout=15)
                if rc: raise RuntimeError(err)
                check('Java / unknown CA',[java,'-cp',str(base),'TLSProbe',url,'4'],{},'REJECTED')
            ruby=shutil.which('ruby')
            if ruby:
                src=(audit.PROBES/'ruby_probe.rb').read_text(encoding='utf-8')
                check('Ruby / unknown CA',[ruby,'-e',src,url,'4'],{},'REJECTED')
                check('Ruby / trusted local CA',[ruby,'-e',src,url,'4'],{'SSL_CERT_FILE':str(ca)},'ACTION')
            git=shutil.which('git')
            if git:
                env={'GIT_TRACE_CURL':'1','GIT_TRACE_CURL_NO_DATA':'1','GIT_TERMINAL_PROMPT':'0'}
                check('Git / unknown CA',[git,'-c','credential.helper=','ls-remote',url],env,'REJECTED',True)
                check('Git / trusted local CA, non-repository 404',[git,'-c','http.sslCAInfo='+str(ca),'-c','credential.helper=','ls-remote',url],env,'ACTION',True)
            php=shutil.which('php')
            if php:
                src=(audit.PROBES/'php_probe.php').read_text(encoding='utf-8').replace('<?php','',1)
                check('PHP / untrusted cause hidden',[php,'-r',src,url,'4'],{},'UNKNOWN')
                check('PHP / trusted local CA',[php,'-d','openssl.cafile='+str(ca),'-r',src,url,'4'],{},'ACTION')
        finally:
            server.shutdown();server.server_close();thread.join()
    print(json.dumps({'local_tls_checks':len(results),'local_tls_skipped':len(skipped),
                     'results':results,'skipped':skipped},ensure_ascii=False,indent=2))
if __name__=='__main__': main()
