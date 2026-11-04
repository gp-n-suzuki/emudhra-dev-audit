"""Local synthetic TLS integration for the actual package-manager executables."""
import contextlib
import hashlib
import gzip
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit
import connection_evidence
import package_checks
from integration_local_tls import create_certificates
from fixture_safety import safe_chain_active


class ObservedTLSServer(http.server.ThreadingHTTPServer):
    def __init__(self, address, handler):
        self.tls_attempts=0
        super().__init__(address,handler)

    def get_request(self):
        try:
            connection=super().get_request()
        except OSError:
            self.tls_attempts+=1
            raise
        self.tls_attempts+=1
        return connection


class Handler(http.server.BaseHTTPRequestHandler):
    requests=[]
    cross_base=''
    def do_POST(self):
        length=int(self.headers.get('Content-Length','0'))
        body=self.rfile.read(length)
        if b'must-not-be-sent' in body:
            raise AssertionError('synthetic credential reached the fixture request body')
        self.do_GET()

    def do_GET(self):
        Handler.requests.append((self.server.server_port,self.path,dict(self.headers)))
        if self.path.startswith('/cross/'):
            self.send_response(302); self.send_header('Location',self.cross_base+self.path[len('/cross/'):])
            body=b''
        elif self.path.startswith('/redirect/'):
            self.send_response(302); self.send_header('Location','/final/'+self.path.lstrip('/'))
            body=b''
        elif self.path.endswith('/config.json'):
            body=json.dumps({'api':'https://localhost:'+str(self.server.server_port),
                             'dl':'https://localhost:'+str(self.server.server_port)+'/unused'}).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
        elif self.path.startswith('/api/v1/crates'):
            body=b'{"crates":[],"meta":{"total":0}}'
            self.send_response(200); self.send_header('Content-Type','application/json')
        elif self.path.endswith('/packages.json'):
            body=json.dumps({'packages':{},'search':'https://localhost:'+str(self.server.server_port)+'/composer-search?q=%query%'}).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
        elif self.path.startswith('/composer-search'):
            body=b'{"results":[]}'
            self.send_response(200); self.send_header('Content-Type','application/json')
        elif self.path.rstrip('/').endswith('/emudhra-audit-fixture'):
            accept=self.headers.get('Accept','')
            if 'application/vnd.pypi.simple' in accept or self.headers.get('User-Agent','').lower().startswith('uv/'):
                body=b''
                self.send_response(404)
            else:
                body=json.dumps({'name':'emudhra-audit-fixture','version':'0.0.0',
                                 'dist-tags':{'latest':'0.0.0'},'versions':{'0.0.0':{'name':'emudhra-audit-fixture','version':'0.0.0'}}}).encode()
                self.send_response(200); self.send_header('Content-Type','application/json')
        elif self.path.endswith('specs.4.8.gz'):
            body=gzip.compress(b'\x04\x08[\x00')
            self.send_response(200); self.send_header('Content-Type','application/octet-stream')
        elif self.path.endswith('/release-stable.toml'):
            body=b'schema-version = "1"\nversion = "0.0.0"\n'
            self.send_response(200); self.send_header('Content-Type','text/plain')
        elif self.path.endswith('/index.yaml'):
            body=b'apiVersion: v1\nentries: {}\n'
            self.send_response(200); self.send_header('Content-Type','text/yaml')
        elif self.path == '/' or self.path.startswith('/final/redirect/'):
            body=(b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
                  b'<GetCallerIdentityResult><UserId>fixture</UserId><Account>000000000000</Account>'
                  b'<Arn>arn:aws:sts::000000000000:assumed-role/fixture/example</Arn></GetCallerIdentityResult>'
                  b'<ResponseMetadata><RequestId>fixture</RequestId></ResponseMetadata></GetCallerIdentityResponse>')
            self.send_response(200); self.send_header('Content-Type','text/xml')
        else:
            self.send_response(404); body=b''
        self.send_header('Content-Length',str(len(body))); self.end_headers()
        if body: self.wfile.write(body)
    def log_message(self,*args): pass
    def handle(self):
        try: super().handle()
        except (ConnectionResetError,BrokenPipeError): pass


class Proxy(http.server.BaseHTTPRequestHandler):
    requests=[]
    def do_CONNECT(self):
        Proxy.requests.append((self.path,dict(self.headers)))
        self.send_response(502); self.send_header('Content-Length','0'); self.end_headers()
    def log_message(self,*args): pass


def expired_cert(folder):
    (folder/'index.txt').write_text('')
    (folder/'serial').write_text('1000\n')
    (folder/'newcerts').mkdir()
    config=folder/'ca.conf'
    config.write_text('''[ca]
default_ca = fixture
[fixture]
database = {d}/index.txt
serial = {d}/serial
new_certs_dir = {d}/newcerts
certificate = {d}/ca.pem
private_key = {d}/ca-key.pem
default_md = sha256
policy = fixture_policy
x509_extensions = leaf
[fixture_policy]
commonName = supplied
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
'''.format(d=folder))
    output=folder/'expired.pem'
    command=['openssl','ca','-batch','-config',str(config),'-in',str(folder/'server.csr'),
             '-out',str(output),'-notext','-startdate','20200101000000Z','-enddate','20200102000000Z']
    rc,_,err=audit.run(command,timeout=15,cwd=folder)
    if rc: raise RuntimeError(audit.redact(err))
    return output


def main():
    results, skips, partial=[],[],[]
    protected=safe_chain_active()
    with tempfile.TemporaryDirectory(prefix='p2-tls-fixture-') as temporary:
        root=Path(temporary); servers=[]; certs=[]; urls=[]
        try:
            for index in range(4):
                folder=root/str(index); folder.mkdir()
                ca,cert,key=create_certificates(folder,san='DNS:wrong.invalid' if index==2 else 'DNS:localhost',
                                                ca_name='P2 TLS fixture '+str(index))
                if index == 1:
                    # A server may append an unrelated certificate. Its key is
                    # not proof that the accepted leaf was signed through it.
                    cert.write_bytes(cert.read_bytes()+b'\n'+ca.read_bytes()+b'\n'+certs[0].read_bytes())
                if index == 3: cert=expired_cert(folder)
                server=ObservedTLSServer(('127.0.0.1',0),Handler)
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(str(cert),str(key))
                server.socket=ctx.wrap_socket(server.socket,server_side=True)
                thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
                servers.append((server,thread)); certs.append(ca); urls.append('https://localhost:'+str(server.server_port)+'/')
            all_ca=root/'all-ca.pem'; all_ca.write_bytes(b'\n'.join(x.read_bytes() for x in certs))
            Handler.cross_base=urls[1]
            cargo_paths=sorted((Path.home()/'.rustup/toolchains').glob('*/bin/cargo'))
            node='/opt/homebrew/bin/node'
            yarn_path=None; yarn_version=None
            prior=Path('.artifacts/p0-p1-20261028/release-final-full-online/report.json')
            if prior.is_file() and package_checks.native(node):
                prior_data=json.loads(prior.read_text())
                with mock.patch.object(package_checks.shutil,'which',return_value=node):
                    for item in prior_data['records']:
                        meta=item.get('metadata',{})
                        if meta.get('tool_id') != 'yarn' or not meta.get('application'): continue
                        candidate=meta.get('path',''); manager=package_checks.node_manager(candidate,'yarn')
                        if manager:
                            yarn_path,yarn_version=candidate,manager[1]; break
            shared=Path(sys.prefix)/'lib'/('python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor))/'site-packages'
            clients=[('go',shutil.which('go'),package_checks.go_modules),
                     ('uv',shutil.which('uv'),package_checks.uv_packages),
                     ('cargo',str(cargo_paths[0]) if cargo_paths else None,package_checks.cargo_registry),
                     ('rubygems',os.environ.get('P2_TEST_GEM') or shutil.which('gem'),lambda instance,path,*args:
                      package_checks.rubygems_source(instance,path,package_checks.gem_ruby(path),*args)),
                     ('bundler',os.environ.get('P2_TEST_BUNDLER') or shutil.which('bundle'),lambda instance,path,*args:
                      package_checks.bundler_source(instance,path,package_checks.gem_ruby(path),*args)),
                     ('composer',shutil.which('composer'),lambda instance,path,*args:
                      package_checks.composer_repository(instance,path,package_checks.composer_php(path),*args)),
                     ('yarn',yarn_path,lambda instance,path,*args:
                      package_checks.node_registry(instance,path,node,yarn_version,'yarn',*args)),
                     ('kubectl',shutil.which('kubectl'),package_checks.kubectl_api),
                     ('aws',shutil.which('aws'),package_checks.aws_api),
                     ('rustup',shutil.which('rustup'),package_checks.rustup_metadata),
                     ('helm',shutil.which('helm'),package_checks.helm_repository),
                     ('pipx-shared-fixture',sys.executable if (shared/'pip/__init__.py').is_file() else None,
                      lambda instance,path,*args:package_checks.pipx_transport(instance,path,path,str(shared),str(root/'fixture-venv'),*args))]
            for name,path,probe in clients:
                selected=os.environ.get('P2_TEST_CLIENTS','').split(',')
                if selected != [''] and name not in selected: continue
                if protected and name in ('uv','yarn','pipx-shared-fixture'):
                    skips.append({'client':name,'reason':'Safe Chain integration may be active; direct fixture probe withheld'}); continue
                interpreter=(package_checks.gem_ruby(path) if name in ('rubygems','bundler') else
                             package_checks.composer_php(path) if name=='composer' else node if name=='yarn' else path) if path else None
                if not path or not interpreter or (name not in ('rubygems','bundler','composer','yarn') and not package_checks.native(path)):
                    skips.append({'client':name,'reason':'native executable unavailable'}); continue
                env=package_checks.isolated_environment(root)
                env['RUSTUP_AUTO_INSTALL']='0'
                version_command=([package_checks.gem_ruby(path),path,'--version'] if name in ('rubygems','bundler') else
                                 [package_checks.composer_php(path),'-d','auto_prepend_file=','-d','auto_append_file=',path,'--version','--no-plugins','--no-scripts'] if name=='composer' else
                                 [node,path,'--version'] if name=='yarn' else [path,'version','--client'] if name=='kubectl' else
                                 [path,'version' if name=='go' else '--version'])
                rc,_,_=audit.run(version_command,timeout=8,env=env,cwd=root,inherit_env=False)
                if rc:
                    skips.append({'client':name,'reason':'executable cannot run on this host'}); continue
                if name == 'kubectl':
                    initial=len(Handler.requests)
                    local_targets=[('control',urls[0],True)]+[('test',urls[0],False)]*4
                    fixture_env={k:'' for k in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy')}
                    fixture_env.update(NO_PROXY='localhost,127.0.0.1',no_proxy='localhost,127.0.0.1',
                                       SSL_CERT_FILE=str(certs[0]),KUBECONFIG='/invalid/unused-kubeconfig')
                    instance=audit.Audit(SimpleNamespace(project=None,offline=False,workers=4,timeout=4))
                    try:
                        with mock.patch.dict(os.environ,fixture_env),contextlib.redirect_stdout(io.StringIO()):
                            probe(instance,path,audit.run,audit.classify,audit.redact,local_targets)
                        row=next(r for r in instance.records if r['samples'])
                        if '対話認証' in row['detail']:
                            if Handler.requests[initial:]:
                                raise AssertionError('kubectl reported a prompt but sent an HTTP request')
                            skips.append({'client':name,'reason':'anonymous temporary kubeconfig prompted for interactive credentials before sending HTTP'})
                            continue
                    finally:
                        instance.tmp.cleanup()
                if name == 'rustup':
                    before=len(Handler.requests); attempts=[s.tls_attempts for s,_ in servers]
                    fixture_env={k:'' for k in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy')}
                    fixture_env.update(NO_PROXY='localhost,127.0.0.1',no_proxy='localhost,127.0.0.1',
                                       SSL_CERT_FILE=str(certs[0]),CURL_CA_BUNDLE=str(certs[0]),RUSTUP_USE_CURL='1')
                    instance=audit.Audit(SimpleNamespace(project=None,offline=False,workers=4,timeout=4))
                    try:
                        with mock.patch.dict(os.environ,fixture_env),contextlib.redirect_stdout(io.StringIO()):
                            probe(instance,path,audit.run,audit.classify,audit.redact,
                                  [('control',urls[0],True)]+[('untrusted',urls[1],False)]*4)
                        row=next(r for r in instance.records if r['samples'])
                        requests=Handler.requests[before:]
                        if not any(port==servers[0][0].server_port for port,_,_ in requests):
                            if (servers[0][0].tls_attempts==attempts[0] or servers[1][0].tls_attempts==attempts[1]
                                or any(port==servers[1][0].server_port for port,_,_ in requests)
                                or any(s['status']!='UNKNOWN' for s in row['samples'])):
                                raise AssertionError('rustup fixture did not safely attempt both TLS endpoints')
                            partial.append({'client':name,'case':'untrusted-only','target_tls_attempts':servers[1][0].tls_attempts-attempts[1],
                                            'http_to_target':0,'sample':'UNKNOWN'})
                            skips.append({'client':name,'reason':'rustup curl backend did not accept the fixture CA; positive TLS cases not demonstrated'})
                            continue
                    finally:
                        instance.tmp.cleanup()
                cases=[('trusted',1,all_ca),('untrusted',1,certs[0]),('hostname',2,all_ca),
                       ('expired',3,all_ca),('redirect',1,all_ca),('cross-host-redirect',0,certs[0])]
                if name in ('rubygems','bundler'):
                    cases.extend([('matched-chain',1,all_ca),('unrelated-chain',1,all_ca)])
                for case,index,ca in cases:
                    selected_cases=os.environ.get('P2_TEST_CASES','').split(',')
                    if selected_cases != [''] and case not in selected_cases: continue
                    target=urls[index]+('redirect/' if case=='redirect' else 'cross/' if case=='cross-host-redirect' else '')
                    targets=[('control',urls[0],True)]+[('test '+str(i),target,False) for i in range(4)]
                    env={k:'' for k in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy')}
                    env.update(NO_PROXY='localhost,127.0.0.1',no_proxy='localhost,127.0.0.1',
                               SSL_CERT_FILE=str(ca),PIP_CERT=str(ca),REQUESTS_CA_BUNDLE=str(ca),CURL_CA_BUNDLE=str(ca),NODE_EXTRA_CA_CERTS=str(ca),CARGO_HTTP_CAINFO=str(ca),COMPOSER_CAFILE=str(ca),AWS_CA_BUNDLE=str(ca),UV_SYSTEM_CERTS='false',
                               BUNDLE_SSL_CA_CERT=str(ca),
                               AWS_ACCESS_KEY_ID='synthetic-id-must-not-be-sent',AWS_SECRET_ACCESS_KEY='synthetic-secret-must-not-be-sent',
                               AWS_SESSION_TOKEN='synthetic-session-must-not-be-sent',KUBECONFIG='/invalid/unused-kubeconfig',
                               P2_TEST_TOKEN='must-not-be-sent',GOPROXY='',UV_OFFLINE='',UV_INSECURE_HOST='',CARGO_NET_OFFLINE='')
                    if name == 'rustup': env.update(RUSTUP_USE_CURL='1',CURL_CA_BUNDLE=str(ca))
                    before=len(Handler.requests)
                    attempts_before=[server.tls_attempts for server,_ in servers]
                    instance=audit.Audit(SimpleNamespace(project=None,offline=False,workers=4,timeout=4))
                    try:
                        pins=connection_evidence.TLS_PINS
                        if case in ('matched-chain','unrelated-chain'):
                            # Independent OpenSSL extraction verifies the observer's SPKI encoding.
                            certificate=certs[0] if case=='unrelated-chain' else certs[1]
                            rc,pubkey,_=audit.run(['openssl','x509','-in',str(certificate),'-pubkey','-noout'])
                            if rc: raise AssertionError('fixture public key unavailable')
                            public_file=root/'public.pem'; public_file.write_text(pubkey)
                            der=root/'public.der'
                            rc,_,_=audit.run(['openssl','pkey','-pubin','-in',str(public_file),'-outform','DER','-out',str(der)])
                            if rc: raise AssertionError('fixture SPKI unavailable')
                            pins=frozenset([hashlib.sha256(der.read_bytes()).hexdigest()])
                        with mock.patch.dict(os.environ,env),mock.patch.object(connection_evidence,'TLS_PINS',pins),contextlib.redirect_stdout(io.StringIO()):
                            probe(instance,path,audit.run,audit.classify,audit.redact,targets)
                        row=next(r for r in instance.records if r['samples']); samples=row['samples']
                        observed=name in ('cargo','rubygems','bundler')
                        if samples[0]['status'] != ('CONTROL_OK' if observed else 'UNKNOWN'):
                            raise AssertionError(name+' '+case+' control '+json.dumps(samples[0],ensure_ascii=False))
                        if not observed and name not in ('composer','bundler') and '通信応答を観測' not in samples[0]['detail']:
                            raise AssertionError(name+' '+case+' did not observe the control response '+json.dumps(samples[0],ensure_ascii=False))
                        expected='REJECTED' if observed and case=='untrusted' else 'ACTION' if case=='matched-chain' else 'UNKNOWN'
                        if any(s['status'] != expected for s in samples[1:]):
                            raise AssertionError(name+' '+case+' '+json.dumps(samples[1],ensure_ascii=False))
                        if case=='untrusted' and observed and row['status']!='REJECTED':
                            raise AssertionError(name+' rejection was not reflected in the main result')
                        if case=='matched-chain' and row['status']!='ACTION':
                            raise AssertionError(name+' accepted matching chain was not actionable')
                        if case=='trusted' and name not in ('composer','bundler') and not all('HTTPS接続は成立' in s['detail'] for s in samples[1:]):
                            raise AssertionError(name+' '+case+' accepted TLS was not detected '+json.dumps(samples[1],ensure_ascii=False))
                        if case in ('hostname','expired') and any('HTTPS接続は成立' in s['detail'] for s in samples[1:]):
                            raise AssertionError(name+' '+case+' certificate was accepted')
                        requests=Handler.requests[before:]
                        observed_ports={port for port,_,_ in requests}
                        if servers[0][0].server_port not in observed_ports:
                            raise AssertionError(name+' '+case+' did not reach the trusted control server: '+json.dumps(samples[0],ensure_ascii=False))
                        target_port=servers[index][0].server_port
                        if case in ('trusted','redirect','matched-chain') and target_port not in observed_ports:
                            raise AssertionError(name+' '+case+' did not reach the trusted target server: '+json.dumps(samples[1],ensure_ascii=False))
                        if case in ('untrusted','hostname','expired') and target_port in observed_ports:
                            raise AssertionError(name+' '+case+' sent an HTTP request to an invalid TLS target')
                        if case in ('untrusted','hostname','expired') and servers[index][0].tls_attempts == attempts_before[index]:
                            raise AssertionError(name+' '+case+' never attempted the target TLS connection')
                        if case == 'cross-host-redirect' and servers[1][0].server_port in observed_ports:
                            raise AssertionError(name+' sent an HTTP request to the untrusted redirect destination')
                        for port,_,headers in requests:
                            host=next((value for key,value in headers.items() if key.lower()=='host'),'')
                            if host.lower() != 'localhost:'+str(port):
                                raise AssertionError(name+' sent an unexpected Host header to the fixture')
                            if any(k.lower() in ('authorization','cookie','proxy-authorization','x-amz-security-token') for k in headers):
                                raise AssertionError(name+' sent credentials to the test site')
                        if case=='redirect' and not any(p.startswith('/redirect/') for _,p,_ in requests):
                            raise AssertionError(name+' did not request the redirecting endpoint')
                        if case=='cross-host-redirect':
                            if not any(port==servers[0][0].server_port and p.startswith('/cross/') for port,p,_ in requests):
                                raise AssertionError(name+' did not request the trusted initial endpoint')
                            if name in ('go','uv','composer') and not any('certificate' in s['detail'].lower() or 'issuer' in s['detail'].lower() for s in samples[1:]):
                                raise AssertionError(name+' did not observe the downstream certificate failure: '+json.dumps(samples[1],ensure_ascii=False))
                            if name in ('go','uv','cargo','composer') and servers[1][0].tls_attempts == attempts_before[1]:
                                raise AssertionError(name+' did not attempt TLS to the redirect destination')
                        results.append({'client':name,'case':case,'control':samples[0]['status'],
                                        'sample':samples[1]['status'],'main':row['status'],
                                        'http_to_control':sum(port==servers[0][0].server_port for port,_,_ in requests),
                                        'http_to_target':sum(port==target_port for port,_,_ in requests),
                                        'target_tls_attempts':servers[index][0].tls_attempts-attempts_before[index],
                                        'redirect_destination_tls_attempts':servers[1][0].tls_attempts-attempts_before[1] if case=='cross-host-redirect' else None,
                                        'http_to_redirect_destination':sum(port==servers[1][0].server_port for port,_,_ in requests) if case=='cross-host-redirect' else None})
                    finally:
                        instance.tmp.cleanup()
                proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
                proxy_thread=threading.Thread(target=proxy.serve_forever,daemon=True); proxy_thread.start()
                try:
                    proxy_url='http://127.0.0.1:'+str(proxy.server_port)
                    env={k:'' for k in ('HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy','NO_PROXY','no_proxy')}
                    env.update(HTTP_PROXY=proxy_url,http_proxy=proxy_url,HTTPS_PROXY=proxy_url,https_proxy=proxy_url,P2_TEST_TOKEN='must-not-be-sent',
                               GOPROXY='',UV_OFFLINE='',UV_INSECURE_HOST='',CARGO_NET_OFFLINE='')
                    if name == 'rustup': env.update(RUSTUP_USE_CURL='1')
                    targets=[('control','https://p2-fixture.invalid/',True)]+[('test '+str(i),'https://p2-fixture.invalid/',False) for i in range(4)]
                    before=len(Proxy.requests)
                    instance=audit.Audit(SimpleNamespace(project=None,offline=False,workers=4,timeout=4))
                    try:
                        with mock.patch.dict(os.environ,env),contextlib.redirect_stdout(io.StringIO()):
                            probe(instance,path,audit.run,audit.classify,audit.redact,targets)
                        row=next(r for r in instance.records if r['samples']); samples=row['samples']
                        if any(s['status'] != 'UNKNOWN' for s in samples):
                            raise AssertionError(name+' proxy failure was not unknown')
                        if not Proxy.requests[before:]:
                            raise AssertionError(name+' did not use the configured HTTPS proxy: '+json.dumps(samples[0],ensure_ascii=False))
                        for _,headers in Proxy.requests[before:]:
                            if any(k.lower() in ('authorization','cookie','proxy-authorization') for k in headers):
                                raise AssertionError(name+' sent credentials to the proxy')
                        results.append({'client':name,'case':'proxy','control':samples[0]['status'],
                                        'sample':samples[1]['status'],'main':row['status']})
                    finally:
                        instance.tmp.cleanup()
                finally:
                    proxy.shutdown(); proxy.server_close(); proxy_thread.join()
        finally:
            for server,thread in servers:
                server.shutdown(); server.server_close(); thread.join()
    print(json.dumps({'checks':results,'partial_checks':partial,'skips':skips},ensure_ascii=False,indent=2))


if __name__=='__main__': main()
