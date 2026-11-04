"""Local TLS checks for wget, HTTPie and Perl LWP; no downloads or trust-store writes."""
import contextlib
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
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit
from integration_local_tls import create_certificates


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length','0'); self.end_headers()
    def do_HEAD(self):
        self.send_response(200); self.send_header('Content-Length','0'); self.end_headers()
    def log_message(self, *args): pass
    def handle(self):
        try: super().handle()
        except (ConnectionResetError, BrokenPipeError): pass


def main():
    results, skips = [], []
    with tempfile.TemporaryDirectory(prefix='emudhra-client-fixture-') as tmp:
        root = Path(tmp); servers = []; cas = []; urls = []
        try:
            for index in range(3):
                folder = root/str(index); folder.mkdir()
                ca, cert, key = create_certificates(folder, san='DNS:wrong.invalid' if index == 2 else 'DNS:localhost', ca_name='local client fixture '+str(index))
                server = http.server.ThreadingHTTPServer(('127.0.0.1',0), Handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(str(cert),str(key))
                server.socket = context.wrap_socket(server.socket,server_side=True)
                thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
                servers.append((server,thread)); cas.append(ca)
                urls.append('https://localhost:'+str(server.server_port)+'/')
            all_ca = root/'all-ca.pem'; all_ca.write_bytes(b'\n'.join(path.read_bytes() for path in cas))
            for kind, path in [('wget',shutil.which('wget')),('httpie',shutil.which('http')),('perl',shutil.which('perl'))]:
                if not path:
                    skips.append({'client':kind,'reason':'installed executable unavailable'}); continue
                for case, index, ca in [('untrusted',1,cas[0]),('trusted',1,all_ca),('hostname',2,all_ca)]:
                    targets = [('control',urls[0],True)] + [('test '+str(i),urls[index],False) for i in range(4)]
                    env = {name:'' for name in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy')}
                    env.update(NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1',
                               SSL_CERT_FILE=str(ca), REQUESTS_CA_BUNDLE=str(ca), PERL_LWP_SSL_CA_FILE=str(ca))
                    report_dir = root/(kind+'-'+case)
                    with mock.patch.dict(os.environ,env), mock.patch.object(audit,'TARGETS',targets), \
                         mock.patch.object(audit.Audit,'config_inventory'), contextlib.redirect_stdout(io.StringIO()):
                        audit.main(['--only',kind,'--'+kind,path,'--timeout','5','--out',str(report_dir)])
                    report=json.loads((report_dir/'report.json').read_text())
                    rows=[row for row in report['records'] if row.get('samples')]
                    if kind == 'perl': rows=[row for row in rows if 'LWP' in row['name']]
                    if not rows:
                        skips.append({'client':kind,'reason':'client transport unavailable'}); break
                    row=rows[0]
                    allowed = ('REJECTED','UNKNOWN') if case == 'untrusted' else ('UNKNOWN',)
                    if row['status'] not in allowed:
                        raise AssertionError(json.dumps({'client':kind,'case':case,'status':row['status'],'samples':row['samples']},ensure_ascii=False))
                    if case == 'trusted' and not all(s['status'] in ('CONTROL_OK','UNKNOWN') and 'HTTPS接続は成立' in s['detail'] if not s['control'] else s['status']=='CONTROL_OK' for s in row['samples']):
                        raise AssertionError('trusted TLS was not observed: '+kind+' '+json.dumps(row['samples'][:2],ensure_ascii=False))
                    results.append({'client':kind,'case':case,'status':row['status'],
                                    'samples':[{'status':s['status'],'detail':s['detail']} for s in row['samples'][:2]]})
        finally:
            for server,thread in servers:
                server.shutdown(); server.server_close(); thread.join()
    print(json.dumps({'checks':results,'skips':skips},ensure_ascii=False,indent=2))


if __name__ == '__main__': main()
