"""Exercise new probes through the CLI against disposable localhost TLS servers.

This checks transport/error classification, not the public eMudhra certificates.
Pass installed runtime paths; no downloads or changes to OS trust stores.
"""
import argparse
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit
from integration_local_tls import Handler, create_certificates


def main():
    parser = argparse.ArgumentParser()
    for kind in ('bun', 'deno', 'perl'): parser.add_argument('--'+kind)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix='emudhra-language-tls-') as tmp:
        root = Path(tmp)
        servers = []
        try:
            cas, urls = [], []
            for index in range(3):
                base = root/str(index); base.mkdir()
                ca, cert, key = create_certificates(base, san='DNS:wrong.invalid' if index == 2 else 'DNS:localhost,IP:127.0.0.1', ca_name='eMudhra local fixture '+str(index))
                cas.append(ca)
                server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(str(cert), str(key))
                server.socket = ctx.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                servers.append((server, thread)); urls.append('https://localhost:'+str(server.server_port)+'/')
            all_ca = root/'all-ca.pem'; all_ca.write_bytes(b'\n'.join(ca.read_bytes() for ca in cas))
            for kind in ('bun', 'deno', 'perl'):
                path = getattr(args, kind)
                if not path: continue
                for case, bundle, index, expected in [('untrusted',cas[0],1,'REJECTED'), ('trusted',all_ca,1,'UNKNOWN'), ('hostname',all_ca,2,'UNKNOWN')]:
                    # Some IO::Socket::SSL/LibreSSL combinations hide the cause.
                    # A generic verification failure must stay unresolved.
                    allowed = [expected,'UNKNOWN'] if kind=='perl' and case=='untrusted' else [expected]
                    env = dict(NO_PROXY='localhost,127.0.0.1',no_proxy='localhost,127.0.0.1')
                    env[{'bun':'NODE_EXTRA_CA_CERTS','deno':'DENO_CERT','perl':'SSL_CERT_FILE'}[kind]] = str(bundle)
                    targets = [('control',urls[0],True)]+[('local '+str(i),urls[index],False) for i in range(4)]
                    output = root/(kind+'-'+case)
                    with mock.patch.dict(os.environ,env), mock.patch.object(audit,'TARGETS',targets), \
                         mock.patch.object(audit.Audit,'config_inventory'), contextlib.redirect_stdout(io.StringIO()):
                        for key in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy'):
                            os.environ.pop(key,None)
                        audit.main(['--only',kind,'--'+kind,str(Path(path).resolve()),'--timeout','5','--out',str(output)])
                    rows = json.loads((output/'report.json').read_text())['records']
                    row = next(r for r in rows if r.get('samples'))
                    if case == 'trusted' and row['status'] != 'SKIP' and not all('HTTPS接続は成立' in s['detail'] for s in row['samples'] if not s['control']):
                        raise AssertionError('trusted connection was not observed: '+kind)
                    result = dict(runtime=kind,case=case,result=row['status'],expected=allowed)
                    if row['status']=='SKIP': result['skipped'] = row['samples'][0]['detail']
                    elif row['status'] not in allowed:
                        raise AssertionError(json.dumps(dict(result=result,samples=row['samples']),ensure_ascii=False))
                    results.append(result)
        finally:
            for server,thread in servers:
                server.shutdown(); server.server_close(); thread.join()
    print(json.dumps(results,ensure_ascii=False,indent=2))


if __name__ == '__main__': main()
