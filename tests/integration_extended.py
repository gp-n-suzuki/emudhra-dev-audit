"""Local TLS and credential-isolation checks for the additional probes."""
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
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit
from integration_local_tls import create_certificates
from fixture_safety import safe_chain_active


class Handler(http.server.BaseHTTPRequestHandler):
    requests = []
    paths = []
    def do_GET(self):
        self.requests.append(dict(self.headers))
        self.paths.append(self.path)
        if self.path == '/redirect' or self.path.startswith('/git-redirect/'):
            self.send_response(302); self.send_header('Location', '/redirected')
            self.send_header('Content-Length', '0'); self.end_headers(); return
        self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers()
    do_HEAD = do_GET
    def log_message(self, *args): pass
    def handle(self):
        try: super().handle()
        except (ConnectionResetError, BrokenPipeError): pass


class ExtendedTLS(unittest.TestCase):
    def test_python_wrong_certificate_purpose_is_not_trust_rejection(self):
        folder=self.base/'wrong-purpose'; folder.mkdir()
        ca,cert,key=create_certificates(folder,purpose='clientAuth')
        # This test isolates certificate purpose only if the runtime actually
        # trusts the fixture CA via its normal SSL_CERT_FILE handling.
        check_ca=('import pathlib,ssl,sys; '
                  'ca=ssl.PEM_cert_to_DER_cert(pathlib.Path(sys.argv[1]).read_text()); '
                  'print("present" if ca in ssl.create_default_context().get_ca_certs(binary_form=True) else "absent")')
        rc,out,err=audit.run([sys.executable,'-B','-c',check_ca,str(ca)],
                             env=dict(self.clean,SSL_CERT_FILE=str(ca)),cwd=self.base)
        self.assertEqual(rc,0,audit.redact(err))
        if out.strip() != 'present':
            self.skipTest('Runtime default SSL context did not load the SSL_CERT_FILE fixture CA')
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert,key)
        server.socket=ctx.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            data=self.run_probe([sys.executable,'-B',str(audit.PROBES/'python_probe.py'),'urllib',
                                 'https://localhost:'+str(server.server_port)+'/', '4'],
                                'UNKNOWN', {'SSL_CERT_FILE':str(ca)})
            self.assertEqual(data.get('verify_code'),26)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='emudhra-extended-')
        cls.base = Path(cls.tmp.name)
        cls.ca, cert, key = create_certificates(cls.base)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
        cls.url = 'https://localhost:' + str(cls.server.server_port) + '/'
        wrong = cls.base/'wrong-host'; wrong.mkdir()
        cls.wrong_ca, cert, key = create_certificates(wrong, 'DNS:wrong.example')
        cls.wrong_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
        cls.wrong_server.socket = ctx.wrap_socket(cls.wrong_server.socket, server_side=True)
        cls.wrong_thread = threading.Thread(target=cls.wrong_server.serve_forever, daemon=True); cls.wrong_thread.start()
        cls.wrong_url = 'https://localhost:' + str(cls.wrong_server.server_port) + '/'
        cls.clean = {'HTTPS_PROXY':'', 'https_proxy':'', 'HTTP_PROXY':'', 'http_proxy':'',
                     'ALL_PROXY':'', 'all_proxy':'', 'NO_PROXY':'localhost', 'no_proxy':'localhost'}
        cls.swift = cls.base/'native-probe'
        cls.npmroot = None
        cls.protected = safe_chain_active()
        if not cls.protected and shutil.which('npm'):
            rc, out, _ = audit.run(['npm', 'root', '-g'])
            if not rc: cls.npmroot = Path(out.strip())/'npm'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
        cls.wrong_server.shutdown(); cls.wrong_server.server_close(); cls.wrong_thread.join(); cls.tmp.cleanup()

    def run_probe(self, command, expected, env=None):
        rc, out, err = audit.run(command, timeout=15, env=dict(self.clean, **(env or {})), cwd=self.base)
        data = audit.parse_probe(out, err, rc)
        if expected == 'ACTION':
            self.assertEqual(data.get('state'), 'accepted', audit.redact(str(data)))
            expected = 'UNKNOWN'  # Accepted localhost is not proof of the target certificate.
        self.assertEqual(audit.classify(data)[0], expected, audit.redact(str(data)))
        return data

    @unittest.skipUnless(shutil.which('php'), 'PHP unavailable')
    def test_php_stream_reports_verification_context_without_accepting_peer(self):
        before = len(Handler.requests)
        data = self.run_probe(['php', str(audit.PROBES/'php_probe.php'), self.url, '4'], 'UNKNOWN')
        self.assertIn('certificate verify failed', data['detail'])
        self.assertIn('OpenSSL', data['openssl_version'])
        self.assertIn('ini_cafile', data['ca_locations'])
        self.assertEqual(len(Handler.requests), before)

    @unittest.skipUnless(shutil.which('php'), 'PHP unavailable')
    def test_php_matching_openssl_reproduces_unknown_ca_as_inference(self):
        import php_diagnostics
        data = self.run_probe(['php', str(audit.PROBES/'php_probe.php'), self.url, '4'], 'UNKNOWN')
        if not php_diagnostics.matching_openssl(data['openssl_version'],audit.run):
            self.skipTest('Matching OpenSSL CLI unavailable')
        enriched = php_diagnostics.corroborate(data,self.url,4,audit.run)
        self.assertEqual(enriched['state'],'inferred_rejection',audit.redact(str(enriched)))
        self.assertIn('別接続',enriched['detail'])

    @unittest.skipUnless(shutil.which('php'), 'PHP unavailable')
    def test_php_matching_openssl_does_not_infer_hostname_rejection(self):
        import php_diagnostics
        data = self.run_probe(['php','-d','openssl.cafile='+str(self.wrong_ca),
                              str(audit.PROBES/'php_probe.php'),self.wrong_url,'4'],'UNKNOWN')
        self.assertEqual(php_diagnostics.corroborate(data,self.wrong_url,4,audit.run)['state'],'unknown')

    @unittest.skipUnless(shutil.which('php'), 'PHP unavailable')
    def test_php_stream_hostname_error_stays_unknown(self):
        self.run_probe(['php', '-d', 'openssl.cafile='+str(self.wrong_ca),
                        str(audit.PROBES/'php_probe.php'), self.wrong_url, '4'], 'UNKNOWN')

    @unittest.skipUnless(shutil.which('php'), 'PHP unavailable')
    def test_php_curl_rejects_untrusted_ca(self):
        self.run_probe(['php', str(audit.PROBES/'php_curl_probe.php'), self.url, '4'], 'REJECTED')

    @unittest.skipUnless(shutil.which('php'), 'PHP unavailable')
    def test_php_curl_uses_configured_ca(self):
        self.run_probe(['php', '-d', 'curl.cainfo='+str(self.ca), str(audit.PROBES/'php_curl_probe.php'), self.url, '4'], 'ACTION')

    @unittest.skipUnless(shutil.which('php'), 'PHP unavailable')
    def test_php_curl_hostname_error_stays_unknown(self):
        self.run_probe(['php', '-d', 'curl.cainfo='+str(self.wrong_ca), str(audit.PROBES/'php_curl_probe.php'), self.wrong_url, '4'], 'UNKNOWN')

    def npm_probe(self, expected, ca=False, url=None, cafile=None, extra=''):
        if self.protected: self.skipTest('Safe Chain integration may be active')
        if not self.npmroot or not shutil.which('node'): self.skipTest('npm/Node unavailable')
        rcfile = self.base/'test.npmrc'
        rcfile.write_text(('cafile='+str(cafile or self.ca)+'\n' if ca else '') +
                          '//localhost:'+str(self.server.server_port)+'/:_authToken=fixture-secret\n'+extra)
        before = len(Handler.requests)
        self.run_probe(['node', str(audit.PROBES/'npm_probe.cjs'), str(self.npmroot), 'probe', url or self.url, '4'], expected,
                       {'npm_config_userconfig':str(rcfile), 'npm_config_globalconfig':str(self.base/'empty.npmrc')})
        for headers in Handler.requests[before:]:
            self.assertFalse(any(k.lower() in ('authorization','cookie') for k in headers))

    def test_npm_rejects_untrusted_ca(self): self.npm_probe('REJECTED')
    def test_npm_honors_cafile_without_sending_token(self): self.npm_probe('ACTION', ca=True)
    def test_npm_hostname_error_stays_unknown(self):
        self.npm_probe('UNKNOWN', ca=True, url=self.wrong_url, cafile=self.wrong_ca)
    def test_npm_does_not_follow_redirect(self):
        before=len(Handler.requests)
        self.npm_probe('UNKNOWN', ca=True, url=self.url+'redirect')
        self.assertEqual(len(Handler.requests)-before, 1)
    def test_npm_disabled_validation_sends_nothing(self):
        before=len(Handler.requests)
        self.npm_probe('SKIP', extra='strict-ssl=false\n')
        self.assertEqual(len(Handler.requests), before)

    def macos_probe(self, expected, ca=False, url=None, cafile=None):
        if sys.platform != 'darwin' or not shutil.which('swiftc'): self.skipTest('macOS Swift unavailable')
        if not self.swift.exists():
            rc, out, err = audit.run(['swiftc', '-module-cache-path', str(self.base/'swift-cache'),
                                      str(audit.PROBES/'macos_probe.swift'), '-o', str(self.swift)], timeout=90)
            self.assertEqual(rc, 0, audit.redact(err))
        command = [str(self.swift), url or self.url, '4']
        if ca: command += [str(cafile or self.ca)]
        self.run_probe(command, expected)

    def test_macos_rejects_untrusted_ca(self): self.macos_probe('REJECTED')
    def test_macos_accepts_explicit_test_ca(self): self.macos_probe('ACTION', ca=True)
    def test_macos_hostname_error_stays_unknown(self):
        self.macos_probe('UNKNOWN', ca=True, url=self.wrong_url, cafile=self.wrong_ca)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS only')
    def test_macos_controller_builds_with_installed_sdk(self):
        args=SimpleNamespace(project=self.base, only='native', offline=False, timeout=4, workers=1)
        with mock.patch.object(audit, 'TARGETS', [('control',self.url,True),('test',self.url,False)]), contextlib.redirect_stdout(io.StringIO()):
            instance=audit.Audit(args)
            try: instance.macos_trust()
            finally: instance.tmp.cleanup()
        row=instance.records[-1]
        self.assertEqual(len(row['samples']),2,str(row))
        self.assertEqual(row['samples'][1]['status'],'REJECTED',str(row))

    def check_git(self, entry, expected, config='', url=None):
        if not shutil.which('git'): self.skipTest('Git unavailable')
        home = self.base/'git-home'; home.mkdir(exist_ok=True)
        (home/'.netrc').write_text('machine '+entry+' login fixture password fixture-secret\n')
        (home/'.netrc').chmod(0o600)
        (home/'empty.gitconfig').write_text(config)
        args = SimpleNamespace(project=home, git=[], offline=False, timeout=4, workers=1)
        before = len(Handler.requests)
        environment = {k:v for k,v in os.environ.items() if not k.startswith('GIT_CONFIG_')
                       and k not in ('GIT_SSL_CERT','GIT_SSL_KEY','GIT_SSL_NO_VERIFY')}
        environment.update(dict(self.clean, HOME=str(home), NETRC=str(home/'.netrc'),
                           GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(home/'empty.gitconfig'),
                           GIT_SSL_CAINFO=str(self.ca)))
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(audit, 'TARGETS',
                [('control',url or self.url,True), ('test',url or self.url,False)]), contextlib.redirect_stdout(io.StringIO()):
            instance = audit.Audit(args)
            try: instance.git(instance.host)
            finally: instance.tmp.cleanup()
        row = instance.records[-1]
        if expected == 'ACTION':
            expected = 'UNKNOWN'
            self.assertTrue(any('HTTPS接続は成立' in s['detail'] for s in row['samples'] if not s['control']))
        self.assertEqual(row['status'], expected, str(row))
        if expected == 'SKIP': self.assertEqual(len(Handler.requests), before)
        else: self.assertGreater(len(Handler.requests), before)
        for headers in Handler.requests[before:]: self.assertNotIn('Authorization', headers)

    def test_git_unrelated_netrc_can_probe(self): self.check_git('private.example', 'ACTION')
    def test_git_matching_netrc_sends_nothing(self): self.check_git('localhost', 'SKIP')
    def test_git_scoped_redirect_setting_is_disabled(self):
        before=len(Handler.paths)
        url=self.url+'git-redirect/'
        self.check_git('private.example','ACTION',config='[http "'+url+'"]\n\tfollowRedirects = true\n',url=url)
        paths=Handler.paths[before:]
        self.assertEqual(len(paths),2,paths)
        self.assertTrue(all(path.startswith('/git-redirect/') for path in paths),paths)


if __name__ == '__main__': unittest.main(verbosity=2)
