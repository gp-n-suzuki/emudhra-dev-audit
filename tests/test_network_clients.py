"""Connection evidence from the actual client, with proxy and trust ambiguity."""
import unittest

import audit


class ClientResults(unittest.TestCase):
    def test_generic_samples_with_authenticated_proxy_are_withheld(self):
        import contextlib,io,os
        from types import SimpleNamespace
        from unittest import mock
        instance=audit.Audit(SimpleNamespace(project=None,offline=False,workers=1,timeout=1))
        try:
            probe=mock.Mock()
            with mock.patch.dict(os.environ,{'HTTPS_PROXY':'http://person:fixture-secret@proxy.invalid'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                row=instance.sample('example',probe,{'tool_id':'example'})
            self.assertEqual(row['status'],'SKIP')
            self.assertNotIn('fixture-secret',str(row))
            probe.assert_not_called()
        finally: instance.tmp.cleanup()

    def test_npm_proxy_credentials_from_config_are_not_sent_or_logged(self):
        import json,shutil,subprocess,tempfile
        from pathlib import Path
        node=shutil.which('node')
        if not node: self.skipTest('Node unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); package=root/'npm'; config=package/'node_modules/@npmcli/config'
            (config/'lib/definitions').mkdir(parents=True)
            (config/'index.js').write_text("module.exports=class { constructor(){this.flat={strictSSL:true,httpsProxy:'http://person:fixture-secret@proxy.invalid'}} async load(){} get(){return null} }\n")
            (config/'lib/definitions/index.js').write_text('exports.definitions={}; exports.shorthands={}; exports.flatten=()=>({});\n')
            (package/'package.json').write_text('{"version":"1.0.0"}')
            result=subprocess.run([node,str(Path(audit.PROBES)/'npm_probe.cjs'),str(package),'probe','https://fixture.invalid/','1'],
                                  capture_output=True,text=True,timeout=8)
            data=audit.parse_probe(result.stdout,result.stderr,result.returncode)
            self.assertEqual(data['state'],'skipped')
            self.assertNotIn('fixture-secret',result.stdout+result.stderr)

    def test_aws_ca_bundle_cannot_reference_an_excluded_env_file(self):
        from unittest import mock
        with mock.patch.object(audit.subprocess,'Popen') as process:
            rc,out,err=audit.run(['/example/tool'],env={'AWS_CA_BUNDLE':'/private/.env.private'},inherit_env=False)
        self.assertEqual(rc,126)
        self.assertIn('AWS_CA_BUNDLE',err)
        process.assert_not_called()

    def test_accepted_without_matching_chain_requires_review(self):
        status, detail = audit.classify({'state': 'accepted', 'detail': 'HTTP 200'})
        self.assertEqual(status, 'UNKNOWN')
        self.assertIn('証明書', detail)
        self.assertEqual(audit.classify({'state': 'accepted', 'detail': 'HTTP 200'}, True)[0], 'CONTROL_OK')
        self.assertEqual(audit.classify({'state': 'accepted', 'target_chain_verified': True})[0], 'ACTION')

    def test_client_results_do_not_confuse_proxy_or_unrelated_errors(self):
        for client in ('wget', 'httpie'):
            with self.subTest(client=client):
                self.assertEqual(audit.client_result(client, 0, 'HTTP/1.1 200 OK', '')['state'], 'accepted')
                self.assertEqual(audit.client_result(client, 1, '', 'HTTP/1.1 200 Connection established\nproxy failed')['state'], 'unknown')
                result = audit.client_result(client, 1, '', 'certificate verify failed: hostname mismatch')
                self.assertEqual(audit.classify(result)[0], 'UNKNOWN')
                result = audit.client_result(client, 1, '', 'certificate verify failed: unable to get local issuer certificate')
                self.assertEqual(audit.classify(result)[0], 'REJECTED')
                self.assertEqual(audit.client_result(client, 1, '', 'timed out')['state'], 'unknown')

    def test_subprocess_is_not_started_when_config_points_to_an_env_file(self):
        from unittest import mock
        with mock.patch.object(audit.subprocess, 'Popen') as popen:
            rc,out,err = audit.run(['/example/tool'], env={'PIP_CONFIG_FILE':'/example/.env.private'})
        self.assertNotEqual(rc, 0)
        self.assertIn('PIP_CONFIG_FILE', err)
        self.assertNotIn('/example/', err)
        popen.assert_not_called()

    def test_subprocess_can_avoid_inheriting_unrelated_credentials(self):
        import os, sys
        from unittest import mock
        with mock.patch.dict(os.environ, {'P2_PRIVATE_TOKEN':'not-for-the-child'}):
            rc,out,err = audit.run([sys.executable, '-B', '-c',
                'import os; print("leaked" if "P2_PRIVATE_TOKEN" in os.environ else "isolated"); '
                'print(os.environ.get("P2_ALLOWED", "missing"))'],
                env={'P2_ALLOWED':'visible'}, inherit_env=False)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines(), ['isolated', 'visible'])

    def test_subprocess_rejects_env_directory_in_a_ca_directory_list(self):
        import os
        from unittest import mock
        with mock.patch.object(audit.subprocess,'Popen') as popen:
            rc,out,err=audit.run(['/example/tool'],env={'SSL_CERT_DIR':'/safe/certs'+os.pathsep+'/private/.env.private'})
        self.assertNotEqual(rc,0)
        self.assertIn('SSL_CERT_DIR',err)
        popen.assert_not_called()

    def test_subprocess_rejects_env_symlink_hidden_in_ca_directory(self):
        from pathlib import Path
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'payload').write_text('fixture')
            (root/'.env.private').symlink_to(root/'payload')
            (root/'01234567.0').symlink_to(root/'.env.private')
            with mock.patch.object(audit.subprocess,'Popen') as popen:
                rc,_,_=audit.run(['/example/tool'],env={'SSL_CERT_DIR':str(root)},inherit_env=False)
            self.assertEqual(rc,126)
            popen.assert_not_called()

    def test_client_diagnostics_do_not_suggest_disabling_tls_checks(self):
        error = "ERROR: cannot verify certificate\nTo connect insecurely, use `--no-check-certificate'."
        result = audit.client_result('wget', 5, '', error)
        self.assertNotIn('--no-check-certificate', result['detail'])

    def test_wget_gnutls_unknown_issuer_is_not_confused_with_expiry(self):
        error = "ERROR: The certificate of 'localhost' is not trusted.\nERROR: The certificate's issuer is unknown."
        self.assertEqual(audit.classify(audit.client_result('wget', 5, '', error))[0], 'REJECTED')
        self.assertEqual(audit.classify(audit.client_result('wget', 5, '', error+'\ncertificate has expired'))[0], 'UNKNOWN')
