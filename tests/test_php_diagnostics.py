import unittest
from unittest import mock
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit
import php_diagnostics


class PHPDiagnosticsTests(unittest.TestCase):
    def test_native_japanese_trust_error_and_expiry_are_distinct(self):
        data=dict(state='error',detail='SSLCertVerificationError: “localhost”証明書は信頼されていません')
        self.assertEqual(audit.classify(data)[0],'REJECTED')
        data['detail']+=': 証明書の有効期限が切れています'
        self.assertEqual(audit.classify(data)[0],'UNKNOWN')

    def test_mismatched_library_and_unavailable_ca_stay_unknown(self):
        data=dict(state='unknown',detail='certificate verify failed',openssl_version='OpenSSL 4.0.3 29 Sep 2026',
                  ca_locations={'ini_cafile':'/missing/ca.pem'})
        runner=mock.Mock()
        self.assertEqual(php_diagnostics.corroborate(data,audit.TARGETS[1][1],4,runner)['state'],'unknown')
        runner.assert_not_called()
        runner.return_value=(0,'OpenSSL 3.5.9 29 Sep 2026','')
        with mock.patch.object(php_diagnostics.Path,'is_file',return_value=True):
            self.assertIsNone(php_diagnostics.matching_openssl(data['openssl_version'],runner))

    def test_reproduction_errors_and_acceptance_never_become_inference(self):
        data=dict(state='unknown',detail='certificate verify failed',openssl_version='OpenSSL 4.0.3 29 Sep 2026')
        for rc,error in ((1,'verify error:num=10:certificate has expired'),(1,'verify error:num=62:hostname mismatch'),
                         (0,'Verification: OK'),(124,'verify error:num=20:unable to get local issuer certificate'),
                         (1,'connection refused')):
            with self.subTest(error=error), mock.patch.dict('os.environ',{},clear=True), \
                    mock.patch.object(php_diagnostics,'ca_arguments',return_value=[]), \
                    mock.patch.object(php_diagnostics,'matching_openssl',return_value='/test/openssl'):
                result=php_diagnostics.corroborate(data,audit.TARGETS[1][1],4,mock.Mock(return_value=(rc,'',error)))
                self.assertEqual(result['state'],'unknown')

    def test_proxy_configuration_prevents_comparison_of_different_routes(self):
        data=dict(state='unknown',detail='certificate verify failed')
        runner=mock.Mock()
        with mock.patch.dict('os.environ',{'HTTPS_PROXY':'http://proxy.invalid'}):
            self.assertEqual(php_diagnostics.corroborate(data,audit.TARGETS[1][1],4,runner),data)
        runner.assert_not_called()

    def test_env_file_is_never_used_as_a_ca_bundle(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'.env'
            self.assertIsNone(php_diagnostics.ca_arguments({'ini_cafile':str(path)}))

    def test_ca_directory_cannot_hide_an_env_alias_in_a_symlink_chain(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'payload').write_text('fixture')
            (root/'.env.secret').symlink_to(root/'payload')
            (root/'01234567.0').symlink_to(root/'.env.secret')
            self.assertIsNone(php_diagnostics.ca_arguments({'ini_capath':str(root)}))

    def test_inference_is_distinct_from_measured_rejection(self):
        status,_=audit.classify(dict(state='inferred_rejection',detail='same CA repro'))
        self.assertEqual(status,'INFERRED_REJECTED')
        self.assertEqual(audit.classify(dict(state='inferred_rejection'),True)[0],'UNKNOWN')

    def test_inferred_samples_keep_parent_inferred(self):
        import contextlib,io,tempfile,json
        from types import SimpleNamespace
        args=SimpleNamespace(offline=False,timeout=4,workers=1,project=Path.cwd())
        with contextlib.redirect_stdout(io.StringIO()):
            instance=audit.Audit(args)
            try:
                instance.sample('PHP',lambda url:dict(state='accepted' if url==audit.TARGETS[0][1] else 'inferred_rejection',detail='fixture'))
                with tempfile.TemporaryDirectory() as tmp:
                    audit.write_reports(instance,Path(tmp))
                    r=json.loads((Path(tmp)/'report.json').read_text(encoding='utf-8'))['records'][0]
                self.assertEqual(r['status'],'INFERRED_REJECTED')
                self.assertEqual(r['assessment_method'],'corroborated')
                self.assertEqual(r['review_state'],'complete')
            finally: instance.tmp.cleanup()

if __name__=='__main__': unittest.main(verbosity=2)
