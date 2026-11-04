"""Offline regression tests. No connection to public test hosts."""
import os
import tempfile
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit

class ClassificationTests(unittest.TestCase):
    def result(self, text): return audit.classify({'state':'error','detail':text})[0]
    def test_accept_is_action_only_when_target_chain_is_verified(self): self.assertEqual(audit.classify({'state':'accepted','target_chain_verified':True})[0],'ACTION')
    def test_control_is_ok(self): self.assertEqual(audit.classify({'state':'accepted'},True)[0],'CONTROL_OK')
    def test_issuer_rejected(self): self.assertEqual(self.result('unable to get local issuer certificate'),'REJECTED')
    def test_untrusted_root(self): self.assertEqual(self.result('CERT_E_UNTRUSTEDROOT'),'REJECTED')
    def test_self_signed(self): self.assertEqual(self.result('self-signed certificate in certificate chain'),'REJECTED')
    def test_revoked(self): self.assertEqual(self.result('certificate revoked'),'REJECTED')
    def test_macos_pip_revoked(self):
        self.assertEqual(self.result("SSLCertVerificationError: ('“EM DV TLS CA - G3B” certificate is revoked',)"),'REJECTED')
    def test_macos_go_revoked(self):
        self.assertEqual(self.result('tls: failed to verify certificate: x509: “EM DV TLS CA - G3B” certificate is revoked'),'REJECTED')
    def test_unconfirmed_revocation_not_pass(self):
        for detail in ('certificate is not revoked', 'certificate revocation status unknown'):
            with self.subTest(detail=detail): self.assertEqual(self.result(detail),'UNKNOWN')
    def test_revoked_control_not_pass(self):
        self.assertEqual(audit.classify({'state':'error','detail':'certificate is revoked'},True)[0],'UNKNOWN')
    def test_revoked_with_expiry_not_pass(self):
        self.assertEqual(self.result('certificate is revoked; certificate has expired'),'UNKNOWN')
    def test_java_pkix(self): self.assertEqual(self.result('PKIX path building failed: unable to find valid certification path'),'REJECTED')
    def test_go_unknown_authority(self): self.assertEqual(self.result('x509: certificate signed by unknown authority'),'REJECTED')
    def test_expired_not_pass(self): self.assertEqual(self.result('certificate verify failed: certificate has expired'),'UNKNOWN')
    def test_java_expired_not_pass(self): self.assertEqual(self.result('PKIX path validation failed | CertificateExpiredException'),'UNKNOWN')
    def test_future_not_pass(self): self.assertEqual(self.result('certificate verify failed: not yet valid'),'UNKNOWN')
    def test_hostname_not_pass(self): self.assertEqual(self.result('CERTIFICATE_VERIFY_FAILED hostname mismatch'),'UNKNOWN')
    def test_ct_not_pass(self): self.assertEqual(self.result('certificate transparency required'),'UNKNOWN')
    def test_dns_not_pass(self): self.assertEqual(self.result('getaddrinfo ENOTFOUND'),'UNKNOWN')
    def test_timeout_not_pass(self): self.assertEqual(self.result('TIMEOUT'),'UNKNOWN')
    def test_handshake_not_pass(self): self.assertEqual(self.result('SSLHandshakeException: protocol_version'),'UNKNOWN')
    def test_control_cert_error_not_success(self): self.assertEqual(audit.classify({'state':'error','detail':'self-signed certificate'},True)[0],'UNKNOWN')
    def test_skip(self): self.assertEqual(audit.classify({'state':'skipped','detail':'missing'})[0],'SKIP')
    def test_unknown_code_not_pass(self): self.assertEqual(audit.classify({'state':'unknown','detail':'certificate verify failed'})[0],'UNKNOWN')
    def test_generic_and_non_trust_verification_failures_stay_unknown(self):
        for reason in ('certificate verify failed', 'CERTIFICATE_VERIFY_FAILED',
                       'certificate verify failed: unsuitable certificate purpose',
                       'certificate verify failed: certificate signature failure',
                       'certificate verify failed: EE certificate key too weak',
                       'RemoteCertificateChainErrors: NotValidForUsage'):
            with self.subTest(reason=reason): self.assertEqual(self.result(reason),'UNKNOWN')

    def test_structured_openssl_reason_is_authoritative(self):
        for code,expected in ((20,'REJECTED'),(23,'REJECTED'),(26,'UNKNOWN'),(10,'UNKNOWN'),(7,'UNKNOWN'),(999,'UNKNOWN')):
            with self.subTest(code=code):
                self.assertEqual(audit.classify({'state':'error','detail':'certificate verify failed',
                                                'verify_code':code})[0],expected)
    def test_negative_native_status_uses_specific_native_reason(self):
        self.assertEqual(audit.classify({'state':'error','detail':'証明書は信頼されていません',
                                        'verify_code':-25318})[0],'REJECTED')
        self.assertEqual(audit.classify({'state':'error','detail':'certificate verify failed',
                                        'verify_code':-1})[0],'UNKNOWN')

    def test_rejection_summary_is_plain_but_preserves_raw_sample_details(self):
        instance = audit.Audit(SimpleNamespace(offline=False, workers=1, project=None))
        self.addCleanup(instance.tmp.cleanup)
        def probe(url):
            if url == audit.TARGETS[0][1]:
                return {'state':'accepted', 'detail':'HTTP 200'}
            return {'state':'error', 'verify_code':20, 'detail':'unable to get local issuer certificate'}
        with mock.patch('builtins.print'):
            row = instance.sample('fixture', probe)
        self.assertEqual(row['status'], 'REJECTED')
        self.assertIn('検査用サイトへの接続をブロック', row['detail'])
        self.assertNotIn('信頼エラー', row['detail'])
        self.assertIn('unable to get local issuer certificate', row['samples'][1]['detail'])

class GitTests(unittest.TestCase):
    def test_404_after_tls_is_accept(self):
        s='=> Send header: GET /info/refs?service=git-upload-pack HTTP/1.1\n<= Recv header: HTTP/1.1 404 Not Found\nfatal: repository not found'
        self.assertEqual(audit.git_result(s,128)['state'],'accepted')
    def test_positive_expiry_log_not_error(self):
        s='server certificate expiration date OK\n=> Send header: GET /info/refs HTTP/1.1\n<= Recv header: HTTP/1.1 404 Not Found'
        self.assertEqual(audit.git_result(s,128)['state'],'accepted')
    def test_connect_alone_not_accept(self):
        s='=> Send header: CONNECT host:443 HTTP/1.1\n<= Recv header: HTTP/1.1 200 Connection established\nTLS error'
        self.assertEqual(audit.git_result(s,128)['state'],'unknown')
    def test_proxy_reject_not_accept(self):
        s='=> Send header: CONNECT host:443 HTTP/1.1\n<= Recv header: HTTP/1.1 403 Forbidden'
        self.assertEqual(audit.git_result(s,128)['state'],'unknown')
    def test_gnutls_signer_not_trusted(self):
        d=audit.git_result('server verification failed: certificate signer not trusted.',128)
        self.assertEqual(audit.classify(d)[0],'REJECTED')
    def test_h2(self):
        s='== Info: [HTTP/2] [1] [:method: GET]\n<= Recv header: HTTP/2 404'
        self.assertEqual(audit.git_result(s,128)['state'],'accepted')
    def test_git_expiry(self):
        s='fatal: server certificate verification failed. certificate has expired'
        data=audit.git_result(s,128)
        self.assertEqual(audit.classify(data)[0],'UNKNOWN')

class VersionTests(unittest.TestCase):
    def test_pip_old(self): self.assertEqual(audit.reference('pip','26.2.1')[0],'UPDATE')
    def test_pip_fixed(self): self.assertEqual(audit.reference('pip','26.2.2')[0],'REFERENCE_OK')
    def test_node_branch(self): self.assertEqual(audit.reference('node','v22.23.4')[0],'REFERENCE_OK')
    def test_node_old(self): self.assertEqual(audit.reference('node','v22.23.3')[0],'UPDATE')
    def test_unknown_node_branch(self): self.assertEqual(audit.reference('node','v28.1.0')[0],'MANUAL')
    def test_go(self): self.assertEqual(audit.reference('go','go version go1.26.10 linux/amd64')[0],'REFERENCE_OK')
    def test_old_go_branch_is_update_candidate(self):
        self.assertEqual(audit.reference('go','go version go1.23.0 darwin/amd64')[0],'UPDATE')
    def test_future_go_branch_is_not_assumed_patched(self):
        self.assertEqual(audit.reference('go','go version go1.28.0 darwin/amd64')[0],'MANUAL')
    def test_rust_other_branch(self): self.assertEqual(audit.reference('rustls-webpki','0.102.99')[0],'MANUAL')
    def test_prerelease(self): self.assertEqual(audit.reference('pip','26.2.2rc1')[0],'MANUAL')

class GitTargetSafetyTests(unittest.TestCase):
    url='https://example.com/'
    def test_unrelated_credentials_and_rewrite_allow_diagnostic(self):
        self.assertIsNone(audit.git_target_blocker(self.url, {'private.example'}, ['https://private.example/']))
    def test_matching_or_default_netrc_withholds_request(self):
        for hosts in ({'example.com'}, {'default'}):
            self.assertIsNotNone(audit.git_target_blocker(self.url, hosts, []))
    def test_netrc_hostname_case_cannot_bypass_guard(self):
        self.assertIsNotNone(audit.git_target_blocker(self.url, {'EXAMPLE.COM'}, []))
    def test_matching_rewrite_withholds_request(self):
        self.assertIsNotNone(audit.git_target_blocker(self.url, set(), ['https://']))
    def test_client_identity_withholds_request(self):
        self.assertIsNotNone(audit.git_target_blocker(self.url, set(), [], client_identity=True))
    def test_netrc_only_returns_hosts(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'netrc'
            path.write_text('machine private.example login alice password secret-value\n')
            hosts,failed=audit.netrc_targets([path])
            self.assertFalse(failed)
            self.assertEqual(hosts,{'private.example'})
    def test_unparseable_netrc_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'netrc'
            path.write_text('malformed secret-value\n')
            hosts,failed=audit.netrc_targets([path])
            self.assertTrue(failed)

class JavaBlocklistTests(unittest.TestCase):
    def check_blocklist(self,text):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder); (home/'lib/security').mkdir(parents=True)
            (home/'lib/security/blocked.certs').write_text(text,encoding='utf-8')
            return audit.java_blocklist(home, {'A'*64,'B'*64})[0]
    def test_all_reference_certificates_blocked(self):
        self.assertEqual(self.check_blocklist('Algorithm=SHA-256\n'+'A'*64+'\n'+'B'*64+'\n'),'REFERENCE_OK')
    def test_missing_reference_certificate_requires_update(self):
        self.assertEqual(self.check_blocklist('Algorithm=SHA-256\n'+'A'*64+'\n'),'UPDATE')
    def test_unknown_algorithm_remains_manual(self):
        self.assertEqual(self.check_blocklist('Algorithm=SHA-1\n'+'A'*64+'\n'+'B'*64+'\n'),'MANUAL')
    def test_bom_does_not_prove_java_loaded_the_list(self):
        self.assertEqual(self.check_blocklist('\ufeffAlgorithm=SHA-256\n'+'A'*64+'\n'+'B'*64+'\n'),'MANUAL')

class SafetyTests(unittest.TestCase):
    def test_redact_proxy(self): self.assertNotIn('secret',audit.redact('http://user:secret@proxy:8080'))
    def test_redact_header(self): self.assertNotIn('abc',audit.redact('Authorization: Bearer abc'))
    def test_redact_env(self):
        with mock.patch.dict(os.environ,{'MY_API_KEY':'private-value-456'}):
            self.assertNotIn('private-value-456',audit.redact('error private-value-456'))
    def test_parse_missing_json_is_unknown(self): self.assertEqual(audit.parse_probe('some log','err',1)['state'],'unknown')
    def test_parse_noise(self): self.assertEqual(audit.parse_probe('noise\nEMUDHRA_JSON:{"state":"accepted"}')['state'],'accepted')
    def test_html_escape(self):
        row={'name':'<script>','status':'UNKNOWN','detail':'<img src=x>','action':'','metadata':{},'samples':[]}
        result=audit.render_report([row],'now')
        self.assertNotIn('<img src=x>',result)
    def test_docker_env_passed_inside(self):
        with mock.patch.object(audit,'run',return_value=(0,'','')) as call:
            c=audit.Context(['docker','exec','dev'])
            c.call(['git','--version'],env={'GIT_TRACE_CURL':'1'})
            command=call.call_args[0][0]
            self.assertIn('GIT_TRACE_CURL=1',command)
            self.assertLess(command.index('GIT_TRACE_CURL=1'),command.index('dev'))
    def test_no_plain_http_targets(self): self.assertTrue(all(u.startswith('https://') for _,u,_ in audit.TARGETS))

if __name__=='__main__': unittest.main(verbosity=2)
