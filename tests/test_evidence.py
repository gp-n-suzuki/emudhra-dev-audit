"""Evidence must remain distinct from an application's measured TLS result."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit
import evidence


def crlset(pins, **extra):
    header = dict(Version=0, ContentType='CRLSet', Sequence=12, DeltaFrom=0,
                  BlockedSPKIs=[base64.b64encode(bytes.fromhex(p)).decode() for p in pins])
    header.update(extra)
    data = json.dumps(header).encode()
    return struct.pack('<H', len(data)) + data


class EvidenceTests(unittest.TestCase):
    def test_browser_permission_denial_is_explicit_uncertainty(self):
        with mock.patch.object(evidence.sys,'platform','darwin'), mock.patch.object(Path,'iterdir',side_effect=PermissionError):
            findings=evidence.browser_evidence([],{'tls_spki_sha256':['ab'*32]})
        self.assertEqual(len(findings),2)
        self.assertTrue(all(f['status']=='UNKNOWN' and '権限' in f['detail'] for f in findings))

    def test_crlset_matching_keys_is_static_evidence_only(self):
        result = evidence.crlset_evidence(crlset(['ab'*32]), ['AB'*32], now=100)
        self.assertEqual(result['status'], 'REFERENCE_OK')
        self.assertEqual(result['matched'], 1)
        self.assertEqual(result['kind'], 'static')
        self.assertIn('適用中', result['detail'])

    def test_crlset_missing_key_does_not_prove_browser_vulnerability(self):
        result = evidence.crlset_evidence(crlset([]), ['ab'*32], now=100)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(result['matched'], 0)

    def test_crlset_expired_malformed_and_empty_reference_cannot_pass(self):
        cases = [(crlset(['ab'*32], NotAfter=99), ['ab'*32]),
                 (crlset(['ab'*32], Version=1), ['ab'*32]),
                 (b'\x02\x00[]', ['ab'*32]),
                 (crlset(['ab'*32], NotAfter=float('nan')), ['ab'*32]),
                 (crlset(['ab'*32], Sequence=-1), ['ab'*32]),
                 (crlset(['ab'*32])+b'broken-body', ['ab'*32]),
                 (crlset(['ab'*32]), [])]
        for raw, pins in cases:
            with self.subTest(raw=raw):
                self.assertEqual(evidence.crlset_evidence(raw,pins,now=100)['status'],'UNKNOWN')

    def test_bundle_absence_is_not_live_rejection(self):
        pem='-----BEGIN CERTIFICATE-----\n'+base64.b64encode(b'fixture-der').decode()+'\n-----END CERTIFICATE-----\n'
        result=evidence.bundle_evidence(pem,['ab'*32])
        self.assertEqual(result['status'],'UNKNOWN')
        self.assertEqual(result['matched'],0)
        self.assertIn('判断できません',result['detail'])
        self.assertEqual(result['kind'],'static')
        self.assertIn('ファイル',result['detail'])

    def test_bundle_presence_or_empty_input_does_not_prove_a_connection(self):
        der=b'fixture-der'
        pem='-----BEGIN CERTIFICATE-----\n'+base64.b64encode(der).decode()+'\n-----END CERTIFICATE-----\n'
        self.assertEqual(evidence.bundle_evidence(pem,[hashlib.sha256(der).hexdigest()])['status'],'UNKNOWN')
        self.assertEqual(evidence.bundle_evidence('', ['ab'*32])['status'],'UNKNOWN')

    def test_version_inference_handles_old_fixed_and_preview(self):
        for version, status in [('4.96.1','UPDATE'),('4.96.3','REFERENCE_OK'),('4.96.3-rc.1','UNKNOWN'),('5.0.0','UNKNOWN')]:
            with self.subTest(version=version):
                result=evidence.version_evidence('Docker Desktop',version,'4.96.2','https://vendor.example/')
                self.assertEqual(result['status'],status)
                self.assertEqual(result['kind'],'version')

    def test_project_scan_is_bounded_and_ignores_private_and_build_trees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for folder in ('app','target','node_modules'):
                (root/folder).mkdir(); (root/folder/'Cargo.lock').write_text('')
            (root/'.env.private').symlink_to(root/'app',target_is_directory=True)
            (root/'link').symlink_to(root/'app',target_is_directory=True)
            paths, truncated=evidence.project_inventory(root)
            self.assertEqual([p.relative_to(root).as_posix() for p in paths],['app/Cargo.lock'])
            self.assertFalse(truncated)
            _,truncated=evidence.project_inventory(root,max_dirs=1)
            self.assertTrue(truncated)

    def test_configured_file_cannot_point_to_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'payload').write_text('fixture')
            (root/'.env.secret').symlink_to(root/'payload')
            (root/'ca.pem').symlink_to(root/'.env.secret')
            self.assertIsNone(evidence.read_public_file(root/'ca.pem'))

    def test_every_intermediate_symlink_target_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'payload').write_text('fixture')
            (root/'.env.private').symlink_to(root/'payload')
            (root/'alias').symlink_to(root/'.env.private')
            self.assertIsNone(evidence.read_public_file(root/'alias'))
            self.assertFalse(audit.app_inventory.safe(root/'alias'))

    def test_evidence_is_visible_but_does_not_replace_unknown(self):
        row={'name':'PHP','status':'UNKNOWN','detail':'certificate verify failed','metadata':{},'samples':[],'action':'',
             'evidence':[{'check':'CA file','kind':'static','status':'REFERENCE_OK','detail':'<fixture> absent'}]}
        rendered=audit.render_report([row],'now')
        self.assertNotIn('証明書データは対応済み',rendered)
        self.assertNotIn('class="STATIC_OK"',rendered)
        self.assertIn('&lt;fixture&gt; absent',rendered)
        self.assertNotIn('<fixture>',rendered)
        self.assertIn('<section class="UNKNOWN" data-review="unverified"',rendered)

    def test_promoted_update_is_visible_in_summary_and_attention_filter(self):
        row={'name':'Rust','status':'MANUAL','detail':'unmeasured','metadata':{},'samples':[],'action':'',
             'evidence':[{'check':'rustup','kind':'version','status':'UPDATE','detail':'old release'}]}
        rendered=audit.render_report([row],'now')
        self.assertIn('更新が必要: 1ツール',rendered)
        self.assertIn('data-review="action"',rendered)
        self.assertIn('data-filter="update"',rendered)


if __name__ == '__main__': unittest.main(verbosity=2)
