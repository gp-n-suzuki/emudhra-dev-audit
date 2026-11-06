"""Saved product versions are scoped evidence, never replacement TLS observations."""
import copy
import json
from pathlib import Path
import unittest
import contextlib
import io
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import audit
import reporting
import verdicts


FIXTURE = Path(__file__).parent/'fixtures/safechain-2.7.6.json'
HASH_OLD = '9a162f410c74ebf27121ac44bf99097c06829a02bdf311f1b95f5c2bda66d088'
HASH_FIXED = '1a51dde4a747d4cc3cc9fbee744322b805e9b3a99adba50173b248e315e9fa49'


def captured(version='1.5.26', digest=None, **security):
    app = json.loads(FIXTURE.read_text())[0]
    app['metadata']['security_tool'].update(version=version, **security)
    if digest is not None:
        app['metadata']['security_tool']['binary_sha256'] = digest
    return app


def product(rows):
    return next(r for r in verdicts.prepare(rows) if r['metadata'].get('product_release_evidence'))


class ReleaseEvidenceTests(unittest.TestCase):
    def test_catalog_is_utf8_even_when_default_text_encoding_is_legacy_windows(self):
        import release_evidence
        original_read = Path.read_text
        for encoding in ('cp932','cp1252'):
            def legacy_read(path, *args, **kwargs):
                kwargs.setdefault('encoding',encoding)
                return original_read(path,*args,**kwargs)
            with self.subTest(encoding=encoding), patch.object(Path,'read_text',legacy_read):
                release_evidence.policy.cache_clear()
                self.assertEqual(verdicts.prepare([]),[])
                self.assertEqual(release_evidence.policy()['known_fixed_versions'],['1.5.27'])
        release_evidence.policy.cache_clear()

    def test_saved_safechain_record_requires_the_official_binary_update(self):
        records = json.loads(FIXTURE.read_text())
        original = copy.deepcopy(records)
        actual = verdicts.prepare(records)
        updates = [r for r in actual if r['status'] == 'UPDATE']
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]['metadata']['assessed_version'], '1.5.26')
        self.assertEqual(updates[0]['metadata']['reference_floor'], '1.5.27')
        self.assertEqual(updates[0]['metadata']['evidence_origin'], 'derived-from-recorded-evidence')
        self.assertFalse(updates[0]['metadata']['new_observation'])
        self.assertEqual(updates[0]['review_state'], 'action')
        self.assertEqual(reporting.group_tools(actual)[0][0]['state'], 'action')
        self.assertTrue(any(r.get('metadata', {}).get('p2_coverage') and
                            r['review_state'] == 'unverified' for r in actual))
        self.assertEqual(records, original)
        self.assertEqual(actual, verdicts.prepare(actual))
        self.assertEqual([r['samples'] for r in actual if r['samples']], [])

    def test_exact_official_binary_releases_and_raw_version_preservation(self):
        for text, digest, expected in [('1.5.26', HASH_OLD, 'UPDATE'),
                                      ('1.5.27', HASH_FIXED, 'INFERRED_OK'),
                                      (' v1.5.27 ', HASH_FIXED, 'INFERRED_OK')]:
            with self.subTest(text=text):
                result = product([captured(text, digest)])
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['metadata']['version'], text)
                self.assertIsNone(result['metadata']['first_fixed_version'])
        for text in ('1.5.25', '1.5.28', '2.0.0', '', '1.5.27-rc.1',
                     '1.5.27+custom', '01.5.27', 'release 1.5.27', '1.5', '1.5.27\nother', 27):
            with self.subTest(text=text):
                self.assertEqual(product([captured(text, HASH_FIXED)])['status'], 'MANUAL')

    def test_unknown_distribution_is_review_without_guessing_from_path(self):
        result = product([captured()])
        self.assertEqual(result['status'], 'MANUAL')
        self.assertEqual(result['review_state'], 'review')
        self.assertEqual(result['metadata']['release_distribution'], 'unknown')

    def test_npm_and_custom_builds_do_not_inherit_the_bundled_node_fix(self):
        for extra in ({'runtime': 'node (PATH)', 'version_source': 'package.json'},
                      {'distribution': 'custom'}, {'distribution': 'npm'}):
            with self.subTest(extra=extra):
                result = product([captured('1.5.27', HASH_FIXED, **extra)])
                self.assertEqual(result['status'], 'MANUAL')
        # A patched Node elsewhere is not this executable's runtime.
        node = dict(name='Node.js / バージョン', status='INFO', detail='', action='', samples=[],
                    assessment_method='inventory', metadata=dict(tool_id='node', tool_name='Node.js',
                    executable='/unrelated/node', version='26.12.1'))
        self.assertEqual(product([captured('1.5.26', runtime='node (PATH)'), node])['status'], 'MANUAL')

    def test_saved_probe_cannot_supply_other_installations_or_containers(self):
        for key, value in [('executable', '/other/safe-chain'), ('execution_context', 'container:one')]:
            rows = json.loads(FIXTURE.read_text())
            rows[1]['metadata'][key] = value
            with self.subTest(key=key):
                self.assertEqual(product(rows)['status'], 'MANUAL')
        rows = json.loads(FIXTURE.read_text())
        rows[1]['metadata']['synthetic_tls_state'] = 'partial'
        self.assertEqual(product(rows)['status'], 'MANUAL')

    def test_conflicting_recorded_versions_and_hashes_are_not_upgraded(self):
        app = captured('1.5.26', HASH_FIXED)
        self.assertEqual(product([app])['status'], 'MANUAL')

    def test_distribution_conflict_and_unknown_recorded_hash_block_legacy_inference(self):
        rows = json.loads(FIXTURE.read_text())
        rows[0]['metadata']['security_tool']['binary_sha256'] = '0'*64
        self.assertEqual(product(rows)['status'], 'MANUAL')
        first = captured('1.5.27', HASH_FIXED)
        conflicting = captured('1.5.27', distribution='custom')
        for records in ([first, conflicting], [conflicting, first]):
            with self.subTest(order=records[0]['metadata']['security_tool']):
                actual = product(records)
                self.assertEqual(actual['status'], 'MANUAL')
                self.assertEqual(actual['metadata']['release_distribution'], 'conflict')
        app = captured('1.5.27', HASH_FIXED)
        app['metadata']['application_version'] = '1.5.26'
        self.assertEqual(product([app])['status'], 'MANUAL')

    def test_fixed_binary_keeps_measured_failure_and_disabled_verification(self):
        for method in ('measured', 'configuration'):
            bad = dict(name='Safe Chain / independent finding', status='ACTION', detail='captured issue',
                       action='review', assessment_method=method,
                       metadata=dict(tool_id='safe-chain', tool_name='Safe Chain', executable='/fixture/.safe-chain/bin/safe-chain'),
                       samples=[dict(target='fixture', status='ACTION', detail='accepted')] if method=='measured' else [])
            before = copy.deepcopy(bad)
            actual = verdicts.prepare([captured('1.5.27', HASH_FIXED), bad])
            self.assertEqual(reporting.group_tools(actual)[0][0]['state'], 'action')
            self.assertEqual(next(r for r in actual if r['name']==bad['name'])['samples'], bad['samples'])
            self.assertEqual(bad, before)

    def test_saved_safechain_json_and_html_keep_version_and_unmeasured_separate(self):
        rows = json.loads(FIXTURE.read_text())
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=rows), Path(tmp))
            result = json.loads((Path(tmp)/'report.json').read_text())
            html = (Path(tmp)/'report.html').read_text()
        derived = next(r for r in result['records'] if r['metadata'].get('product_release_evidence'))
        self.assertEqual(derived['status'], 'UPDATE')
        self.assertIn('公式対策バージョン未満', html)
        self.assertIn('1.5.27', html)
        self.assertIn('普段の設定', html)
        self.assertEqual(result['summary']['tool_review_counts']['action'], 1)

    def test_other_aikido_products_do_not_match_safechain(self):
        for name in ('endpoint', 'noon'):
            app = captured('1.5.27', HASH_FIXED)
            app['metadata']['tool_id'] = name
            self.assertFalse(any(r['metadata'].get('product_release_evidence') for r in verdicts.prepare([app])))

    def test_reassessment_discloses_old_observation_date_and_no_new_traffic(self):
        origin = dict(generated_at='2026-11-02T12:08:18+09:00', sha256='b82221b4', new_network_requests=False)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=[captured()], source_observation=origin), Path(tmp))
            result = json.loads((Path(tmp)/'report.json').read_text())
            html = (Path(tmp)/'report.html').read_text()
            summary = (Path(tmp)/'summary.txt').read_text()
        self.assertEqual(result['source_observation'], origin)
        for text in (html, summary):
            self.assertIn('取得済み記録の再判定', text)
            self.assertIn(origin['generated_at'], text)
            self.assertIn('新規の通信検査は実施していません', text)


if __name__ == '__main__':
    unittest.main()
