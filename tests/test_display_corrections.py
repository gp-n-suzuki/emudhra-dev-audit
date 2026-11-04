"""Six scoped presentation corrections, using synthetic saved-record shapes."""
import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import unittest

import presentation
import remediation
import reporting
import verdicts
from test_action_presentation import export, record


FIXTURE = {x['display_number']: x['record'] for x in json.loads(
    (Path(__file__).parent/'fixtures/display-corrections-2.7.8.json').read_text(encoding='utf-8'))}
RETRY_NOTE = '証明書エラーを観測した後、再試行中にタイムアウト。検査は完了していない'


def saved(*numbers):
    return [copy.deepcopy(FIXTURE[n]) for n in numbers]


def model(rows):
    # These records are already canonical; preserve the deliberately supplied
    # grouping identities and JSON-array order while testing the projection.
    return reporting.action_model([verdicts.finish(r) for r in copy.deepcopy(rows)])


class Headings(HTMLParser):
    def __init__(self):
        super().__init__()
        self.current = None
        self.heading = False
        self.headings = {}
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id', '').startswith('item-'):
            self.current = attrs['id']
        if tag in ('h3', 'h4') and self.current:
            self.heading = True
            self.headings.setdefault(self.current, '')
    def handle_data(self, data):
        if self.heading:
            self.headings[self.current] += data
    def handle_endtag(self, tag):
        if tag in ('h3', 'h4'): self.heading = False
        if tag == 'section': self.current = None


class DisplayCorrectionTests(unittest.TestCase):
    def test_bundler_action_never_recommends_bun_or_deno(self):
        report, page, text, console = export(saved(10, 163, 473))
        remedy = report['records'][0]['remediation']
        self.assertIn('Bundler', remedy['title'])
        for output in (json.dumps(remedy, ensure_ascii=False), page, text, console):
            self.assertNotIn('Bun・Deno', output)
        self.assertEqual(report['records'][0]['status'], 'ACTION')

    def test_actual_bun_and_deno_still_receive_runtime_guidance(self):
        for name in ('Bun', 'Deno'):
            row = verdicts.prepare([record('UPDATE', name=name, version='1.0', reference_floor='2.0')])[0]
            self.assertIn('実行環境', remediation.plan(row)['title'])

    def test_own_go_guidance_is_not_embedded_application_guidance(self):
        report, page, text, console = export(saved(30, 253))
        remedy = report['records'][0]['remediation']
        self.assertIn('Go本体', remedy['title'])
        self.assertIn('1.23.0', remedy['reference'])
        self.assertIn('1.26.10', remedy['reference'])
        self.assertNotIn('同梱', json.dumps(remedy, ensure_ascii=False))
        self.assertNotIn('削除', json.dumps(remedy, ensure_ascii=False))
        self.assertEqual(reporting.result_label(report['records'][0], reporting.STATUS_LABELS), 'Go本体が対策版未満')
        self.assertNotIn('同梱Go', reporting.application_details(report['records'][0]))
        tool = report['presentation']['tools'][0]
        self.assertEqual(tool['primary_action'], 'update')
        self.assertTrue(any(x.get('failure') == 'cpu_mismatch' for x in tool['communication']))
        for output in (page, text, console): self.assertIn('CPU', output)

    def test_embedded_go_does_not_inherit_toolchain_guidance(self):
        row = saved(30)[0]
        row['metadata'].update(tool_id='example', tool_name='Example', path='/Applications/Example')
        row['name'] = 'アプリ / Example'
        row['metadata']['inspections'][0]['path'] = '/Applications/Example'
        remedy = remediation.plan(row)
        self.assertNotIn('Go本体', remedy['title'])
        self.assertIn('同梱', ' '.join(remedy['steps']))

    def test_bundler_saved_version_and_probe_replace_only_generic_fallbacks(self):
        rows = saved(163, 473, 10, 278)
        before = copy.deepcopy(rows)
        data = model(rows)
        unit = data['tools'][0]['units'][0]
        self.assertFalse(any(x['state'] == 'missing' for x in unit['version']))
        self.assertFalse(any(x['state'] == 'not_run' and x['record_indices'] == [0] for x in unit['communication']))
        self.assertTrue(any(x['state'] == 'not_run' and x['record_indices'] == [3] for x in unit['communication']))
        self.assertTrue(any(x['state'] == 'problem' for x in unit['communication']))
        self.assertTrue(any('一部の検査先' in x['reason'] for x in unit['gaps']))
        self.assertTrue(any('実効CA' in x['reason'] for x in unit['gaps']))
        self.assertIn('missing', [x['state'] for x in data['records'][0]['version']])
        self.assertEqual(rows, before)
        self.assertEqual(unit['record_indices'], list(range(4)))

    def test_saved_unambiguous_aliases_reconcile_rubygems_and_homebrew_bundler(self):
        for numbers in ((137, 469, 65, 270), (129, 471, 274, 275)):
            data = model(saved(*numbers))
            unit = data['tools'][0]['units'][0]
            self.assertFalse(any(x['state'] == 'missing' for x in unit['version']))
            self.assertFalse(any(x['state'] == 'not_run' and x['record_indices'] == [0] for x in unit['communication']))
            self.assertTrue(any(x['state'] == 'not_run' and x['record_indices'] == [3] for x in unit['communication']))
            self.assertIn('investigate', unit['actions'])

    def test_node_launcher_evidence_keeps_app_specific_ca_unchecked(self):
        data = model(saved(92, 47, 48, 49))
        unit = data['tools'][0]['units'][0]
        self.assertFalse(any(x['state'] == 'missing' for x in unit['version']))
        self.assertFalse(any(x['state'] == 'not_run' and x['record_indices'] == [0] for x in unit['communication']))
        self.assertTrue(any(x['state'] == 'rejected' for x in unit['communication']))
        self.assertTrue(any('実効CA' in x['reason'] for x in unit['gaps']))
        self.assertEqual(unit['primary_action'], 'investigate')

    def test_version_alone_does_not_suppress_unmeasured_communication(self):
        unit = model(saved(163, 473))['tools'][0]['units'][0]
        self.assertFalse(any(x['state'] == 'missing' for x in unit['version']))
        self.assertIn('not_run', [x['state'] for x in unit['communication']])

    def test_probe_alone_does_not_supply_a_version(self):
        unit = model(saved(163, 10))['tools'][0]['units'][0]
        self.assertIn('missing', [x['state'] for x in unit['version']])

    def test_group_identity_alone_never_overrides_different_paths_contexts_or_venvs(self):
        for change in ('path', 'context', 'venv', 'ruby'):
            with self.subTest(change=change):
                rows = saved(163, 473, 10)
                for row in rows: row['metadata']['result_identity'] = ['bundler', '/forced-group']
                if change == 'path':
                    for row in rows[1:]: row['metadata']['executable'] = '/other/bundle'
                elif change == 'context':
                    for row in rows[1:]: row['metadata']['execution_context'] = 'コンテナ separate'
                elif change == 'venv':
                    rows[0]['metadata']['prefix'] = '/venv/one'
                    for row in rows[1:]: row['metadata']['prefix'] = '/venv/two'
                else:
                    rows[0]['metadata']['runtime_executable'] = '/other/ruby'
                    rows[1]['metadata']['runtime_executable'] = '/probe/ruby'
                unit = model(rows)['tools'][0]['units'][0]
                self.assertIn('missing', [x['state'] for x in unit['version']])
                self.assertTrue(any(x['state'] == 'not_run' and x['record_indices'] == [0] for x in unit['communication']))

    def test_ambiguous_alias_is_not_reconciled(self):
        rows = saved(163, 473, 10)
        other = copy.deepcopy(rows[0])
        other['metadata']['path'] = '/other/bundle'
        other['metadata']['discovered_paths'] = [rows[0]['metadata']['path']]
        rows.append(other)
        for row in rows: row['metadata']['result_identity'] = ['bundler', '/forced-group']
        unit = model(rows)['tools'][0]['units'][0]
        self.assertIn('missing', [x['state'] for x in unit['version']])
        self.assertTrue(any(x['state'] == 'not_run' and 0 in x['record_indices'] for x in unit['communication']))
        self.assertEqual(unit['fallback_resolutions'], [])

    def test_conflicting_versions_and_explicit_failure_stay_visible(self):
        rows = saved(163, 473, 10)
        conflict = copy.deepcopy(rows[1]); conflict['metadata']['version'] = 'Bundler version 4.0.20'
        failed = copy.deepcopy(rows[1]); failed.update(status='UNKNOWN', detail='明示的な取得失敗')
        failed['metadata']['version'] = ''
        unit = model(rows+[conflict, failed])['tools'][0]['units'][0]
        self.assertIn('missing', [x['state'] for x in unit['version']])
        self.assertTrue(any('明示的な取得失敗' in x['reason'] for x in unit['gaps']))
        self.assertTrue(any(x['state'] == 'problem' for x in unit['communication']))

    def test_bundle_and_bundler_installations_are_not_merged(self):
        data = model(saved(163, 473, 171, 474))
        self.assertEqual(len(data['tools'][0]['units']), 2)

    def test_explicit_discovery_failure_and_lower_configuration_action_are_retained(self):
        rows = saved(163, 473, 10)
        rows[0]['detail'] = '明示的な取得失敗：読み取り権限がありません'
        unit = model(rows)['tools'][0]['units'][0]
        self.assertTrue(any('明示的な取得失敗' in x['reason'] for x in unit['gaps']))
        self.assertIn('missing', [x['state'] for x in unit['version']])
        rows = saved(163, 473, 10)
        rows[0]['metadata']['inspections'] = [dict(component='TLS設定', status='ACTION', method='configuration', detail='検証無効')]
        unit = model(rows)['tools'][0]['units'][0]
        self.assertIn('configure', unit['actions'])
        self.assertEqual(unit['fallback_resolutions'], [])

    def test_saved_venv_metadata_is_not_a_shared_interpreter_identity(self):
        rows = saved(163, 473, 10)
        for row in rows:
            row['metadata'].update(tool_id='python', tool_name='Python', result_identity=['python','/shared/python'])
        rows[0]['metadata']['python_environment'] = dict(prefix='/venv/one', interpreter='/shared/python')
        for row in rows[1:]: row['metadata']['python_environment'] = dict(prefix='/venv/two', interpreter='/shared/python')
        unit = model(rows)['tools'][0]['units'][0]
        self.assertIn('missing', [x['state'] for x in unit['version']])
        self.assertEqual(unit['fallback_resolutions'], [])

    def test_saved_probe_body_versions_are_visible_without_new_fix_claims(self):
        for probe, discovery in ((40,173), (38,165), (39,202), (62,136), (63,130), (244,120), (246,172)):
            with self.subTest(probe=probe):
                rows = saved(probe, discovery)
                raw_version = rows[0]['metadata']['version']
                expected = raw_version[0] if isinstance(raw_version, list) else raw_version
                report, page, text, console = export(rows)
                tool = report['presentation']['tools'][0]
                found = [v for v in tool['version'] if v.get('version') == expected]
                self.assertTrue(found, expected)
                self.assertTrue(all(v['state'] == 'observed' and v['target'] == 'application' and not v['reference_floor'] for v in found))
                self.assertFalse(any(v['state'] == 'missing' for v in tool['version']))
                self.assertFalse(any('本体版は未取得です' in g['reason'] for g in tool['gaps']))
                self.assertTrue(any(r['status'] == rows[0]['status'] and r['metadata'].get('version') == raw_version for r in report['records']))
                if rows[0]['status'] == 'UNKNOWN':
                    self.assertIn('indeterminate', [e['state'] for e in tool['communication']])
                for output in (page, text, console): self.assertIn(expected, output)

    def test_error_text_in_probe_version_field_is_not_a_body_version(self):
        unit = model(saved(220, 211))['tools'][0]['units'][0]
        self.assertFalse(any(v['state'] == 'observed' for v in unit['version']))
        self.assertIn('missing', [v['state'] for v in unit['version']])
        self.assertEqual(unit['fallback_resolutions'], [])
        self.assertTrue(any(e.get('failure') == 'cpu_mismatch' for e in unit['communication']))

    def test_manual_and_failed_version_claims_still_block_conflicting_fallbacks(self):
        for status, method in ((status, method) for status in ('MANUAL', 'UNKNOWN', 'SKIP') for method in ('version', 'manual')):
            with self.subTest(status=status, method=method):
                rows = saved(163, 473, 10)
                conflict = copy.deepcopy(rows[1])
                conflict.update(status=status, assessment_method=method, detail='別の取得済み版・対応状況未照合')
                conflict['metadata']['version'] = '4.0.20'
                unit = model(rows+[conflict])['tools'][0]['units'][0]
                self.assertEqual(unit['fallback_resolutions'], [])
                self.assertIn('missing', [v['state'] for v in unit['version']])
                self.assertTrue(any(e['state'] == 'not_run' and 0 in e['record_indices'] for e in unit['communication']))
                if method == 'version':
                    self.assertTrue(any(v['version'] == '4.0.20' for v in unit['version']))

    def test_discovery_body_claims_participate_in_conflict_detection(self):
        for field in ('version', 'application_version', 'security_tool', 'internal_conflict'):
            with self.subTest(field=field):
                rows = saved(163, 473, 10)
                if field == 'security_tool':
                    rows[0]['metadata'][field] = dict(version='4.0.20')
                elif field == 'internal_conflict':
                    rows[0]['metadata'].update(application_version='Bundler version 1.17.2', version='4.0.20')
                else:
                    rows[0]['metadata'][field] = '4.0.20'
                unit = model(rows)['tools'][0]['units'][0]
                self.assertEqual(unit['fallback_resolutions'], [])
                self.assertTrue(any(e['state'] == 'not_run' and 0 in e['record_indices'] for e in unit['communication']))

    def test_component_runtime_version_cannot_replace_missing_application_version(self):
        rows = saved(163, 473)
        rows[1].update(status='UNKNOWN', assessment_method='measured')
        rows[1]['metadata'].update(runtime_component='node', version='24.22.1', runtime_version='24.22.1')
        unit = model(rows)['tools'][0]['units'][0]
        self.assertIn('missing', [v['state'] for v in unit['version']])
        self.assertEqual(unit['fallback_resolutions'], [])

    def test_certificate_retry_timeout_is_annotated_without_promoting_unknown(self):
        for number in (274, 276):
            report, page, text, console = export(saved(number))
            row = report['records'][0]
            self.assertEqual(row['status'], 'UNKNOWN')
            self.assertEqual([x['status'] for x in row['samples']], [x['status'] for x in FIXTURE[number]['samples']])
            communication = report['presentation']['tools'][0]['communication']
            self.assertTrue(any(RETRY_NOTE in x['reason'] for x in communication))
            annotation = next(x for x in communication if RETRY_NOTE in x['reason'])
            self.assertEqual(annotation['state'], 'indeterminate')
            self.assertEqual(annotation['sample_indices'], [3])
            self.assertNotIn('checked', report['presentation']['tools'][0]['actions'])
            for output in (page, text, console): self.assertIn(RETRY_NOTE, output)

    def test_retry_annotation_never_crosses_samples_or_tools(self):
        base = saved(274)[0]
        for samples in ([dict(status='UNKNOWN', detail='TIMEOUT: waiting')],
                        [dict(status='UNKNOWN', detail='TIMEOUT: waiting'), dict(status='UNKNOWN', detail='Retrying fetcher due to error (2/4): Bundler::Fetcher::CertificateFailureError')],
                        [dict(status='UNKNOWN', detail='CertificateFailureError TIMEOUT: waiting')]):
            row = copy.deepcopy(base); row['samples'] = samples
            self.assertNotIn(RETRY_NOTE, json.dumps(model([row]), ensure_ascii=False))
        base['metadata']['tool_id'] = 'other'
        self.assertNotIn(RETRY_NOTE, json.dumps(model([base]), ensure_ascii=False))

    def test_filter_and_primary_counts_are_explained_dynamically(self):
        rows = [record('UPDATE', version='1.0', reference_floor='2.0'), record('MANUAL', 'manual', name='Other')]
        report, page, text, console = export(rows)
        expected = '追加確認が必要：行動別フィルター2ツール（重複を含む）＝主分類1ツール＋他の主分類に併存1ツール'
        self.assertIn(expected, report['presentation']['counting_note'])
        for output in (page, text, console): self.assertIn(expected, output)
        self.assertIn('行動別フィルター（重複を含む）', page)
        self.assertIn('追加確認が必要（主分類）', page)

    def test_evidence_headings_use_array_index_plus_one_even_after_sorting(self):
        rows = [record('MANUAL', 'manual', name='Zulu'), record('ACTION', 'measured', name='Alpha'),
                record('NOT_FOUND', 'inventory', name='Middle')]
        report, page, _, _ = export(rows)
        parser = Headings(); parser.feed(page)
        for i, row in enumerate(report['records']):
            self.assertIn('記録'+str(i+1)+'：', parser.headings['item-'+str(i)])
        self.assertIn('href="#item-0"', page)
        self.assertIn('>記録1</a>', page)


if __name__ == '__main__': unittest.main()
