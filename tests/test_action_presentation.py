"""The exported next action must preserve independent version and TLS evidence."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import audit
import reporting
import verdicts


ROOT = Path(__file__).resolve().parents[1]


def record(status, method='version', name='Example', path='/fixture/example', **metadata):
    metadata.setdefault('tool_id', name.lower().replace(' ', '-'))
    if metadata.get('application'):
        metadata.setdefault('uninspected', [])
    return dict(name=name, status=status, assessment_method=method,
                detail='保存した根拠', action='', samples=[],
                metadata=dict(tool_name=name, executable=path, **metadata))


def export(records):
    with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as console:
        out = Path(tmp)
        audit.write_reports(SimpleNamespace(records=copy.deepcopy(records)), out)
        return (json.loads((out/'report.json').read_text(encoding='utf-8')),
                (out/'report.html').read_text(encoding='utf-8'),
                (out/'summary.txt').read_text(encoding='utf-8'), console.getvalue())


class ActionPresentationTests(unittest.TestCase):
    def tool(self, rows, name='Example'):
        report, _, _, _ = export(rows)
        return next(t for t in report['presentation']['tools'] if t['name'] == name)

    def test_fixed_version_does_not_hide_unmeasured_communication(self):
        tool = self.tool([record('INFERRED_OK', version='2.0', reference_floor='2.0')])
        self.assertEqual(tool['primary_action'], 'investigate')
        self.assertEqual(tool['version'][0]['state'], 'fixed')
        self.assertEqual(tool['communication'][0]['state'], 'not_run')
        self.assertTrue(tool['gaps'])
        self.assertNotIn('checked', tool['actions'])

    def test_old_version_survives_successful_rejection(self):
        rows = [record('UPDATE', version='1.0', reference_floor='2.0'), record('REJECTED', 'measured')]
        tool = self.tool(rows)
        self.assertEqual(tool['primary_action'], 'update')
        self.assertIn('below_fixed', [x['state'] for x in tool['version']])
        self.assertIn('rejected', [x['state'] for x in tool['communication']])

    def test_update_and_disabled_verification_are_both_actions_and_filter_members(self):
        bad = record('ACTION', 'configuration')
        bad['detail'] = 'http.sslVerify=false を検出'
        report, page, text, console = export([record('UPDATE', version='1.0', reference_floor='2.0'), bad])
        tool = report['presentation']['tools'][0]
        self.assertIn('update', tool['actions'])
        self.assertIn('configure', tool['actions'])
        self.assertEqual(report['presentation']['action_counts']['update'], 1)
        self.assertEqual(report['presentation']['action_counts']['configure'], 1)
        self.assertEqual(sum(report['presentation']['primary_action_counts'].values()), 1)
        for output in (page, text, console):
            self.assertIn('更新が必要', output)
            self.assertIn('設定の修正が必要', output)
        self.assertIn('data-actions=', page)

    def test_measured_action_is_explicit_even_with_a_fixed_version(self):
        bad = record('ACTION', 'measured')
        bad['detail'] = '問題の証明書を受け入れた'
        bad['samples'] = [dict(target='fixture', status='ACTION', control=False, detail='accepted')]
        tool = self.tool([record('INFERRED_OK', version='2.0'), bad])
        self.assertEqual(tool['primary_action'], 'connection_problem')
        self.assertIn('問題', tool['primary_label'])
        self.assertIn('problem', [x['state'] for x in tool['communication']])
        self.assertNotIn('checked', tool['actions'])

    def test_control_success_is_not_rejection_evidence(self):
        tool = self.tool([record('CONTROL_OK', 'measured')])
        self.assertEqual(tool['primary_action'], 'investigate')
        self.assertIn('control_only', [x['state'] for x in tool['communication']])

    def test_multiple_installations_preserve_both_the_update_and_the_gap(self):
        tool = self.tool([record('REJECTED', 'measured', path='/one/example'),
                          record('UPDATE', path='/two/example', version='1.0', reference_floor='2.0')])
        self.assertEqual(len(tool['units']), 2)
        self.assertEqual(tool['primary_action'], 'update')
        self.assertIn('investigate', tool['actions'])
        self.assertNotIn('checked', tool['actions'])
        self.assertEqual({u['primary_action'] for u in tool['units']}, {'checked', 'update'})

    def test_partial_checks_in_one_installation_do_not_hide_missing_checks(self):
        pending = record('MANUAL', 'manual')
        pending['detail'] = '普段の設定での通信は未確認'
        pending['action'] = '普段の取得先とCA設定を確認する'
        tool = self.tool([record('REJECTED', 'measured'), pending])
        self.assertEqual(len(tool['units']), 1)
        self.assertEqual(tool['primary_action'], 'investigate')
        self.assertIn('rejected', [x['state'] for x in tool['communication']])
        self.assertIn('not_run', [x['state'] for x in tool['communication']])
        self.assertTrue(any('普段' in gap['reason'] for gap in tool['gaps']))

    def test_not_installed_not_applicable_and_information_are_separate(self):
        report, page, _, _ = export([record('NOT_FOUND', 'inventory', name='Absent'),
                                     record('NOT_APPLICABLE', 'inventory', name='Other OS'),
                                     record('INFO', 'inventory', name='Environment')])
        actual = {t['name']: t['primary_action'] for t in report['presentation']['tools']}
        self.assertEqual(actual, {'Absent':'not_found', 'Other OS':'not_applicable', 'Environment':'info'})
        self.assertEqual(report['presentation']['primary_action_counts']['checked'], 0)
        self.assertIn('対象外', page)

    def test_real_safechain_keeps_update_separate_from_local_synthetic_tls(self):
        rows = json.loads((ROOT/'tests/fixtures/safechain-2.7.6.json').read_text(encoding='utf-8'))
        tool = self.tool(rows, 'Safe Chain')
        self.assertEqual(tool['primary_action'], 'update')
        self.assertIn('below_fixed', [x['state'] for x in tool['version']])
        self.assertIn('synthetic_only', [x['state'] for x in tool['communication']])
        self.assertIn('not_run', [x['state'] for x in tool['communication']])
        self.assertNotIn('checked', tool['actions'])

    def test_go_old_own_binary_and_cpu_failure_are_independent(self):
        app = record('MANUAL', 'version', name='Go', path='/fixture/go', tool_id='go',
                     application=True, inspections=[dict(component='go', version='1.23.0', status='MANUAL',
                       method='version', path='/fixture/go', source='https://pkg.go.dev/vuln/GO-2026-6809')])
        # The application path, unlike executable, is part of the collector contract.
        app['metadata']['path'] = '/fixture/go'
        failed = record('UNKNOWN', 'inventory', name='Go', path='/fixture/go', tool_id='go')
        failed['detail'] = '標準ライブラリの診断プログラムをビルドできません: Bad CPU type in executable'
        tool = self.tool([app, failed], 'Go')
        self.assertEqual(tool['primary_action'], 'update')
        self.assertTrue(any(x['state']=='below_fixed' and x['version']=='1.23.0' for x in tool['version']))
        self.assertTrue(any(x['state']=='not_run' and x.get('failure')=='cpu_mismatch' for x in tool['communication']))

    def test_custom_android_jbr_is_a_vendor_question_not_a_definite_update(self):
        app = record('MANUAL', 'version', name='Android Studio', path='/Applications/Android Studio.app',
                     tool_id='android-studio', application=True, inspections=[dict(component='Java 21.0.9',
                       version='21.0.9+-14787801-b1163.94', vendor='JetBrains s.r.o.', status='MANUAL', method='version',
                       path='/Applications/Android Studio.app/Contents/jbr/Contents/Home/release')])
        app['metadata']['path'] = '/Applications/Android Studio.app'
        tool = self.tool([app], 'Android Studio')
        self.assertEqual(tool['primary_action'], 'investigate')
        self.assertNotIn('update', tool['actions'])
        self.assertIn('custom_unknown', [x['state'] for x in tool['version']])
        self.assertTrue(any('配布元' in gap['next_step'] for gap in tool['gaps']))

    def test_pip_missing_launcher_binding_has_a_specific_next_step(self):
        app = record('MANUAL', 'manual', name='pip', path='/fixture/shims/pip', tool_id='pip', application=True,
                     inspections=[])
        app['metadata']['path'] = '/fixture/shims/pip'
        tool = self.tool([app], 'pip')
        self.assertEqual(tool['primary_action'], 'investigate')
        self.assertIn('missing', [x['state'] for x in tool['version']])
        self.assertTrue(any('Python' in gap['reason'] and '導入先' in gap['next_step'] for gap in tool['gaps']))

    def test_presentation_is_additive_and_uses_only_saved_evidence(self):
        rows = [record('UPDATE', version='1.0', reference_floor='2.0'), record('REJECTED', 'measured')]
        baseline = verdicts.prepare(copy.deepcopy(rows))
        report, _, _, _ = export(rows)
        self.assertEqual(report['schema_version'], 3)
        self.assertEqual(report['presentation']['schema_version'], 1)
        for before, after in zip(baseline, report['records']):
            for key in ('name','status','metadata','detail','samples','assessment_method','scope'):
                self.assertEqual(before[key], after[key])
        self.assertEqual(report['summary']['tool_review_counts'], reporting.tool_counts(baseline))
        with patch.object(Path, 'resolve', side_effect=AssertionError('live path resolution')), \
             patch('subprocess.Popen', side_effect=AssertionError('new process')), \
             patch('socket.socket', side_effect=AssertionError('network')):
            self.assertEqual(reporting.action_model(baseline), report['presentation'])

    def test_lower_component_actions_and_uninspected_scope_remain_visible(self):
        app = record('MANUAL', 'manual', application=True, inspections=[
            dict(component='TLS config', status='ACTION', method='configuration', detail='verification disabled'),
            dict(component='embedded Node', status='REFERENCE_OK', method='version', version='24.22.1', detail='fixed')],
            uninspected=['JCEFは未検査'])
        tool = self.tool([app, record('REJECTED', 'measured')])
        self.assertEqual(tool['primary_action'], 'configure')
        self.assertIn('investigate', tool['actions'])
        self.assertIn('component_fixed', [entry['state'] for entry in tool['version']])
        self.assertTrue(any('JCEF' in gap['reason'] for gap in tool['gaps']))

    def test_inventory_checked_and_unexplained_action_do_not_become_safe(self):
        for status, expected in [('CHECKED', 'info'), ('ACTION', 'action_required')]:
            with self.subTest(status=status):
                self.assertEqual(self.tool([record(status, 'inventory')])['primary_action'], expected)

    def test_cli_exit_retains_incomplete_transport_after_a_good_version(self):
        rows = [record('INFERRED_OK', version='2.0', reference_floor='2.0')]
        def execute(instance):
            instance.records = copy.deepcopy(rows)
        with tempfile.TemporaryDirectory() as tmp, patch.object(audit.Audit, 'execute', execute), \
             contextlib.redirect_stdout(io.StringIO()):
            code = audit.main(['--only', 'python', '--out', str(Path(tmp)/'report')])
        self.assertEqual(code, 2)

    def test_inventory_parent_cannot_hide_a_lower_configuration_action(self):
        row = record('INFO', 'inventory', inspections=[dict(component='TLS config', status='ACTION',
                     method='configuration', detail='verification disabled')])
        tool = self.tool([row])
        self.assertEqual(tool['primary_action'], 'configure')
        self.assertEqual(tool['units'][0]['primary_action'], 'configure')

    def test_attempted_manual_probe_is_indeterminate_instead_of_not_run(self):
        row = record('MANUAL', 'measured')
        row['samples'] = [dict(target='fixture', status='UNKNOWN', detail='timeout', control=False)]
        tool = self.tool([row])
        self.assertEqual([entry['state'] for entry in tool['communication']], ['indeterminate'])

    def test_python_body_installed_pip_and_ensurepip_are_distinct_version_subjects(self):
        rows = []
        for suffix, version, floor in [('Python本体', '3.15.2', '3.15.2'),
                                       ('pip バージョン', '26.2.2', '26.2.2'),
                                       ('ensurepip同梱pip（新規venv用）', '26.2.2', '26.2.2')]:
            item = record('INFERRED_OK', name='Python', path='/fixture/python3', tool_id='python',
                          version=version, reference_floor=floor, python_version='3.15.2', prefix='/fixture')
            item['name'] = 'ホスト / Python 3.15.2 [/fixture] / '+suffix
            rows.append(item)
        report, page, text, console = export(rows)
        versions = report['presentation']['tools'][0]['version']
        self.assertEqual([(v['component'], v['target']) for v in versions],
                         [('本体','application'), ('pip','component'), ('ensurepip同梱pip（新規venv用）','component')])
        self.assertEqual(len({tuple(v['record_indices']) for v in versions}), 3)
        for output in (page, text, console):
            self.assertIn('pip', output)
            self.assertIn('ensurepip同梱pip', output)

    def test_osv_api_query_is_not_a_local_certificate_test(self):
        row = record('CHECKED', 'measured', name='OSV-Scanner', probe='synthetic_osv_query')
        row['detail'] = '本体で公式APIへの合成照会を試し、結果を受け取りました。'
        row['scope'] = '合成依存1件の公式API照会のみ。検査用サイトへの接続は含みません。'
        report, page, text, console = export([row])
        communication = report['presentation']['tools'][0]['communication']
        self.assertEqual(communication[0]['state'], 'synthetic_api_query')
        for output in (page, text, console):
            self.assertIn('公式APIへの合成データ照会', output)
            self.assertNotIn('ローカル合成証明書のみ確認', output)

    def test_child_configuration_reason_appears_in_every_output(self):
        row = record('MANUAL', 'manual', inspections=[dict(component='Git TLS', status='ACTION',
                     method='configuration', detail='http.sslVerify=false を検出')])
        report, page, text, console = export([row])
        tool = report['presentation']['tools'][0]
        self.assertTrue(any('http.sslVerify=false' in x['reason'] for x in tool['action_reasons']))
        for output in (page, text, console):
            self.assertIn('http.sslVerify=false', output)


if __name__ == '__main__': unittest.main()
