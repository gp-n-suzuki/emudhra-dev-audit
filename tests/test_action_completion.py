"""Version remediation and unmeasured transport are separate user decisions."""
import copy
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit
import reporting
import verdicts
from test_action_presentation import record, export
from test_report_usability import Page


def fixed(path='/fixture/product'):
    return record('INFERRED_OK', name='Product', path=path, version='2.1.0',
                  reference_floor='2.0.0', source='https://vendor.invalid/security')


class ActionCompletionTests(unittest.TestCase):
    def tool(self, rows):
        return export(rows)[0]['presentation']['tools'][0]

    def test_fixed_installation_is_complete_and_unmeasured_transport_stays_visible(self):
        rows = [fixed()]
        before = copy.deepcopy(rows)
        report, page, summary, console = export(rows)
        tool = report['presentation']['tools'][0]
        self.assertEqual(tool['primary_action'], 'version_complete')
        self.assertNotIn('investigate', tool['actions'])
        self.assertEqual(tool['communication'][0]['state'], 'not_run')
        self.assertTrue(tool['gaps'])
        self.assertEqual(rows, before)
        for output in (page, summary, console):
            self.assertIn('バージョン対策完了', output)
            self.assertIn('未実施', output)
        self.assertIn('追加の更新は不要', page)
        self.assertNotIn('自動検査で分からなかった点を確認する', page)

    def test_missing_reference_or_identity_does_not_complete(self):
        for field in ('source', 'reference_floor', 'executable'):
            item = fixed()
            item['metadata'].pop(field)
            with self.subTest(field=field):
                self.assertNotEqual(self.tool([item])['primary_action'], 'version_complete')

    def test_real_connection_problem_and_disabled_setting_override_completed_version(self):
        for method, expected in [('measured', 'connection_problem'), ('configuration', 'configure')]:
            issue = record('ACTION', method, name='Product', path='/fixture/product')
            with self.subTest(method=method):
                tool = self.tool([fixed(), issue])
                self.assertEqual(tool['primary_action'], expected)
                self.assertTrue(tool['units'][0]['completed_versions'])

    def test_old_or_unknown_other_installation_stays_actionable(self):
        for status, expected in [('UPDATE', 'update'), ('MANUAL', 'investigate')]:
            other = record(status, name='Product', path='/fixture/other', version='1.0.0',
                           reference_floor='2.0.0')
            tool = self.tool([fixed(), other])
            self.assertEqual(tool['primary_action'], expected)
            self.assertIn('version_complete', [u['primary_action'] for u in tool['units']])

    def test_conflicting_same_installation_versions_do_not_complete(self):
        other = fixed()
        other['metadata']['version'] = '3.0.0'
        tool = self.tool([fixed(), other])
        self.assertNotEqual(tool['primary_action'], 'version_complete')
        self.assertFalse(tool['units'][0]['completed_versions'])

    def test_unverified_release_condition_and_component_do_not_complete(self):
        for extra in ({'component_only': True}, {'release_distribution': 'custom'}, {'release_review': True}):
            item = fixed()
            item['metadata'].update(extra)
            self.assertNotEqual(self.tool([item])['primary_action'], 'version_complete')

    def test_unknown_required_component_keeps_application_pending(self):
        item = fixed()
        item['metadata'].update(application=True, path='/fixture/product', uninspected=[], inspections=[
            dict(component='electron', method='version', status='INFERRED_OK', version='44.9.1',
                 reference_floor='44.9.1', source='https://vendor.invalid/security', path='/fixture/product/Electron'),
            dict(component='unknown-runtime', method='version', status='MANUAL', version='1.0', detail='適用条件不明')])
        self.assertEqual(self.tool([item])['primary_action'], 'investigate')

    def test_unknown_items_show_the_failure_next_to_the_action(self):
        item = record('UNKNOWN', 'measured', name='Product', path='/fixture/product')
        item['detail'] = '検査用サイトへの接続がタイムアウトしました。'
        item['samples'] = [dict(target='emSign / CTなし', status='UNKNOWN', detail='TIMEOUT:', control=False)]
        root = Page(audit.render_report([item], 'fixture')).root
        self.assertIn('タイムアウト', next(root.find(cls='target-concern')).text)
        self.assertIn('プロンプト', next(root.find(cls='target-concern')).text)
        unit = next(root.find(cls='tool-record'))
        self.assertIn('emSign / CTなし', unit.text)
        self.assertIn('タイムアウト', unit.text)

    def test_system_bundler_instructions_name_the_runtime_and_a_read_only_command(self):
        item = record('ACTION', 'measured', name='Bundler', path='/usr/bin/bundle', tool_id='bundler',
                      runtime_executable='/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/ruby')
        unit = next(Page(audit.render_report([item], 'fixture')).root.find(cls='first-actions'))
        self.assertIn('/usr/bin/bundle', unit.text)
        self.assertNotIn('type -a ruby bundle', unit.text)
        details = next(Page(audit.render_report([item], 'fixture')).root.find(cls='tool-record'))
        self.assertIn('/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/ruby', details.text)
        self.assertIn('type -a ruby bundle', details.text)
        self.assertIn('ソフトウェアアップデート', unit.text)
        self.assertNotIn('sudo gem', unit.text)
        self.assertNotIn('そのRubyが使うCA・証明書検証設定を確認', unit.text)

    def test_visible_version_labels_use_version_instead_of_short_form(self):
        page = Page(audit.render_report([fixed()], 'fixture')).root
        self.assertIn('バージョンの判定', page.text)
        self.assertNotIn('版の判定', page.text)
        self.assertNotIn('対策版', page.text)

    def test_rubygems_does_not_get_bundler_configuration_commands(self):
        item = record('ACTION', 'measured', name='RubyGems', path='/opt/homebrew/bin/gem', tool_id='rubygems',
                      runtime_executable='/opt/homebrew/Cellar/ruby/4.0.9/bin/ruby')
        unit = next(Page(audit.render_report([item], 'fixture')).root.find(cls='first-actions'))
        self.assertIn('DEFAULT_CERT_FILE', unit.text)
        self.assertNotIn('gem config get', unit.text)
        self.assertNotIn('bundle config get', unit.text)

    def test_cli_completed_version_with_unmeasured_transport_returns_completion(self):
        rows = [fixed(), record('MANUAL', 'manual', name='Product', path='/fixture/product')]
        def execute(instance): instance.records = copy.deepcopy(rows)
        with tempfile.TemporaryDirectory() as tmp, patch.object(audit.Audit, 'execute', execute), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(['--out', str(Path(tmp)/'report')]), 0)

    def test_shared_display_identity_does_not_complete_a_different_executable(self):
        good = fixed()
        other = record('MANUAL', 'manual', name='Product', path='/fixture/other')
        for item in (good, other): item['metadata']['result_identity'] = ['product', 'shared']
        self.assertEqual(self.tool([good, other])['primary_action'], 'investigate')

    def test_conflicting_runtimes_and_environments_do_not_complete(self):
        for field in ('runtime_executable', 'prefix'):
            good, other = fixed(), fixed()
            good['metadata'][field], other['metadata'][field] = '/fixture/one', '/fixture/two'
            with self.subTest(field=field):
                tool = self.tool([good, other])
                self.assertEqual(tool['primary_action'], 'investigate')
                self.assertFalse(tool['units'][0]['completed_versions'])

    def test_mixed_version_and_measured_completion_is_not_all_transport_checked(self):
        measured = record('REJECTED', 'measured', name='Product', path='/fixture/other')
        tool = self.tool([fixed(), measured])
        self.assertEqual(tool['primary_action'], 'complete')
        self.assertEqual({u['primary_action'] for u in tool['units']}, {'version_complete', 'checked'})

    def test_raw_manual_version_conflict_vetoes_completion(self):
        other = record('MANUAL', 'manual', name='Product', path='/fixture/product', version='1.0.0')
        tool = self.tool([fixed(), other])
        self.assertEqual(tool['primary_action'], 'investigate')
        self.assertFalse(tool['units'][0]['completed_versions'])

    def test_rejected_transport_does_not_hide_conflicting_fixed_versions(self):
        other = fixed()
        other['metadata']['version'] = '3.0.0'
        measured = record('REJECTED', 'measured', name='Product', path='/fixture/product')
        tool = self.tool([fixed(), other, measured])
        self.assertEqual(tool['primary_action'], 'investigate')
        self.assertTrue(any('一致しません' in g['reason'] for g in tool['gaps']))

    def test_inventory_without_runtime_observation_does_not_contradict_captured_runtime(self):
        good = fixed()
        good['metadata']['resolved_executable'] = '/fixture/product'
        inventory = record('MANUAL', 'manual', name='Product', path='/fixture/product', application=True,
                           coverage_state='uninspected', inspections=[], uninspected=[])
        inventory['metadata']['path'] = '/fixture/product'
        inventory['detail'] = 'このツールの通信は未確認。導入を確認しました。'
        self.assertEqual(self.tool([good, inventory])['primary_action'], 'version_complete')

    def test_static_setting_names_do_not_undo_version_completion(self):
        settings = record('MANUAL', 'static', name='Product', path='/fixture/product',
                          p2_settings=True, setting_names=['SSL_CERT_FILE'], setting_observations=[])
        self.assertEqual(self.tool([fixed(), settings])['primary_action'], 'version_complete')


if __name__ == '__main__':
    unittest.main()
