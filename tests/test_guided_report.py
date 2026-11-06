"""Approved guided report behavior, using synthetic observations only."""
import copy
import unittest

import audit
import ai_prompts
import reporting
import verdicts
from test_report_usability import Page


def record(name, tool_id, path, status='MANUAL', method='manual', **metadata):
    return dict(name=name, status=status, assessment_method=method,
                detail='保存した観測。', action='', samples=[],
                metadata=dict(tool_id=tool_id, tool_name=name, executable=path, **metadata))


class GuidedReportTests(unittest.TestCase):
    def test_outdated_row_and_affected_component_are_explicitly_marked_before_fixed_rows(self):
        old = record('Python / pip', 'python', '/fixture/old/python', 'UPDATE', 'version',
                     version='21.2.4', reference_floor='26.2.2', python_version='3.9.6')
        old['metadata']['tool_name'] = 'Python'
        fixed = copy.deepcopy(old)
        fixed['status'] = 'INFERRED_OK'
        fixed['metadata'].update(executable='/fixture/new/python', version='26.2.2', python_version='3.13.18')
        before = copy.deepcopy([fixed, old])
        root = Page(audit.render_report([fixed, old], '2026-11-06')).root
        rows = list(next(root.find(cls='installation-overview')).find('tr'))[1:]
        self.assertIn('先に対応', rows[0].text)
        self.assertEqual(next(rows[0].find(cls='result-badge')).text, '! 更新が必要')
        marked = list(rows[0].find(cls='version-attention'))
        self.assertEqual(len(marked), 1)
        self.assertIn('pip 21.2.4', marked[0].text)
        self.assertIn('更新対象', marked[0].text)
        self.assertNotIn('本体 3.9.6', marked[0].text)
        self.assertFalse(list(rows[1].find(cls='version-attention')))
        self.assertNotIn('先に対応', rows[1].text)
        self.assertEqual([fixed, old], before)

    def test_conditional_component_and_unknown_rows_are_not_labeled_required(self):
        app = record('Postman', 'postman', '/fixture/Postman.app', 'UPDATE', 'version', application=True,
                     inspections=[dict(component='electron', status='UPDATE', method='version', version='38.8.6', reference_floor='42.11.16')])
        unknown = record('Example', 'example', '/fixture/example')
        root = Page(audit.render_report([app, unknown], '2026-11-06')).root
        tables = list(root.find(cls='installation-overview'))
        badges = [badge.text for table in tables for badge in table.find(cls='result-badge')]
        self.assertIn('? 対応を確認', badges)
        self.assertIn('未確認', badges)
        self.assertFalse(any('対応が必要' in text or '更新が必要' in text for text in badges))
        self.assertTrue(any('対応確認' in row.text for table in tables for row in table.find(cls='version-attention')))

    def test_priority_navigation_separates_work_from_completed_and_undetected_targets(self):
        fixed = record('uv', 'uv', '/fixture/uv', 'INFERRED_OK', 'version', version='0.9.11', reference_floor='0.9.11')
        update = record('Python', 'python', '/fixture/python', 'UPDATE', 'version', version='1.0', reference_floor='2.0')
        absent = record('Dart', 'dart', '', 'NOT_FOUND', 'inventory')
        page = Page(audit.render_report([fixed, update, absent], '2026-11-06')).root
        nav = next(page.find('nav'))
        self.assertIn('対応が必要', nav.text)
        self.assertLess(nav.text.index('Python'), nav.text.index('uv'))
        closed = [d for d in nav.find('details') if 'open' not in d.attrs]
        self.assertTrue(any('uv' in d.text for d in closed))
        self.assertTrue(any('Dart' in d.text for d in closed))

    def test_installation_total_and_affected_total_do_not_count_packages_as_pythons(self):
        items = []
        for name in ('pip', 'ensurepip同梱pip（新規venv用）'):
            item = record('Python / '+name, 'python', '/fixture/old/python', 'UPDATE', 'version',
                          version='21.2.4', reference_floor='26.2.2', python_version='3.9.6', prefix='/fixture/old')
            item['metadata']['tool_name'] = 'Python'
            items.append(item)
        items.append(record('Python', 'python', '/fixture/new/python', 'MANUAL', 'manual',
                            version='3.13.18', python_version='3.13.18', prefix='/fixture/new'))
        page = Page(audit.render_report(items, '2026-11-06')).root
        summary = next(page.find(cls='target-overview'))
        self.assertIn('2導入先', summary.text)
        self.assertIn('対応が必要 1', summary.text)
        self.assertIn('更新対象 2項目', summary.text)
        self.assertIn('3.9.6', summary.text)
        self.assertIn('3.13.18', summary.text)
        self.assertIn('21.2.4', summary.text)
        self.assertEqual(len(list(summary.find('tr'))), 3)
        self.assertFalse(list(summary.find('details')))

    def test_unknown_result_leads_with_observed_failure_and_a_concrete_next_step(self):
        item = record('Example', 'example', '/fixture/example', 'UNKNOWN', 'measured')
        item['detail'] = '検査用サイトへの接続がタイムアウトしました。'
        item['samples'] = [dict(target='emSign / CTなし', status='UNKNOWN', detail='TIMEOUT:')]
        page = Page(audit.render_report([item], '2026-11-06')).root
        lead = next(page.find(cls='target-concern'))
        self.assertIn('タイムアウト', lead.text)
        self.assertIn('エラー', lead.text)
        self.assertIn('プロンプト', lead.text)
        self.assertNotIn('作業の要否を判定できません', page.text)

    def test_update_without_a_comparison_does_not_claim_a_known_version_threshold(self):
        item = record('Example', 'example', '/fixture/example', 'UPDATE', 'version')
        root = Page(audit.render_report([item], '2026-11-06')).root
        self.assertNotIn('対策バージョン未満', next(root.find(cls='target-concern')).text)

    def test_version_table_keeps_fixed_and_outdated_installations_separate(self):
        old = record('Python / pip', 'python', '/fixture/old/python', 'UPDATE', 'version', version='21.2.4', reference_floor='26.2.2')
        old['metadata']['tool_name'] = 'Python'
        new = copy.deepcopy(old)
        new['status'] = 'INFERRED_OK'
        new['metadata'].update(executable='/fixture/new/python', version='26.2.2')
        root = Page(audit.render_report([old, new], '2026-11-06')).root
        rows = list(next(root.find(cls='installation-overview')).find('tr'))[1:]
        self.assertIn('21.2.4', rows[0].text)
        self.assertIn('基準未満', rows[0].text)
        self.assertIn('26.2.2', rows[1].text)
        self.assertIn('基準を満たす', rows[1].text)

    def test_product_specific_guidance_cannot_hide_a_separate_version_update(self):
        for name, tool_id, path in (('Homebrew', 'homebrew', '/opt/homebrew/bin/brew'),
                                    ('Google Chrome', 'chrome', '/Applications/Google Chrome.app')):
            with self.subTest(name=name):
                items = [record(name, tool_id, path, 'UPDATE', 'version', version='1.0', reference_floor='2.0'),
                         record(name, tool_id, path, 'INFO', 'inventory', package_query_succeeded=True,
                                packages={'ca-certificates':['2026-10-20']})]
                model = reporting.action_model(verdicts.prepare(items))
                tasks = model['tools'][0]['work']['tasks']
                self.assertTrue(any(t['classification'] in ('required', 'conditional') and t['steps'] for t in tasks))
                self.assertFalse(all(t['classification'] == 'unneeded' for t in tasks))

    def test_conflicting_ca_versions_do_not_complete_the_update(self):
        items = [record('Homebrew', 'homebrew', '/opt/homebrew/bin/brew', 'INFO', 'inventory',
                        package_query_succeeded=True, packages={'ca-certificates':[version]})
                 for version in ('2026-10-20', '2026-01-01')]
        tasks = reporting.action_model(verdicts.prepare(items))['tools'][0]['work']['tasks']
        self.assertFalse(any(t['classification'] == 'unneeded' for t in tasks))

    def test_missing_ca_identity_does_not_complete_another_installation(self):
        items = [record('Homebrew', 'homebrew', '', 'INFO', 'inventory',
                        package_query_succeeded=True, packages={'ca-certificates':['2026-10-20']}),
                 record('Homebrew', 'homebrew', '/usr/local/bin/brew')]
        tasks = reporting.action_model(verdicts.prepare(items))['tools'][0]['work']['tasks']
        self.assertFalse(any(t['classification'] == 'unneeded' for t in tasks))

    def test_known_chrome_rejection_is_not_described_as_unverified(self):
        item = record('Google Chrome', 'chrome', '/Applications/Google Chrome.app', 'REJECTED', 'measured')
        work = reporting.action_model(verdicts.prepare([item]))['tools'][0]['work']
        self.assertFalse(any('実通信による拒否は未確認' in note for note in work['notes']))

    def test_below_fixed_embedded_components_remain_conditional_candidates(self):
        item = record('Postman', 'postman', '/Applications/Postman.app', 'UPDATE', 'version',
                      application=True, inspections=[
                          dict(component='electron', status='UPDATE', method='version', version='38.8.6',
                               reference_floor='42.11.16', path='/Applications/Postman.app/Electron')])
        work = reporting.action_model(verdicts.prepare([item]))['tools'][0]['work']
        candidates = [t for t in work['tasks'] if 'アプリの対応' in t['title']]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]['classification'], 'conditional')
        self.assertIn('38.8.6', candidates[0]['fact'])

    def test_os_maintenance_is_shared_only_for_the_same_recorded_runtime(self):
        items = [record('Bundler', 'bundler', path, 'ACTION', 'measured',
                        runtime_executable='/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/ruby')
                 for path in ('/usr/bin/bundle', '/usr/bin/bundler')]
        model = reporting.action_model(verdicts.prepare(items))
        self.assertEqual(len(model['tools'][0]['units']), 2)
        self.assertEqual(len(model['tools'][0]['work']['tasks']), 1)
        self.assertEqual(model['tools'][0]['work']['tasks'][0]['record_indices'], [0, 1])

    def test_free_text_names_and_verified_settings_are_safe_to_share(self):
        item = record('Example /Users/alice/private-project token fixture-secret', 'example', '/fixture/example', 'CHECKED', 'configuration')
        records = verdicts.prepare([item])
        prompt = ai_prompts.make(reporting.action_model(records), records, '2026-11-05', '2026-11-02')
        self.assertNotIn('private-project', prompt)
        self.assertNotIn('fixture-secret', prompt)
        self.assertIn('取得した設定を確認済み', prompt)

    def test_b_layout_keeps_technical_records_closed_and_prompts_editable(self):
        items = [record('Bundler', 'bundler', '/usr/bin/bundle', 'ACTION', 'measured',
                        runtime_executable='/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/ruby'),
                 record('Homebrew', 'homebrew', '/usr/local/bin/brew')]
        page = Page(audit.render_report(items, '2026-11-05')).root
        nav = next(page.find('nav'))
        self.assertEqual(len(list(nav.find('button'))), 2)
        for card in page.find('article'):
            self.assertTrue(list(card.find(cls='work-guidance')))
            details = next(card.find(cls='tool-record'))
            self.assertNotIn('open', details.attrs)
        self.assertEqual(len(list(page.find('textarea'))), 3)

    def test_ca_update_completion_is_limited_to_its_recorded_homebrew_installation(self):
        items = [record('Homebrew', 'homebrew', '/opt/homebrew/bin/brew', 'INFO', 'inventory',
                        execution_context='ホスト', package_query_succeeded=True,
                        packages={'ca-certificates':['2026-10-20']}, effective_ca_verified=False),
                 record('Homebrew', 'homebrew', '/usr/local/bin/brew')]
        before = copy.deepcopy(items)
        prepared = verdicts.prepare(items)
        tool = reporting.action_model(prepared)['tools'][0]
        opt_index = next(i for i, r in enumerate(prepared) if r['metadata']['executable'].startswith('/opt/'))
        other_index = 1-opt_index
        tasks = tool['work']['tasks']
        completed = [t for t in tasks if t['classification'] == 'unneeded']
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]['certainty'], 'established')
        self.assertEqual(completed[0]['record_indices'], [opt_index])
        self.assertIn('CAパッケージ', completed[0]['title'])
        self.assertTrue(any(t['classification'] == 'conditional' and t['record_indices'] == [other_index] for t in tasks))
        self.assertTrue(any('通信' in note and '未確認' in note for note in tool['work']['notes']))
        self.assertEqual(items, before)

    def test_unknown_evidence_does_not_create_a_mandatory_repair(self):
        items = [record('Example', 'example', '/fixture/example')]
        task = reporting.action_model(verdicts.prepare(items))['tools'][0]['work']['tasks'][0]
        self.assertEqual(task['classification'], 'unassigned')
        self.assertEqual(task['certainty'], 'deferred')
        self.assertEqual(task['steps'], [])

    def test_system_bundler_keeps_known_problem_but_moves_usage_investigation_to_details(self):
        item = record('Bundler', 'bundler', '/usr/bin/bundle', 'ACTION', 'measured',
                      runtime_executable='/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/ruby')
        work = reporting.action_model(verdicts.prepare([item]))['tools'][0]['work']
        self.assertEqual(work['tasks'][0]['classification'], 'conditional')
        self.assertIn('macOS', work['tasks'][0]['title'])
        self.assertNotIn('利用状況', ' '.join(step['text'] for step in work['tasks'][0]['steps']))
        self.assertTrue(work['details'])
        self.assertTrue(any('解消' in note and '未確認' in note for note in work['notes']))

    def test_editable_prompts_cover_actual_inventory_without_copying_private_logs(self):
        item = record('Example', 'example', '/Users/fixture/private-project/bin/example',
                      token='fixture-secret-value')
        item['detail'] = 'https://internal.invalid/private?token=fixture-secret-value'
        before = copy.deepcopy(item)
        page = Page(audit.render_report([item], '2026-11-05T12:30:00+09:00')).root
        prompts = list(page.find('textarea', 'ai-prompt'))
        self.assertEqual(len(prompts), 2, 'One overall prompt and one tool-specific prompt')
        for prompt in prompts:
            self.assertNotIn('readonly', prompt.attrs)
            self.assertIn('判定保留', prompt.text)
            self.assertIn('修正の優先度', prompt.text)
            self.assertIn('確認の優先度', prompt.text)
            self.assertNotIn('fixture-secret-value', prompt.text)
            self.assertNotIn('private-project', prompt.text)
            self.assertNotIn('internal.invalid', prompt.text)
            self.assertNotIn('個人のMac', prompt.text)
            self.assertNotIn('3つまで', prompt.text)
        self.assertIn('表示対象：1', prompts[0].text)
        self.assertIn('検査記録：1', prompts[0].text)
        self.assertEqual(item, before)

    def test_prompt_rules_prefer_readable_prose_without_forcing_a_wide_table(self):
        item = record('Example', 'example', '/fixture/example')
        page = Page(audit.render_report([item], '2026-11-06')).root
        for prompt in page.find('textarea', 'ai-prompt'):
            self.assertIn('読み', prompt.text)
            self.assertIn('件数で省略', prompt.text)
            self.assertIn('判定保留', prompt.text)
            self.assertIn('表は比較', prompt.text)
            self.assertNotIn('次の列の一覧表', prompt.text)
            self.assertNotIn('全対応候補と保留事項を一覧に', prompt.text)


if __name__ == '__main__':
    unittest.main()
