"""Synthetic reports explain a decision and a safe first action together."""
import copy
import contextlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import audit
import reporting
import verdicts


def record(name='Example', status='MANUAL', method='manual', **meta):
    return dict(name=name, status=status, assessment_method=method,
                detail='通信は未検査です。', action='', samples=[],
                metadata=dict(tool_id='example', tool_name='Example',
                              executable='/fixture/example', **meta))


class Node:
    def __init__(self, tag='', attrs=()):
        self.tag, self.attrs, self.children = tag, dict(attrs), []

    @property
    def text(self):
        return ''.join(child.text if isinstance(child, Node) else child for child in self.children)

    def find(self, tag=None, cls=None):
        for child in self.children:
            if isinstance(child, Node):
                if (tag is None or child.tag == tag) and (cls is None or cls in child.attrs.get('class', '').split()):
                    yield child
                yield from child.find(tag, cls)


class Page(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.root = Node()
        self.stack = [self.root]
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        node = Node(tag, attrs)
        self.stack[-1].children.append(node)
        if tag not in ('area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'):
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack)-1, 0, -1):
            if self.stack[index].tag == tag:
                self.stack = self.stack[:index]
                break

    def handle_data(self, text):
        self.stack[-1].children.append(text)


class ReportUsabilityTests(unittest.TestCase):
    def test_first_screen_explains_uncertainty_and_private_sharing_before_counts(self):
        page = Page(audit.render_report([record()], 'fixture')).root
        header = next(page.find('header'))
        help_panel = next(header.find(cls='report-help'), None)
        self.assertIsNotNone(help_panel, 'Readers need help and sharing guidance before the result counts')
        self.assertIn('編集できるプロンプト', help_panel.text)
        self.assertNotIn('担当', help_panel.text)
        self.assertIn('共有する前', help_panel.text)
        self.assertIn('PC情報', help_panel.text)
        self.assertIn('必須・条件付き・不要', help_panel.text)
        self.assertIn('確定・暫定・判定保留', help_panel.text)
        self.assertIn('導入先ごとのバージョンと次の操作', help_panel.text)
        self.assertLess(header.text.index(help_panel.text), header.text.index('対象の診断結果'))

    def test_installation_pairs_reasons_with_distinct_actions_and_full_path(self):
        old = record('Python / pip バージョン', 'UPDATE', 'version',
                     version='26.2.1', reference_floor='26.2.2')
        old['metadata'].update(tool_id='python', tool_name='Python', executable='/fixture/old/python3')
        disabled = copy.deepcopy(old)
        disabled.update(name='Python / 証明書検証の設定', status='ACTION',
                        assessment_method='configuration', detail='証明書検証を無効にする設定を検出しました。')
        disabled['metadata'] = dict(tool_id='python', tool_name='Python', executable='/fixture/old/python3')
        before = copy.deepcopy([old, disabled])
        page = Page(audit.render_report([old, disabled], 'fixture')).root
        unit = next(page.find(cls='installation-result'))
        reasons = next(unit.find(cls='decision-reasons'), None)
        actions = next(page.find(cls='first-actions'), None)
        self.assertIsNotNone(reasons, 'The installation needs a nearby explanation')
        self.assertIsNotNone(actions, 'Independent first actions must be prominent')
        self.assertIn('証明書検証を無効', reasons.text)
        self.assertIn('通信検証は未実施', reasons.text)
        self.assertIn('pipを更新', actions.text)
        self.assertIn('証明書検証の設定を確認', actions.text)
        self.assertNotIn('CAと関連パッケージを更新', actions.text)
        path = next(unit.find(cls='installation-location'), None)
        self.assertIsNotNone(path)
        self.assertIn('/fixture/old/python3', path.text)
        self.assertEqual([old, disabled], before)

    def test_common_check_is_shown_once_but_every_reason_and_record_survives(self):
        item = record(application=True, path='/fixture/example', inspections=[],
                      uninspected=['同梱情報を取得できません。', '実通信は未検査'])
        item['detail'] = '同梱情報を取得できません。'
        item['action'] = '配布元の対策情報を確認してください。'
        unit = next(Page(audit.render_report([item], 'fixture')).root.find(cls='installation-result'))
        self.assertEqual(unit.text.count(item['action']), 1)
        self.assertFalse(list(unit.find(cls='first-actions')))
        reasons = next(unit.find(cls='decision-reasons'))
        self.assertIn('同梱情報を取得できません。', reasons.text)
        self.assertIn('実通信は未検査', reasons.text)
        self.assertTrue(list(unit.find(cls='inspection-data')))

    def test_different_sources_keep_separate_checks(self):
        items = [record(source=source) for source in ('https://one.invalid/advisory', 'https://two.invalid/advisory')]
        for index, item in enumerate(items):
            item['detail'] = '不足した情報 '+str(index)
            item['action'] = '配布元の対応情報を確認してください。'
        unit = next(Page(audit.render_report(items, 'fixture')).root.find(cls='installation-result'))
        self.assertEqual(unit.text.count(items[0]['action']), 2)
        self.assertFalse(list(unit.find(cls='first-actions')))
        for item in items:
            self.assertIn(item['detail'], unit.text)
            self.assertIn(item['metadata']['source'], audit.render_report(items, 'fixture'))

    def test_only_saved_unambiguous_host_aliases_are_presented_as_aliases(self):
        app = record(application=True, path='/fixture/real/example',
                     discovered_paths=['/fixture/real/example', '/fixture/link/example'])
        probe = record(status='REJECTED', method='measured')
        probe['metadata']['executable'] = '/fixture/link/example'
        page = Page(audit.render_report([app, probe], 'fixture')).root
        units = list(page.find(cls='installation-result'))
        self.assertEqual(len(units), 1)
        aliases = list(units[0].find(cls='location-aliases'))
        self.assertEqual(len(aliases), 1)
        self.assertIn('/fixture/link/example', aliases[0].text)
        other = copy.deepcopy(app)
        other['metadata']['path'] = '/fixture/other/example'
        ambiguous = Page(audit.render_report([app, other, probe], 'fixture')).root
        self.assertFalse(list(ambiguous.find(cls='location-aliases')))
        container = copy.deepcopy(app)
        container['metadata']['execution_context'] = 'コンテナ fixture'
        mixed = Page(audit.render_report([app, container], 'fixture')).root
        container_unit = next(u for u in mixed.find(cls='installation-result') if 'コンテナ fixture' in u.text)
        self.assertFalse(list(container_unit.find(cls='location-aliases')))

    def test_non_os_runtime_does_not_get_an_unconditional_os_update_instruction(self):
        item = record('.NET', 'UPDATE', 'version', version='1.0', reference_floor='2.0')
        item['metadata'].update(tool_id='dotnet', tool_name='.NET', executable='/fixture/third-party/dotnet')
        actions = next(Page(audit.render_report([item], 'fixture')).root.find(cls='first-actions'))
        self.assertNotIn('OSの更新を適用', actions.text)
        self.assertIn('導入元', actions.text)

    def test_unknown_browser_or_client_origin_does_not_get_os_specific_steps(self):
        for name in ('Safari', 'curl'):
            with self.subTest(name=name):
                item = record(name, 'ACTION', 'measured')
                actions = next(Page(audit.render_report([item], 'fixture')).root.find(cls='first-actions'))
                self.assertNotIn('macOSのソフトウェアアップデート', actions.text)
                self.assertNotIn('OS付属', actions.text)

    def test_embedded_configuration_problem_also_gets_setting_guidance(self):
        item = record(application=True, path='/fixture/example', inspections=[
            dict(component='TLS設定', status='ACTION', method='configuration',
                 detail='証明書検証が無効です。')])
        actions = next(Page(audit.render_report([item], 'fixture')).root.find(cls='first-actions'))
        self.assertIn('証明書検証の設定を確認', actions.text)
        self.assertIn('設定名・値・設定元', actions.text)

    def test_one_record_can_require_both_setting_repair_and_runtime_update(self):
        item = record('Go / 証明書検証の設定', 'ACTION', 'configuration', application=True,
                      path='/fixture/go', inspections=[dict(component='go', version='1.23.0',
                        status='UPDATE', method='version', path='/fixture/go')])
        item['metadata']['tool_id'] = 'go'
        item['detail'] = '証明書検証を無効にする設定を検出しました。'
        root = Page(audit.render_report([item], 'fixture')).root
        actions = next(root.find(cls='first-actions'))
        self.assertIn('証明書検証の設定を確認する', actions.text)
        self.assertIn('対応バージョンへ更新してください', actions.text)

    def test_unspecified_setting_problem_does_not_claim_verification_is_disabled(self):
        item = record(status='ACTION', method='configuration')
        item['detail'] = '独自CAの設定を確認する必要があります。'
        actions = next(Page(audit.render_report([item], 'fixture')).root.find(cls='first-actions'))
        self.assertNotIn('検出された証明書検証の無効設定', actions.text)
        self.assertIn('記録された問題', actions.text)

    def test_record_specific_steps_survive_a_generic_remediation_in_the_same_category(self):
        for name, method in (('Safari', 'measured'), ('Example', 'configuration')):
            with self.subTest(name=name):
                item = record(name, 'ACTION', method)
                item['detail'] = '合成の問題検出結果です。'
                item['action'] = '失効情報・独自CA・TLS検査プロキシを確認し、同じプロファイルで再検査してください。'
                if name == 'Safari':
                    item['metadata'].update(tool_id='safari', tool_name='Safari')
                    item['samples'] = [dict(target='合成の検証先', status='ACTION', detail='合成の受入れ結果')]
                root = Page(audit.render_report([item], 'fixture')).root
                actions = next(root.find(cls='first-actions'))
                self.assertIn(item['action'], actions.text)
                self.assertIn('設定元' if method == 'configuration' else 'ブラウザを更新して再確認', actions.text)

    def test_exactly_repeated_record_instruction_is_shown_once(self):
        item = record('Example', 'ACTION', 'measured')
        item['action'] = 'この項目の特定の設定を確認してください。'
        actions = next(Page(audit.render_report([item], 'fixture')).root.find(cls='first-actions'))
        self.assertEqual(actions.text.count(item['action']), 1)

    def test_null_discovered_paths_can_render_without_inventing_aliases(self):
        item = record(application=True, path='/fixture/example', discovered_paths=None)
        root = Page(audit.render_report([item], 'fixture')).root
        unit = next(root.find(cls='installation-result'))
        self.assertIn('/fixture/example', next(unit.find(cls='installation-location')).text)
        self.assertFalse(list(unit.find(cls='location-aliases')))

    def test_export_preserves_machine_evidence_and_independent_installations(self):
        old = record('Python / pip バージョン', 'UPDATE', 'version', version='26.2.1', reference_floor='26.2.2')
        old['metadata'].update(tool_id='python', tool_name='Python', executable='/fixture/one/bin/python', prefix='/fixture/one')
        new = copy.deepcopy(old)
        new['metadata'].update(executable='/fixture/two/bin/python', prefix='/fixture/two', version='26.2.2')
        new['status'] = 'INFERRED_OK'
        rows = [old, new]
        before = copy.deepcopy(rows)
        expected = verdicts.prepare(copy.deepcopy(rows))
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=rows), Path(tmp))
            data = json.loads((Path(tmp)/'report.json').read_text())
            page = Page((Path(tmp)/'report.html').read_text()).root
        self.assertEqual(rows, before)
        self.assertEqual(data['schema_version'], 3)
        self.assertEqual(data['presentation']['schema_version'], 1)
        for saved, original in zip(data['records'], expected):
            for key in ('status', 'detail', 'metadata', 'samples', 'assessment_method', 'scope'):
                self.assertEqual(saved[key], original[key])
        self.assertEqual(len(data['presentation']['tools'][0]['units']), 2)
        units = list(page.find(cls='installation-result'))
        self.assertEqual(len(units), 2)
        for unit, saved in zip(units, data['presentation']['tools'][0]['units']):
            self.assertEqual(unit.attrs['data-action'], saved['primary_action'])
        self.assertIn('通信検証は未実施', page.text)

    def test_disclosures_references_and_untrusted_text_remain_accessible_and_safe(self):
        item = record()
        item['detail'] = '合成 <img src=x onerror=alert(1)> & 記録'
        item['action'] = '<script>synthetic()</script>'
        item['metadata']['executable'] = '/fixture/<unsafe>/tool'
        root = Page(audit.render_report([item], 'fixture')).root
        ids = [node.attrs['id'] for node in root.find() if 'id' in node.attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for link in root.find('a'):
            href = link.attrs.get('href', '')
            if href.startswith('#'):
                self.assertIn(href[1:], ids)
        for details in root.find('details'):
            elements = [child for child in details.children if isinstance(child, Node)]
            self.assertEqual(elements[0].tag, 'summary')
            self.assertTrue(elements[0].text.strip())
        def depth(node, count=0):
            count += node.tag == 'details'
            return max([count]+[depth(child, count) for child in node.children if isinstance(child, Node)])
        self.assertLessEqual(depth(root), 3)
        self.assertEqual(len(list(root.find('script'))), 1)
        self.assertFalse(list(root.find('img')))
        self.assertIn(item['detail'], root.text)
        self.assertIn(item['action'], root.text)
        self.assertEqual(next(root.find('html')).attrs['lang'], 'ja')


if __name__ == '__main__':
    unittest.main()
