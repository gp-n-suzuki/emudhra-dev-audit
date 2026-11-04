"""The first screen explains what was established without overstating evidence."""
import contextlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit


def record(name, status, method, **extra):
    return dict(name=name, status=status, assessment_method=method,
                detail='観測した内容', action='対象の設定を確認してください。',
                metadata={}, samples=[], **extra)


class Overview(HTMLParser):
    def __init__(self):
        super().__init__()
        self.capture = False
        self.text = ''

    def handle_starttag(self, tag, attrs):
        if dict(attrs).get('id') == 'current-status':
            self.capture = True

    def handle_endtag(self, tag):
        if tag == 'header':
            self.capture = False

    def handle_data(self, data):
        if self.capture:
            self.text += data


class ResultLists(HTMLParser):
    def __init__(self):
        super().__init__()
        self.groups = {}
        self.stack = []
        self.group = None
        self.collapsed = []
        self.tools = []
        self.tool = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'article' and 'data-tool' in attrs:
            self.tool = dict(name=attrs['data-tool'], state=attrs['data-state'],
                             states=attrs['data-states'].split(), checks=[], text='')
            self.tools.append(self.tool)
        if tag == 'div':
            self.stack.append(self.group)
            self.group = attrs.get('data-result-group', self.group)
        if tag == 'section' and 'data-review' in attrs:
            self.groups.setdefault(self.group, []).append(attrs['data-review'])
            if self.tool is not None:
                self.tool['checks'].append(attrs['data-review'])
        if tag == 'details' and attrs.get('class') in ('result-record', 'tool-record'):
            self.collapsed.append('open' not in attrs)

    def handle_endtag(self, tag):
        if tag == 'div':
            self.group = self.stack.pop()
        if tag == 'article':
            self.tool = None

    def handle_data(self, data):
        if self.tool is not None:
            self.tool['text'] += data


class ReportGuidanceTests(unittest.TestCase):
    def test_bundled_electron_below_fix_is_not_presented_as_an_available_app_update(self):
        row = self.app_record('Example.app', '/Applications/Example.app')
        row['metadata'].update(version='44.4.3', reference_floor='44.9.1', inspections=[{
            'component': 'electron', 'status': 'UPDATE', 'method': 'version',
            'version': '44.4.3', 'reference_floor': '44.9.1', 'detail': '同梱版を照合',
            'path': '/Applications/Example.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist'}])
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as console:
            out = Path(tmp)
            audit.write_reports(SimpleNamespace(records=[row]), out)
            page = (out/'report.html').read_text()
            text = (out/'summary.txt').read_text()
            saved = json.loads((out/'report.json').read_text())['records'][0]
        for output in (self.expanded_result_text(page), text, console.getvalue()):
            self.assertIn('同梱Electronが対策版未満', output)
            self.assertIn('対応版が提供されている場合', output)
            self.assertIn('独自修正', output)
            self.assertIn('配布元の対応状況を確認する', output)
            self.assertNotIn('このアプリの対応版へ更新する', output)
        self.assertIn('electron：44.4.3 / 照合基準 44.9.1', page)
        self.assertEqual(saved['status'], 'UPDATE')
        self.assertEqual(saved['metadata']['version'], '44.4.3')
        self.assertEqual(saved['metadata']['reference_floor'], '44.9.1')
        self.assertEqual(saved['remediation']['title'], '配布元の対応状況を確認する')

    def test_app_without_a_compared_version_does_not_claim_to_be_below_a_fix(self):
        row = self.app_record('Example.app', '/Applications/Example.app')
        row['metadata']['inspections'] = [{'component': 'CAファイル', 'status': 'UPDATE',
                                          'method': 'static', 'detail': 'データの更新を確認'}]
        page = audit.render_report([row], 'fixture')
        self.assertNotIn('が対策版未満', self.expanded_result_text(page))
        self.assertIn('同梱ソフトウェアの対応を確認', page)

    def expanded_result_text(self, page):
        # The user has opened a tool and a check, but not the inspection data.
        class VisibleResult(HTMLParser):
            def __init__(self):
                super().__init__()
                self.details = []
                self.text = ''
            def handle_starttag(self, tag, attrs):
                if tag == 'details':
                    self.details.append(dict(attrs).get('class') in ('tool-record', 'result-record', 'missing-tools') or 'open' in dict(attrs))
            def handle_endtag(self, tag):
                if tag == 'details': self.details.pop()
            def handle_data(self, data):
                if all(self.details): self.text += data
        visible = VisibleResult(); visible.feed(page)
        return visible.text

    def test_app_result_and_action_precede_collapsed_paths_and_limits(self):
        path = '/Applications/Example.app/Contents/Resources/very/deep/dependency'
        row = self.app_record('Example.app', path, coverage='partial')
        row['detail'] = '探索の深さの上限: '+path
        row['metadata']['uninspected'] = ['探索の深さの上限: '+path, '実通信は未検査']
        page = audit.render_report([row], 'fixture')
        visible = self.expanded_result_text(page)
        self.assertIn('同梱Go', visible)
        self.assertIn('1.27.2', visible)
        self.assertIn('配布元の対応状況を確認する', visible)
        self.assertIn('不足情報と次の確認', visible)
        self.assertIn('探索の深さの上限', visible)
        self.assertIn(path, page)
        self.assertIn('探索の深さの上限', page)
        self.assertLess(page.index('配布元の対応状況を確認する'), page.index('探索の深さの上限'))

    def test_ca_file_is_in_inspection_data_and_main_result_is_unconfirmed(self):
        row = self.app_record('Example.app', '/Applications/Example.app', status='MANUAL', coverage='uninspected')
        row['metadata']['inspections'] = [{'component':'CAファイル', 'status':'MANUAL', 'method':'static',
                                            'detail':'参照証明書なし', 'path':'/private/cert.pem'}]
        page = audit.render_report([row], 'fixture')
        visible = self.expanded_result_text(page)
        self.assertIn('通信の検証', visible)
        self.assertIn('未実施', visible)
        self.assertIn('CAファイル', visible)
        self.assertIn('CAファイル', page)

    def test_scan_paths_and_limits_are_in_inspection_data(self):
        row = record('アプリ / 探索範囲', 'UNKNOWN', 'inventory')
        row['metadata'] = dict(application_scan=True,
            searched=[dict(path='/example/long/install/location', status='searched')],
            incomplete=['探索時間の上限: /example/long/install/location'])
        row['detail'] = '探索時間の上限: /example/long/install/location'
        page = audit.render_report([row], 'fixture')
        self.assertNotIn('/example/long/install/location', self.expanded_result_text(page))
        self.assertIn('/example/long/install/location', page)

    def test_report_does_not_generate_retired_browser_page_or_script(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp)
            audit.write_reports(SimpleNamespace(records=[record('Git', 'REJECTED', 'measured')]), out)
            self.assertFalse((out/'browser-check.html').exists())
            self.assertFalse((out/'browser-ui.js').exists())
            self.assertNotIn('browser-check.html', (out/'report.html').read_text())

    def app_record(self, name, path, status='UPDATE', coverage='static_checked'):
        row = record('アプリ / '+name+' ['+path+']', status, 'version')
        row['metadata'] = {
                          'application': True, 'path': path, 'discovered_paths': [path],
                          'coverage_state': coverage,
                          'inspections': [{'component': 'go', 'status': status, 'version': '1.27.2',
                                           'detail': '同梱Goの照合', 'path': path}],
                          'uninspected': ['実通信は未検査']}
        return row

    def test_app_installations_share_one_collapsed_tool_without_hiding_unknowns(self):
        rows = [self.app_record('scanner', '/one/scanner'),
                self.app_record('scanner', '/two/scanner', 'MANUAL', 'uninspected'),
                self.app_record('scanner', '/three/scanner', 'INFERRED_OK')]
        _, page, _, _ = self.outputs(rows)
        result = ResultLists(); result.feed(page)
        self.assertEqual([t['name'] for t in result.tools], ['scanner'])
        self.assertEqual(result.tools[0]['states'], ['investigate'])
        self.assertEqual(len(result.tools[0]['checks']), 3)
        self.assertTrue(all(result.collapsed))
        self.assertNotIn('data-filter="app-', page)
        self.assertIn('data-axis="version"', page)
        self.assertIn('1.27.2', page)
        self.assertIn('実通信は未検査', page)

    def test_app_paths_group_with_runtime_and_browser_but_keep_other_apps_separate(self):
        rows = [record('Python / certifi', 'UPDATE', 'version'),
                self.app_record('python3', '/usr/local/bin/python3'),
                record('Chrome CRLSet', 'STATIC_OK', 'static'),
                self.app_record('Google Chrome.app', '/Applications/Google Chrome.app', 'MANUAL', 'uninspected'),
                self.app_record('scanner.exe', r'C:\\Tools\\scanner.exe'),
                self.app_record('scanner.exe', r'D:\\Tools\\scanner.exe')]
        _, page, _, _ = self.outputs(rows)
        result = ResultLists(); result.feed(page)
        counts = {t['name']: len(t['checks']) for t in result.tools}
        self.assertEqual(counts, {'Python': 2, 'Google Chrome': 2, 'scanner': 2})

    def test_partial_app_keeps_update_and_unknown_visible(self):
        _, page, _, _ = self.outputs([self.app_record('scanner', '/bin/scanner', coverage='partial')])
        result = ResultLists(); result.feed(page)
        self.assertEqual(result.tools[0]['states'], ['investigate'])
        self.assertIn('追加確認が必要', result.tools[0]['text'])
        self.assertIn('部品の更新要否を確認', result.tools[0]['text'])
        self.assertIn('更新が必要', result.tools[0]['text'])  # Original component UPDATE is retained.

    def outputs(self, records):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()) as console:
                audit.write_reports(SimpleNamespace(records=records), out)
            page = (out/'report.html').read_text(encoding='utf-8')
            # Report folders are portable without the retired browser workflow.
            for asset in ('ui.css',):
                self.assertTrue((out/asset).is_file(), asset)
            summary = (out/'summary.txt').read_text(encoding='utf-8')
            overview = Overview()
            overview.feed(page)
            return overview.text, page, summary, console.getvalue()

    def test_action_and_unresolved_counts_are_first_in_all_user_outputs(self):
        rows = [record('Java', 'ACTION', 'measured'), record('pip', 'UPDATE', 'version'),
                record('PHP', 'UNKNOWN', 'measured')]
        overview, page, summary, console = self.outputs(rows)
        for output in (summary, console):
            self.assertIn('対応が必要なツールが2件あります', output)
            self.assertIn('問題の証明書を受け入れた・対応が必要: 1ツール', output)
            self.assertIn('更新が必要: 1ツール', output)
            self.assertIn('追加確認が必要: 1ツール', output)
        self.assertNotIn('href="browser-check.html"', page)
        self.assertIn('data-filter="update"', page)
        self.assertIn('data-filter="investigate"', page)
        self.assertNotIn('data-filter="attention"', page)

    def test_unresolved_only_report_does_not_request_remediation(self):
        _, _, summary, console = self.outputs([record('PHP', 'UNKNOWN', 'measured'),
                                               record('Safari', 'MANUAL', 'manual')])
        for output in (summary, console):
            self.assertIn('追加確認が必要なツールが2件あります', output)
            self.assertIn('更新が必要: 0ツール', output)
            self.assertIn('追加確認が必要: 2ツール', output)
            self.assertNotIn('対応が必要な項目が2件あります', output)
        self.assertIn('追加確認が必要 2', console)

    def test_inventory_separates_every_state_and_collapses_procedures(self):
        rows = [record('Java', 'ACTION', 'measured'), record('uv', 'UPDATE', 'version'),
                record('Python', 'UNKNOWN', 'measured'), record('Safari', 'MANUAL', 'manual'),
                record('curl', 'REJECTED', 'measured'), record('.NET', 'NOT_FOUND', 'inventory'),
                record('環境', 'INFO', 'inventory')]
        _, page, _, _ = self.outputs(rows)
        result = ResultLists()
        result.feed(page)
        self.assertEqual(result.groups, {'connection_problem':['action'], 'update':['action'],
                                        'investigate':['unverified','unverified'], 'checked':['complete'],
                                        'not_found':['scope'], 'info':['info']})
        self.assertTrue(result.collapsed and all(result.collapsed))

    def test_tools_appear_once_with_all_checks_inside_and_mixed_states_visible(self):
        rows = [record('ホスト / Java: /jdk/bin/java', 'INFO', 'inventory'),
                record('Java JSSE [/jdk/bin/java]', 'ACTION', 'measured'),
                record('Java / Azulブロックリスト', 'UPDATE', 'static'),
                record('ホスト / curl: /usr/bin/curl', 'REJECTED', 'measured'),
                record('ホスト / curl: /legacy/bin/curl', 'UNKNOWN', 'measured'),
                record('Docker / registryのTLS設定', 'ACTION', 'configuration'),
                record('Docker / Engine', 'UNKNOWN', 'inventory'),
                record('Docker / Docker Desktop', 'INFERRED_OK', 'version'),
                record('ホスト / Python 3.13 [/venv] / pip バージョン', 'UPDATE', 'version'),
                record('ホスト / Python 3.13 [/venv] / certifi', 'REJECTED', 'measured')]
        _, page, _, _ = self.outputs(rows)
        result = ResultLists()
        result.feed(page)
        self.assertEqual(sorted(t['name'] for t in result.tools), ['Docker', 'Java', 'Python', 'curl'])
        tools = {t['name']: t for t in result.tools}
        self.assertEqual(tools['Java']['checks'], ['action', 'review', 'info'])
        self.assertEqual(tools['curl']['state'], 'investigate')
        self.assertEqual(tools['curl']['checks'], ['complete', 'unverified'])
        self.assertIn('実行失敗・結果を判定できない', tools['curl']['text'])
        self.assertEqual(tools['Docker']['state'], 'configure')
        self.assertEqual(tools['Docker']['states'], ['configure'])
        self.assertIn('設定の修正が必要', tools['Docker']['text'])
        self.assertIn('追加確認が必要', tools['Docker']['text'])
        self.assertEqual(tools['Python']['checks'], ['action', 'complete'])
        self.assertIn('4ツール', page)
        self.assertTrue(all(result.collapsed))

    def test_browser_aliases_and_context_do_not_create_duplicate_tool_rows(self):
        rows = [record('ブラウザ / Google Chrome', 'CHECKED', 'inventory'),
                record('ブラウザ / Chrome / 保存済みCRLSet', 'UNKNOWN', 'static'),
                record('ブラウザ / Microsoft Edge', 'CHECKED', 'inventory'),
                record('ブラウザ / Edge / 保存済みCRLSet', 'UNKNOWN', 'static'),
                record('検査対象', 'INFO', 'inventory'),
                record('OS / 環境設定', 'INFO', 'inventory'),
                record('検査範囲 / ホストのみの検査', 'SKIP', 'unmeasured'),
                record('ホスト / PHP curl拡張', 'REJECTED', 'measured'),
                record('ホスト / PHP OpenSSL streams / CA参照先', 'CHECKED', 'configuration')]
        _, page, _, _ = self.outputs(rows)
        result = ResultLists()
        result.feed(page)
        self.assertEqual(sorted(t['name'] for t in result.tools), ['Google Chrome', 'Microsoft Edge', 'PHP'])
        self.assertEqual([len(t['checks']) for t in result.tools], [2, 2, 2])
        for row in rows:
            self.assertIn(row['name'], page)

    def test_unresolved_row_shows_the_observed_failure_without_changing_verdict(self):
        row = record('Python', 'UNKNOWN', 'inventory')
        row['detail'] = 'Bad CPU type in executable'
        _, page, _, _ = self.outputs([row])
        self.assertIn('起動できない（CPU形式）', page)
        self.assertIn('class="UNKNOWN" data-review="unverified"', page)

    def test_saved_data_and_versions_never_look_like_a_completed_connection_test(self):
        rows = [record('Node', 'INFERRED_OK', 'version'), record('CA', 'STATIC_OK', 'static'),
                record('探索', 'CHECKED', 'inventory'), record('.NET', 'NOT_FOUND', 'inventory')]
        overview, _, summary, console = self.outputs(rows)
        for output in (summary, console):
            self.assertIn('追加確認が必要なツールが2件あります', output)
            self.assertIn('照合した本体版は対応基準を満たす', output)
            self.assertIn('通信: 未実施', output)
        self.assertIn('検査先の証明書を拒否できた: 0ツール', overview)
        self.assertNotIn('すべて対策済み', overview)

    def test_inferred_refusal_is_separate_from_directly_measured_refusal(self):
        rows = [record('curl', 'REJECTED', 'measured'),
                record('PHP', 'INFERRED_REJECTED', 'corroborated')]
        overview, _, summary, console = self.outputs(rows)
        for output in (overview, summary, console):
            self.assertIn('検査先の証明書を拒否できた: 1ツール', output)
            self.assertIn('検査用サイトのブロックを推定: 1ツール', output)

    def test_rejection_overview_describes_only_the_observed_endpoint(self):
        row = record('curl', 'REJECTED', 'measured')
        row['detail'] = '代表接続先の信頼エラーを検査データに記録。'
        overview, page, summary, console = self.outputs([row])
        for output in (summary, console):
            self.assertIn('検査先の証明書を拒否できた', output)
        visible = self.expanded_result_text(page)
        self.assertIn('検査先の証明書を拒否できた', visible)
        self.assertIn('検査したクライアントと接続先に限ります', visible)
        self.assertIn('代表接続先の信頼エラー', page)
        for output in (overview, page, summary, console):
            self.assertNotIn('問題の証明書をブロックできました', output)

    def test_inferred_rejection_retains_the_inference_in_plain_language(self):
        _, page, summary, console = self.outputs([record('PHP', 'INFERRED_REJECTED', 'corroborated')])
        for output in (self.expanded_result_text(page), summary):
            self.assertIn('検査先の証明書を拒否できた（推定）', output)
        self.assertIn('検査用サイトのブロックを推定: 1ツール', console)

    def test_empty_report_does_not_claim_a_completed_diagnosis(self):
        _, page, summary, _ = self.outputs([])
        for output in (page, summary):
            self.assertIn('検査結果がありません', output)

    def test_report_includes_explicit_scope_and_offline_context(self):
        rows = [record('検査対象', 'INFO', 'inventory'),
                record('curl', 'SKIP', 'unmeasured', required=True)]
        rows[0]['detail'] = 'ホストのみ（プロジェクト設定・依存関係・venvは検査しません）'
        overview, page, _, _ = self.outputs(rows)
        self.assertIn('ホストのみ', overview)
        self.assertIn('追加確認が必要: 1ツール', overview)
        self.assertIn('接続結果は未確認', page)

    def test_action_reports_announce_specific_remediation_for_each_target(self):
        rows = [record('Java JSSE', 'ACTION', 'measured'),
                record('ホスト / Node.js TLS設定', 'ACTION', 'configuration'),
                record('Python / ensurepip同梱pip（新規venv用）', 'UPDATE', 'version')]
        rows[0]['metadata'] = {'java_home': '/opt/example-jdk'}
        _, page, summary, console = self.outputs(rows)
        for output in (page, summary, console):
            self.assertIn('このJDKを対応版へ更新する', output)
            self.assertIn('NODE_TLS_REJECT_UNAUTHORIZED=0', output)
            self.assertIn('Python本体を更新する', output)
            self.assertIn('再診断', output)
        self.assertIn('/opt/example-jdk', page)

    def test_version_action_shows_the_recorded_version_and_fixed_reference(self):
        row = record('pip', 'UPDATE', 'version')
        row['metadata'] = {'version': '26.2.1', 'reference_floor': '26.2.2'}
        _, page, summary, _ = self.outputs([row])
        for output in (page, summary):
            self.assertIn('現在: 26.2.1', output)
            self.assertIn('参考修正版: 26.2.2', output)
            self.assertIn('このPythonのpipを更新する', output)

    def test_successful_record_does_not_offer_unnecessary_remediation(self):
        _, page, summary, console = self.outputs([record('Java JSSE', 'REJECTED', 'measured')])
        for output in (page, summary, console):
            self.assertNotIn('このJDKを対応版へ更新する', output)

    def test_uv_update_has_tool_specific_instructions(self):
        _, page, summary, console = self.outputs([record('uvバージョン', 'UPDATE', 'version')])
        for output in (page, summary, console):
            self.assertIn('uv本体を更新する', output)


if __name__ == '__main__':
    unittest.main()
