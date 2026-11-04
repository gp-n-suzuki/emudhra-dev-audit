"""User-facing verdicts retain provenance, installation boundaries, and uncertainty."""
import contextlib
import io
import json
from html.parser import HTMLParser
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import audit
import app_inventory
import evidence
import reporting
import language_checks
import verdicts


def record(name, status, metadata, method='inventory', detail='観測データ'):
    return dict(name=name, status=status, detail=detail, action='', metadata=metadata,
                samples=[], assessment_method=method)


def instance(path, alias):
    return record('アプリ / Codex [' + path + ']', 'INFO', {
        'application': True, 'tool_id': 'codex', 'tool_name': 'Codex',
        'path': path, 'discovered_paths': [alias], 'inspections': [], 'uninspected': []})


class OfficialResultClassificationTests(unittest.TestCase):
    def test_official_release_versions_are_scoped_to_known_series(self):
        import official_versions
        cases = [
            ('codex', 'codex-cli 0.159.3', 'npm', 'UPDATE'),
            ('codex', 'codex-cli 0.164.0', 'npm', 'REFERENCE_OK'),
            ('codex', 'codex-cli 0.165.0', 'npm', 'REFERENCE_OK'),
            ('codex', 'codex-cli 0.166.0', 'npm', 'REFERENCE_OK'),
            ('codex', 'codex-cli 1.0.0', 'npm', 'MANUAL'),
            ('codex', 'codex-cli 0.165.0-rc.1', 'npm', 'MANUAL'),
            ('codex', 'codex-cli 0.165.0+vendor.1', 'vendor', 'MANUAL'),
            ('codex', '', 'npm', 'MANUAL'),
            ('claude-code', '2.1.312 (Claude Code)', 'native', 'MANUAL'),
            ('python', 'Python 3.13.17', 'official', 'UPDATE'),
            ('python', 'Python 3.13.18', 'official', 'REFERENCE_OK'),
            ('python', 'Python 3.13.18', 'vendor', 'MANUAL'),
            ('python', 'Python 3.16.0', 'official', 'MANUAL'),
            ('python', 'Python 3.13.17+backport', 'vendor', 'MANUAL'),
        ]
        for tool, version, distribution, expected in cases:
            with self.subTest(tool=tool, version=version, distribution=distribution):
                result = official_versions.assess(tool, version, distribution=distribution)
                self.assertEqual(result['status'], expected)
                if expected != 'MANUAL':
                    self.assertTrue(result['source'].startswith('https://'))
                    self.assertTrue(result['scope'])
        self.assertEqual(official_versions.python_distribution(
            '/Library/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python'), 'official')
        self.assertEqual(official_versions.python_distribution(
            r'C:\Program Files\Python313\python.exe'), 'official')
        self.assertEqual(official_versions.python_distribution('/opt/vendor/python3'), 'unknown')

    def test_electron_preview_and_future_series_are_not_inferred_safe(self):
        for version in ('45.0.0-beta.6', '45.0.0', '46.0.0', '44.9.1-rc.1'):
            with self.subTest(version=version):
                result = app_inventory.version_check(audit.reference, 'electron', version, '/app')
                self.assertEqual(result['status'], 'MANUAL')

    def test_official_bun_dart_and_flutter_stable_affected_ranges(self):
        cases = [('bun', '1.3.99', 'UPDATE'), ('bun', '1.4.4', 'INFERRED_OK'),
                 ('bun', '1.5.0', 'INFERRED_OK'), ('bun', '2.0.0', 'MANUAL'),
                 ('dart', '3.12.99', 'UPDATE'), ('dart', '3.13.7', 'INFERRED_OK'),
                 ('dart', '3.14.0', 'INFERRED_OK'), ('dart', '3.14.0-beta.1', 'MANUAL'),
                 ('dart', 'Dart SDK version: 3.14.0 (beta)', 'MANUAL'),
                 ('dart', '4.0.0', 'MANUAL'), ('flutter', '3.46.0', 'UPDATE'),
                 ('flutter', '3.47.8', 'INFERRED_OK'), ('flutter', '3.48.0', 'INFERRED_OK'),
                 ('flutter', '4.0.0', 'MANUAL')]
        for tool, version, expected in cases:
            with self.subTest(tool=tool, version=version):
                status, _, meta = language_checks.version_result(tool, version)
                self.assertEqual(status, expected)
                self.assertTrue(meta['source'].startswith('https://github.com/'))
        self.assertIn('Android', language_checks.SDK_SCOPE)
        self.assertIn('macOS', language_checks.SDK_SCOPE)
        status, _, meta = language_checks.version_result('bun', '1.4.4-canary.1')
        self.assertEqual(status, 'MANUAL')
        self.assertEqual(meta['version'], '1.4.4-canary.1')

    def test_uv_and_pip_official_stable_version_floors(self):
        cases = [('uv', '0.12.99', 'UPDATE'), ('uv', '0.13.4', 'UPDATE'), ('uv', '0.13.5', 'REFERENCE_OK'),
                 ('uv', '0.14.0', 'REFERENCE_OK'), ('uv', '1.0.0', 'MANUAL'),
                 ('uv', '0.13.4-rc1', 'MANUAL'),
                 ('pip', '25.3.9', 'UPDATE'), ('pip', '26.2.2', 'REFERENCE_OK'),
                 ('pip', '26.3.0', 'REFERENCE_OK'), ('pip', '27.0.0', 'MANUAL'),
                 ('pip', '26.2.2+deb1', 'MANUAL')]
        for tool, version, expected in cases:
            with self.subTest(tool=tool, version=version):
                self.assertEqual(audit.reference(tool, version)[0], expected)
        self.assertEqual(audit.REFERENCE_URLS['uv'],
                         'https://github.com/astral-sh/uv/releases/tag/0.13.5')

    def test_vendor_suffix_and_unreviewed_new_series_are_not_treated_as_official(self):
        for tool, version in (('node', 'v26.12.1-vendor.1'), ('pip', '26.2.2+vendor.1'),
                              ('go', 'go version go1.27.3-custom linux/amd64')):
            with self.subTest(tool=tool, version=version):
                self.assertEqual(audit.reference(tool, version)[0], 'MANUAL')
        result = evidence.version_evidence('Docker Desktop', '4.97.0', '4.96.2', 'https://example.org')
        self.assertEqual(result['status'], 'UNKNOWN')

    def test_go_and_rust_version_rows_link_directly_to_upstream_evidence(self):
        self.assertEqual(audit.REFERENCE_URLS['go'],'https://pkg.go.dev/vuln/GO-2026-6809')
        self.assertTrue(audit.REFERENCE_URLS['rustls-webpki'].startswith('https://github.com/rustls/webpki/'))
        for component in ('webpki-roots', 'webpki-root-certs'):
            self.assertTrue(audit.REFERENCE_URLS[component].startswith('https://github.com/rustls/webpki-roots/'))
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp)/'Cargo.lock'
            lock.write_text('[[package]]\nname = "rustls-webpki"\nversion = "0.103.16"\n')
            fixture = SimpleNamespace(host=SimpleNamespace(find=lambda name: None))
            rows = evidence.rust_evidence(fixture, [lock], audit.reference)
            row = next(r for r in rows if r['check'] == 'rustls-webpki')
            self.assertEqual(row['source'], audit.REFERENCE_URLS['rustls-webpki'])

    def test_unknown_scope_and_p2_transport_do_not_become_warnings(self):
        rows = [record('Codex / 固有の通信', 'MANUAL', {
                    'tool_id': 'codex', 'tool_name': 'Codex', 'executable': '/one/codex',
                    'p2_coverage': True}, 'manual'),
                record('Codex / バージョン', 'UNKNOWN', {
                    'tool_id': 'codex', 'tool_name': 'Codex', 'executable': '/one/codex', 'version': ''}),
                record('探索の上限', 'UNKNOWN', {}, 'inventory'),
                record('Java / 接続', 'ACTION', {}, 'measured')]
        result = verdicts.prepare(rows)
        self.assertEqual([r['review_state'] for r in result].count('review'), 0)
        self.assertEqual([r['review_state'] for r in result].count('unverified'), 3)
        self.assertEqual([r['review_state'] for r in result].count('action'), 1)
        self.assertTrue(next(r for r in result if r['status'] == 'ACTION')['requires_attention'])

    def test_embedded_version_and_missing_vendor_blocklist_remain_specific_reviews(self):
        embedded = record('アプリ / Example', 'UPDATE', {'application':True, 'inspections':[], 'uninspected':[]}, 'version')
        blocklist = record('Java / Azulブロックリスト', 'UPDATE', {}, 'static')
        states = verdicts.prepare([embedded, blocklist])
        self.assertEqual([r['review_state'] for r in states], ['review', 'review'])
        self.assertTrue(all(r['requires_attention'] for r in states))

    def test_saved_report_is_reevaluated_by_snapshot_alias_without_merging_installations(self):
        old_path = '/usr/local/Cellar/codex/0.42.0/bin/codex'
        new_path = '/home/test/lib/node_modules/@openai/codex/bin/codex.js'
        old_alias, new_alias = '/usr/local/bin/codex', '/home/test/bin/codex'
        rows = [instance(new_path, new_alias), instance(old_path, old_alias)]
        for alias, version, status in ((new_alias, 'codex-cli 0.165.0', 'INFO'), (old_alias, '', 'UNKNOWN')):
            rows.extend([
                record('Codex / バージョン', status, {'tool_id': 'codex', 'tool_name': 'Codex',
                       'executable': alias, 'version': version}),
                record('Codex / 固有の通信', 'MANUAL', {'tool_id': 'codex', 'tool_name': 'Codex',
                       'executable': alias, 'p2_coverage': True}, 'manual')])
        # Simulate a 2.6.0 report that had already normalized these records.
        for row in rows:
            row.update(review_state='review', requires_attention=True, required=True, scope='旧版の範囲')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=rows, source_observation={
                'tool_version':'2.6.0', 'generated_at':'2026-10-29T11:51:32+09:00'}), Path(tmp))
            saved = json.loads((Path(tmp) / 'report.json').read_text())
            page = (Path(tmp) / 'report.html').read_text()
        versions = {r['metadata'].get('executable'): r for r in saved['records'] if r['name'] == 'Codex / バージョン'}
        self.assertEqual(versions[new_alias]['status'], 'INFERRED_OK')
        self.assertEqual(versions[old_alias]['status'], 'UNKNOWN')
        self.assertEqual(versions[old_alias]['review_state'], 'unverified')
        self.assertEqual(saved['summary']['tool_review_counts']['review'], 0)
        self.assertEqual(saved['source_observation']['tool_version'], '2.6.0')
        self.assertEqual(saved['source_observation']['generated_at'], '2026-10-29T11:51:32+09:00')
        self.assertIn('対応版を使用中', page)
        self.assertEqual(page.count('class="installation-result"'), 2)
        self.assertIn('npm / codex-cli 0.165.0', page)
        self.assertIn('Homebrew (Intel)', page)
        self.assertNotIn('PATHで使用中', page)
        self.assertEqual(len(saved['records']), len(rows))

    def test_explicit_old_and_new_versions_are_independent(self):
        rows = []
        for path, alias, version in (
            ('/one/lib/node_modules/@openai/codex/bin/codex.js', '/one/codex', 'codex-cli 0.159.3'),
            ('/two/lib/node_modules/@openai/codex/bin/codex.js', '/two/codex', 'codex-cli 0.165.0')):
            rows.append(instance(path, alias))
            rows.append(record('Codex / バージョン', 'INFO', {
                'tool_id':'codex', 'tool_name':'Codex', 'executable':alias, 'version':version}))
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=rows), Path(tmp))
            saved = json.loads((Path(tmp) / 'report.json').read_text())
            page = (Path(tmp) / 'report.html').read_text()
        self.assertEqual({r['status'] for r in saved['records'] if r['name'] == 'Codex / バージョン'},
                         {'UPDATE', 'INFERRED_OK'})
        old = next(r for r in saved['records'] if r['status'] == 'UPDATE')
        fixed = next(r for r in saved['records'] if r['status'] == 'INFERRED_OK')
        self.assertEqual(old['remediation']['title'], 'この導入のCodexを対策版へ更新する')
        self.assertEqual(old['remediation']['target'], '/one/codex')
        self.assertNotIn('remediation', fixed)
        self.assertIn('更新が必要', page)
        self.assertIn('対応版を使用中', page)
        self.assertEqual(page.count('class="installation-result"'), 2)

    def test_official_python_pip_and_node_have_targeted_update_guidance(self):
        import remediation
        cases = [('Python / バージョン', {'tool_id':'python', 'packages':{}, 'executable':'/python'},
                  'このPython本体を対策版へ更新する'),
                 ('Python / pip バージョン', {'tool_id':'python', 'executable':'/python'},
                  'このPythonのpipを更新する'),
                 ('Node.js バージョン', {'tool_id':'node', 'executable':'/node'},
                  'Node.jsとnpmを対応版へ更新する')]
        for name, meta, expected in cases:
            with self.subTest(name=name):
                value = verdicts.finish(record(name, 'UPDATE', meta, 'version'))
                guide = remediation.plan(value)
                self.assertEqual(guide['title'], expected)
                self.assertEqual(guide['target'], meta['executable'])

    def test_fixed_version_does_not_hide_explicit_tls_failure(self):
        path, alias = '/lib/node_modules/@openai/codex/bin/codex.js', '/bin/codex'
        rows = [instance(path, alias),
                record('Codex / バージョン', 'INFO', {'tool_id':'codex', 'tool_name':'Codex',
                       'executable':alias, 'version':'codex-cli 0.165.0'}),
                record('Codex / TLS検証の無効化', 'ACTION', {'tool_id':'codex', 'tool_name':'Codex',
                       'executable':alias}, 'configuration')]
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=rows), Path(tmp))
            saved = json.loads((Path(tmp) / 'report.json').read_text())
            page = (Path(tmp) / 'report.html').read_text()
        self.assertEqual(saved['summary']['tool_review_counts']['action'], 1)
        self.assertTrue(any(r['status'] == 'ACTION' for r in saved['records']))
        self.assertIn('TLS検証の無効化', page)
        self.assertIn('対応版を使用中', page)
        # After opening the installation, the action is already visible.
        self.assertIn('<section class="ACTION" data-review="action" data-method="configuration"', page)
        self.assertIn('class="action-reason action-configure"', page)
        self.assertIn('Codex / TLS検証の無効化', page.split('検査データ・原記録')[0])

    def test_conflicting_alias_snapshot_is_not_used_to_guess_version_origin(self):
        rows = [instance('/one/lib/node_modules/@openai/codex/bin/codex.js', '/shared/codex'),
                instance('/two/lib/node_modules/@openai/codex/bin/codex.js', '/shared/codex'),
                record('Codex / バージョン', 'INFO', {'tool_id':'codex', 'tool_name':'Codex',
                       'executable':'/shared/codex', 'version':'codex-cli 0.165.0'})]
        result = verdicts.prepare(rows)
        version = next(r for r in result if r['name'] == 'Codex / バージョン')
        self.assertNotEqual(version['status'], 'INFERRED_OK')
        self.assertEqual(version['review_state'], 'unverified')

    def test_container_path_never_uses_the_host_alias_snapshot(self):
        alias = '/usr/local/bin/python3'
        real = '/Library/Frameworks/Python.framework/Versions/3.13/bin/python3'
        inventory = record('アプリ / Python ['+real+']', 'INFO', {
            'application':True, 'tool_id':'python', 'tool_name':'Python', 'path':real,
            'discovered_paths':[alias], 'inspections':[], 'uninspected':[]})
        def python(context):
            return record(context+' / Python 3.13.18 [/env]', 'INFO', {
                'tool_id':'python', 'tool_name':'Python', 'executable':alias,
                'execution_context':context, 'prefix':'/env', 'version':'3.13.18', 'packages':{}})
        result = verdicts.prepare([inventory, python('ホスト'), python('コンテナ sample')])
        host = next(r for r in result if r['name'].startswith('ホスト / Python '))
        container = next(r for r in result if r['name'].startswith('コンテナ sample / Python '))
        self.assertEqual(host['status'], 'INFERRED_OK')
        self.assertEqual(container['review_state'], 'unverified')
        self.assertEqual(container['metadata']['distribution'], 'unknown')
        tool = next(t for t in reporting.group_tools(result)[0] if t['name'] == 'Python')
        self.assertEqual(len(tool['units']), 2)

    def test_claude_recorded_version_remains_unverified_without_official_fix_evidence(self):
        row = record('Claude Code / バージョン', 'INFO', {'tool_id':'claude-code',
                     'tool_name':'Claude Code', 'executable':'/bin/claude', 'version':'2.1.312 (Claude Code)'})
        result = verdicts.prepare([row])[0]
        self.assertEqual(result['review_state'], 'unverified')
        self.assertNotIn(result['status'], ('INFERRED_OK', 'UPDATE'))
        self.assertEqual(result['metadata']['version'], '2.1.312 (Claude Code)')

    def test_browser_evidence_does_not_replace_snapshot_alias_mapping(self):
        path, alias = '/lib/node_modules/@openai/codex/bin/codex.js', '/bin/codex'
        browser = record('ブラウザ / 実際のプロファイル', 'INFO', {})
        browser['evidence'] = [{'check':'Google Chrome', 'kind':'inventory', 'status':'INFO',
                                'detail':'記録されたブラウザ'}]
        version = record('Codex / バージョン', 'INFO', {'tool_id':'codex', 'tool_name':'Codex',
                         'executable':alias, 'version':'codex-cli 0.165.0'})
        result = verdicts.prepare([browser, instance(path, alias), version])
        self.assertEqual(next(r for r in result if r['name'] == version['name'])['status'], 'INFERRED_OK')

    def test_summary_prioritizes_successful_version_comparison_and_handles_info_only(self):
        fixed = verdicts.prepare([record('pip', 'INFERRED_OK', {}, 'version'),
                                  record('pip / 通信', 'SKIP', {}, 'unmeasured')])
        state = reporting.overview(fixed)
        self.assertIn('照合した版', state['title'])
        self.assertNotEqual(state['tone'], 'review')
        info = verdicts.prepare([record('環境', 'INFO', {})])
        self.assertNotEqual(reporting.overview(info)['title'], '検査結果がありません')

    def test_python_collection_compares_official_installations_and_preserves_vendor_unknown(self):
        paths = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3',
                 '/Library/Frameworks/Python.framework/Versions/3.14/bin/python3',
                 '/opt/vendor/bin/python3']
        versions = dict(zip(paths, ('3.13.18', '3.14.9', '3.13.18')))
        args = SimpleNamespace(project=None, python=paths, scan_venvs=[], offline=True, timeout=1, workers=1)
        instance = audit.Audit(args)
        def metadata(ctx, command):
            path = command[0]
            return {'state':'meta', 'data':{'executable':path, 'version':versions[path],
                'prefix':path.rsplit('/bin/', 1)[0], 'base_prefix':path.rsplit('/bin/', 1)[0],
                'packages':{}}}
        try:
            with mock.patch.object(audit.sys, 'executable', str(audit.ROOT/'runtime/bin/python3')), \
                 mock.patch.object(instance.host, 'find', return_value=None), \
                 mock.patch.object(instance, 'json_probe', side_effect=metadata), \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.python(instance.host)
                with tempfile.TemporaryDirectory() as tmp:
                    audit.write_reports(instance, Path(tmp))
                    report = json.loads((Path(tmp)/'report.json').read_text())
                    page = (Path(tmp)/'report.html').read_text()
        finally:
            instance.tmp.cleanup()
        observations = {r['metadata']['executable']:r for r in report['records']
                        if r.get('metadata',{}).get('packages') == {}}
        self.assertEqual(observations[paths[0]]['status'], 'INFERRED_OK')
        self.assertEqual(observations[paths[1]]['status'], 'UPDATE')
        self.assertEqual(observations[paths[2]]['review_state'], 'unverified')
        self.assertIn('対応版を使用中', page)
        self.assertIn('更新が必要', page)

    def test_node_and_go_collection_bind_version_and_transport_to_the_same_executable(self):
        nodes = ['/opt/first/bin/node', '/opt/second/bin/node']
        go = '/opt/go/bin/go'
        args = SimpleNamespace(project=None, node=nodes, offline=True, timeout=1, workers=1)
        instance = audit.Audit(args)
        def paths(ctx, name, explicit=None, all_paths=False):
            return nodes if name == 'node' else [go] if name == 'go' else []
        def metadata(ctx, command):
            path = command[0]
            return {'state':'meta', 'data':{'version':'v26.12.0' if path == nodes[0] else 'v26.12.1'}}
        try:
            with mock.patch.object(instance, 'paths', side_effect=paths), \
                 mock.patch.object(instance, 'json_probe', side_effect=metadata), \
                 mock.patch.object(instance.host, 'call', return_value=(0, 'go version go1.27.3 darwin/arm64', '')), \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.node(instance.host)
                instance.other_languages(instance.host, {'go'})
                with tempfile.TemporaryDirectory() as tmp:
                    audit.write_reports(instance, Path(tmp))
                    report = json.loads((Path(tmp)/'report.json').read_text())
        finally:
            instance.tmp.cleanup()
        for tool, executable in [('node', nodes[0]), ('node', nodes[1]), ('go', go)]:
            matching = [r for r in report['records'] if r['metadata'].get('tool_id') == tool
                        and r['metadata'].get('executable') == executable]
            self.assertTrue(any(r['assessment_method'] == 'version' for r in matching))
            self.assertTrue(any(r['status'] == 'SKIP' for r in matching))
        node_tool = next(t for t in reporting.group_tools(report['records'])[0] if t['name'] == 'Node.js')
        self.assertEqual(len(node_tool['units']), 2)
        class Visible(HTMLParser):
            def __init__(self): super().__init__(); self.stack=[]; self.text=''
            def handle_starttag(self, tag, attrs):
                if tag == 'details': self.stack.append(dict(attrs).get('class') in ('tool-record', 'result-record', 'missing-tools'))
            def handle_endtag(self, tag):
                if tag == 'details': self.stack.pop()
            def handle_data(self, data):
                if all(self.stack): self.text += data
        # Long executable paths stay inside inspection data even after opening a result.
        page = audit.render_report(report['records'], 'fixture')
        visible = Visible(); visible.feed(page)
        for path in nodes: self.assertNotIn(path, visible.text)

    def test_legacy_node_and_go_version_rows_reuse_the_recorded_executable(self):
        rows = [record('ホスト / Node.js /snapshot/bin/node', 'REFERENCE_OK',
                       {'version':'v26.12.1', 'reference_floor':'26.12.1'}, 'version'),
                record('ホスト / Node.js fetch [/snapshot/bin/node]', 'SKIP',
                       {'tool_id':'node', 'executable':'/snapshot/bin/node'}, 'unmeasured'),
                record('ホスト / Goバージョン [/snapshot/bin/go]', 'REFERENCE_OK',
                       {'version':'go version go1.27.3 linux/amd64', 'reference_floor':'1.27.3'}, 'version'),
                record('ホスト / Go TLS [/snapshot/bin/go]', 'SKIP',
                       {'tool_id':'go', 'executable':'/snapshot/bin/go'}, 'unmeasured')]
        normalized = verdicts.prepare(rows)
        tools = {t['name']:t for t in reporting.group_tools(normalized)[0]}
        self.assertEqual(len(tools['Node.js']['units']), 1)
        self.assertEqual(len(tools['Go']['units']), 1)
        self.assertEqual(next(r for r in normalized if r['name'].startswith('ホスト / Node.js /'))['metadata']['executable'], '/snapshot/bin/node')

    def test_legacy_pip_uv_and_bun_are_reassessed_with_current_official_floors(self):
        rows = [record('ホスト / Python 3.12 [/venv] / pip バージョン', 'MANUAL',
                       {'version':'25.3.9', 'reference_floor':None}, 'version'),
                record('uvバージョン', 'MANUAL', {'version':'uv 0.12.99', 'reference_floor':None}, 'version'),
                record('Bun バージョン', 'MANUAL', {'version':'1.3.99', 'reference_floor':'1.4.4',
                       'source':language_checks.REFERENCES['bun'][1]}, 'version'),
                record('Flutter SDK', 'MANUAL', {'version':'3.47.8-beta.1', 'reference_floor':'3.47.8',
                       'source':language_checks.REFERENCES['flutter'][1]}, 'version')]
        for row in rows: row.update(review_state='review', requires_attention=True, scope='旧基準')
        normalized = {r['name']:r for r in verdicts.prepare(rows)}
        for name in ('ホスト / Python 3.12 [/venv] / pip バージョン', 'uvバージョン', 'Bun バージョン'):
            self.assertEqual(normalized[name]['status'], 'UPDATE')
            self.assertEqual(normalized[name]['review_state'], 'action')
        self.assertEqual(normalized['Flutter SDK']['review_state'], 'unverified')
        self.assertEqual(normalized['Flutter SDK']['metadata']['version'], '3.47.8-beta.1')


if __name__ == '__main__':
    unittest.main()
