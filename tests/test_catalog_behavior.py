"""User-visible inventory and verdict contracts for installed tools."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import app_inventory
import audit
import reporting
import verdicts


class CatalogBehavior(unittest.TestCase):
    def scan(self, **kwargs):
        return app_inventory.scan(audit.reference, path_dirs=kwargs.pop('path_dirs', []),
                                  install_dirs=kwargs.pop('install_dirs', []), **kwargs)

    def test_inventory_finds_only_catalog_tools_and_reports_unknown_gui(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'bin').mkdir()
            for name in ('wget', 'unrelated-utility'):
                path = root/'bin'/name
                path.write_text('#!/bin/sh\nexit 0\n')
                path.chmod(0o755)
            (root/'apps'/'Cursor.app').mkdir(parents=True)
            (root/'apps'/'Unrelated.app').mkdir()
            rows = self.scan(path_dirs=[root/'bin'], install_dirs=[root/'apps'])
            found = {r['metadata'].get('tool_id'): r for r in rows if r['metadata'].get('application')}
            self.assertIn('wget', found)
            self.assertIn('cursor', found)
            self.assertEqual(found['cursor']['review_state'], 'unverified')
            self.assertIn('通信', found['cursor']['detail'])
            self.assertNotIn('unrelated-utility', str(rows))
            self.assertNotIn('Unrelated.app', str(rows))

    def test_same_executable_aliases_are_one_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root/'wget'
            actual.write_text('#!/bin/sh\nexit 0\n')
            actual.chmod(0o755)
            other = root/'wget.exe'
            try:
                other.symlink_to(actual)
            except OSError:
                self.skipTest('symlinks unavailable')
            rows = self.scan(path_dirs=[root])
            found = [r for r in rows if r['metadata'].get('tool_id') == 'wget']
            self.assertEqual(len(found), 1)
            self.assertEqual(len(found[0]['metadata']['discovered_paths']), 2)

    def test_virtualenv_aliases_do_not_merge_different_environments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root/'base-python'; base.write_text('fixture'); base.chmod(0o755)
            bins = []
            for name in ('first', 'second'):
                env = root/name; (env/'bin').mkdir(parents=True)
                (env/'pyvenv.cfg').write_text('home = fixture\n')
                for command in ('python', 'python3'):
                    (env/'bin'/command).symlink_to(base)
                bins.append(env/'bin')
            rows = self.scan(path_dirs=bins)
            found = [r for r in rows if r['metadata'].get('tool_id') == 'python' and r['metadata'].get('application')]
            self.assertEqual(len(found), 2)
            self.assertTrue(all(len(r['metadata']['discovered_paths']) == 2 for r in found))

    def test_discovered_executables_are_selected_for_runtime_probes(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node = root/'managed/node'; node.parent.mkdir(); node.write_text('fixture'); node.chmod(0o755)
            args = SimpleNamespace(project=None)
            instance = audit.Audit(args)
            instance.discovered = {'node': [str(node)]}
            try:
                with mock.patch.object(instance.host, 'find', return_value=None):
                    self.assertIn(str(node), instance.paths(instance.host, 'node'))
            finally:
                instance.tmp.cleanup()

    def test_absent_and_nonapplicable_are_distinct(self):
        rows = self.scan()
        missing = next(r for r in rows if r['metadata'].get('tool_id') == 'osv-scanner')
        self.assertEqual(missing['status'], 'NOT_FOUND')
        if os.name != 'nt':
            windows = next(r for r in rows if r['metadata'].get('tool_id') == 'winget')
            self.assertEqual(windows['status'], 'NOT_APPLICABLE')
        page = audit.render_report(rows, 'fixture')
        self.assertIn('data-result-group="not_found"', page)
        if os.name != 'nt': self.assertIn('data-result-group="not_applicable"', page)

    def test_old_version_is_a_scoped_update_action(self):
        row = verdicts.finish(dict(name='pip', status='UPDATE', detail='旧版', metadata={}, samples=[]), 'version')
        self.assertEqual(row['review_state'], 'action')
        self.assertEqual(verdicts.summarize([row])['review_counts']['action'], 1)

    def test_advisory_explicitly_includes_older_go_branches(self):
        status, detail, floor = audit.reference('go', 'go1.25.4')
        self.assertEqual(status, 'UPDATE')
        self.assertEqual(floor, '1.26.10')
        self.assertIn('配布元', detail)

    def test_plain_inventory_evidence_does_not_mean_protection_confirmed(self):
        parent = {'name': 'fixture'}
        row = verdicts.observation(parent, {'check': '導入版', 'kind': 'inventory',
                                             'status': 'INFO', 'detail': '導入版を取得'}, 'ツール')
        self.assertEqual(row['review_state'], 'info')
        self.assertNotEqual(row['status'], 'CHECKED')

    def test_manager_metadata_and_safe_chain_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            for relative in ('.nvm/nvm.sh', '.sdkman/bin/sdkman-init.sh',
                             '.mix/archives/hex-2.0.0/hex/ebin/hex.app',
                             '.local/share/powershell/Modules/PowerShellGet/3.0/PowerShellGet.psd1',
                             '.local/share/powershell/Modules/Microsoft.PowerShell.PSResourceGet/1.0/Microsoft.PowerShell.PSResourceGet.psd1'):
                path = home/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
            bin_dir = home/'bin'
            bin_dir.mkdir()
            wrapper = bin_dir/'aikido-npm'
            wrapper.write_text('#!/bin/sh\nexit 0\n'); wrapper.chmod(0o755)
            with mock.patch.object(Path, 'home', return_value=home), \
                 mock.patch.object(app_inventory, 'default_locations', return_value=([bin_dir], [])):
                rows = app_inventory.scan(audit.reference)
            found = {r['metadata'].get('tool_id') for r in rows if r['metadata'].get('application')}
            self.assertTrue({'nvm', 'sdkman', 'hex', 'powershellget', 'psresourceget', 'safe-chain'} <= found)

    def test_antigravity_ide_is_known(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'Antigravity.app').mkdir()
            (root/'Antigravity IDE.app').mkdir()
            rows = self.scan(install_dirs=[root])
            found = [r for r in rows if r['metadata'].get('tool_id') == 'antigravity']
            self.assertEqual(len(found), 2)
            self.assertEqual(len({r['metadata']['path'] for r in found}), 2)

    def test_inspection_budget_does_not_turn_absent_tools_into_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wget = root/'wget'
            wget.write_bytes(b'\x7fELF' + b'0'*200); wget.chmod(0o755)
            rows = self.scan(path_dirs=[root], max_bytes=1)
            missing = next(r for r in rows if r['metadata'].get('tool_id') == 'osv-scanner')
            found = next(r for r in rows if r['metadata'].get('tool_id') == 'wget' and r['metadata'].get('application'))
            self.assertEqual(missing['status'], 'NOT_FOUND')
            self.assertEqual(found['review_state'], 'unverified')

    def test_probe_matches_only_same_tool_and_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root/'curl'; path.write_text('x'); path.chmod(0o755)
            inventory = next(r for r in self.scan(path_dirs=[root]) if r['metadata'].get('tool_id') == 'curl' and r['metadata'].get('application'))
            measured = dict(name='ホスト / curl', status='REJECTED', detail='信頼エラーで拒否',
                            metadata={'tool_id':'curl', 'executable':str(path)}, samples=[{'status':'REJECTED'}])
            other = dict(measured, metadata={'tool_id':'wget', 'executable':str(path)})
            rows = verdicts.prepare([inventory, measured])
            self.assertFalse(any(r['review_state'] == 'review' for r in rows))
            self.assertTrue(any(r['status'] == 'REJECTED' for r in rows))
            self.assertEqual(len(reporting.group_tools(rows)[0][0]['units']), 1)
            rows = verdicts.prepare([inventory, other])
            self.assertTrue(any(r['review_state'] == 'unverified' for r in rows))
            self.assertEqual(len(reporting.group_tools(rows)[0][0]['units']), 2)

    def test_all_outputs_count_tools_consistently(self):
        import contextlib
        import io
        import json
        from types import SimpleNamespace
        records = [
            verdicts.finish(dict(name='Node.js / 一つ目', status='MANUAL', detail='未確認', metadata={}, samples=[])),
            verdicts.finish(dict(name='Node.js / 二つ目', status='UPDATE', detail='旧版', metadata={}, samples=[]), 'version'),
        ]
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as output:
            instance = SimpleNamespace(records=records)
            audit.write_reports(instance, Path(tmp))
            report = json.loads((Path(tmp)/'report.json').read_text())
            page = (Path(tmp)/'report.html').read_text()
            summary = (Path(tmp)/'summary.txt').read_text()
            self.assertEqual(report['summary']['review_counts']['action'], 1)
            self.assertEqual(report['summary']['review_counts']['unverified'], 1)
            self.assertEqual(report['summary']['tool_review_counts']['action'], 1)
            self.assertIn('更新が必要 <span>1ツール</span>', page)
            self.assertIn('更新が必要: 1ツール', summary)
            self.assertEqual(summary.count('ツール: Node.js'), 1)
            self.assertIn('Node.js / 一つ目', summary)
            self.assertIn('Node.js / 二つ目', summary)
            self.assertIn('更新が必要 1', output.getvalue())

    def test_old_version_guidance_checks_vendor_before_assuming_update(self):
        import remediation
        row = verdicts.finish(dict(name='uv', status='UPDATE', detail='旧版',
                                    metadata={'version':'0.13.0', 'reference_floor':'0.13.4'}, samples=[]), 'version')
        guide = remediation.plan(row)
        self.assertEqual(guide['title'], 'uv本体を更新する')
        self.assertIn('バックポート', ' '.join(guide['steps']))

    def test_installed_homebrew_nss_is_visible_as_its_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            cellar = Path(tmp)/'Cellar'
            (cellar/'nss/3.114').mkdir(parents=True)
            rows = self.scan(install_dirs=[cellar])
            row = next(r for r in rows if r['metadata'].get('tool_id') == 'nss' and r['metadata'].get('application'))
            self.assertEqual(row['review_state'], 'review')
            self.assertEqual(row['metadata']['inspections'][0]['version'], '3.114')
            self.assertIn('NSS', reporting.tool_name(row))
            self.assertIn('配布元', row['action'])

    def test_known_gui_version_is_read_without_starting_the_app(self):
        import plistlib
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            info = root/'Cursor.app/Contents/Info.plist'
            info.parent.mkdir(parents=True)
            info.write_bytes(plistlib.dumps({'CFBundleShortVersionString':'2.5.0', 'CFBundleIdentifier':'example.cursor'}))
            row = next(r for r in self.scan(install_dirs=[root]) if r['metadata'].get('tool_id') == 'cursor' and r['metadata'].get('application'))
            self.assertEqual(row['metadata']['application_version'], '2.5.0')
            self.assertEqual(row['review_state'], 'unverified')
            self.assertIn('通信', row['detail'])

    def test_unverified_release_branches_and_prereleases_are_not_compared(self):
        import language_checks
        self.assertEqual(audit.reference('pip', '25.3.9')[0], 'UPDATE')
        self.assertEqual(audit.reference('uv', '0.12.99')[0], 'UPDATE')
        self.assertEqual(audit.reference('pip', '26.2.2-rc1')[0], 'MANUAL')
        self.assertEqual(language_checks.version_result('bun', '1.3.99')[0], 'UPDATE')
        self.assertEqual(language_checks.version_result('dart', '3.12.99')[0], 'UPDATE')

    def test_known_windows_and_linux_nested_installations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            examples = [
                ('win32', {'ProgramFiles':str(root/'Program Files'), 'LOCALAPPDATA':str(root/'Local')},
                 root/'Program Files/Google/Chrome/Application/chrome.exe', 'chrome'),
                ('win32', {'ProgramFiles':str(root/'Program Files'), 'LOCALAPPDATA':str(root/'Local')},
                 root/'Local/Programs/Microsoft VS Code/Code.exe', 'vscode'),
                ('linux', {},
                 root/'opt/google/chrome/google-chrome', 'chrome'),
            ]
            for platform, environ, path, expected in examples:
                path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture')
                path.chmod(0o755)
                locations = app_inventory.known_installations(platform, environ, root, system_root=root)
                self.assertIn((path, expected), locations)

    def test_windows_registration_without_path_is_found_but_not_confirmed(self):
        registration = {'tool_id':'vscode', 'display_name':'Microsoft Visual Studio Code',
                        'version':'1.99.0', 'location':''}
        with mock.patch.object(app_inventory.sys,'platform','win32'), \
             mock.patch.object(app_inventory,'windows_registrations',return_value=([registration],[])), \
             mock.patch.object(app_inventory,'default_locations',return_value=([],[])), \
             mock.patch.object(app_inventory,'managed_locations',return_value=([],[])), \
             mock.patch.object(app_inventory,'managed_metadata',return_value=([],[])), \
             mock.patch.object(app_inventory,'known_installations',return_value=[]):
            rows = app_inventory.scan(audit.reference)
        found = [r for r in rows if r['metadata'].get('tool_id') == 'vscode']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['status'], 'MANUAL')
        self.assertEqual(found[0]['metadata']['discovery_state'], 'registry_only')
        self.assertEqual(found[0]['metadata']['version'], '1.99.0')

    def test_installed_client_with_unsupported_probe_needs_review(self):
        from types import SimpleNamespace
        import contextlib
        import io
        instance = audit.Audit(SimpleNamespace(project=None, offline=False, workers=1, timeout=1))
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                row = instance.sample('Node.js / fetch', lambda url: {'state':'skipped',
                    'detail':'API unavailable','optional_missing':True}, {'tool_id':'node','executable':'/node'})
            result = verdicts.finish(row)
            self.assertEqual(result['review_state'], 'unverified')
        finally: instance.tmp.cleanup()

    def test_old_version_machine_action_does_not_assume_update_exists(self):
        from types import SimpleNamespace
        import contextlib
        import io
        instance = audit.Audit(SimpleNamespace(project=None))
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                instance.ref('pip','26.2.1','pip')
            self.assertIn('バックポート', instance.records[0]['action'])
            self.assertNotIn('修正版に更新', instance.records[0]['action'])
        finally: instance.tmp.cleanup()

    def test_sdk_features_are_registered_under_the_owning_tool(self):
        import tool_catalog
        self.assertIn('Go Modules', tool_catalog.BY_ID['go']['features'])
        self.assertIn('Swift Package Manager', tool_catalog.BY_ID['swift']['features'])
        self.assertIn('pub', tool_catalog.BY_ID['dart']['features'])
        self.assertIn('.NET Framework', tool_catalog.BY_ID['dotnet']['features'])

    def test_unknown_is_not_success_exit_state(self):
        row = verdicts.finish(dict(name='Cursor', status='UNKNOWN', detail='読取不可', metadata={}, samples=[]))
        self.assertEqual(row['review_state'], 'unverified')
        self.assertFalse(row['requires_attention'])
