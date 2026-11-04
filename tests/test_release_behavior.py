"""Distribution-facing behavior, with no public network connections."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit


class ReleaseBehaviorTests(unittest.TestCase):
    def test_help_is_utf8_even_when_redirected_to_legacy_windows_encoding(self):
        buffer=io.BytesIO()
        output=io.TextIOWrapper(buffer,encoding='cp1252')
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
            audit.main(['--help'])
        output.flush()
        self.assertEqual(result.exception.code,0)
        self.assertIn('eMudhra開発環境診断',buffer.getvalue().decode('utf-8'))

    def test_argument_errors_are_utf8_with_legacy_stderr(self):
        buffer=io.BytesIO()
        output=io.TextIOWrapper(buffer,encoding='cp1252')
        with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as result:
            audit.main(['--project',str(Path(tempfile.gettempdir())/'missing-emudhra-project-不存在')])
        output.flush()
        self.assertEqual(result.exception.code,2)
        self.assertIn('存在するディレクトリ',buffer.getvalue().decode('utf-8'))

    def test_launch_defaults_to_installed_pc_tools_with_no_project(self):
        for arguments in ([], ['--offline']):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as tmp:
                seen = []
                def execute(instance):
                    seen.append((instance.args.project, instance.args.host_only))
                    instance.add('検査対象', 'INFO', 'このPCにインストールされている開発環境')
                with mock.patch.object(audit.Path, 'cwd', return_value=Path(tmp)), \
                     mock.patch.object(audit.Audit, 'execute', execute), contextlib.redirect_stdout(io.StringIO()):
                    code = audit.main(arguments)
                self.assertEqual(code, 0)
                self.assertEqual(seen, [(None, True)])
                self.assertEqual(len(list(Path(tmp).glob('emudhra-report-*/report.json'))), 1)

    def test_project_remains_an_explicit_optional_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = []
            def execute(instance):
                seen.append((instance.args.project, instance.args.host_only))
            with mock.patch.object(audit.Audit, 'execute', execute), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--project', tmp, '--out', str(Path(tmp)/'report')])
            self.assertEqual(seen, [(Path(tmp), False)])

    def test_host_only_does_not_scan_current_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'pyvenv.cfg').write_text('fixture')
            with mock.patch.object(audit.Path,'cwd',return_value=root), \
                 mock.patch.object(audit.Audit,'config_inventory',autospec=True), \
                 mock.patch.object(audit.evidence,'mac_bundles',return_value=[]), \
                 contextlib.redirect_stdout(io.StringIO()):
                code=audit.main(['--host-only','--offline','--only','native','--out',str(root/'report')])
            report=json.loads((root/'report/report.json').read_text(encoding='utf-8'))
            self.assertEqual(code,0)
            self.assertFalse(any('未検査のPython仮想環境' in r['name'] for r in report['records']))

    def test_non_mac_browser_import_explains_supported_scope_before_running(self):
        for platform in ('win32','linux'):
            with self.subTest(platform=platform), mock.patch.object(audit.sys,'platform',platform), \
                 mock.patch.object(audit.Audit,'execute') as execute, contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit):
                    audit.main(['--host-only','--browser-results','observations.json'])
                self.assertIn('macOS',err.getvalue())
                execute.assert_not_called()


if __name__=='__main__': unittest.main()
