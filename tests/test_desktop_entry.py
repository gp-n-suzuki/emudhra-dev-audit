"""Double-click runs are independent, open finished reports and retain failures."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import desktop_entry


class DesktopEntryTests(unittest.TestCase):
    def test_finished_reports_open_for_every_diagnostic_verdict(self):
        for verdict in (0, 1, 2):
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                def diagnose(arguments):
                    self.assertNotIn('--project', arguments)
                    out = Path(arguments[arguments.index('--out') + 1])
                    self.assertEqual(out.parent, root/'結果')
                    (out/'report.html').write_text('finished')
                    return verdict
                def opened(path):
                    self.assertEqual(path.read_text(), 'finished')
                    return True
                with mock.patch.object(desktop_entry, 'PACKAGE', root), \
                     mock.patch.object(desktop_entry.audit, 'main', side_effect=diagnose), \
                     mock.patch.object(desktop_entry, 'open_report', side_effect=opened) as browser, \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(desktop_entry.main(), 0)
                browser.assert_called_once()

    def test_repeated_launch_does_not_replace_or_open_a_previous_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def diagnose(arguments):
                out = Path(arguments[arguments.index('--out') + 1])
                (out/'report.html').write_text('finished')
                return 0
            with mock.patch.object(desktop_entry, 'PACKAGE', root), \
                 mock.patch.object(desktop_entry, 'datetime') as clock, \
                 mock.patch.object(desktop_entry.audit, 'main', side_effect=diagnose), \
                 mock.patch.object(desktop_entry, 'open_report', return_value=True) as browser, \
                 contextlib.redirect_stdout(io.StringIO()):
                clock.now.return_value.strftime.return_value = '20261027-120000'
                desktop_entry.main()
                desktop_entry.main()
            paths = [call.args[0] for call in browser.call_args_list]
            self.assertEqual(len(set(paths)), 2)
            self.assertTrue(all(path.read_text() == 'finished' for path in paths))

    def test_launch_failure_never_opens_an_old_report_and_requests_visible_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'report.html').write_text('old result')
            with mock.patch.object(desktop_entry, 'PACKAGE', root), \
                 mock.patch.object(desktop_entry.audit, 'main', side_effect=OSError('cannot write')), \
                 mock.patch.object(desktop_entry, 'open_report') as browser, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(desktop_entry.main(), 3)
            browser.assert_not_called()
            self.assertIn('診断を完了できませんでした', output.getvalue())

    def test_missing_report_is_not_treated_as_a_successful_launch(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(desktop_entry, 'PACKAGE', Path(tmp)), \
             mock.patch.object(desktop_entry.audit, 'main', return_value=2), \
             mock.patch.object(desktop_entry, 'open_report') as browser, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(desktop_entry.main(), 3)
            browser.assert_not_called()

    def test_browser_failure_keeps_the_report_and_prints_its_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def diagnose(arguments):
                (Path(arguments[arguments.index('--out') + 1])/'report.html').write_text('finished')
                return 0
            with mock.patch.object(desktop_entry, 'PACKAGE', root), \
                 mock.patch.object(desktop_entry.audit, 'main', side_effect=diagnose), \
                 mock.patch.object(desktop_entry, 'open_report', side_effect=OSError('no browser')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(desktop_entry.main(), 3)
            report = next((root/'結果').glob('*/report.html'))
            self.assertIn(str(report), output.getvalue())
            self.assertIn('結果画面を開けませんでした', output.getvalue())

    def test_os_openers_receive_literal_paths_with_spaces_and_metacharacters(self):
        path = Path('/tmp/日本語 space & %/report.html')
        with mock.patch.object(desktop_entry.sys, 'platform', 'win32'), \
             mock.patch.object(desktop_entry.os, 'startfile', create=True) as start:
            self.assertTrue(desktop_entry.open_report(path))
            start.assert_called_once_with(str(path))
        for platform, command in (('darwin', '/usr/bin/open'), ('linux', 'xdg-open')):
            with self.subTest(platform=platform), \
                 mock.patch.object(desktop_entry.sys, 'platform', platform), \
                 mock.patch.object(desktop_entry.subprocess, 'run', return_value=mock.Mock(returncode=0)) as run:
                self.assertTrue(desktop_entry.open_report(path))
                self.assertEqual(run.call_args.args[0], [command, str(path)])
                self.assertNotIn('shell', run.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
