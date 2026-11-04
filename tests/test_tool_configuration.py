"""Read version and relevant setting names without exposing configuration values."""
import contextlib
import io
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import audit


class ToolConfiguration(unittest.TestCase):
    def test_cloud_cli_version_uses_isolated_configuration(self):
        args = SimpleNamespace(project=None)
        instance = audit.Audit(args); instance.discovered = {'aws':['/fixture/aws']}
        try:
            with mock.patch.object(instance.host,'call',return_value=(0,'aws-cli/2.31.0','')) as call, \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.configuration_checks()
            row = next(r for r in instance.records if r.get('metadata',{}).get('tool_id')=='aws')
            self.assertEqual(row['status'], 'INFO')
            self.assertEqual(row['metadata']['version'], 'aws-cli/2.31.0')
            self.assertTrue(call.call_args.kwargs['env']['HOME'].startswith(instance.tmp.name))
        finally: instance.tmp.cleanup()

    def test_linux_nss_package_metadata_is_visible(self):
        args = SimpleNamespace(project=None)
        instance = audit.Audit(args)
        try:
            with mock.patch.object(audit.sys,'platform','linux'), \
                 mock.patch.object(instance.host,'find',side_effect=lambda n: '/usr/bin/dpkg-query' if n == 'dpkg-query' else None), \
                 mock.patch.object(instance.host,'call',return_value=(0,'libnss3\t2:3.114.0-1\n','')), \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.configuration_checks()
            row = next(r for r in instance.records if r.get('metadata',{}).get('tool_id') == 'nss')
            self.assertEqual(row['status'], 'MANUAL')
            self.assertEqual(row['metadata']['version'], '2:3.114.0-1')
            self.assertIn('配布元', row['detail'])
        finally: instance.tmp.cleanup()

    def test_unrecognized_verify_key_does_not_prove_tls_was_disabled(self):
        args = SimpleNamespace(project=None)
        instance = audit.Audit(args)
        instance.discovered = {'cargo':['/fixture/cargo']}
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp); (home/'config.toml').write_text('[http]\nssl-verify = false\n')
            try:
                with mock.patch.dict('os.environ', {'CARGO_HOME':str(home), 'CARGO_HTTP_SSL_VERIFY':'false'}), \
                     mock.patch.object(instance.host,'call',return_value=(0,'cargo 1.0.0','')), \
                     contextlib.redirect_stdout(io.StringIO()):
                    instance.configuration_checks()
                rows = [r for r in instance.records if r['name'].startswith('Cargo /')]
                self.assertTrue(any(r['status']=='INFO' and 'ssl-verify' in r['detail'] for r in rows))
                self.assertFalse(any(r['status']=='MANUAL' for r in rows))
                self.assertFalse(any(r['status']=='ACTION' for r in rows))
            finally: instance.tmp.cleanup()

    def test_windows_cargo_explicit_revocation_disable_is_reported(self):
        args = SimpleNamespace(project=None)
        instance = audit.Audit(args); instance.discovered = {'cargo':['/fixture/cargo']}
        try:
            with tempfile.TemporaryDirectory() as tmp, \
                 mock.patch.dict('os.environ', {'CARGO_HOME':tmp,'CARGO_HTTP_CHECK_REVOKE':'false'}), \
                 mock.patch.object(audit.sys, 'platform', 'win32'), \
                 mock.patch.object(instance.host,'call',return_value=(0,'cargo 1.0.0','')), \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.configuration_checks()
            self.assertTrue(any(r['status']=='ACTION' and '失効' in r['detail'] for r in instance.records))
        finally: instance.tmp.cleanup()

    def test_versions_and_cargo_configuration_are_scoped(self):
        args = SimpleNamespace(project=None)
        instance = audit.Audit(args)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cargo_home = root/'cargo'; cargo_home.mkdir()
            (cargo_home/'config.toml').write_text('[http]\ncainfo="/private/cert.pem"\nproxy="https://user:secret@proxy"\n')
            instance.discovered = {'cargo':[str(root/'cargo-bin')], 'swift':[str(root/'swift')], 'cc':[str(root/'clang')]}
            try:
                with mock.patch.dict('os.environ', {'CARGO_HOME':str(cargo_home)}), \
                     mock.patch.object(instance.host,'call',return_value=(0,'tool 1.2.3','')) as runner, \
                     contextlib.redirect_stdout(io.StringIO()):
                    instance.configuration_checks()
                ids = {r.get('metadata',{}).get('tool_id') for r in instance.records}
                self.assertTrue({'cargo','swift','cc'} <= ids)
                cargo = next(r for r in instance.records if r['name']=='Cargo / 設定')
                self.assertIn('http.cainfo', cargo['metadata']['setting_names'])
                self.assertIn('http.proxy', cargo['metadata']['setting_names'])
                self.assertNotIn('secret', str(instance.records))
                self.assertNotIn('/private/cert.pem', str(instance.records))
                self.assertTrue(all(c.kwargs.get('env',{}).get('RUSTUP_AUTO_INSTALL') == '0' for c in runner.call_args_list))
            finally:
                instance.tmp.cleanup()
