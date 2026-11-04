"""New runtime checks through the CLI; subprocess output is the external boundary."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit


class LanguageChecks(unittest.TestCase):
    def run_report(self, language, version, online=False, probe='rejected', libs=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root/language
            exe.write_text('fixture')
            exe.chmod(0o755)
            calls = []
            def run(command, **kwargs):
                command = list(map(str, command)); calls.append((command, kwargs))
                if '--version' in command: return 0, version, ''
                if any('perl_probe.pl' in x for x in command) and 'meta' in command:
                    return 0, 'EMUDHRA_JSON:'+json.dumps({'state':'meta','data':{'version':'5.40.0','mozilla_ca':version}}), ''
                if '-eval' in command or any('beam_probe.exs' in x for x in command):
                    return 0, 'EMUDHRA_RUNTIME:27\n'+''.join('EMUDHRA_LIB:'+k+':'+v+'\n' for k,v in (libs or {}).items()), ''
                url = next((x for x in command if x.startswith('https://')), '')
                if not url: raise AssertionError(command)
                data = {'state':'accepted','detail':'HTTP 404'} if 'example.com' in url or probe=='accepted' else {'state':'error','detail':'certificate is revoked' if probe=='rejected' else 'certificate has expired'}
                return 0, 'EMUDHRA_JSON:'+json.dumps(data), ''
            args = ['--only',language,'--'+language,str(exe),'--out',str(root/'report')]
            if not online: args += ['--offline']
            with mock.patch.object(audit.Context,'find',return_value=None), mock.patch.object(audit,'run',side_effect=run), \
                 mock.patch.object(audit.Audit,'config_inventory'), contextlib.redirect_stdout(io.StringIO()):
                code = audit.main(args)
            return code,json.loads((root/'report/report.json').read_text()),calls

    def test_bun_and_deno_have_version_and_separate_connection_results(self):
        for language,version in [('bun','1.4.3'),('deno','deno 2.9.7 (stable, release, aarch64-apple-darwin)')]:
            with self.subTest(language=language):
                code,report,calls = self.run_report(language,version,online=True)
                self.assertEqual(code,1)
                self.assertTrue(any(r['status']=='UPDATE' and r['assessment_method']=='version' for r in report['records']))
                self.assertTrue(any(r['status']=='REJECTED' and r['samples'] for r in report['records']))
                self.assertTrue(all(call[1].get('cwd') is not None for call in calls))
                if language == 'bun':
                    self.assertTrue(all('--no-env-file' in call[0] for call in calls))

    def test_fixed_version_never_hides_a_failed_probe(self):
        for language,version in [('bun','1.4.4'),('deno','deno 2.9.8')]:
            code,report,_ = self.run_report(language,version,online=True,probe='accepted')
            self.assertEqual(code,2)
            self.assertTrue(any(r['status']=='INFERRED_OK' for r in report['records']))
            self.assertTrue(any(r['status']=='UNKNOWN' and r['samples'] for r in report['records']))

    def test_offline_does_not_connect_and_prerelease_is_unresolved(self):
        for version in ['1.4.4-canary.1','2.0.0','unknown']:
            code,report,calls = self.run_report('bun',version)
            self.assertEqual(code,2)
            self.assertFalse(any(r['status']=='INFERRED_OK' for r in report['records']))
            self.assertFalse(any(x.startswith('https://') for command,_ in calls for x in command))

    def test_expiry_is_not_mistaken_for_certificate_block(self):
        _,report,_ = self.run_report('deno','deno 2.9.8',online=True,probe='expired')
        self.assertTrue(any(r['status']=='UNKNOWN' and r['samples'] for r in report['records']))
        self.assertFalse(any(r['status']=='REJECTED' for r in report['records']))

    def test_dart_sdk_check_explains_build_targets_even_on_mac(self):
        with mock.patch.object(sys,'platform','darwin'):
            code,report,_ = self.run_report('dart','Dart SDK version: 3.13.6 (stable)')
        self.assertEqual(code,1)
        row = next(r for r in report['records'] if r['status']=='UPDATE')
        self.assertIn('Android',row['scope'])
        self.assertIn('macOS',row['scope'])
        self.assertIn('SDKを更新',row['remediation']['title'])

    def test_perl_checks_mozilla_ca_without_treating_missing_library_as_safe(self):
        for version,status in [('20261019','UPDATE'),('20261020','INFERRED_OK'),('', 'MANUAL')]:
            _,report,_ = self.run_report('perl',version)
            self.assertTrue(any('Mozilla::CA' in r['name'] and r['status']==status for r in report['records']))

    def test_beam_library_versions_do_not_certify_all_runtime_connections(self):
        for language in ['erlang','elixir']:
            _,report,_ = self.run_report(language,'Elixir 1.19.0',libs={'certifi':'2.17.0','castore':'1.0.22'})
            self.assertTrue(any('certifi' in r['name'] and r['status']=='MANUAL' for r in report['records']))
            self.assertTrue(any('castore' in r['name'] and r['status']=='INFERRED_OK' for r in report['records']))
            self.assertTrue(any(r['review_state']=='unverified' and '通信' in r['name'] for r in report['records']))

    def test_flutter_reads_cached_sdk_without_running_updating_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); launcher=root/'bin/flutter'; launcher.parent.mkdir(); launcher.write_text('do not execute')
            cache=root/'bin/cache'; cache.mkdir()
            (cache/'flutter.version.json').write_text(json.dumps({'frameworkVersion':'3.47.7','channel':'stable'}))
            with mock.patch.object(audit.Context,'find',return_value=None), mock.patch.object(audit,'run',side_effect=AssertionError('must not execute flutter')), \
                 mock.patch.object(audit.Audit,'config_inventory'), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','flutter','--flutter',str(launcher),'--offline','--out',str(root/'report')])
            rows=json.loads((root/'report/report.json').read_text())['records']
            self.assertTrue(any(r['status']=='UPDATE' and 'Flutter' in r['name'] for r in rows))
            self.assertTrue(any(r['review_state']=='action' for r in rows))

    def test_uncached_windows_dart_wrapper_is_never_started(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); wrapper=root/'bin/dart.bat'; wrapper.parent.mkdir(); wrapper.write_text('updating wrapper')
            internal=root/'bin/internal'; internal.mkdir(); (internal/'shared.bat').write_text('fixture')
            with mock.patch.object(audit.Context,'find',return_value=None), mock.patch.object(audit,'run') as runner, \
                 mock.patch.object(audit.Audit,'config_inventory'), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','dart','--dart',str(wrapper),'--offline','--out',str(root/'report')])
            runner.assert_not_called()

    def test_invalid_flutter_metadata_leaves_an_unresolved_result(self):
        for data in ['[]', 'null', '"unexpected"', '{broken']:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); launcher = root/'bin/flutter'; launcher.parent.mkdir(); launcher.write_text('fixture')
                cache = root/'bin/cache'; cache.mkdir(); (cache/'flutter.version.json').write_text(data)
                with mock.patch.object(audit.Context,'find',return_value=None), mock.patch.object(audit,'run') as runner, \
                     mock.patch.object(audit.Audit,'config_inventory'), contextlib.redirect_stdout(io.StringIO()):
                    code = audit.main(['--only','flutter','--flutter',str(launcher),'--offline','--out',str(root/'report')])
                self.assertEqual(code, 2)
                runner.assert_not_called()
                rows = json.loads((root/'report/report.json').read_text())['records']
                self.assertTrue(any(r['name']=='Flutter SDK' and r['status']=='MANUAL' for r in rows))

    def test_deno_trust_errors_are_distinct_from_expired_certificates(self):
        for detail in ['invalid peer certificate: UnknownIssuer','invalid peer certificate: Revoked']:
            self.assertEqual(audit.classify({'state':'error','detail':detail})[0],'REJECTED')
        self.assertEqual(audit.classify({'state':'error','detail':'invalid peer certificate: Expired'})[0],'UNKNOWN')
