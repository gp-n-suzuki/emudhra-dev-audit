"""PowerShell and other .NET runtimes are distinct installed clients."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import audit
import verdicts


class PowerShellScope(unittest.TestCase):
    def test_each_dotnet_runtime_uses_its_own_version(self):
        args = SimpleNamespace(project=None, offline=False, timeout=3, workers=1)
        instance = audit.Audit(args)
        calls = []
        executed = []
        def call(command, **kwargs):
            if 'exec' in command:
                executed.append(command)
                return 0, 'EMUDHRA_JSON:{\"state\":\"accepted\",\"detail\":\"HTTP 200\"}', ''
            if '--list-runtimes' in command:
                return 0, 'Microsoft.NETCore.App 8.0.1 [/sdk/shared]\nMicrosoft.NETCore.App 9.0.2 [/sdk/shared]\n', ''
            if '--list-sdks' in command: return 0, '9.0.100 [/sdk]\n', ''
            return 1, '', 'unexpected'
        def sample(name, probe, meta=None, **kwargs):
            calls.append((name, meta or {}, probe))
            probe('https://example.com/')
        try:
            with mock.patch.object(instance.host, 'find', side_effect=lambda n: '/sdk/dotnet' if n == 'dotnet' else None), \
                 mock.patch.object(instance.host, 'call', side_effect=call), \
                 mock.patch.object(instance, 'sample', side_effect=sample), \
                 mock.patch.object(audit, 'run', return_value=(0, '', '')) as runner, \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.other_languages(instance.host, {'dotnet'})
            runtime_calls = [(name, meta) for name, meta, _ in calls if meta.get('tool_id') == 'dotnet']
            self.assertEqual({meta['runtime_version'] for _, meta in runtime_calls}, {'8.0.1', '9.0.2'})
            self.assertEqual({command[command.index('--fx-version')+1] for command in executed}, {'8.0.1','9.0.2'})
            self.assertTrue(all(call.kwargs['env']['DOTNET_CLI_HOME'].startswith(instance.tmp.name)
                                for call in runner.call_args_list))
        finally:
            instance.tmp.cleanup()

    def test_each_powershell_also_runs_its_own_web_cmdlet_probe(self):
        args = SimpleNamespace(project=None, offline=False, timeout=3, workers=1)
        instance = audit.Audit(args); calls=[]
        try:
            with mock.patch.object(instance.host,'find',side_effect=lambda n: {'pwsh':'/first/pwsh','powershell.exe':'/second/powershell.exe'}.get(n)), \
                 mock.patch.object(instance, 'sample', side_effect=lambda name,probe,meta=None,**kw: calls.append((name,meta or {}))), \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.other_languages(instance.host, {'dotnet'})
            web=[(name,meta) for name,meta in calls if 'Invoke-WebRequest' in name]
            self.assertEqual({meta['tool_id'] for _,meta in web}, {'powershell','windows-powershell'})
        finally: instance.tmp.cleanup()

    def test_both_shells_are_probed_and_do_not_certify_dotnet(self):
        args = SimpleNamespace(project=None, offline=False, timeout=3, workers=1)
        instance = audit.Audit(args)
        calls = []
        def find(name):
            return {'pwsh': '/opt/pwsh', 'powershell.exe': 'C:/Windows/powershell.exe',
                    'dotnet': '/opt/dotnet'}.get(name)
        def call(command, **kwargs):
            if '--list-runtimes' in command: return 0, 'Microsoft.NETCore.App 8.0.0 [/opt/dotnet/shared]', ''
            return 0, '', ''
        def sample(name, probe, meta=None, **kwargs):
            calls.append((name, meta or {}))
        try:
            with mock.patch.object(instance.host, 'find', side_effect=find), \
                 mock.patch.object(instance.host, 'call', side_effect=call), \
                 mock.patch.object(instance, 'sample', side_effect=sample), \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.other_languages(instance.host, {'dotnet'})
            names = [name for name, _ in calls]
            self.assertTrue(any('PowerShell 7' in name for name in names))
            self.assertTrue(any('Windows PowerShell' in name for name in names))
            self.assertTrue(any('dotnet' in r['name'].lower() or '.NET' in r['name'] for r in instance.records))
            self.assertNotEqual(next(meta['tool_id'] for name, meta in calls if 'PowerShell 7' in name),
                                next(meta['tool_id'] for name, meta in calls if 'Windows PowerShell' in name))
        finally:
            instance.tmp.cleanup()
