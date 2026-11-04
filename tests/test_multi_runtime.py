"""Detected SDK installations must each have their own probe."""
import contextlib
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import audit


class MultipleRuntimeTests(unittest.TestCase):
    def test_each_discovered_npm_is_checked_with_an_isolated_cache(self):
        args = SimpleNamespace(project=None, offline=True, timeout=3, workers=1)
        instance = audit.Audit(args)
        instance.discovered = {'npm':['/first/npm','/second/npm']}
        transports = []
        try:
            def call(command, **kwargs):
                if '--version' in command: return 0, '11.0.0', ''
                if 'config' in command: return 0, 'true' if 'strict-ssl' in command else '', ''
                return 1, '', ''
            with mock.patch.dict('os.environ', {'PATH':''}), \
                 mock.patch.object(instance.host,'find',return_value=None), \
                 mock.patch.object(instance.host,'call',side_effect=call) as runner, \
                 mock.patch.object(instance,'npm_transport',side_effect=lambda cmd,meta: transports.append(meta['executable'])), \
                 contextlib.redirect_stdout(io.StringIO()):
                instance.tools()
            self.assertEqual(set(transports), {'/first/npm','/second/npm'})
            npm_calls = [c for c in runner.call_args_list if c.args[0][0] in instance.discovered['npm']]
            self.assertTrue(all(c.kwargs['env']['npm_config_cache'].startswith(instance.tmp.name) for c in npm_calls))
        finally:
            instance.tmp.cleanup()

    def test_each_discovered_ruby_and_php_is_tested(self):
        args = SimpleNamespace(project=None, offline=True, timeout=3, workers=1)
        instance = audit.Audit(args)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instance.discovered = {'ruby':[str(root/'a/ruby'), str(root/'b/ruby')],
                                   'php':[str(root/'a/php'), str(root/'b/php')]}
            calls = []
            try:
                with mock.patch.object(instance.host,'find',return_value=None), \
                     mock.patch.object(instance.host,'call',return_value=(0,'1.0','')), \
                     mock.patch.object(instance,'sample',side_effect=lambda name, probe, meta=None, **kw: calls.append((name,meta or {}))), \
                     contextlib.redirect_stdout(io.StringIO()):
                    instance.other_languages(instance.host, {'ruby','php'})
                ruby = {meta['executable'] for name, meta in calls if meta.get('tool_id')=='ruby'}
                php = {meta['executable'] for name, meta in calls if meta.get('tool_id')=='php'}
                self.assertTrue(set(instance.discovered['ruby']) <= ruby)
                self.assertTrue(set(instance.discovered['php']) <= php)
            finally:
                instance.tmp.cleanup()
