"""Captured versions must improve verdicts without guessing another installation's TLS."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import audit
import reporting
import verdicts


def row(tool, version='', path='/one/tool', **meta):
    return dict(name=tool+' / バージョン', status='INFO', detail=version, action='', samples=[],
                assessment_method='inventory', metadata=dict(tool_id=tool, tool_name=tool,
                executable=path, version=version, **meta))


class CapturedVersionTests(unittest.TestCase):
    def test_captured_uv_inventory_is_compared_and_unknown_old_copy_stays_separate(self):
        rows = [row('uv', 'uv 0.13.5 (Homebrew 2026-10-20 aarch64-apple-darwin)'),
                row('uv', '', '/old/uv'), row('uv', 'uvx 0.13.3', '/old/uvx')]
        actual = verdicts.prepare(rows)
        by_path = {r['metadata']['executable']:r for r in actual}
        self.assertEqual({p:r['status'] for p,r in by_path.items()},
                         {'/one/tool':'INFERRED_OK','/old/uv':'INFO','/old/uvx':'UPDATE'})
        self.assertEqual(by_path['/one/tool']['metadata']['reference_floor'], '0.13.5')
        self.assertIn('標準の証明書', by_path['/one/tool']['scope'])
        self.assertTrue(by_path['/one/tool']['metadata']['source'].startswith('https://github.com/astral-sh/uv/'))
        self.assertEqual(len(reporting.group_tools(actual)[0][0]['units']), 3)
        self.assertEqual(actual, verdicts.prepare(actual))

    def test_inventory_known_components_use_their_own_versions(self):
        for tool, text in [('node','v22.23.4'), ('go','go version go1.27.3 darwin/arm64'),
                           ('pip','pip 26.2.2 from /one/pip (python 3.13)'),
                           ('certifi','2026.10.19'), ('bun','1.4.4'), ('dart','3.13.7')]:
            with self.subTest(tool=tool):
                self.assertEqual(verdicts.prepare([row(tool,text)])[0]['status'], 'INFERRED_OK')

    def test_preview_vendor_and_unknown_series_do_not_turn_green(self):
        for version in ['uv 0.13.4-rc1', 'uv 0.13.4+vendor.1', 'uv 1.0.0', 'unreadable']:
            with self.subTest(version=version):
                self.assertNotEqual(verdicts.prepare([row('uv',version)])[0]['status'], 'INFERRED_OK')
        for tool, text in [('rust','rustc 1.97.1'), ('claude-code','2.1.312 (Claude Code)'),
                           ('pyenv','pyenv 2.8.11')]:
            self.assertNotEqual(verdicts.prepare([row(tool,text)])[0]['status'], 'INFERRED_OK')

    def test_version_in_measured_or_configuration_row_is_not_a_success(self):
        for method, status in [('measured','UNKNOWN'), ('configuration','ACTION')]:
            record = row('uv','uv 0.13.4')
            record.update(assessment_method=method, status=status)
            self.assertEqual(verdicts.prepare([record])[0]['status'], status)

    def test_heroku_reported_node_is_scoped_and_has_targeted_guidance(self):
        rows = [row('heroku','heroku/11.4.0 darwin-arm64 node-v22.22.2','/old/heroku'),
                row('heroku','heroku/11.5.0 darwin-arm64 node-v22.23.4','/new/heroku')]
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=rows), Path(tmp))
            saved = json.loads((Path(tmp)/'report.json').read_text())['records']
            page = (Path(tmp)/'report.html').read_text()
        parts = [r for r in saved if r['metadata'].get('runtime_component')]
        self.assertEqual([r['status'] for r in parts], ['UPDATE','INFERRED_OK'])
        self.assertEqual(parts[0]['review_state'], 'review')
        self.assertIn('Node.js', parts[0]['remediation']['title'])
        self.assertEqual(parts[0]['remediation']['target'], '/old/heroku')
        self.assertIn('22.22.2', page)
        self.assertIn('22.23.4', page)
        self.assertIn('使用するNode.jsは対策バージョン', page)
        self.assertIn('標準の証明書', parts[1]['scope'])
        self.assertEqual(saved, verdicts.prepare(saved))

    def test_reported_node_version_must_not_be_replaced_by_host_node(self):
        rows = [row('node','v26.12.1','/bin/node'),
                row('heroku','heroku/11.4.0 darwin-arm64 node-v22.22.2')]
        part = next(r for r in verdicts.prepare(rows) if r['metadata'].get('runtime_component'))
        self.assertEqual(part['metadata']['runtime_version'], '22.22.2')
        self.assertEqual(part['status'], 'UPDATE')

    def test_recorded_adapter_links_only_to_exact_runtime_in_same_context(self):
        rows = [row('node','v22.23.4','/bin/node', execution_context='ホスト'),
                row('node','v22.22.2','/bin/node', execution_context='コンテナ old')]
        for context in ('ホスト','コンテナ old','コンテナ absent'):
            r = row('pnpm', '', '/bin/pnpm', runtime_executable='/bin/node', execution_context=context,
                    probe='synthetic_node_registry')
            r.update(name='pnpm / registry', status='MANUAL', assessment_method='manual')
            rows.append(r)
        parts = [r for r in verdicts.prepare(rows) if r['metadata'].get('runtime_component')]
        self.assertEqual({r['metadata']['execution_context']:r['status'] for r in parts},
                         {'ホスト':'INFERRED_OK','コンテナ old':'UPDATE'})
        with mock.patch.object(Path,'resolve', side_effect=AssertionError('no live filesystem')):
            verdicts.prepare(rows)

    def test_conflicting_runtime_versions_and_unlinked_tools_stay_unknown(self):
        rows = [row('node','v22.23.4','/bin/node'),row('node','v22.22.2','/bin/node'),
                row('pnpm','11.0.0',runtime_executable='/bin/node',probe='synthetic_node_registry'),
                row('gemini-cli','0.1.4')]
        self.assertFalse(any(r['metadata'].get('runtime_component') for r in verdicts.prepare(rows)))

    def test_fixed_component_does_not_hide_disabled_tls_or_network_evidence(self):
        rows = [row('heroku','heroku/11.5.0 darwin-arm64 node-v22.23.4')]
        bad = row('heroku')
        bad.update(name='heroku / TLS設定',status='ACTION',assessment_method='configuration')
        rows.append(bad)
        measured = row('heroku')
        measured.update(name='heroku / 通信',status='UNKNOWN',assessment_method='measured',
                        samples=[dict(status='UNKNOWN',target='test',detail='timeout')])
        rows.append(measured)
        result = verdicts.prepare(rows)
        self.assertEqual(reporting.group_tools(result)[0][0]['state'], 'action')
        self.assertEqual(next(r for r in result if r['name']=='heroku / 通信')['samples'], measured['samples'])


class RuntimeCollectionTests(unittest.TestCase):
    def test_node_cli_entrypoint_is_bound_without_running_the_cli(self):
        import version_inference
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root/'node_modules/@google/gemini-cli/bin/gemini.js'
            script.parent.mkdir(parents=True)
            script.write_text('#!/usr/bin/env node\n')
            (script.parent.parent/'package.json').write_text(json.dumps({
                'name':'@google/gemini-cli','bin':{'gemini':'bin/gemini.js'}}))
            node = root/'node'; node.write_bytes(b'\x7fELF'+bytes(32))
            cli = root/'gemini'; cli.symlink_to(script)
            fixture = SimpleNamespace(discovered={'gemini-cli':[str(cli)]}, package_protected=set(),
                work=root, host=SimpleNamespace(find=lambda name:str(node),call=mock.Mock(return_value=(0,'v22.23.4',''))),
                records=[])
            def add(name,status,detail,meta):
                fixture.records.append(dict(name=name,status=status,detail=detail,metadata=meta,samples=[],action=''))
            fixture.add=add
            version_inference.collect(fixture)
            self.assertEqual(fixture.host.call.call_count, 1)
            self.assertEqual(fixture.host.call.call_args[0][0], [str(node),'--version'])
            part = verdicts.prepare(fixture.records)[0]
            self.assertEqual(part['status'],'INFERRED_OK')
            self.assertEqual(part['metadata']['executable'],str(cli))
            self.assertEqual(part['metadata']['runtime_executable'],str(node))
            fixture.records=[]; fixture.host.call.reset_mock()
            fixture.package_protected={'gemini-cli'}
            version_inference.collect(fixture)
            self.assertEqual(fixture.host.call.call_args[0][0], [str(node),'--version'])
            self.assertTrue(fixture.records[0]['metadata']['package_transport_unmeasured'])

    def test_node_dependency_range_or_another_bin_is_not_a_runtime_binding(self):
        import version_inference
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); script=root/'bin/tool.js'; script.parent.mkdir()
            script.write_text('#!/usr/bin/env node\n')
            node=root/'node'; node.write_bytes(b'\x7fELF'+bytes(32))
            manifest=root/'package.json'
            for data in ({'name':'@google/gemini-cli','engines':{'node':'>=22.23.4'}},
                         {'name':'@google/gemini-cli','bin':{'gemini':'bin/other.js'}},
                         {'name':'unrelated','bin':{'gemini':'bin/tool.js'}}):
                manifest.write_text(json.dumps(data))
                self.assertIsNone(version_inference.node_entrypoint(script,'gemini-cli',lambda _:str(node)))

    def test_failed_node_version_is_unknown_without_recording_error_output(self):
        import version_inference
        fixture=SimpleNamespace(discovered={'npm':['/bin/npm']},package_protected=set(),work=Path('/tmp'),
            host=SimpleNamespace(find=lambda _:None, call=mock.Mock(return_value=(1,'','private-message'))),records=[])
        fixture.add=lambda name,status,detail,meta: fixture.records.append(dict(
            name=name,status=status,detail=detail,metadata=meta,samples=[],action=''))
        with mock.patch.object(version_inference,'node_entrypoint',return_value=('/node','/npm.js')):
            version_inference.collect(fixture)
        result=verdicts.prepare(fixture.records)
        self.assertEqual(result[0]['status'],'UNKNOWN')
        self.assertNotIn('private-message',json.dumps(result))

    def test_env_alias_and_unrecognized_launchers_are_not_opened_or_executed(self):
        import version_inference
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); script=root/'script'; script.write_text('#!/bin/sh\nnode whatever.js\n')
            secret=root/'.env.private'; secret.symlink_to(script)
            alias=root/'alias'; alias.symlink_to(secret)
            with mock.patch.object(Path,'open',side_effect=AssertionError('no env reads')):
                self.assertIsNone(version_inference.node_entrypoint(alias,'gemini-cli',lambda _: '/bin/node'))
            self.assertIsNone(version_inference.node_entrypoint(script,'gemini-cli',lambda _: '/bin/node'))


if __name__ == '__main__': unittest.main()
