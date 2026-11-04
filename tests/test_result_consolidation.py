"""Result contracts for the 2.7.0 real-machine review."""
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
import app_inventory
import evidence
import remediation
import reporting
import verdicts


def row(name, status, meta, method='inventory'):
    return dict(name=name, status=status, metadata=meta, assessment_method=method,
                detail='fixture', action='', samples=[])


class ResultConsolidationTests(unittest.TestCase):
    def test_embedded_fixed_go_is_visible_without_claiming_measured_tls(self):
        check = app_inventory.version_check(audit.reference, 'go', '1.27.3', '/tools/gh')
        record = row('アプリ / GitHub CLI', 'MANUAL', dict(application=True, tool_id='gh',
                     tool_name='GitHub CLI', path='/tools/gh', discovered_paths=['/bin/gh'],
                     inspections=[check], uninspected=['実通信は未検査']), 'version')
        records = verdicts.prepare([record, row('GitHub CLI / 通信', 'MANUAL', {
            'tool_id':'gh', 'tool_name':'GitHub CLI', 'executable':'/bin/gh'}, 'manual')])
        self.assertEqual(records[0]['status'], 'INFERRED_OK')
        self.assertEqual(reporting.group_tools(records)[0][0]['counts'], {'complete':1})
        label = reporting.result_label(records[0], reporting.STATUS_LABELS)
        self.assertEqual(label, '同梱Goは対策版')
        self.assertIn('同梱Goは対策版', audit.render_report(records, 'fixture'))
        self.assertFalse(any(r['status'] == 'REJECTED' for r in records))
        self.assertEqual(records, verdicts.prepare(records))
        dangerous = copy.deepcopy(record)
        dangerous['metadata']['inspections'] = [app_inventory.version_check(
            audit.reference, 'go', '1.27.2', '/tools/gh')]
        dangerous['status'] = 'UPDATE'
        self.assertEqual(verdicts.prepare([dangerous])[0]['review_state'], 'review')
        for extra in (dict(component='Java 21', method='version', status='MANUAL'),
                      dict(check, path='/tools/bom.json')):
            unknown = copy.deepcopy(record)
            unknown['metadata']['inspections'] = [extra]
            self.assertEqual(verdicts.prepare([unknown])[0]['status'], 'MANUAL')

    def test_ca_absence_alone_stays_unverified(self):
        record = row('アプリ / Example', 'MANUAL', dict(application=True, tool_id='example',
                     path='/example', inspections=[dict(component='CAファイル', method='static',
                     status='UNKNOWN', detail='対象証明書なし')], uninspected=[]))
        self.assertEqual(verdicts.prepare([record])[0]['review_state'], 'unverified')

    def test_python39_and_xcode_guidance_is_executable(self):
        for suffix in ('pip バージョン', 'ensurepip同梱pip（新規venv用）'):
            with self.subTest(suffix=suffix):
                item = row('ホスト / Python 3.9.6 [/xcode] / '+suffix, 'UPDATE', {
                    'tool_id':'python', 'executable':'/usr/bin/python3',
                    'prefix':'/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9',
                    'version':'21.2.4', 'reference_floor':'26.2.2'}, 'version')
                guide = remediation.plan(verdicts.prepare([item])[0])
                text = json.dumps(guide, ensure_ascii=False)
                self.assertIn('Python 3.10以上', text)
                self.assertIn('Apple', text)
                self.assertIn('移行', text)
                self.assertNotIn('pipを更新する', guide['title'])
                self.assertNotIn('pip install', text)
        item['metadata']['python_version'] = '3.11.15'
        item['metadata']['prefix'] = '/venv'
        item['name'] = 'Python / pip バージョン'
        guide = remediation.plan(verdicts.prepare([item])[0])
        self.assertEqual(guide['title'], 'このPythonのpipを更新する')

    def test_duplicate_rustup_and_jdk_checks_merge_but_other_installations_do_not(self):
        rust = row('Rust / rustup', 'UPDATE', dict(version='1.29.0', reference_floor='1.29.2',
                   source=evidence.RUSTUP_SOURCE), 'version')
        version = row('rustup / バージョン', 'INFO', dict(tool_id='rustup', tool_name='rustup',
                      executable='/rustup', version='rustup 1.29.0 (fixture)'))
        java = row('Java / Azulブロックリスト', 'UPDATE', dict(java_home='/jdk/one', source='https://vendor'), 'static')
        other = copy.deepcopy(java); other['metadata']['java_home'] = '/jdk/two'
        records = verdicts.prepare([rust, dict(rust, origin='Rust'), rust, version, java, java, other])
        self.assertEqual(sum(r['name'] == 'Rust / rustup' for r in records), 1)
        self.assertEqual(sum(r['name'] == 'Java / Azulブロックリスト' for r in records), 2)
        groups = {g['name']:g for g in reporting.group_tools(records)[0]}
        self.assertEqual(len(groups['rustup']['units']), 1)
        self.assertEqual(len(groups['Java']['units']), 2)
        self.assertEqual(records, verdicts.prepare(records))
        # A separate process/container or a different version must survive.
        remote = copy.deepcopy(other); remote['metadata']['execution_context'] = 'コンテナ example'
        result = verdicts.prepare([other, remote])
        self.assertEqual(len(reporting.group_tools(result)[0][0]['units']), 2)

    def test_rust_evidence_is_collected_once_and_bound_to_its_executable(self):
        host = SimpleNamespace(find=lambda name:'/rustup', call=mock.Mock(return_value=(0,'rustup 1.29.0 (fixture)','')))
        fixture = SimpleNamespace(host=host, args=SimpleNamespace(project=None), records=[
            row('Rust / バージョン','INFO',{}), row('Rust / バージョン','INFO',{}), row('Rust','INFO',{})])
        with mock.patch.object(evidence, 'mac_bundles', return_value=[]):
            evidence.collect(fixture, audit.reference)
        self.assertEqual(host.call.call_count, 1)
        records = verdicts.prepare(fixture.records)
        fixed = next(r for r in records if r['name'] == 'Rust / rustup')
        self.assertEqual(fixed['metadata']['executable'], '/rustup')

    def test_docker_lists_only_identifiers_and_gives_historical_fallback(self):
        host = SimpleNamespace(find=lambda name:'/docker', call=mock.Mock(side_effect=[
            (0,'{}',''), (0,json.dumps({'registry.example:5000':{'Secure':False, 'Password':'DO-NOT-COPY'},
                                      'safe.example':{'Secure':True},
                                      'https://user:SECRET@private.example/path?token=SECRET':{'Secure':False}}),'')]))
        fixture = SimpleNamespace(host=host, args=SimpleNamespace(offline=False))
        check = next(x for x in evidence.docker_evidence(fixture, []) if x['kind'] == 'configuration')
        self.assertEqual(check['insecure_registries'], ['registry.example:5000'])
        self.assertEqual(check['count'], 2)
        text = json.dumps(check)
        self.assertNotIn('SECRET', text); self.assertNotIn('DO-NOT-COPY', text)
        record = row('Docker / registryのTLS設定', 'ACTION', dict(count=2, insecure_registries=check['insecure_registries']), 'configuration')
        guide = remediation.plan(verdicts.finish(record))
        self.assertIn('registry.example:5000', json.dumps(guide))
        record['metadata'] = {'count':1}
        guide = remediation.plan(verdicts.finish(record))
        self.assertIn('docker info --format', ' '.join(guide['steps']))
        self.assertNotIn('「検査データ」にある', ' '.join(guide['steps']))

    def test_pip_entry_points_join_the_captured_python_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root/'runtime'; runtime.write_text('#!/bin/sh\nexit 0\n'); runtime.chmod(0o755)
            for name in ('one', 'two'):
                env = root/name; (env/'bin').mkdir(parents=True)
                (env/'pyvenv.cfg').write_text('home = /runtime\n')
                interpreter = env/'bin/python3'; interpreter.symlink_to(runtime)
                for name in ('pip', 'pip3'):
                    script = env/'bin'/name
                    script.write_text('#!'+str(interpreter)+'\nprint("not executed")\n'); script.chmod(0o755)
            records = app_inventory.scan(audit.reference, path_dirs=[root/'one/bin',root/'two/bin'], install_dirs=[])
            # The probe captures the interpreter identity; report rendering must not inspect today's filesystem.
            for name in ('one', 'two'):
                env = root/name
                meta = dict(tool_id='python', tool_name='Python', executable=str(env/'bin/python3'),
                            prefix=str(env), version='3.13.18', packages={'pip':'26.2.2'},
                            python_identity=list(verdicts.installation_identity('python', env/'bin/python3')))
                records += [row('Python environment', 'INFO', meta), row('Python / pip バージョン', 'INFERRED_OK',
                            dict(tool_id='python', tool_name='Python', executable=meta['executable'], prefix=meta['prefix'], version='26.2.2', reference_floor='26.2.2'), 'version')]
            with mock.patch.object(Path, 'resolve', side_effect=AssertionError('report must use snapshot')):
                result = verdicts.prepare(records)
                groups = {g['name']:g for g in reporting.group_tools(result)[0]}
            self.assertNotIn('pip', groups)
            self.assertEqual(len(groups['Python']['units']), 2)
            self.assertEqual(groups['Python']['counts'], {'complete':2})

    def test_jdk_alias_grouping_survives_repeated_report_generation(self):
        app = row('アプリ / Java', 'MANUAL', dict(application=True, tool_id='java', tool_name='Java',
                  path='/jdk/bin/java', discovered_paths=['/bin/java'], inspections=[], uninspected=[]))
        measured = row('Java JSSE', 'REJECTED', dict(tool_id='java', tool_name='Java',
                       java_home='/jdk', executable='/bin/java'), 'measured')
        blocklist = row('Java / Azulブロックリスト', 'UPDATE', dict(java_home='/jdk'), 'static')
        once = verdicts.prepare([app, measured, blocklist, blocklist])
        self.assertEqual(once, verdicts.prepare(once))
        self.assertEqual(len(reporting.group_tools(once)[0][0]['units']), 1)
        self.assertEqual(reporting.group_tools(once)[0][0]['state'], 'review')

    def test_python_header_identifies_runtime_instead_of_pip(self):
        meta = dict(tool_id='python', tool_name='Python', executable='/env/bin/python3', prefix='/env')
        records = [row('Python / pip バージョン', 'INFERRED_OK', dict(meta, version='26.2.2'), 'version'),
                   row('ホスト / Python 3.13.18 [/env]', 'INFO', dict(meta, version='3.13.18', packages={}))]
        self.assertIn('env / Python 3.13.18', audit.render_report(records, 'fixture'))

    def test_pip_can_join_an_unstartable_interpreter_without_becoming_complete(self):
        records = []
        for tool, path in [('python','/env/bin/python3'), ('pip','/env/bin/pip'), ('pip','/env/bin/pip3')]:
            records.append(row('アプリ / '+tool, 'MANUAL', dict(tool_id=tool, tool_name=tool.title(),
                           application=True, path=path, discovered_paths=[path],
                           python_identity=['python','/env/bin/python3'], inspections=[], uninspected=[])))
        result = verdicts.prepare(records)
        groups = reporting.group_tools(result)[0]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['name'], 'Python')
        self.assertEqual(groups[0]['counts'], {'unverified':1})


if __name__ == '__main__': unittest.main()
