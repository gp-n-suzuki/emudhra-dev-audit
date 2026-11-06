"""Saved evidence completes only the matched component or connection scope."""
import copy
import unittest
from unittest.mock import patch
from pathlib import Path

import ai_prompts
import presentation
import reporting
import verdicts
from test_action_presentation import record


def discovered(name, path, **meta):
    value = record('MANUAL', 'manual', name=name, path=path, application=True,
                   coverage_state='uninspected', inspections=[], uninspected=[
                       'TLS構成と修正版の照合に必要な情報を取得できません（通信の有無も未確認）',
                       'アプリの実効CA・独自検証設定・実通信は未検査'], **meta)
    value['metadata']['path'] = path
    value['detail'] = 'このツールの通信は未確認。導入を確認しました。'
    return value


def measured(name='curl', path='/fixture/curl', **meta):
    value = record('REJECTED', 'measured', name=name, path=path, **meta)
    value['samples'] = [dict(target='control', status='CONTROL_OK', control=True, detail='HTTP 200'),
                        dict(target='test', status='REJECTED', control=False, detail='certificate rejected')]
    return value


def composer():
    value = record('UNKNOWN', 'measured', name='Composer', path='/fixture/composer',
                   tool_id='composer', probe='synthetic_composer_search')
    value['samples'] = [dict(target='control',url='https://control.invalid/',control=True,status='UNKNOWN',
                            detail='In CurlDownloader.php line 966: HTTP 404')]
    for host in ('one.invalid','two.invalid'):
        url='https://'+host+'/'
        log=('In TlsChainDenylist.php line 69:\n The TLS certificate chain presented for "'+url+
             'packages.json" contains the distrusted certificate "EM DV TLS CA - G3B", this may be a man-in-the-middle attack. '
             'The request was aborted before it was sent.')
        # Symfony output wraps inside words and hostnames, with padded lines.
        wrapped='\n'.join('  '+log[i:i+55]+'  ' for i in range(0,len(log),55))
        value['samples'].append(dict(target=host,url=url,control=False,status='UNKNOWN',detail=wrapped))
    return value


class ScopedCompletionTests(unittest.TestCase):
    def model(self, rows):
        prepared=verdicts.prepare(copy.deepcopy(rows))
        before=copy.deepcopy(prepared)
        with patch.object(Path,'resolve',side_effect=AssertionError('live identity')), \
             patch('subprocess.Popen',side_effect=AssertionError('process')), \
             patch('socket.socket',side_effect=AssertionError('network')):
            model=reporting.action_model(prepared)
        self.assertEqual(prepared,before)
        return model,prepared

    def test_generic_inventory_does_not_undo_rejected_connection(self):
        for name in ('curl','Git','Ruby'):
            with self.subTest(name=name):
                model,_=self.model([discovered(name,'/fixture/tool'), measured(name,'/fixture/tool')])
                tool=model['tools'][0]
                self.assertEqual(tool['primary_action'],'checked')
                self.assertTrue(tool['units'][0]['confirmed_communications'])
                self.assertTrue(tool['gaps'])
                self.assertFalse(any(g.get('blocks_completion',True) for g in tool['gaps']))
                self.assertTrue(any(t['classification']=='unneeded' for t in tool['work']['tasks']))

    def test_rejection_does_not_hide_another_route_failure_or_setting(self):
        for status,method in [('ACTION','configuration'),('UNKNOWN','measured'),('UPDATE','version')]:
            other=record(status,method,name='curl',path='/fixture/tool',version='1.0',reference_floor='2.0')
            model,_=self.model([discovered('curl','/fixture/tool'),measured('curl','/fixture/tool'),other])
            self.assertNotIn(model['tools'][0]['primary_action'],('checked','scoped_complete','version_complete'))
            self.assertTrue(model['tools'][0]['units'][0]['confirmed_communications'])

    def test_missing_runtime_field_is_not_a_conflicting_runtime(self):
        good=record('INFERRED_OK',name='Corepack',path='/fixture/corepack',runtime_component='node',
                    runtime_version='26.12.1',runtime_executable='/fixture/node',runtime_basis='entrypoint',
                    entrypoint='/fixture/corepack',reference_floor='26.12.1',
                    source='https://nodejs.org/en/blog/vulnerability/october-2026-security-releases')
        rows=[good,discovered('Corepack','/fixture/corepack'),record('MANUAL','manual',name='Corepack',path='/fixture/corepack',p2_coverage=True)]
        model,prepared=self.model(rows);unit=model['tools'][0]['units'][0]
        self.assertEqual(unit['primary_action'],'scoped_complete')
        self.assertTrue(unit['completed_versions'])
        self.assertFalse(any('一致しません' in g['reason'] for g in unit['gaps']))
        self.assertIn('未評価',unit['primary_label'])
        prompt=ai_prompts.make(model,prepared,'fixture','2026-11-02')
        self.assertIn('確認済みの範囲',prompt)
        other=copy.deepcopy(good);other['metadata']['runtime_executable']='/fixture/other-node'
        model,_=self.model(rows+[other])
        self.assertEqual(model['tools'][0]['primary_action'],'investigate')
        self.assertFalse(model['tools'][0]['units'][0]['completed_versions'])

    def test_known_old_or_unknown_embedded_component_is_not_hidden(self):
        app=discovered('Corepack','/fixture/corepack')
        app['metadata'].update(inspections=[dict(component='node',version='26.12.1',status='INFERRED_OK',
                                               reference_floor='26.12.1',source='https://vendor.invalid',method='version'),
                                          dict(component='other',version='1.0',status='MANUAL',method='version')])
        model,_=self.model([app])
        self.assertEqual(model['tools'][0]['primary_action'],'investigate')

    def test_python_captured_environment_binds_pip_launcher_without_guessing(self):
        common=dict(tool_id='python',prefix='/fixture/env',python_identity=['python','/fixture/env/bin/python'])
        env=record('MANUAL','version',name='Python',path='/fixture/env/bin/python',
                   version='3.13.18',packages={'pip':'26.2.2'},**common)
        package=record('INFERRED_OK','version',name='Python',path='/fixture/env/bin/python',
                       version='26.2.2',reference_floor='26.2.2',source='https://pip.pypa.io/en/stable/news/#v26-2-2',**common)
        package['name']='Python / pip バージョン'
        launcher=discovered('pip','/fixture/env/bin/pip',python_identity=common['python_identity'])
        connection=measured('Python','/fixture/env/bin/python',**common)
        model,_=self.model([env,package,launcher,connection])
        unit=model['tools'][0]['units'][0]
        self.assertEqual(unit['primary_action'],'scoped_complete')
        self.assertEqual(len(unit['completed_versions']),1)
        self.assertFalse(unit['identity_conflict'])
        unknown=discovered('pip','/fixture/other/pip')
        model,_=self.model([env,package,unknown,connection])
        self.assertEqual(next(t for t in model['tools'] if t['name']=='pip')['primary_action'],'investigate')

    def test_java_home_properties_bind_aliases_but_not_another_jdk(self):
        rows=[]
        for executable in ('/fixture/launcher/java','/fixture/jdk/bin/java'):
            rows.append(measured('Java',executable,java_home='/fixture/jdk',tool_id='java',
                                 version='17.0.21.0.3',runtime_version='17.0.21.0.3+1-LTS'))
            rows.append(discovered('Java',executable))
        block=record('STATIC_OK','static',name='Java',path='/fixture/jdk',java_home='/fixture/jdk',tool_id='java')
        block['name']='Java / Azulブロックリスト'
        model,_=self.model(rows+[block])
        self.assertEqual(model['tools'][0]['primary_action'],'scoped_complete')
        self.assertEqual(len(model['tools'][0]['units'][0]['confirmed_communications']),2)
        other=record('UNKNOWN','measured',name='Java',path='/fixture/other/bin/java',java_home='/fixture/other',tool_id='java')
        model,_=self.model(rows+[block,other])
        self.assertEqual(model['tools'][0]['primary_action'],'investigate')
        self.assertEqual(len(model['tools'][0]['units']),2)
        conflict=copy.deepcopy(rows[2])
        conflict['metadata']['runtime_version']='17.0.21.0.3+2-LTS'
        model,_=self.model(rows+[block,conflict])
        self.assertEqual(model['tools'][0]['primary_action'],'investigate')
        self.assertTrue(model['tools'][0]['units'][0]['identity_conflict'])

    def test_composer_fixed_body_does_not_complete_unknown_transport_conditions(self):
        body=record('MANUAL','version',name='Composer',path='/fixture/composer',tool_id='composer',
                    version='2.11.1',release_status='fixed',reference_floor='2.11.0',version_basis='official-release',
                    release_condition='本体は対策版・通信環境を確認',source='https://github.com/composer/composer/releases/tag/2.11.0')
        model,_=self.model([body])
        unit=model['tools'][0]['units'][0]
        self.assertEqual(unit['primary_action'],'investigate')
        self.assertTrue(unit['completed_versions'])
        self.assertFalse(unit['version_complete'])

    def test_composer_wrapped_denylist_log_is_derived_without_changing_samples(self):
        row=composer();model,prepared=self.model([row])
        tool=model['tools'][0]
        self.assertEqual(prepared[0]['status'],'UNKNOWN')
        self.assertEqual(prepared[0]['samples'],row['samples'])
        self.assertEqual(tool['primary_action'],'scoped_complete')
        fact=next(c for c in tool['communication'] if c['state']=='rejected_before_send')
        self.assertEqual(fact['sample_indices'],[1,2])
        self.assertEqual(fact['basis'],'composer-denylist-log')
        self.assertIn('保存ログ',fact['label'])
        self.assertTrue(tool['gaps'])

    def test_composer_negative_partial_timeout_and_wrong_origin_do_not_complete(self):
        original=composer()
        for change in ('partial','timeout','wrong-origin','post-send','other-probe','accepted'):
            row=copy.deepcopy(original)
            if change=='partial':row['samples'][2]['detail']='unknown failure'
            elif change=='timeout':row['samples'][1]['detail']='TIMEOUT: '+row['samples'][1]['detail']
            elif change=='wrong-origin':row['samples'][1]['url']='https://another.invalid/'
            elif change=='post-send':row['samples'][1]['detail']=''.join(row['samples'][1]['detail'].split()).replace('beforeitwassent','afteritwassent')
            elif change=='other-probe':row['metadata']['probe']='other'
            elif change=='accepted':row['samples'][1]['status']='ACTION'
            with self.subTest(change=change):
                model,_=self.model([row])
                self.assertNotEqual(model['tools'][0]['primary_action'],'scoped_complete')


if __name__=='__main__':unittest.main()
