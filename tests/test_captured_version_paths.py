"""Captured release and component fields remain connected during reassessment."""
import copy
import unittest
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

import audit

import verdicts


def version_row(tool, text):
    return dict(name=tool+' / バージョン', status='INFO', detail=text, action='', samples=[],
                assessment_method='inventory', metadata=dict(tool_id=tool, tool_name=tool,
                executable='/fixture/'+tool, version=text))


def application(component='electron', version='44.9.0', status='MANUAL'):
    check = dict(component=component, version=version, method='version', status=status,
                 path='/fixture/App.app/Contents/component', source='https://example.invalid/old-snapshot',
                 reference_floor='44.0.0' if component=='electron' else None)
    return dict(name='アプリ / Fixture', status=status, detail='captured', action='', samples=[],
                assessment_method='version', metadata=dict(tool_id='vscode', tool_name='VS Code',
                application=True, path='/fixture/App.app', inspections=[check]))


class CapturedVersionPaths(unittest.TestCase):
    def test_reassessment_replaces_stale_parent_explanation_in_all_exports(self):
        row=application('go','1.27.3','UPDATE')
        row.update(detail='1.27.4未満なので更新',action='1.27.4へ更新')
        row['metadata'].update(reference_floor='1.27.4',source='https://example.invalid/stale')
        row['metadata']['inspections'][0].update(reference_floor='1.27.4',detail=row['detail'])
        row['metadata'].update(uninspected=[],discovered_paths=['/fixture/App.app'])
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            out=Path(tmp)
            audit.write_reports(SimpleNamespace(records=[row]),out)
            saved=json.loads((out/'report.json').read_text(encoding='utf-8'))['records'][0]
            page=(out/'report.html').read_text(encoding='utf-8')
            summary=(out/'summary.txt').read_text(encoding='utf-8')
        self.assertEqual(saved['status'],'INFERRED_OK')
        self.assertEqual(saved['metadata']['reference_floor'],'1.27.3')
        self.assertNotEqual(saved['metadata']['source'],'https://example.invalid/stale')
        for value in (saved['detail'],saved['action'],page,summary,json.dumps(saved.get('remediation',{}))):
            self.assertNotIn('1.27.4未満',value)
            self.assertNotIn('1.27.4へ更新',value)

    def test_deno_and_rustup_inventory_versions_reach_the_release_rules(self):
        for tool, text, expected in [('deno','deno 2.9.7','UPDATE'),
                                     ('deno','deno 2.9.8','INFERRED_OK'),
                                     ('rustup','rustup 1.29.0 (28d1352db 2026-03-05)','UPDATE'),
                                     ('rustup','rustup 1.29.2','INFERRED_OK')]:
            with self.subTest(tool=tool,text=text):
                self.assertEqual(verdicts.prepare([version_row(tool,text)])[0]['status'], expected)

    def test_recorded_components_are_recompared_instead_of_trusting_old_verdicts(self):
        for component, version, expected in [('electron','44.9.0','UPDATE'),
                                              ('electron','44.9.1','INFERRED_OK'),
                                              ('go','1.27.2','UPDATE'),
                                              ('go','1.27.3','INFERRED_OK'),
                                              ('go','1.23.0','UPDATE'),
                                              ('certifi','2026.10.1','UPDATE'),
                                              ('certifi','2026.10.18','INFERRED_OK'),
                                              ('nss','3.114','UPDATE'),
                                              ('bun','1.4.3','UPDATE'),
                                              ('bun','1.4.4','INFERRED_OK')]:
            with self.subTest(component=component,version=version):
                row=application(component,version,'INFERRED_OK')
                original=copy.deepcopy(row)
                result=verdicts.prepare([row])[0]
                self.assertEqual(result['status'],expected)
                self.assertEqual(row,original)
                self.assertEqual([result],verdicts.prepare([result]))
                self.assertEqual(result['metadata']['inspections'][0]['version'],version)

    def test_another_binary_and_unbound_sbom_are_not_component_proof(self):
        for path in ('/unrelated/node','/fixture/App.app/Contents/bom.json',
                     '/fixture/App.app/../Other.app/component'):
            row=application('go','1.27.2')
            row['metadata']['inspections'][0]['path']=path
            self.assertEqual(verdicts.prepare([row])[0]['status'],'MANUAL')

    def test_unknown_components_and_application_measured_failures_remain(self):
        row=application('electron','44.9.1-custom')
        self.assertEqual(verdicts.prepare([row])[0]['status'],'MANUAL')
        row=application('electron','44.9.1','ACTION')
        row['assessment_method']='measured'
        row['samples']=[dict(status='ACTION',target='fixture',detail='accepted')]
        original=copy.deepcopy(row)
        result=verdicts.prepare([row])[0]
        self.assertEqual(result['status'],'ACTION')
        self.assertEqual(result['samples'],original['samples'])

    def test_android_jbr_review_and_fixed_jbr_do_not_cover_jcef_or_transport(self):
        for runtime,state in [('21.0.9+-14787801-b1163.94','review'),
                              ('21.0.11+1-b1163.125','unverified')]:
            row=application('Java 21.0.9',runtime)
            row['metadata']['tool_id']='android-studio'
            row['metadata']['inspections'][0].update(vendor='JetBrains s.r.o.')
            result=verdicts.prepare([row])[0]
            self.assertEqual(result['status'],'MANUAL')
            self.assertEqual(result['review_state'],state)
            check=result['metadata']['inspections'][0]
            self.assertIn('JCEF',check['scope'])
            self.assertEqual([result],verdicts.prepare([result]))
            self.assertEqual(result['samples'],[])

    def test_old_green_unbound_or_ambiguous_component_is_not_reused(self):
        for version,path in [('1.27.3','/unrelated/go'),
                             ('1.27.3','/fixture/App.app/Contents/bom.json'),
                             ('1.27.3 custom','/fixture/App.app/Contents/component')]:
            row = application('go',version,'INFERRED_OK')
            row['metadata']['inspections'][0]['path'] = path
            with self.subTest(version=version,path=path):
                self.assertEqual(verdicts.prepare([row])[0]['status'],'MANUAL')


if __name__ == '__main__':
    unittest.main()
