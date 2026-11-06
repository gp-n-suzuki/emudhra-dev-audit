"""Release evidence stays scoped to an installation and never invents TLS success."""
import copy
import json
from pathlib import Path
import plistlib
import tempfile
import unittest

import audit
import app_inventory
import reporting
import verdicts


def version(tool, text, path='/bin/tool'):
    return dict(name=tool+' / バージョン', status='INFO', detail=text, action='', samples=[],
                assessment_method='inventory', metadata=dict(tool_id=tool, tool_name=tool,
                executable=path, version=text))


def zed(ver='1.26.2', bundle='dev.zed.Zed'):
    return dict(name='アプリ / Zed', status='MANUAL', detail='通信は未検査', action='', samples=[],
                assessment_method='manual', metadata=dict(application=True, tool_id='zed', tool_name='Zed',
                path='/Applications/Zed.app', application_version=ver, bundle_identifier=bundle,
                inspections=[], uninspected=['通信は未検査'], discovered_paths=['/Applications/Zed.app']))


class PublishedVersionTests(unittest.TestCase):
    def test_mise_official_fixed_release_and_old_install_remain_separate(self):
        rows = [version('mise', '2026.10.17 macos-arm64 (2026-10-20)', '/new/mise'),
                version('mise', '2026.10.15', '/old/mise')]
        actual = verdicts.prepare(rows)
        by_path = {r['metadata']['executable']: r for r in actual}
        self.assertEqual(by_path['/new/mise']['status'], 'INFERRED_OK')
        self.assertEqual(by_path['/old/mise']['status'], 'UPDATE')
        self.assertEqual(by_path['/new/mise']['metadata']['reference_floor'], '2026.10.17')
        self.assertIn('npm', by_path['/new/mise']['scope'])
        self.assertEqual(len(reporting.group_tools(actual)[0][0]['units']), 2)

    def test_published_zed_dependencies_are_exact_and_visible(self):
        actual = verdicts.prepare([zed()])
        self.assertEqual(actual[0]['status'], 'INFERRED_OK')
        self.assertEqual(actual[0]['metadata']['version_basis'], 'published-dependencies')
        deps = actual[0]['metadata']['published_dependencies']
        self.assertIn(('rustls-webpki', '0.103.16'), [(d['component'],d['version']) for d in deps])
        self.assertIn('OS', actual[0]['scope'])
        page = audit.render_report(actual, 'fixture')
        self.assertIn('公開依存関係は対策バージョン', page)
        self.assertIn('rustls-webpki', page)
        self.assertIn('0.103.16', page)
        self.assertIn('Cargo.lock', page)
        self.assertEqual(actual, verdicts.prepare(actual))

    def test_unknown_releases_and_custom_builds_are_not_assumed_fixed(self):
        for r in [zed('1.26.3'), zed('1.26.2-preview'), zed(bundle='local.zed'),
                  version('mise','2026.10.17-rc1'), version('mise','2026.10.17+custom'),
                  version('mise','2027.1.1'), version('claude-code','2.1.312 (Claude Code)')]:
            self.assertNotEqual(verdicts.prepare([r])[0]['status'], 'INFERRED_OK')

    def test_unmeasured_note_moves_to_data_without_overriding_version(self):
        fixed = version('mise','2026.10.17')
        pending = version('mise','')
        pending.update(name='mise / 固有の通信', status='MANUAL', assessment_method='manual', detail='通信は未検査')
        pending['metadata']['p2_coverage'] = True
        original = copy.deepcopy(pending)
        actual = verdicts.prepare([fixed,pending])
        tool = reporting.group_tools(actual)[0][0]
        self.assertEqual(tool['state'],'complete')
        page = audit.render_report(actual,'fixture')
        self.assertNotIn('class="pending-check"',page)
        self.assertIn('通信は未検査',page)
        self.assertEqual(pending, original)
        self.assertEqual(next(r for r in actual if r['name']==pending['name'])['status'],'MANUAL')

    def test_app_inventory_communication_note_is_evidence_after_version_match(self):
        record=version('mise','2026.10.17')
        app=dict(name='アプリ / mise',status='MANUAL',detail='このツールの通信は未確認',action='',samples=[],
                 assessment_method='manual',metadata=dict(application=True,tool_id='mise',tool_name='mise',
                 path='/bin/tool',discovered_paths=['/bin/tool'],inspections=[],uninspected=[]))
        page=audit.render_report(verdicts.prepare([record,app]),'fixture')
        self.assertNotIn('class="pending-check"',page)
        self.assertIn('このツールの通信は未確認',page)

    def test_configuration_and_real_acceptance_keep_priority(self):
        for method in ('configuration','measured'):
            bad = version('mise','2026.10.17')
            bad.update(name='mise / TLS', status='ACTION', assessment_method=method)
            if method == 'measured': bad['samples']=[dict(status='ACCEPTED',detail='chain confirmed',target='fixture')]
            actual = verdicts.prepare([version('mise','2026.10.17'),bad])
            self.assertEqual(reporting.group_tools(actual)[0][0]['state'],'action')
            self.assertEqual(next(r for r in actual if r['name']==bad['name'])['samples'],bad['samples'])
        bad=zed(); bad['status']='UPDATE'; bad['metadata']['inspections']=[dict(component='go',status='UPDATE')]
        self.assertEqual(verdicts.prepare([bad])[0]['status'],'UPDATE')

    def test_missing_network_in_other_installation_is_not_covered(self):
        other=version('mise','', '/old/mise'); other.update(status='MANUAL',assessment_method='unmeasured')
        actual=verdicts.prepare([version('mise','2026.10.17','/new/mise'), other])
        self.assertEqual(sorted(u['state'] for u in reporting.group_tools(actual)[0][0]['units']), ['complete','unverified'])

    def test_framework_symlink_outside_app_is_not_bundled_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); app=root/'Visual Studio Code.app'
            external=root/'external/Info.plist'; external.parent.mkdir()
            external.write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.github.Electron.framework','CFBundleVersion':'43.8.1'}))
            framework=app/'Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist'
            framework.parent.mkdir(parents=True); framework.symlink_to(external)
            rows=app_inventory.scan(audit.reference,path_dirs=[],install_dirs=[],extra_paths=[app])
            row=next(r for r in rows if r['metadata'].get('application'))
            self.assertEqual(row['metadata']['inspections'], [])

    def test_known_app_launcher_resolves_to_its_enclosing_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); app=root/'Desktop/Visual Studio Code.app'
            script=app/'Contents/Resources/app/bin/code'; script.parent.mkdir(parents=True)
            script.write_text('#!/bin/sh\nexit 0\n'); script.chmod(0o755)
            framework=app/'Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist'
            framework.parent.mkdir(parents=True)
            framework.write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.github.Electron.framework','CFBundleVersion':'43.6.0'}))
            (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.microsoft.VSCode','CFBundleShortVersionString':'1.117.0'}))
            bindir=root/'bin'; bindir.mkdir(); (bindir/'code').symlink_to(script)
            actual=app_inventory.scan(audit.reference,path_dirs=[bindir],install_dirs=[])
            rows=[r for r in actual if r['metadata'].get('application') and r['metadata'].get('tool_id')=='vscode']
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['metadata']['path'],str(app.resolve()))
            self.assertIn(str(bindir/'code'),rows[0]['metadata']['discovered_paths'])
            self.assertEqual(rows[0]['status'],'UPDATE')
            self.assertEqual(rows[0]['metadata']['inspections'][0]['version'],'43.6.0')


if __name__ == '__main__': unittest.main()
