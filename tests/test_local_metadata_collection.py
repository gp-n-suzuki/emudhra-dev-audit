"""Local package inventory is bound to its launcher, not a project environment."""
import json
from pathlib import Path
import plistlib
import tempfile
from types import SimpleNamespace
import unittest

import app_inventory
import audit
import reporting


def write(path, text):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(text if isinstance(text,bytes) else text.encode('utf-8'))
    return path


def scan(path):
    rows=app_inventory.scan(audit.reference,path_dirs=[],install_dirs=[],extra_paths=[path])
    return next(r for r in rows if r['metadata'].get('application'))


class LocalMetadataCollection(unittest.TestCase):
    def test_poetry_own_environment_is_inventory_not_project_or_import_proof(self):
        with tempfile.TemporaryDirectory(prefix='poetry fixture ') as tmp:
            env=Path(tmp)/'own'
            entry=write(env/'bin/poetry',"#!/bin/sh\n'''exec' \""+str(env/'bin/python')+"\" \"$0\" \"$@\"\n' '''\nfrom poetry.console.application import main\n")
            write(env/'pyvenv.cfg','home = /fixture/python\n')
            site=env/'lib/python3.13/site-packages'
            write(site/'poetry-2.2.1.dist-info/METADATA','Name: poetry\nVersion: 2.2.1\nAuthor-email: secret@example.invalid\n')
            write(site/'certifi-2026.10.18.dist-info/METADATA','Name: certifi\nVersion: 2026.10.18\n')
            write(Path(tmp)/'project/.venv/lib/python3.13/site-packages/certifi-1.dist-info/METADATA','Name: certifi\nVersion: 1.0.0\n')
            row=scan(entry)
            meta=row['metadata']['python_environment']
            self.assertEqual(meta['prefix'],str(env.resolve()))
            self.assertFalse(meta['runtime_usage_verified'])
            packages={p['name']:p for p in meta['packages']}
            self.assertEqual(packages['poetry']['version'],'2.2.1')
            self.assertEqual(packages['certifi']['reference_status'],'REFERENCE_OK')
            self.assertEqual(packages['certifi']['reference_floor'],'2026.10.18')
            self.assertNotIn('secret@example.invalid',json.dumps(row))
            self.assertNotIn('1.0.0',json.dumps(meta))
            self.assertEqual(row['status'],'MANUAL')
            self.assertIn('2026.10.18',reporting.application_details(row))

    def test_ambiguous_launcher_or_outside_metadata_does_not_bind(self):
        with tempfile.TemporaryDirectory() as tmp:
            env=Path(tmp)/'env'
            entry=write(env/'bin/pip','#!/usr/bin/env python\n')
            write(env/'pyvenv.cfg','home = /python\n')
            self.assertNotIn('python_environment',scan(entry)['metadata'])
            write(entry,'#!'+str(env/'bin/python')+'\n')
            outside=write(Path(tmp)/'outside/METADATA','Name: certifi\nVersion: 2026.10.18\n')
            link=env/'lib/python3.13/site-packages/certifi-2026.10.18.dist-info/METADATA'
            link.parent.mkdir(parents=True)
            link.symlink_to(outside)
            self.assertEqual(scan(entry)['metadata']['python_environment']['packages'],[])

    def test_homebrew_package_record_preserves_executable_and_parsed_versions(self):
        calls=[]; rows=[]
        def call(args,**kwargs):
            calls.append(args)
            return 0,'ca-certificates 2026-10-20\ncurl 8.23.0\nopenssl@3 3.5.9\n',''
        fake=SimpleNamespace(host=SimpleNamespace(find=lambda name:'/fixture/brew',call=call),
                             add=lambda *args,**kwargs:rows.append((args,kwargs)))
        audit.Audit.homebrew_packages(fake)
        self.assertEqual(len(calls),1)
        args,kwargs=rows[0]
        meta=args[3]
        self.assertEqual(meta['tool_id'],'homebrew')
        self.assertEqual(meta['executable'],'/fixture/brew')
        self.assertEqual(meta['packages']['ca-certificates'],['2026-10-20'])
        self.assertFalse(meta['effective_ca_verified'])
        self.assertEqual(args[1],'INFO')

    def test_alternate_electron_framework_is_read_before_walk_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            app=Path(tmp)/'Kiro.app'
            write(app/'Contents/Frameworks/Electron Framework.framework/Resources/Info.plist',
                  plistlib.dumps(dict(CFBundleIdentifier='org.electronjs.framework',CFBundleVersion='44.9.0')))
            rows=app_inventory.scan(audit.reference,path_dirs=[],install_dirs=[],extra_paths=[app],max_entries=0)
            row=next(r for r in rows if r['metadata'].get('application'))
            self.assertTrue(any(c.get('component')=='electron' and c['status']=='UPDATE' for c in row['metadata']['inspections']))


if __name__=='__main__': unittest.main()
