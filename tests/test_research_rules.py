"""Published remediation facts must retain their distribution and TLS conditions."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import contextlib
import io
from types import SimpleNamespace

import audit
import reporting
import tool_catalog
import verdicts
import version_inference


def row(tool, version, path='/one/tool', **meta):
    return dict(name=tool+' / バージョン', status='INFO', detail=version, samples=[], action='',
                assessment_method='inventory', metadata=dict(tool_id=tool, tool_name=tool,
                executable=path, version=version, **meta))


class ResearchRulesTests(unittest.TestCase):
    def test_new_official_release_boundaries(self):
        cases = [('aws','aws-cli/2.38.4 Python/3.14.8 Darwin/25.0.0','aws-cli/2.38.3 Python/3.14.8 Darwin/25.0.0'),
                 ('gcloud','Google Cloud SDK 590.0.1','Google Cloud SDK 590.0.0'),
                 ('buildkit','buildctl github.com/moby/buildkit v0.34.1 abcdef','buildctl github.com/moby/buildkit v0.34.0 abcdef'),
                 ('terraform','Terraform v1.16.7','Terraform v1.16.6'),
                 ('terraform','Terraform v1.17.0','Terraform v1.16.6'),
                 ('gh','gh version 2.102.1 (2026-10-20)','gh version 2.102.0 (2026-10-19)'),
                 ('hex','Hex:    2.5.4','Hex:    2.5.3'),
                 ('git','git version 2.56.0.windows.3','git version 2.56.0.windows.2'),
                 ('docker','Docker version 29.9.2, build abcdef','Docker version 29.9.1, build abcdef')]
        for tool, fixed, old in cases:
            with self.subTest(tool=tool, fixed=fixed):
                actual = verdicts.prepare([row(tool,fixed),row(tool,old,'/old/tool')])
                self.assertEqual({r['metadata']['executable']:r['status'] for r in actual},
                                 {'/one/tool':'INFERRED_OK','/old/tool':'UPDATE'})
                good = next(r for r in actual if r['status']=='INFERRED_OK')
                self.assertEqual(good['metadata']['version_basis'],'official-release')
                self.assertTrue(good['metadata']['source'].startswith('https://'))
                self.assertEqual(actual, verdicts.prepare(actual))

    def test_unknown_distribution_preview_and_new_series_are_not_fixed(self):
        for tool, text in [('aws','aws-cli/1.43.117'),('terraform','Terraform v2.0.0'),
                           ('terraform','Terraform v1.17.0-rc1'),('gh','gh version 2.102.1+custom'),
                           ('git','git version 2.56.0'),('buildkit','0.34.1+vendor'),
                           ('claude-code','2.1.314 (Claude Code)'),('safe-chain','1.5.26')]:
            self.assertNotEqual(verdicts.prepare([row(tool,text)])[0]['status'],'INFERRED_OK',text)

    def test_uv_root_removal_is_distinct_from_key_rejection(self):
        actual=verdicts.prepare([row('uv','uv 0.13.4'),row('uv','uv 0.13.5','/new/uv')])
        self.assertEqual([r['status'] for r in actual],['UPDATE','INFERRED_OK'])
        self.assertTrue(all(r['metadata']['reference_floor']=='0.13.5' for r in actual))

    def test_conditional_releases_do_not_claim_all_transport_fixed(self):
        for tool, text, phrase in [('composer','Composer version 2.11.0 2026-10-29','PHP'),
                                   ('rebar3','rebar 3.28.0 on Erlang/OTP 29 Erts 17.0','OS'),
                                   ('conda','conda 26.9.4','CA')]:
            actual=verdicts.prepare([row(tool,text)])[0]
            self.assertEqual(actual['status'],'MANUAL')
            self.assertIn(phrase,actual['detail'])
            self.assertEqual(actual['metadata']['release_status'],'fixed')
            self.assertIn(phrase,audit.render_report([actual],'fixture'))

    def test_java_vendor_full_build_is_required(self):
        cases=[('Oracle Corporation','21.0.13.0.3+1','INFERRED_OK'),
               ('Oracle Corporation','21.0.13.0.2+1','UPDATE'),
               ('Amazon.com Inc.','21.0.13+11-LTS','INFERRED_OK'),
               ('Amazon.com Inc.','21.0.13+10-LTS','MANUAL'),
               ('Eclipse Adoptium','21.0.13+9-LTS','INFERRED_OK'),
               ('JetBrains s.r.o.','21.0.13+9','MANUAL'),
               ('Oracle Corporation','21.0.13','MANUAL')]
        for vendor, runtime, expected in cases:
            r=row('java','21.0.13',vendor=vendor,runtime_version=runtime,java_home='/one/jdk')
            self.assertEqual(verdicts.prepare([r])[0]['status'],expected,(vendor,runtime))

    def test_java_measured_metadata_creates_separate_version_without_mutating_samples(self):
        r=row('java','21.0.13',vendor='Oracle Corporation',runtime_version='21.0.13.0.3+1',java_home='/jdk')
        r.update(name='Java JSSE [/one/tool]',status='UNKNOWN',assessment_method='measured',
                 samples=[dict(status='UNKNOWN',target='fixture',detail='timeout')])
        original=copy.deepcopy(r)
        actual=verdicts.prepare([r])
        self.assertEqual(r,original)
        self.assertTrue(any(x['status']=='INFERRED_OK' for x in actual))
        self.assertEqual(next(x for x in actual if x['samples'])['samples'],r['samples'])
        self.assertEqual(actual,verdicts.prepare(actual))

    def test_jbr_build_families_remain_scoped_to_the_runtime(self):
        import research_rules
        for runtime,expected in [('21.0.11+1-b1163.125','REFERENCE_OK'),
                                 ('25.0.4.1+9-b635.79','REFERENCE_OK'),
                                 ('25.0.4.1+9-b508.41','REFERENCE_OK'),
                                 ('25.0.4.1+9-b329.142','REFERENCE_OK'),
                                 ('25.0.4.1+9-b508.40','MANUAL'),
                                 ('21.0.9+1-b1038.91','REFERENCE_OK'),
                                 ('21.0.9+1-b1163.94','MANUAL'),
                                 ('21.0.9+-14787801-b1163.94','MANUAL'),
                                 ('21.0.11+1-b1038.90','MANUAL'),
                                 ('21.0.11+1-b9999.1','MANUAL')]:
            with self.subTest(runtime=runtime):
                result=research_rules.java(dict(vendor='JetBrains s.r.o.',runtime_version=runtime))
                self.assertEqual(result['status'],expected)
                self.assertIn('JCEF',result['scope'])
        # Android Studio carries a Google-specific build suffix, not the official
        # JBR distribution. Keep a component review, never claim a product fix.
        result=research_rules.java(dict(vendor='JetBrains s.r.o.',runtime_version='21.0.9+-14787801-b1163.94'))
        self.assertTrue(result['release_review'])
        self.assertEqual(result['reference_floor'],'21.0.11b1163.125')

    def test_desktop_staged_update_never_turns_entire_docker_green(self):
        r=dict(name='Docker / Docker Desktop',status='REFERENCE_OK',detail='4.96.2',samples=[],action='',
               metadata=dict(version='4.96.2',reference_floor='4.96.2',source='https://docs.docker.com/desktop/release-notes/#4962'),
               assessment_method='version')
        actual=verdicts.prepare([r])[0]
        self.assertNotEqual(actual['status'],'INFERRED_OK')
        self.assertIn('部品',actual['detail'])

    def test_unmeasured_does_not_erase_fixed_release_but_real_issues_remain(self):
        fixed=row('gh','gh version 2.102.1 (2026-10-20)')
        pending=row('gh',''); pending.update(name='gh / 固有の通信',status='MANUAL',assessment_method='unmeasured')
        pending['metadata']['p2_coverage']=True
        self.assertEqual(reporting.group_tools(verdicts.prepare([fixed,pending]))[0][0]['state'],'complete')
        bad=row('gh',''); bad.update(name='gh / TLS',status='ACTION',assessment_method='configuration')
        self.assertEqual(reporting.group_tools(verdicts.prepare([fixed,pending,bad]))[0][0]['state'],'action')

    def test_all_catalog_targets_have_shipped_research(self):
        import research_rules
        facts=research_rules.catalog()
        self.assertEqual(set(facts),{r['id'] for r in tool_catalog.CATALOG})
        self.assertTrue(all(r['sources'] and r['notes'] for r in facts.values()))
        for fact in facts.values():
            self.assertEqual(fact['review']['checked_at'],'2026-11-02')
            for field in ('distribution_scope','os_scope','required_evidence','unconfirmed'):
                self.assertTrue(fact['review'][field])
            self.assertIn('first_fixed_versions',fact['review'])
            self.assertIn('known_fixed_versions',fact['review'])
        unknown=verdicts.prepare([row('claude-code','2.1.314 (Claude Code)')])[0]
        self.assertIn('research',unknown['metadata'])
        self.assertIn('公式の対策バージョン',audit.render_report([unknown],'fixture'))

    def test_corepack_node_binding_uses_recorded_actual_runtime_not_shim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); script=root/'node_modules/corepack/dist/pnpm.js'
            script.parent.mkdir(parents=True); script.write_text('#!/usr/bin/env node\n')
            (script.parent.parent/'package.json').write_text(json.dumps(dict(name='corepack',bin={'pnpm':'dist/pnpm.js'})))
            node=root/'real/node'; node.parent.mkdir(); node.write_bytes(b'\x7fELF'+bytes(32))
            shim=root/'shims/node'; shim.parent.mkdir(); shim.write_text('#!/bin/sh\nexec mise exec node\n')
            self.assertEqual(version_inference.node_entrypoint(script,'pnpm',lambda _:str(shim),
                             {str(shim):{str(node)}}),(str(node),str(script.resolve())))
            self.assertIsNone(version_inference.node_entrypoint(script,'pnpm',lambda _:str(shim)))
            self.assertIsNone(version_inference.node_entrypoint(script,'pnpm',lambda _:str(shim),
                              {str(shim):{str(node),'/another/node'}}))

    def test_firefox_shipped_fallback_is_positive_evidence_not_old_release_failure(self):
        for ver,status in [('158.0.1','INFERRED_OK'),('158.0','MANUAL'),('115.43.1','INFERRED_OK')]:
            r=row('firefox',''); r.update(name='アプリ / Firefox',status='MANUAL',assessment_method='manual')
            r['metadata'].update(application=True,path='/Applications/Firefox.app',application_version=ver,
                                 bundle_identifier='org.mozilla.firefox',inspections=[])
            self.assertEqual(verdicts.prepare([r])[0]['status'],status)

    def test_saved_docker_children_are_reassessed_idempotently(self):
        r=dict(name='Docker Engine / Desktop / BuildKit / registry',status='INFO',detail='',samples=[],metadata={},action='',
               evidence=[dict(check='Docker Desktop',kind='version',status='REFERENCE_OK',detail='4.96.2',
                              version='4.96.2',reference_floor='4.96.2',source='https://docs.docker.com/desktop/release-notes/#4962')])
        actual=verdicts.prepare([r])
        self.assertTrue(all(x['status']!='INFERRED_OK' for x in actual))
        self.assertEqual(actual,verdicts.prepare(actual))

    def test_java_version_output_retains_vendor_and_build(self):
        import research_rules
        meta=research_rules.java_output('openjdk version "21.0.13" 2026-10-20 LTS\nOpenJDK Runtime Environment Corretto-21.0.13.0.11 (build 21.0.13+11-LTS)')
        self.assertEqual(meta['vendor'],'Amazon.com Inc.')
        self.assertEqual(meta['runtime_version'],'21.0.13+11-LTS')
        self.assertEqual(verdicts.prepare([row('java',meta.pop('version'),**meta)])[0]['status'],'INFERRED_OK')

    def test_hex_archive_metadata_is_read_without_running_mix(self):
        import research_rules
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); app=root/'hex-2.5.4/hex-2.5.4/ebin/hex.app'; app.parent.mkdir(parents=True)
            app.write_text('{application,hex,[{vsn,"2.5.4"},{modules,[]}]}')
            found=research_rules.hex_archives(root)
            self.assertEqual(len(found),1)
            self.assertEqual(verdicts.prepare(found)[0]['status'],'INFERRED_OK')
            app.write_text('{application,other,[{vsn,"99.0.0"}]}')
            self.assertEqual(research_rules.hex_archives(root),[])

    def test_bundled_java_keeps_the_vendor_and_unknown_vendor_cannot_borrow_floor(self):
        import app_inventory
        for vendor,expected in [('Oracle Corporation','INFERRED_OK'),('JetBrains s.r.o.','MANUAL')]:
            with tempfile.TemporaryDirectory() as tmp:
                app=Path(tmp)/'fixture.app'; release=app/'Contents/jre/release'; release.parent.mkdir(parents=True)
                release.write_text('JAVA_VERSION="21.0.13.0.3"\nJAVA_RUNTIME_VERSION="21.0.13.0.3+1"\nIMPLEMENTOR="'+vendor+'"\n')
                rows=app_inventory.scan(audit.reference,path_dirs=[],install_dirs=[],extra_paths=[app])
                found=next(r for r in rows if r['metadata'].get('application'))
                checks=found['metadata']['inspections']
                self.assertEqual(next(c for c in checks if c['component'].startswith('Java '))['status'],expected)

    def test_exported_guidance_survives_reassessment(self):
        rows=[row('composer','Composer version 2.10.3'),row('rebar3','rebar 3.28.0')]
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(SimpleNamespace(records=rows),Path(tmp))
            saved=json.loads((Path(tmp)/'report.json').read_text())['records']
            self.assertEqual(saved,verdicts.prepare(saved))


if __name__ == '__main__': unittest.main()
