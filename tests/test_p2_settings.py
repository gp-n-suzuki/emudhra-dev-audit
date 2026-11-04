"""Static settings evidence is scoped, bounded, and never reports secret values."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from unittest import TestCase, mock

import audit
import p2_settings
import verdicts


def installed(tool, path):
    return verdicts.finish(dict(name=tool+' / 導入実体',status='MANUAL',detail='通信は未検査',
        metadata={'application':True,'tool_id':tool,'tool_name':tool,'path':str(path),
                  'discovered_paths':[str(path)],'inspections':[],'uninspected':['実通信は未検査']},samples=[]), 'inventory')


class SettingsEvidence(TestCase):
    def test_partial_includes_and_helm_list_entries_are_recognized(self):
        names,uncertain=p2_settings.setting_names('apt',b'#include "other.conf"\n')
        self.assertTrue(uncertain)
        names,uncertain=p2_settings.setting_names('helm',b'- insecure_skip_tls_verify: true\n')
        self.assertIn('insecure_skip_tls_verify',names)

    def report(self, root, tool, env, installed_tool=True):
        binary=root/tool; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
        rows=[installed(tool,binary)] if installed_tool else []
        clean={'HOME':str(root),'CONDARC':'','CONDA_SSL_VERIFY':'','APT_CONFIG':'',
               'HOMEBREW_CURLRC':'','HELM_REPOSITORY_CONFIG':''}
        clean.update(env)
        with mock.patch.dict(os.environ,clean),mock.patch.object(audit.app_inventory,'scan',return_value=rows), \
             mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
            audit.main(['--only','packages','--offline','--out',str(root/'out')])
        run.assert_not_called()
        text=(root/'out/report.json').read_text()
        return json.loads(text),text

    def test_conda_environment_disables_tls_only_for_installed_conda(self):
        for present in (False,True):
            with self.subTest(present=present),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                report,text=self.report(root,'conda',{'CONDA_SSL_VERIFY':'false'},present)
                actions=[r for r in report['records'] if r['metadata'].get('tool_id')=='conda' and r['review_state']=='action']
                self.assertEqual(bool(actions),present)
                if actions: self.assertIn('CONDA_SSL_VERIFY',actions[0]['detail'])

    def test_condarc_is_partial_evidence_and_does_not_leak_proxy_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); config=root/'condarc'
            config.write_text('ssl_verify: false\nproxy_servers:\n  https: https://user:fixture-secret@proxy.invalid\n')
            report,text=self.report(root,'conda',{'CONDARC':str(config),'CONDA_SSL_VERIFY':'true'})
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='conda' and r['metadata'].get('p2_settings')]
            self.assertTrue(rows)
            self.assertTrue(any('ssl_verify' in r['metadata'].get('setting_names',[]) for r in rows))
            self.assertTrue(any('ssl_verify=false' in r['metadata'].get('setting_observations',[]) for r in rows))
            self.assertTrue(any('適用' in r['detail'] for r in rows))
            self.assertFalse(any(r['review_state']=='action' for r in rows))
            self.assertFalse('fixture-secret' in text)

    def test_homebrew_curlrc_detects_a_setting_without_claiming_effective_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); config=root/'curlrc'
            config.write_text('# comment --insecure\ninsecure\nproxy = https://user:fixture-secret@proxy.invalid\n')
            report,text=self.report(root,'homebrew',{'HOMEBREW_CURLRC':str(config)})
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='homebrew' and r['metadata'].get('p2_settings')]
            self.assertTrue(any('insecure' in r['metadata'].get('setting_names',[]) for r in rows))
            self.assertFalse(any(r['review_state']=='action' for r in rows))
            self.assertFalse('fixture-secret' in text)

    def test_poetry_repository_certificate_setting_is_partial_without_auth_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); config=root/'poetry-config'; config.mkdir()
            (config/'config.toml').write_text('[certificates.private]\ncert = false\nclient-cert = "fixture-secret"\n')
            report,text=self.report(root,'poetry',{'POETRY_CONFIG_DIR':str(config)})
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='poetry' and r['metadata'].get('p2_settings')]
            self.assertTrue(any('certificates' in r['metadata']['setting_names'] for r in rows))
            self.assertTrue(any('certificates cert=false' in r['metadata']['setting_observations'] for r in rows))
            self.assertFalse(any(r['review_state']=='action' for r in rows))
            self.assertNotIn('fixture-secret',text)

    def test_apt_configuration_and_helm_repository_settings_are_scoped_without_secrets(self):
        for tool,variable,content,key in (
            ('apt','APT_CONFIG','Acquire::https::Verify-Peer "false";\nAcquire::https::Proxy "http://u:fixture-secret@proxy.invalid";\n','Verify-Peer'),
            ('helm','HELM_REPOSITORY_CONFIG','repositories:\n- name: demo\n  password: fixture-secret\n  insecure_skip_tls_verify: true\n','insecure_skip_tls_verify')):
            with self.subTest(tool=tool),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); config=root/'config'; config.write_text(content)
                report,text=self.report(root,tool,{variable:str(config)})
                rows=[r for r in report['records'] if r['metadata'].get('tool_id')==tool and r['metadata'].get('p2_settings')]
                self.assertTrue(any(key in r['metadata'].get('setting_names',[]) for r in rows))
                self.assertFalse(any(r['review_state']=='action' for r in rows))
                self.assertFalse('fixture-secret' in text)

    def test_absent_configuration_is_not_reported_as_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            report,_=self.report(root,'conda',{})
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='conda']
            self.assertTrue(rows)
            self.assertFalse(any(r['review_state']=='complete' for r in rows))
