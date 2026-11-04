"""P2 package-manager checks use only the selected installed executable."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from unittest import TestCase, mock

import audit
import package_checks
import verdicts


def installed(tool, path):
    return verdicts.finish(dict(name=tool+' / 導入実体',status='MANUAL',detail='通信は未検査',
        metadata={'application':True,'tool_id':tool,'tool_name':'Go' if tool == 'go' else tool,
                  'path':str(path),'discovered_paths':[str(path)],'inspections':[],
                  'uninspected':['実通信は未検査']},samples=[]), 'inventory')


class PackageTransport(TestCase):
    def test_pipx_uses_only_a_linked_shared_pip_and_managed_interpreter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'pipx'; binary.write_bytes(b'\x7fELF'+b'\0'*40)
            home=root/'pipx-home'; venv=home/'venvs'/'fixture'; bindir=venv/'bin'; bindir.mkdir(parents=True)
            (venv/'pyvenv.cfg').write_text('fixture')
            python=bindir/'python'; python.write_bytes(b'\x7fELF'+b'\0'*40)
            site=venv/'lib/python3.13/site-packages'; site.mkdir(parents=True)
            shared=home/'shared/lib/python3.13/site-packages'; (shared/'pip').mkdir(parents=True)
            (shared/'pip/__init__.py').write_text('')
            (site/'pipx_shared.pth').write_text(str(shared)+'\n')
            calls=[]
            def runner(command,**opts):
                calls.append((command,opts))
                return 0,'EMUDHRA_JSON:{"state":"accepted","detail":"HTTP 200"}',''
            with mock.patch.dict(os.environ,{'PIPX_HOME':str(home),'PIP_INDEX_URL':'https://u:secret@invalid',
                                             'PIPX_SHARED_LIBS':'','PIP_TRUSTED_HOST':'','PIP_CLIENT_CERT':''}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('pipx',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('probe')=='pipx_shared_pip']
            self.assertTrue(rows)
            self.assertTrue(calls)
            for command,opts in calls:
                self.assertEqual(str(python),command[0])
                self.assertEqual(command[1:4],['-I','-S','-B'])
                self.assertIn(str(shared),command)
                self.assertEqual(opts['env']['PIP_CONFIG_FILE'],os.devnull)
                self.assertFalse(opts['inherit_env'])
                self.assertNotIn('PIP_INDEX_URL',opts['env'])
            self.assertNotIn('secret',json.dumps(report))

    def test_pipx_missing_shared_link_is_not_a_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'pipx'; binary.write_bytes(b'\x7fELF'+b'\0'*40)
            with mock.patch.dict(os.environ,{'PIPX_HOME':str(root/'missing')}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('pipx',binary)]), \
                 mock.patch.object(audit,'run') as runner,contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            rows=json.loads((root/'out/report.json').read_text())['records']
            self.assertTrue(any(r['metadata'].get('tool_id')=='pipx' and r['review_state']=='unverified' for r in rows))
            runner.assert_not_called()

    def test_script_candidates_do_not_follow_an_env_symlink_hop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'script').write_text('#!/usr/bin/env ruby\n')
            (root/'.env.private').symlink_to(root/'script')
            (root/'alias').symlink_to(root/'.env.private')
            with mock.patch.object(Path,'open',side_effect=AssertionError('must not open')):
                for helper in (package_checks.gem_ruby,package_checks.composer_php,
                               package_checks.poetry_python,package_checks.azure_python):
                    self.assertIsNone(helper(root/'alias'))
                self.assertIsNone(package_checks.node_manager(root/'alias','yarn'))

    def test_offline_mode_records_installed_go_modules_as_unmeasured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'go'; binary.write_bytes(b'\x7fELF' + b'\0'*40)
            binary.chmod(0o755)
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('go',binary)]), \
                 mock.patch.object(audit,'run') as run, contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--offline','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='go']
            self.assertTrue(any('Go Modules' in r['name'] and r['review_state']=='unverified' for r in rows))
            self.assertTrue(all(not r['samples'] for r in rows))
            run.assert_not_called()

    def test_go_module_requests_use_isolated_credentials_and_keep_their_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'go'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command, options))
                target=options['env']['GOPROXY']
                if target == audit.TARGETS[0][1].rstrip('/'):
                    return 1, '', 'reading '+target+'/example.invalid/emudhra-audit-fixture/@v/v0.0.0.info: 404 Not Found'
                return 1, '', 'x509: certificate signed by unknown authority'
            env={'P2_PRIVATE_TOKEN':'do-not-send','SSL_CERT_FILE':str(root/'ca.pem'),
                 'HTTPS_PROXY':'http://proxy.invalid:3128'}
            with mock.patch.dict(os.environ,env), mock.patch.object(audit.app_inventory,'scan',return_value=[installed('go',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='go']
            row=next(r for r in rows if r['samples'])
            self.assertEqual(row['review_state'],'unverified')
            self.assertIn('診断用',row['scope'])
            self.assertTrue(any(r['review_state']=='unverified' and not r['samples'] for r in rows))
            self.assertIn('診断用の通信で接続エラーを観測',(root/'out/report.html').read_text())
            self.assertEqual(row['metadata']['executable'],str(binary))
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertIn('リダイレクト',row['samples'][0]['detail'])
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(command[0],str(binary))
                self.assertEqual(command[1:4],['list','-m','-json'])
                self.assertFalse(options['inherit_env'])
                self.assertNotIn('P2_PRIVATE_TOKEN',options['env'])
                self.assertEqual(options['env']['SSL_CERT_FILE'],str(root/'ca.pem'))
                self.assertEqual(options['env']['HTTPS_PROXY'],'http://proxy.invalid:3128')
                self.assertEqual(options['env']['GOAUTH'],'off')
                self.assertEqual(options['env']['GOSUMDB'],'off')
                self.assertEqual(options['env']['GOTOOLCHAIN'],'local')
                self.assertEqual(options['env']['GOENV'],'off')
                self.assertNotIn('direct',options['env']['GOPROXY'])

    def test_go_does_not_accept_a_404_from_proxy_or_ambiguous_failure(self):
        control=audit.TARGETS[0][1].rstrip('/')
        origin=control+'/example.invalid/emudhra-audit-fixture/@v/v0.0.0.info'
        failures=[
            'proxyconnect tcp: proxy returned 404 for '+origin,
            'reading '+origin+': 404 Not Found; x509: certificate signed by unknown authority',
            'reading '+origin+': 404 Not Found; TLS handshake timeout',
            'reading '+origin+': 404 Not Found; certificate hostname mismatch',
            'unrelated '+control+'/other: 404 Not Found',
        ]
        for failure in failures:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); binary=root/'go'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
                with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('go',binary)]), \
                     mock.patch.object(audit,'run',return_value=(1,'',failure)), contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                report=json.loads((root/'out/report.json').read_text())
                row=next(r for r in report['records'] if 'Go Modules' in r['name'])
                self.assertEqual(row['samples'][0]['status'],'UNKNOWN')

    def test_downstream_redirect_ca_failure_is_not_a_rejection_by_the_original_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'go'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            def runner(command, **options):
                target=options['env']['GOPROXY']
                if target==audit.TARGETS[0][1].rstrip('/'):
                    return 1,'','reading '+target+'/example.invalid/emudhra-audit-fixture/@v/v0.0.0.info: 404 Not Found'
                return 1,'','Get https://other.invalid/index: x509: certificate signed by unknown authority'
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('go',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='go' and r['samples'])
            self.assertEqual(row['samples'][0]['status'],'UNKNOWN')
            self.assertTrue(all(s['status']=='UNKNOWN' for s in row['samples'][1:]))
            self.assertIn('リダイレクト',row['samples'][1]['detail'])
            self.assertIn('診断用の通信で接続エラーを観測',(root/'out/report.html').read_text())

    def test_cargo_and_uv_ambiguous_proxy_or_tls_failures_are_not_control_ok(self):
        for tool in ('cargo','uv'):
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); binary=root/tool; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
                detail=('failed to get successful HTTP response from '+audit.TARGETS[0][1]+
                        'config.json: 404 Not Found; proxy CONNECT failed' if tool=='cargo' else
                        'No solution found: package was not found in the package registry; TLS handshake timeout')
                with mock.patch.object(audit.app_inventory,'scan',return_value=[installed(tool,binary)]), \
                     mock.patch.object(audit,'run',return_value=(1,'',detail)), contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                report=json.loads((root/'out/report.json').read_text())
                row=next(r for r in report['records'] if r['metadata'].get('tool_id')==tool)
                self.assertEqual(row['samples'][0]['status'],'UNKNOWN')

    def test_tls_failure_in_either_output_stream_overrides_a_success_marker(self):
        for tool in ('go','cargo','uv','rclone'):
            with self.subTest(tool=tool),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); binary=root/tool; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
                def runner(command,**options):
                    target=audit.TARGETS[0][1].rstrip('/')
                    if tool=='go': marker='reading '+target+'/example.invalid/emudhra-audit-fixture/@v/v0.0.0.info: 404 Not Found'
                    elif tool=='cargo': marker='failed to get successful HTTP response from '+target+'/config.json: 404 Not Found'
                    elif tool=='uv': marker='No solution found: package was not found in the package registry'
                    else: marker='listing complete'
                    return (0 if tool=='rclone' else 1),'TLS handshake timeout',marker
                with mock.patch.object(audit.app_inventory,'scan',return_value=[installed(tool,binary)]), \
                     mock.patch.object(audit,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                report=json.loads((root/'out/report.json').read_text())
                row=next(r for r in report['records'] if r['metadata'].get('tool_id')==tool and r['samples'])
                self.assertEqual(row['samples'][0]['status'],'UNKNOWN')

    def test_uv_uses_synthetic_requirements_without_credentials_or_installing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'uv'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                self.assertEqual(Path(command[3]).read_text().strip(),'emudhra-audit-fixture==0.0.0')
                if command[command.index('--index-url')+1] == audit.TARGETS[0][1]:
                    return 1,'','No solution found when resolving dependencies: package was not found in the package registry'
                return 1,'','invalid peer certificate: UnknownIssuer'
            with mock.patch.dict(os.environ,{'UV_INDEX_PRIVATE_PASSWORD':'do-not-send'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('uv',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='uv']
            row=next(r for r in rows if r['samples'])
            self.assertEqual(row['review_state'],'unverified')
            self.assertTrue(any(r['review_state']=='unverified' and not r['samples'] for r in rows))
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(command[:3],[str(binary),'pip','compile'])
                self.assertIn('--no-build',command)
                self.assertNotIn('--only-binary',command)
                self.assertIn('--no-python-downloads',command)
                self.assertIn('--no-config',command)
                self.assertIn('--no-deps',command)
                self.assertEqual(command[command.index('--keyring-provider')+1],'disabled')
                self.assertFalse(options['inherit_env'])
                self.assertNotIn('UV_INDEX_PRIVATE_PASSWORD',options['env'])

    def test_osv_queries_only_a_synthetic_dependency_and_keeps_target_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'osv-scanner'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                fixture=Path(command[command.index('--lockfile')+1].split(':',1)[1])
                dependency=json.loads(fixture.read_text())['results'][0]['packages'][0]['package']
                self.assertEqual(dependency,{'name':'emudhra-audit-fixture','version':'0.0.0','ecosystem':'PyPI'})
                observed=dict(dependency,purl='pkg:pypi/emudhra-audit-fixture@0.0.0')
                return 0,json.dumps({'results':[{'packages':[{'package':observed}]}]}),''
            with mock.patch.dict(os.environ,{'OSV_PRIVATE_TOKEN':'do-not-send'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('osv-scanner',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='osv-scanner']
            row=next(r for r in rows if r['samples'])
            self.assertEqual(row['review_state'],'complete')
            self.assertTrue(any(r['review_state']=='unverified' and not r['samples'] for r in rows))
            self.assertEqual(row['samples'][0]['status'],'UNKNOWN')
            self.assertIn('リダイレクト',row['samples'][0]['detail'])
            self.assertIn('合成データの照会結果を確認',(root/'out/report.html').read_text())
            self.assertEqual(len(calls),1)
            command,options=calls[0]
            self.assertEqual(command[:3],[str(binary),'scan','source'])
            self.assertIn('--no-resolve',command)
            self.assertFalse(options['inherit_env'])
            self.assertNotIn('OSV_PRIVATE_TOKEN',options['env'])

    def test_osv_output_with_tls_failure_is_not_reported_as_control_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'osv-scanner'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            package={'name':'emudhra-audit-fixture','version':'0.0.0','ecosystem':'PyPI'}
            output=json.dumps({'results':[{'packages':[{'package':package}]}]})
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('osv-scanner',binary)]), \
                 mock.patch.object(audit,'run',return_value=(0,output,'TLS handshake timeout')), \
                 contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='osv-scanner')
            self.assertEqual(row['samples'][0]['status'],'UNKNOWN')

    def test_cargo_uses_sparse_metadata_without_credentials_or_installing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'cargo'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                url=command[command.index('--index')+1][len('sparse+'):]
                if url.rstrip('/') == audit.TARGETS[0][1].rstrip('/'):
                    return 1,'','failed to get successful HTTP response from '+url+'config.json: 404 Not Found'
                return 1,'','SSL certificate problem: unable to get local issuer certificate'
            with mock.patch.dict(os.environ,{'CARGO_REGISTRIES_PRIVATE_TOKEN':'do-not-send'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('cargo',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='cargo']
            row=next(r for r in rows if r['samples'])
            self.assertEqual(row['review_state'],'unverified')
            self.assertTrue(any(r['review_state']=='unverified' and not r['samples'] for r in rows))
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(command[:2],[str(binary),'search'])
                self.assertTrue(command[command.index('--index')+1].startswith('sparse+https://'))
                self.assertFalse(options['inherit_env'])
                self.assertEqual(options['env']['RUSTUP_AUTO_INSTALL'],'0')
                self.assertNotIn('CARGO_REGISTRIES_PRIVATE_TOKEN',options['env'])

    def test_cargo_rustup_shim_is_not_started(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); rustup=root/'rustup'; rustup.write_bytes(b'\x7fELF'+b'\0'*40); rustup.chmod(0o755)
            binary=root/'cargo'; binary.symlink_to(rustup)
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('cargo',binary)]), \
                 mock.patch.object(audit,'run') as run, contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='cargo')
            self.assertEqual(row['review_state'],'unverified')
            self.assertFalse(row['samples'])
            run.assert_not_called()

    def test_rclone_uses_an_empty_synthetic_http_remote_without_user_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'rclone'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                self.assertEqual(Path(command[command.index('--config')+1]).read_text(),'')
                if command[command.index('--http-url')+1] == audit.TARGETS[0][1]:
                    return 0,'',''
                return 1,'','x509: certificate signed by unknown authority'
            with mock.patch.dict(os.environ,{'RCLONE_HTTP_HEADERS':'Authorization,secret-value'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('rclone',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='rclone']
            row=next(r for r in rows if r['samples'])
            self.assertEqual(row['review_state'],'unverified')
            self.assertTrue(any(r['review_state']=='unverified' and not r['samples'] for r in rows))
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(command[:2],[str(binary),'lsd'])
                self.assertIn(':http:',command)
                self.assertNotIn('RCLONE_HTTP_HEADERS',options['env'])
                self.assertFalse(options['inherit_env'])

    def test_rubygems_uses_its_neighboring_ruby_and_only_the_synthetic_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); gem=root/'gem'; gem.write_text('#!/usr/bin/env ruby\n'); gem.chmod(0o755)
            ruby=root/'ruby'; ruby.write_bytes(b'\x7fELF'+b'\0'*40); ruby.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                url=command[command.index('--source')+1]
                if url == audit.TARGETS[0][1]:
                    return 0,'GET '+url+'specs.4.8.gz\n200 OK\n',''
                return 1,'','certificate has expired'
            with mock.patch.dict(os.environ,{'GEM_HOST_API_KEY':'do-not-send'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('rubygems',gem)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='rubygems')
            self.assertEqual(row['review_state'],'unverified')
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(Path(command[0]).resolve(),ruby.resolve())
                self.assertEqual(command[3:5],[str(gem),'search'])
                self.assertIn('--clear-sources',command)
                self.assertIn('--norc',command)
                self.assertNotIn('GEM_HOST_API_KEY',options['env'])
                self.assertFalse(options['inherit_env'])

    def test_composer_search_uses_only_a_synthetic_repository_and_no_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); composer=root/'composer'; composer.write_text('#!/usr/bin/env php\n'); composer.chmod(0o755)
            php=root/'php'; php.write_bytes(b'\x7fELF'+b'\0'*40); php.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                doc=json.loads((Path(options['cwd'])/'composer.json').read_text())
                self.assertEqual(doc['repositories'][1],{'packagist.org':False})
                self.assertTrue(doc['repositories'][0]['url'].startswith('https://'))
                self.assertEqual(doc['require'],{})
                return 0,'[]',''
            with mock.patch.dict(os.environ,{'COMPOSER_AUTH':'do-not-send'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('composer',composer)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='composer']
            row=next(r for r in rows if r['samples'])
            self.assertEqual(row['review_state'],'unverified')
            self.assertTrue(all(s['status']=='UNKNOWN' for s in row['samples']))
            self.assertTrue(any(not r['samples'] for r in rows))
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(Path(command[0]).resolve(),php.resolve())
                self.assertIn('--no-plugins',command)
                self.assertIn('--no-scripts',command)
                self.assertIn('--no-cache',command)
                self.assertIn('auto_prepend_file=',command)
                self.assertNotIn('COMPOSER_AUTH',options['env'])
                self.assertFalse(options['inherit_env'])

    def test_bundler_prints_only_a_synthetic_lock_without_installing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); bundle=root/'bundle'; bundle.write_text('#!/usr/bin/env ruby\n'); bundle.chmod(0o755)
            ruby=root/'ruby'; ruby.write_bytes(b'\x7fELF'+b'\0'*40); ruby.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                source=Path(options['env']['BUNDLE_GEMFILE']).read_text()
                self.assertIn('emudhra-audit-fixture',source)
                self.assertNotIn('do-not-send',source)
                return 1,'','certificate signed by unknown authority'
            with mock.patch.dict(os.environ,{'BUNDLE_TOKEN':'do-not-send'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('bundler',bundle)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='bundler']
            row=next(r for r in rows if r['samples'])
            self.assertEqual(row['review_state'],'unverified')
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(Path(command[0]).resolve(),ruby.resolve())
                self.assertEqual(command[3:5],[str(bundle),'lock'])
                self.assertIn('--print',command)
                self.assertNotIn('install',command)
                self.assertEqual(options['env']['BUNDLE_IGNORE_CONFIG'],'1')
                self.assertNotIn('BUNDLE_TOKEN',options['env'])
                self.assertFalse(options['inherit_env'])

    def test_pnpm_and_yarn_use_verified_cli_and_anonymous_synthetic_metadata(self):
        for tool,version,command_name in [('pnpm','11.2.0','view'),('yarn','1.22.19','info')]:
            with self.subTest(tool=tool),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); package=root/'node_modules'/tool; (package/'bin').mkdir(parents=True)
                (package/'package.json').write_text(json.dumps({'name':tool,'version':version}))
                script=package/'bin'/('pnpm.cjs' if tool=='pnpm' else 'yarn.js')
                script.write_text('#!/usr/bin/env node\n'); script.chmod(0o755)
                node=root/'node'; node.write_bytes(b'\x7fELF'+b'\0'*40); node.chmod(0o755)
                calls=[]
                def runner(command, **options):
                    calls.append((command,options))
                    if command[command.index('--registry')+1] == audit.TARGETS[0][1]:
                        value={'name':'emudhra-audit-fixture'}
                        return 0,json.dumps({'type':'inspect','data':value} if tool=='yarn' else value),''
                    return 1,'','certificate signed by unknown authority'
                with mock.patch.object(package_checks.shutil,'which',return_value=str(node)), \
                     mock.patch.dict(os.environ,{'NPM_TOKEN':'do-not-send'}), \
                     mock.patch.object(audit.app_inventory,'scan',return_value=[installed(tool,script)]), \
                     mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                report=json.loads((root/'out/report.json').read_text())
                rows=[r for r in report['records'] if r['metadata'].get('tool_id')==tool]
                row=next(r for r in rows if r['samples'])
                self.assertEqual(row['review_state'],'unverified')
                self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
                self.assertTrue(any(not r['samples'] for r in rows))
                self.assertEqual(len(calls),5)
                for command,options in calls:
                    self.assertEqual(command[:3],[str(node),str(script),command_name])
                    self.assertNotIn('NPM_TOKEN',options['env'])
                    self.assertFalse(options['inherit_env'])
                    self.assertEqual(options['env']['COREPACK_ENABLE_NETWORK'],'0')

    def test_corepack_wrapper_and_old_pnpm_are_not_started_as_pnpm(self):
        for name,version in [('corepack','0.35.0'),('pnpm','10.9.0'),('pnpm','12.0.0')]:
            with self.subTest(name=name,version=version),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); package=root/name; (package/'bin').mkdir(parents=True)
                (package/'package.json').write_text(json.dumps({'name':name,'version':version}))
                script=package/'bin/pnpm.js'; script.write_text('#!/usr/bin/env node\n'); script.chmod(0o755)
                with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('pnpm',script)]), \
                     mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                report=json.loads((root/'out/report.json').read_text())
                row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='pnpm')
                self.assertEqual(row['review_state'],'unverified')
                self.assertFalse(row['samples'])
                run.assert_not_called()

    def test_direct_yarn_berry_uses_its_own_registry_command_without_telemetry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); package=root/'node_modules/@yarnpkg/cli-dist'; (package/'bin').mkdir(parents=True)
            (package/'package.json').write_text(json.dumps({'name':'@yarnpkg/cli-dist','version':'4.5.0'}))
            script=package/'bin/yarn.js'; script.write_text('#!/usr/bin/env node\n'); script.chmod(0o755)
            node=root/'node'; node.write_bytes(b'\x7fELF'+b'\0'*40); node.chmod(0o755)
            calls=[]
            def runner(command,**options):
                calls.append((command,options))
                return 0,json.dumps({'name':'emudhra-audit-fixture'}),''
            with mock.patch.object(package_checks.shutil,'which',return_value=str(node)), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('yarn',script)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='yarn' and r['samples'])
            self.assertEqual(row['review_state'],'unverified')
            self.assertEqual(len(calls),5)
            for command,options in calls:
                self.assertEqual(command[:4],[str(node),str(script),'npm','info'])
                self.assertEqual(options['env']['YARN_ENABLE_TELEMETRY'],'0')
                self.assertTrue(options['env']['YARN_NPM_REGISTRY_SERVER'].startswith('https://'))
                self.assertNotIn('--registry',command)

    def test_explicit_offline_or_insecure_host_setting_withholds_active_check(self):
        for tool, setting in [('go',{'GOPROXY':'off'}),('uv',{'UV_OFFLINE':'1'}),
                              ('uv',{'UV_INSECURE_HOST':'example.invalid'}),('cargo',{'CARGO_NET_OFFLINE':'true'})]:
            with self.subTest(tool=tool,setting=setting), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); binary=root/tool; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
                with mock.patch.dict(os.environ,setting), \
                     mock.patch.object(audit.app_inventory,'scan',return_value=[installed(tool,binary)]), \
                     mock.patch.object(audit,'run') as run, contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                report=json.loads((root/'out/report.json').read_text())
                row=next(r for r in report['records'] if r['metadata'].get('tool_id')==tool)
                self.assertEqual(row['review_state'],'unverified')
                self.assertFalse(row['samples'])
                run.assert_not_called()

    def test_credential_bearing_or_non_https_test_url_is_never_invoked_or_reported(self):
        for url in ('https://user:private-password@example.invalid/', 'https://@example.invalid/', 'http://example.invalid/'):
            with self.subTest(scheme=url.split(':',1)[0]),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); binary=root/'go'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
                targets=[('control',url,True)]+[('test',url,False)]*4
                with mock.patch.object(audit,'TARGETS',targets), \
                     mock.patch.object(audit.app_inventory,'scan',return_value=[installed('go',binary)]), \
                     mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                data=(root/'out/report.json').read_text()
                self.assertNotIn('private-password',data)
                self.assertNotIn('http://example.invalid/',data)
                row=next(r for r in json.loads(data)['records'] if r['metadata'].get('tool_id')=='go')
                self.assertEqual(row['review_state'],'unverified')
                run.assert_not_called()

    def test_uv_does_not_bypass_a_detected_safe_chain_shell_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); uv=root/'uv'; uv.write_bytes(b'\x7fELF'+b'\0'*40); uv.chmod(0o755)
            chain=root/'safe-chain'; chain.write_bytes(b'\x7fELF'+b'\0'*40); chain.chmod(0o755)
            safe=installed('safe-chain',chain)
            safe['metadata']['security_tool']={'shell_sources':['.zshrc'],'configured_wrappers':['uv']}
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('uv',uv),safe]), \
                 mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='uv')
            self.assertEqual(row['review_state'],'unverified')
            self.assertIn('Safe Chain',row['detail'])
            self.assertFalse(row['samples'])
            run.assert_not_called()

    def test_uv_does_not_bypass_safe_chain_shims_on_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); uv=root/'uv'; uv.write_bytes(b'\x7fELF'+b'\0'*40); uv.chmod(0o755)
            base=root/'.safe-chain'; (base/'bin').mkdir(parents=True); (base/'shims').mkdir()
            chain=base/'bin/safe-chain'; chain.write_bytes(b'\x7fELF'+b'\0'*40); chain.chmod(0o755)
            safe=installed('safe-chain',chain)
            safe['metadata']['security_tool']={'shell_sources':[],'configured_wrappers':['uv']}
            with mock.patch.dict(os.environ,{'PATH':str(base/'shims')}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('uv',uv),safe]), \
                 mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='uv')
            self.assertIn('Safe Chain',row['detail'])
            run.assert_not_called()

    def test_safe_chain_integration_with_unknown_wrappers_still_withholds_uv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); uv=root/'uv'; uv.write_bytes(b'\x7fELF'+b'\0'*40); uv.chmod(0o755)
            chain=root/'safe-chain'; chain.write_bytes(b'\x7fELF'+b'\0'*40); chain.chmod(0o755)
            safe=installed('safe-chain',chain)
            safe['metadata']['security_tool']={'shell_sources':['.zshrc'],'configured_wrappers':[]}
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('uv',uv),safe]), \
                 mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='uv')
            self.assertIn('Safe Chain',row['detail'])
            self.assertFalse(row['samples'])
            run.assert_not_called()

    def test_unknown_safe_chain_wrappers_withhold_poetry_and_pipx(self):
        for configured in ([],['uv']):
            with self.subTest(configured=configured),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); rows=[]
                for tool in ('pipx','poetry','safe-chain'):
                    binary=root/tool; binary.write_bytes(b'\x7fELF'+b'\0'*40)
                    row=installed(tool,binary)
                    if tool=='safe-chain': row['metadata']['security_tool']={'shell_sources':['.zshrc'],'configured_wrappers':configured}
                    rows.append(row)
                with mock.patch.object(audit.app_inventory,'scan',return_value=rows), \
                     mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                data=json.loads((root/'out/report.json').read_text())['records']
                for tool in ('pipx','poetry'):
                    self.assertTrue(any(r['metadata'].get('tool_id')==tool and 'Safe Chain' in r['detail'] for r in data))
                run.assert_not_called()

    def test_safe_chain_protected_pip_session_is_not_sampled_directly(self):
        from types import SimpleNamespace
        args=SimpleNamespace(project=None,offline=False,workers=1,timeout=1,python=[],scan_venvs=[])
        instance=audit.Audit(args); instance.package_protected={'pip'}
        context=SimpleNamespace(prefix=[],label='fixture',find=lambda name:'/fixture/python')
        meta={'state':'meta','data':{'prefix':'/fixture','version':'3.13.0','packages':{'pip':'26.2.2'}}}
        def probe(ctx,command,*args,**kwargs):
            self.assertNotEqual(command[-3],'pip')
            return meta if command[-3]=='meta' else {'state':'error','detail':'fixture failure'}
        try:
            with mock.patch.object(instance,'json_probe',side_effect=probe),contextlib.redirect_stdout(io.StringIO()):
                instance.python(context)
            self.assertTrue(any('Safe Chain' in r['detail'] and r['metadata'].get('mode')=='pip' for r in instance.records))
        finally: instance.tmp.cleanup()

    def test_safe_chain_protected_npm_is_not_started_directly(self):
        from types import SimpleNamespace
        instance=audit.Audit(SimpleNamespace(project=None,offline=False,workers=1,timeout=1))
        instance.package_protected={'npm'}
        try:
            with mock.patch.object(instance.host,'find',return_value=None), \
                 mock.patch.object(instance.host,'call') as call, \
                 mock.patch.object(instance,'paths',return_value=['/fixture/npm']),contextlib.redirect_stdout(io.StringIO()):
                instance.tools()
            self.assertTrue(any('Safe Chain' in r['detail'] for r in instance.records))
            call.assert_not_called()
        finally: instance.tmp.cleanup()

    def test_safe_chain_is_detected_even_for_python_only_or_tools_only(self):
        from types import SimpleNamespace
        for selection in ('python','tools'):
            with self.subTest(selection=selection),tempfile.TemporaryDirectory() as tmp:
                binary=Path(tmp)/'safe-chain'; binary.write_bytes(b'\x7fELF'+b'\0'*40)
                row=installed('safe-chain',binary)
                row['metadata']['security_tool']={'shell_sources':['.zshrc'],'configured_wrappers':[]}
                instance=audit.Audit(SimpleNamespace(only=selection,project=None,offline=True,workers=1,timeout=1))
                try:
                    with mock.patch.object(audit.app_inventory,'scan',return_value=[row]), \
                         mock.patch.object(instance,'config_inventory'),mock.patch.object(instance,'python'), \
                         mock.patch.object(instance,'tools'),mock.patch.object(audit.language_checks,'collect'), \
                         mock.patch.object(audit.evidence,'collect'),contextlib.redirect_stdout(io.StringIO()):
                        instance.execute()
                    self.assertTrue({'pip','npm','poetry','pipx'} <= instance.package_protected)
                finally: instance.tmp.cleanup()

    def test_authenticated_proxy_is_not_used_for_diagnostic_traffic(self):
        for variable in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy',
                         'ALL_PROXY','all_proxy','CARGO_HTTP_PROXY'):
            with self.subTest(variable=variable), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); uv=root/'uv'; uv.write_bytes(b'\x7fELF'+b'\0'*40); uv.chmod(0o755)
                with mock.patch.dict(os.environ,{variable:'http://person:private-password@proxy.invalid:3128'}), \
                     mock.patch.object(audit.app_inventory,'scan',return_value=[installed('uv',uv)]), \
                     mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                data=(root/'out/report.json').read_text()
                row=next(r for r in json.loads(data)['records'] if r['metadata'].get('tool_id')=='uv')
                self.assertIn('認証',row['detail'])
                self.assertNotIn('private-password',data)
                self.assertFalse(row['samples'])
                run.assert_not_called()

    def test_observed_response_is_labeled_as_diagnostic_not_real_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'go'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            def runner(command, **options):
                url=options['env']['GOPROXY']+'/example.invalid/emudhra-audit-fixture/@v/v0.0.0.info'
                return 1, '', 'reading '+url+': 404 Not Found'
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('go',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            self.assertIn('診断用の通信応答を観測',(root/'out/report.html').read_text())

    def test_ambiguous_network_failures_stay_unconfirmed_for_each_package_client(self):
        errors=[(1,'certificate has expired'),(1,'certificate hostname mismatch'),
                (1,'proxy CONNECT failed'),(1,'connection refused'),(124,'TIMEOUT')]
        for tool in ('go','uv','cargo'):
            for rc,error in errors:
                with self.subTest(tool=tool,error=error),tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp); binary=root/tool; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
                    with mock.patch.object(audit.app_inventory,'scan',return_value=[installed(tool,binary)]), \
                         mock.patch.object(audit,'run',return_value=(rc,'',error)),contextlib.redirect_stdout(io.StringIO()):
                        audit.main(['--only','packages','--out',str(root/'out')])
                    report=json.loads((root/'out/report.json').read_text())
                    row=next(r for r in report['records'] if r['metadata'].get('tool_id')==tool)
                    self.assertEqual(row['review_state'],'unverified')
                    self.assertTrue(all(s['status']=='UNKNOWN' for s in row['samples']))

    def test_distinct_installs_stay_separate_and_same_executable_alias_is_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            first=root/'first'/'uv'; first.parent.mkdir(); first.write_bytes(b'\x7fELF'+b'\0'*40); first.chmod(0o755)
            alias=root/'alias'; alias.symlink_to(first)
            second=root/'second'/'uv'; second.parent.mkdir(); second.write_bytes(b'\x7fELF'+b'\0'*40); second.chmod(0o755)
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('uv',p) for p in (first,alias,second)]), \
                 mock.patch.object(audit,'run',return_value=(124,'','TIMEOUT')) as run, contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='uv' and r['samples']]
            self.assertEqual({r['metadata']['executable'] for r in rows},{str(first),str(second)})
            self.assertEqual(run.call_count,10)

    def test_unsupported_installed_tools_report_their_specific_communication_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            rows=[]
            for tool in ('gh','homebrew','pipx','docker','psresourceget'):
                path=root/tool; path.write_bytes(b'\x7fELF'+b'\0'*40); path.chmod(0o755)
                rows.append(installed(tool,path))
            with mock.patch.object(audit.app_inventory,'scan',return_value=rows), \
                 mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            by_tool={r['metadata'].get('tool_id'):r for r in report['records'] if r['metadata'].get('p2_coverage')}
            self.assertEqual(set(by_tool),{'gh','homebrew','pipx','docker','psresourceget'})
            self.assertIn('認証',by_tool['gh']['detail'])
            self.assertIn('fallback',by_tool['homebrew']['detail'])
            self.assertIn('pip',by_tool['pipx']['detail'])
            self.assertIn('registry',by_tool['docker']['detail'])
            self.assertIn('repository',by_tool['psresourceget']['detail'])
            self.assertTrue(all(r['review_state']=='unverified' and r['action'] for r in by_tool.values()))
            run.assert_not_called()

    def test_grouped_tool_notes_do_not_link_an_unrelated_vendor_as_their_source(self):
        import p2_coverage
        self.assertFalse(p2_coverage.NOTES['gradle'][2])
        self.assertFalse(p2_coverage.NOTES['vercel'][2])
        self.assertTrue(p2_coverage.NOTES['pipx'][2].startswith('https://pipx.pypa.io/'))

    def test_kubectl_uses_anonymous_temporary_kubeconfig_and_only_the_fixture_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'kubectl'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                config=json.loads(Path(command[command.index('--kubeconfig')+1]).read_text())
                calls.append((command,options,config))
                return 0, '{"fixture":"ok"}', ''
            with mock.patch.dict(os.environ,{'KUBECONFIG':'/private/real-kubeconfig','AWS_SECRET_ACCESS_KEY':'private-secret'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('kubectl',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='kubectl']
            measured=next(r for r in rows if r['samples'])
            self.assertEqual([s['status'] for s in measured['samples']],['UNKNOWN']*5)
            self.assertTrue(any(not r['samples'] and r['review_state']=='unverified' for r in rows))
            self.assertEqual(len(calls),5)
            self.assertEqual({call[2]['clusters'][0]['cluster']['server'] for call in calls},{target[1] for target in audit.TARGETS})
            for command,options,config in calls:
                self.assertEqual(command[0],str(binary))
                self.assertEqual(command[-3:],['get','--raw','/'])
                self.assertEqual(config.get('users',[]),[])
                self.assertFalse(options['inherit_env'])
                self.assertNotIn('KUBECONFIG',options['env'])
                self.assertNotIn('AWS_SECRET_ACCESS_KEY',options['env'])
                self.assertEqual(str(options['cwd']),options['env']['HOME'])

    def test_kubectl_interactive_auth_prompt_is_reported_without_sending_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'kubectl'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('kubectl',binary)]), \
                 mock.patch.object(audit,'run',return_value=(1,'Please enter Username:', 'error: EOF')), \
                 contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='kubectl' and r['samples'])
            self.assertIn('対話',row['detail'])
            self.assertEqual(row['review_state'],'unverified')

    def test_aws_cli_is_unsigned_with_empty_config_and_fixed_diagnostic_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'aws'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                env=options['env']
                calls.append((command,options,Path(env['AWS_CONFIG_FILE']).read_text(),
                              Path(env['AWS_SHARED_CREDENTIALS_FILE']).read_text()))
                return 0, '{"UserId":"fixture","Account":"000000000000","Arn":"arn:aws:sts::000000000000:assumed-role/fixture/example"}', ''
            secrets={'AWS_ACCESS_KEY_ID':'private-id','AWS_SECRET_ACCESS_KEY':'private-secret',
                     'AWS_SESSION_TOKEN':'private-session','AWS_PROFILE':'real-profile'}
            with mock.patch.dict(os.environ,secrets), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('aws',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='aws']
            measured=next(r for r in rows if r['samples'])
            self.assertEqual([s['status'] for s in measured['samples']],['UNKNOWN']*5)
            self.assertIn('通信応答を観測',measured['samples'][0]['detail'])
            self.assertTrue(any(not r['samples'] and r['review_state']=='unverified' for r in rows))
            self.assertEqual(len(calls),5)
            self.assertEqual({call[0][call[0].index('--endpoint-url')+1] for call in calls},{target[1] for target in audit.TARGETS})
            for command,options,config,credentials in calls:
                self.assertEqual(command[0],str(binary))
                self.assertEqual(command[1:3],['sts','get-caller-identity'])
                self.assertIn('--no-sign-request',command)
                self.assertIn('--no-paginate',command)
                self.assertEqual(config,'')
                self.assertEqual(credentials,'')
                self.assertEqual(options['env']['AWS_EC2_METADATA_DISABLED'],'true')
                self.assertEqual(options['env']['AWS_MAX_ATTEMPTS'],'1')
                self.assertFalse(options['inherit_env'])
                self.assertTrue(all(key not in options['env'] for key in secrets))

    def test_aws_fixture_subprocess_receives_no_real_credential_environment(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'aws'
            binary.write_text('#!'+sys.executable+'\n'+'''import json, os, pathlib, sys
for key in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_PROFILE'):
    assert key not in os.environ
assert os.environ['AWS_EC2_METADATA_DISABLED'] == 'true'
assert pathlib.Path(os.environ['AWS_CONFIG_FILE']).read_text() == ''
assert pathlib.Path(os.environ['AWS_SHARED_CREDENTIALS_FILE']).read_text() == ''
assert '--no-sign-request' in sys.argv and '--no-paginate' in sys.argv
print(json.dumps({'UserId':'fixture','Account':'000000000000','Arn':'fixture'}))
''',encoding='utf-8')
            binary.chmod(0o755)
            secrets={'AWS_ACCESS_KEY_ID':'private-id','AWS_SECRET_ACCESS_KEY':'private-secret',
                     'AWS_SESSION_TOKEN':'private-session','AWS_PROFILE':'real-profile'}
            with mock.patch.dict(os.environ,secrets), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('aws',binary)]), \
                 mock.patch.object(package_checks,'native',return_value=True),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='aws' and r['samples'])
            self.assertTrue(all(s['observation']=='connection' for s in row['samples']))
            self.assertTrue(all(s['status']=='UNKNOWN' for s in row['samples']))

    def test_helm_queries_only_a_temporary_unauthenticated_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'helm'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                env=options['env']; work=Path(options['cwd'])
                calls.append((command,options,work == Path(env['HOME']),
                              Path(env['HELM_PLUGINS']).is_dir(),list(Path(env['HELM_PLUGINS']).iterdir())))
                return 0, '"diagnostic" has been added to your repositories\n', ''
            with mock.patch.dict(os.environ,{'HELM_REGISTRY_CONFIG':'/private/real-registry',
                                           'KUBECONFIG':'/private/real-kubeconfig',
                                           'HELM_REPOSITORY_CONFIG':'/private/real-repositories'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('helm',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='helm']
            row=next(r for r in rows if r['samples'])
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertIn('通信応答を観測',row['samples'][0]['detail'])
            self.assertTrue(any(not r['samples'] and r['review_state']=='unverified' for r in rows))
            self.assertEqual(len(calls),5)
            self.assertEqual({c[0][4] for c in calls},{x[1] for x in audit.TARGETS})
            for command,options,own_home,plugins_exist,plugins in calls:
                self.assertEqual(command[:4],[str(binary),'repo','add','diagnostic'])
                self.assertFalse(options['inherit_env'])
                self.assertTrue(own_home and plugins_exist and not plugins)
                self.assertNotIn('KUBECONFIG',options['env'])
                self.assertNotIn('--pass-credentials',command)
                self.assertNotIn('--insecure-skip-tls-verify',command)
                self.assertNotEqual(options['env']['HELM_REPOSITORY_CONFIG'],'/private/real-repositories')

    def test_rustup_checks_a_synthetic_update_manifest_without_installing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'rustup'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                env=options['env']; rustup_home=Path(env['RUSTUP_HOME'])
                calls.append((command,options,(rustup_home/'settings.toml').read_text(),
                              list(rustup_home.glob('toolchains/*'))))
                return 0, 'rustup - up to date : 1.0.0\n', ''
            with mock.patch.dict(os.environ,{'RUSTUP_HOME':'/private/real-rustup','CARGO_HOME':'/private/real-cargo',
                                           'PRIVATE_TOKEN':'must-not-be-sent','RUSTUP_USE_CURL':'1',
                                           'CURL_CA_BUNDLE':str(root/'ca.pem')}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('rustup',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='rustup' and r['samples'])
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertIn('通信応答を観測',row['samples'][0]['detail'])
            self.assertEqual(len(calls),5)
            self.assertEqual({c[1]['env']['RUSTUP_UPDATE_ROOT'] for c in calls},{x[1].rstrip('/') for x in audit.TARGETS})
            for command,options,settings,toolchains in calls:
                self.assertEqual(command,[str(binary),'check'])
                self.assertIn('check-only',settings)
                self.assertFalse(toolchains)
                self.assertFalse(options['inherit_env'])
                self.assertNotIn('PRIVATE_TOKEN',options['env'])
                self.assertEqual(options['env']['RUSTUP_USE_CURL'],'1')
                self.assertEqual(options['env']['CURL_CA_BUNDLE'],str(root/'ca.pem'))
                self.assertNotEqual(options['env']['RUSTUP_HOME'],'/private/real-rustup')
                self.assertNotEqual(options['env']['CARGO_HOME'],'/private/real-cargo')

    def test_git_lfs_lists_only_synthetic_remote_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); lfs=root/'git-lfs'; git=root/'git'
            for binary in (lfs,git): binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                work=Path(options['cwd']); env=options['env']
                calls.append((command,options,(work/'.git/config').read_text(),(work/'.git/HEAD').read_text()))
                return 0, '', ''
            secrets={'GIT_ASKPASS':'/private/auth-helper','SSH_ASKPASS':'/private/ssh-helper',
                     'GIT_CONFIG_GLOBAL':'/private/real-gitconfig','PRIVATE_TOKEN':'must-not-be-sent'}
            with mock.patch.dict(os.environ,secrets), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('git-lfs',lfs)]), \
                 mock.patch.object(package_checks.shutil,'which',return_value=str(git)), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='git-lfs']
            row=next(r for r in rows if r['samples'])
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            for command,options,config,head in calls:
                self.assertEqual(command[:3],[str(lfs),'locks','--limit=1'])
                self.assertTrue(any(target[1] in config for target in audit.TARGETS))
                self.assertIn('helper =',config)
                self.assertIn('followRedirects = false',config)
                self.assertTrue(head.startswith('ref: '))
                self.assertEqual(options['env']['GIT_TERMINAL_PROMPT'],'0')
                self.assertEqual(options['env']['GIT_CONFIG_NOSYSTEM'],'1')
                self.assertFalse(options['inherit_env'])
                self.assertNotIn('PRIVATE_TOKEN',options['env'])
                self.assertNotEqual(options['env'].get('GIT_ASKPASS'),secrets['GIT_ASKPASS'])
                self.assertNotEqual(options['env'].get('GIT_CONFIG_GLOBAL'),secrets['GIT_CONFIG_GLOBAL'])

    def test_git_lfs_without_a_safe_git_executable_remains_unconfirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); lfs=root/'git-lfs'; lfs.write_bytes(b'\x7fELF'+b'\0'*40); lfs.chmod(0o755)
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('git-lfs',lfs)]), \
                 mock.patch.object(package_checks.shutil,'which',return_value=None), \
                 mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='git-lfs')
            self.assertIn('Git',row['detail'])
            self.assertEqual(row['review_state'],'unverified')
            run.assert_not_called()

    def test_git_lfs_does_not_record_server_response_bodies(self):
        from types import SimpleNamespace
        instance=audit.Audit(SimpleNamespace(offline=False,timeout=1,workers=1,project=None))
        try:
            runner=mock.Mock(return_value=(0,'server-body-private-fixture',''))
            package_checks.git_lfs_locks(instance,'/fixture/git-lfs','/fixture/git',runner,audit.classify,audit.redact,
                                         [('control','https://example.invalid/',True)])
            self.assertNotIn('server-body-private-fixture',json.dumps(instance.records))
        finally: instance.tmp.cleanup()

    def test_poetry_uses_its_own_venv_http_implementation_with_isolated_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); venv=root/'poetry-venv'; bindir=venv/'bin'; bindir.mkdir(parents=True)
            (venv/'pyvenv.cfg').write_text('home = /synthetic\n')
            python=bindir/'python'; python.write_bytes(b'\x7fELF'+b'\0'*40); python.chmod(0o755)
            poetry=bindir/'poetry'; poetry.write_text('#!'+str(python)+'\nfrom poetry.console.application import main\n'); poetry.chmod(0o755)
            site=venv/'lib/python3.13/site-packages'; (site/'poetry/utils').mkdir(parents=True); (site/'requests').mkdir()
            (site/'poetry/utils/authenticator.py').write_text(''); (site/'requests/__init__.py').write_text('')
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                return 0, '{"state":"accepted","detail":"HTTP 200"}', ''
            with mock.patch.dict(os.environ,{'POETRY_HTTP_BASIC_PRIVATE_PASSWORD':'do-not-send',
                                           'REQUESTS_CA_BUNDLE':str(root/'ca.pem')}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('poetry',poetry)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            rows=[r for r in report['records'] if r['metadata'].get('tool_id')=='poetry']
            row=next(r for r in rows if r['samples'])
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            self.assertEqual({call[0][-2] for call in calls},{x[1] for x in audit.TARGETS})
            for command,options in calls:
                self.assertEqual(Path(command[0]).resolve(),python.resolve())
                self.assertEqual(command[1:4],['-I','-S','-B'])
                self.assertTrue(command[4].endswith('/probes/poetry_probe.py'))
                self.assertEqual(Path(command[5]).resolve(),site.resolve())
                self.assertFalse(options['inherit_env'])
                self.assertNotIn('POETRY_HTTP_BASIC_PRIVATE_PASSWORD',options['env'])
                self.assertEqual(options['env']['REQUESTS_CA_BUNDLE'],str(root/'ca.pem'))
                self.assertEqual(options['env']['POETRY_KEYRING_ENABLED'],'false')

    def test_poetry_success_output_does_not_hide_a_separate_tls_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); venv=root/'venv'; bindir=venv/'bin'; bindir.mkdir(parents=True)
            (venv/'pyvenv.cfg').write_text('home = /synthetic\n')
            python=bindir/'python'; python.write_bytes(b'\x7fELF'+b'\0'*40); python.chmod(0o755)
            poetry=bindir/'poetry'; poetry.write_text('#!'+str(python)+'\nfrom poetry.console.application import main\n')
            site=venv/'lib/python3.13/site-packages'; (site/'poetry/utils').mkdir(parents=True); (site/'requests').mkdir()
            (site/'poetry/utils/authenticator.py').write_text(''); (site/'requests/__init__.py').write_text('')
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('poetry',poetry)]), \
                 mock.patch.object(audit,'run',return_value=(0,'{"state":"accepted","detail":"HTTP 200"}','TLS handshake timeout')), \
                 contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='poetry' and r['samples'])
            self.assertTrue(all(s['status']=='UNKNOWN' and s['observation']!='connection' for s in row['samples']))

    def test_azure_python_entry_requires_its_own_module_and_skips_pth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); bindir=root/'bin'; bindir.mkdir(); (root/'pyvenv.cfg').write_text('fixture')
            python=bindir/'python'; python.write_bytes(b'\x7fELF'+b'\0'*40)
            az=bindir/'az'; az.write_text('from azure.cli import main\n')
            self.assertIsNone(package_checks.azure_python(az))
            site=root/'lib/python3.13/site-packages'; (site/'azure/cli').mkdir(parents=True)
            (site/'azure/cli/__main__.py').write_text('')
            calls=[]
            def runner(command,**options):
                calls.append((command,options)); return 0,'{}',''
            with mock.patch.object(audit.app_inventory,'scan',return_value=[installed('azure',az)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            self.assertTrue(calls)
            for command,options in calls:
                self.assertEqual(Path(command[0]).resolve(),python.resolve())
                self.assertEqual(command[1:4],['-I','-S','-B'])
                self.assertEqual(Path(command[5]).resolve(),site.resolve())
                self.assertIn('--skip-authorization-header',command)

    def test_azure_rest_uses_no_auth_and_only_temporary_cli_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); az=root/'az'; az.write_bytes(b'\x7fELF'+b'\0'*40); az.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                return 0, '{"fixture":"ok"}', ''
            secrets={'AZURE_CONFIG_DIR':'/private/real-azure','AZURE_CLIENT_SECRET':'do-not-send',
                     'AZURE_ACCESS_TOKEN':'do-not-send','AZURE_SUBSCRIPTION_ID':'do-not-send'}
            with mock.patch.dict(os.environ,secrets), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('azure',az)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='azure' and r['samples'])
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            self.assertEqual({c[0][c[0].index('--url')+1] for c in calls},{x[1] for x in audit.TARGETS})
            for command,options in calls:
                self.assertEqual(command[:3],[str(az),'rest','--method'])
                self.assertIn('--skip-authorization-header',command)
                self.assertFalse(options['inherit_env'])
                self.assertEqual(options['env']['AZURE_CORE_COLLECT_TELEMETRY'],'no')
                self.assertEqual(options['env']['AZURE_EXTENSION_USE_DYNAMIC_INSTALL'],'no')
                self.assertNotEqual(options['env']['AZURE_CONFIG_DIR'],secrets['AZURE_CONFIG_DIR'])
                self.assertTrue(all(key not in options['env'] for key in secrets if key != 'AZURE_CONFIG_DIR'))

    def test_azure_rest_verification_disable_is_action_only_for_an_installed_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); az=root/'az'; az.write_bytes(b'\x7fELF'+b'\0'*40); az.chmod(0o755)
            for is_installed in (False,True):
                rows=[installed('azure',az)] if is_installed else []
                with mock.patch.dict(os.environ,{'AZURE_CLI_DISABLE_CONNECTION_VERIFICATION':'false'}), \
                     mock.patch.object(audit.app_inventory,'scan',return_value=rows), \
                     mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--offline','--out',str(root/str(is_installed))])
                report=json.loads((root/str(is_installed)/'report.json').read_text())
                action=[r for r in report['records'] if r['metadata'].get('tool_id')=='azure' and r['review_state']=='action']
                self.assertEqual(bool(action),is_installed)
                if action: self.assertIn('az rest',action[0]['scope'])
                run.assert_not_called()

    def test_micromamba_queries_a_single_channel_without_rc_or_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'micromamba'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
            calls=[]
            def runner(command, **options):
                calls.append((command,options))
                return 0, '{"result":{"status":"OK","pkgs":[]}}', ''
            with mock.patch.dict(os.environ,{'MAMBA_ROOT_PREFIX':'/private/real-root',
                                           'CONDA_PREFIX':'/private/real-conda','PRIVATE_TOKEN':'do-not-send'}), \
                 mock.patch.object(audit.app_inventory,'scan',return_value=[installed('mamba',binary)]), \
                 mock.patch.object(audit,'run',side_effect=runner),contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','packages','--out',str(root/'out')])
            report=json.loads((root/'out/report.json').read_text())
            row=next(r for r in report['records'] if r['metadata'].get('tool_id')=='mamba' and r['samples'])
            self.assertEqual([s['status'] for s in row['samples']],['UNKNOWN']*5)
            self.assertEqual(len(calls),5)
            self.assertEqual({c[0][c[0].index('--channel')+1] for c in calls},{x[1] for x in audit.TARGETS})
            for command,options in calls:
                self.assertEqual(command[0],str(binary))
                self.assertIn('--no-rc',command)
                self.assertIn('--no-env',command)
                self.assertIn('--override-channels',command)
                self.assertIn('repoquery',command)
                self.assertNotIn('install',command)
                self.assertFalse(options['inherit_env'])
                self.assertNotIn('PRIVATE_TOKEN',options['env'])
                self.assertNotIn('CONDA_PREFIX',options['env'])
                self.assertNotEqual(command[command.index('--root-prefix')+1],'/private/real-root')

    def test_mamba_respects_explicit_offline_or_disabled_verification(self):
        for setting in ({'CONDA_OFFLINE':'true'},{'MAMBA_OFFLINE':'1'},
                        {'CONDA_SSL_VERIFY':'false'},{'MAMBA_SSL_VERIFY':'false'}):
            with self.subTest(setting=next(iter(setting))), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); binary=root/'micromamba'; binary.write_bytes(b'\x7fELF'+b'\0'*40); binary.chmod(0o755)
                with mock.patch.dict(os.environ,setting), \
                     mock.patch.object(audit.app_inventory,'scan',return_value=[installed('mamba',binary)]), \
                     mock.patch.object(audit,'run') as run,contextlib.redirect_stdout(io.StringIO()):
                    audit.main(['--only','packages','--out',str(root/'out')])
                report=json.loads((root/'out/report.json').read_text())
                self.assertTrue(any(r['metadata'].get('tool_id')=='mamba' and r['review_state']=='unverified' for r in report['records']))
                run.assert_not_called()
