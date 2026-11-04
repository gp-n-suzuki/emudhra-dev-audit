"""User-visible verdicts distinguish measured, inferred and still-unresolved work."""
import contextlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit
import evidence


def row(name,status='MANUAL',items=None,samples=None,metadata=None):
    return dict(name=name,status=status,detail='fixture observation',action='',metadata=metadata or {},
                samples=samples or [],evidence=items or [])


def item(check,kind,status,**fields):
    return dict(check=check,kind=kind,status=status,detail=check+' observed',**fields)


class Cards(HTMLParser):
    def __init__(self):
        super().__init__(); self.cards=[]
    def handle_starttag(self,tag,attrs):
        if tag=='section' and 'data-review' in dict(attrs): self.cards.append(dict(attrs))


class VerdictTests(unittest.TestCase):
    def test_detected_jre_without_compiler_requires_followup_and_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            def execute(instance):
                instance.host.call=mock.Mock(return_value=(0,'java version "1.8.0"',''))
                instance.paths=lambda *args,**kwargs:[str(base/'jre/bin/java')]
                instance.java(instance.host)
            with mock.patch.object(audit.Audit,'execute',execute), contextlib.redirect_stdout(io.StringIO()):
                code=audit.main(['--only','java','--project',tmp,'--out',str(base/'report')])
            report=json.loads((base/'report/report.json').read_text(encoding='utf-8'))
            self.assertEqual(code,2)
            self.assertTrue(any(r['status']=='SKIP' and r['review_state']=='unverified' for r in report['records']))

    def test_detected_client_withheld_for_identity_requires_followup(self):
        def execute(instance):
            instance.sample('pip TLS',lambda url:{'state':'skipped','detail':'client-cert configured'})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(audit.Audit,'execute',execute), contextlib.redirect_stdout(io.StringIO()):
            code=audit.main(['--only','python','--project',tmp,'--out',tmp])
            report=json.loads((Path(tmp)/'report.json').read_text(encoding='utf-8'))
        self.assertEqual(code,2)
        self.assertEqual(report['records'][0]['review_state'],'unverified')

    def report(self,rows):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            instance=SimpleNamespace(records=rows)
            audit.write_reports(instance,Path(tmp))
            return (json.loads((Path(tmp)/'report.json').read_text(encoding='utf-8')),
                    (Path(tmp)/'report.html').read_text(encoding='utf-8'),(Path(tmp)/'summary.txt').read_text(encoding='utf-8'))

    def test_rust_update_and_absent_project_replace_blanket_manual(self):
        report,_,_=self.report([row('Rust',items=[item('rustup','version','UPDATE',version='1.29.0'),
                               item('Cargo.lock探索','inventory','INFO',files=[],count=0)])])
        records=report['records']
        self.assertFalse(any(r['status']=='MANUAL' for r in records))
        update=next(r for r in records if r['status']=='UPDATE')
        self.assertEqual(update['assessment_method'],'version')
        self.assertEqual(update['review_state'],'action')
        self.assertTrue(any(r['status']=='NOT_FOUND' for r in records))

    def test_docker_version_and_bad_setting_are_independent_verdicts(self):
        report,_,_=self.report([row('Docker Engine / Desktop / BuildKit / registry',items=[
            item('Docker Desktop','version','REFERENCE_OK',version='4.96.3'),
            item('registryのTLS設定','configuration','ACTION',count=1)])])
        self.assertEqual({r['status'] for r in report['records']},{'MANUAL','ACTION'})
        for r in report['records']:
            self.assertIn(r['assessment_method'],('version','configuration'))
            self.assertTrue(r['scope'])

    def test_php_stream_stays_unresolved_while_ca_file_is_checked(self):
        samples=[dict(target='test',status='UNKNOWN',detail='certificate verify failed')]
        report,_,_=self.report([row('ホスト / PHP OpenSSL streams','UNKNOWN',
            [item('CAファイル照合','static','UNKNOWN',matched=0)],samples)])
        measured=next(r for r in report['records'] if r['assessment_method']=='measured')
        self.assertEqual(measured['status'],'UNKNOWN')
        self.assertEqual(measured['samples'],samples)
        self.assertFalse(any(r['review_state']=='complete' for r in report['records']))
        self.assertFalse(any(r['status']=='REJECTED' for r in report['records']))

    def test_browsers_split_checked_data_from_missing_evidence(self):
        report,_,_=self.report([row('ブラウザ / 実際のプロファイル',items=[
            item('Google Chrome','inventory','INFO'), item('Microsoft Edge','inventory','INFO'),
            item('Safari','inventory','INFO'),
            item('Chrome / 保存済みCRLSet','static','REFERENCE_OK',matched=6,total=6),
            item('Edge / 保存済みCRLSet','static','UNKNOWN',matched=0,total=6)])])
        records=report['records']
        self.assertFalse(any(r['status']=='MANUAL' and 'Chrome' in r['name'] for r in records))
        self.assertTrue(any(r['status']=='STATIC_OK' and 'Chrome' in r['name'] for r in records))
        edge=next(r for r in records if r['status']=='UNKNOWN' and 'Edge' in r['name'])
        self.assertTrue(edge['action'])
        self.assertTrue(any(r['status']=='MANUAL' and 'Safari' in r['name'] for r in records))

    def test_measured_browser_acceptance_replaces_static_uncertainty_with_action(self):
        report,_,_=self.report([row('ブラウザ / 実際のプロファイル',items=[
            item('Microsoft Edge','inventory','INFO'),
            item('Edge / 保存済みCRLSet','static','UNKNOWN',matched=0,total=6)]),
            row('ブラウザ / Edge / 実際のプロファイル','ACTION',
                samples=[dict(target='test',status='ACTION',detail='page loaded')],
                metadata=dict(source_type='native-ui',browser='Edge'))])
        self.assertEqual(report['summary']['review_counts']['action'],1)
        self.assertEqual(report['summary']['review_counts']['review'],0)
        saved=next(r for r in report['records'] if 'CRLSet' in r['name'])
        self.assertEqual(saved['status'],'INFO')
        self.assertEqual(saved['metadata']['matched'],0)

    def test_dotnet_absence_is_scoped_but_detected_project_requires_followup(self):
        for markers,expected in (([],'NOT_FOUND'),(['/project/app.csproj'],'SKIP')):
            with self.subTest(markers=markers):
                report,_,_=self.report([row('.NET HttpClient','SKIP',[
                    item('.NET配置探索','inventory','INFO',executables=[],project_markers=markers)])])
                target=next(r for r in report['records'] if r['status']==expected)
                self.assertEqual(target['review_state'],'scope' if not markers else 'unverified')

    def test_runtime_found_without_a_probe_cannot_be_marked_absent(self):
        report,_,_=self.report([row('.NET HttpClient','SKIP',[
            item('.NET配置探索','inventory','INFO',executables=['/sdk/dotnet'],project_markers=[])])])
        self.assertFalse(any(r['status']=='NOT_FOUND' for r in report['records']))
        self.assertTrue(any(r['review_state']=='unverified' for r in report['records']))

    def test_finished_scope_scan_is_not_a_manual_task(self):
        for truncated,status in ((False,'INFO'),(True,'UNKNOWN')):
            with self.subTest(truncated=truncated):
                report,_,_=self.report([row('対象範囲の確認',items=[
                    item('指定プロジェクト探索','inventory','INFO',files=[],truncated=truncated)])])
                self.assertEqual(report['records'][0]['status'],status)

    def test_unexamined_virtual_environment_is_an_explicit_task(self):
        report,_,_=self.report([row('対象範囲の確認',items=[
            item('指定プロジェクト探索','inventory','INFO',files=['/project/app/.venv/pyvenv.cfg'],truncated=False)])])
        task=next(r for r in report['records'] if r['review_state']=='unverified')
        self.assertIn(str(Path('/project/app/.venv')),task['action'])

    def test_static_proof_does_not_override_measured_acceptance(self):
        samples=[dict(target='test',status='ACTION',detail='HTTP 200')]
        report,_,_=self.report([row('ホスト / PHP OpenSSL streams','ACTION',[
            item('CAファイル照合','static','UNKNOWN',matched=0)],samples)])
        self.assertEqual(report['records'][0]['status'],'ACTION')
        self.assertEqual(report['records'][0]['assessment_method'],'measured')

    def test_schema_counts_filters_and_text_use_same_verdicts(self):
        report,html,text=self.report([row('Rust',items=[item('rustup','version','UPDATE'),
            item('Cargo.lock探索','inventory','INFO',files=[],count=0)])])
        self.assertEqual(report['schema_version'],3)
        self.assertEqual(report['summary']['review_counts']['action'],1)
        self.assertEqual(report['summary']['review_counts']['review'],0)
        self.assertEqual(report['summary']['tool_review_counts']['action'],1)
        parser=Cards(); parser.feed(html)
        self.assertEqual([c['data-review'] for c in parser.cards],['action','scope'])
        self.assertIn('対応が必要',html)
        self.assertIn('推定（バージョン）',text)
        self.assertNotIn('補助根拠:',html)

    def test_report_normalization_is_idempotent(self):
        rows=[row('Rust',items=[item('rustup','version','REFERENCE_OK')])]
        first,_,_=self.report(rows)
        second,_,_=self.report(first['records'])
        self.assertEqual(first['records'],second['records'])

    def test_unmatched_lock_is_not_reported_twice(self):
        path='/project/Cargo.lock'
        report,_,_=self.report([row('Rust',items=[item('Cargo.lock探索','inventory','INFO',files=[path],count=1)]),
            row('対象範囲の確認',items=[item('指定プロジェクト探索','inventory','INFO',files=[path],truncated=False)])])
        tasks=[r for r in report['records'] if r['review_state']=='unverified']
        self.assertEqual(len(tasks),1)

    def test_offline_docker_query_is_uninspected(self):
        audit_fixture=SimpleNamespace(args=SimpleNamespace(offline=True))
        observations=evidence.docker_evidence(audit_fixture,[])
        self.assertEqual(observations[0]['status'],'SKIP')

    def test_failed_registry_settings_query_requires_followup(self):
        host=mock.Mock()
        host.find.return_value='docker'
        host.call.side_effect=[(0,'{"Version":"29.9.2"}',''),(1,'','unavailable')]
        audit_fixture=SimpleNamespace(args=SimpleNamespace(offline=False),host=host)
        observations=evidence.docker_evidence(audit_fixture,[])
        self.assertTrue(any(i['check']=='registryのTLS設定' and i['status']=='UNKNOWN' for i in observations))

    def test_successful_versions_without_communication_still_require_followup(self):
        def execute(instance):
            instance.records=[row('Rust',items=[item('rustup','version','REFERENCE_OK'),
                             item('Cargo.lock探索','inventory','INFO',files=[],count=0)])]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(audit.Audit,'execute',execute), contextlib.redirect_stdout(io.StringIO()):
            code=audit.main(['--host-only','--offline','--only','tools','--out',tmp])
        self.assertEqual(code,2)


if __name__=='__main__': unittest.main(verbosity=2)
