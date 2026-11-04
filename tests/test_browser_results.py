"""Recorded native-browser evidence must be fresh, scoped and fail closed."""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit


@unittest.skipUnless(sys.platform=='darwin','Native browser JSON import is macOS-only in this release')
class BrowserResultsTests(unittest.TestCase):
    def document(self, browser='Safari'):
        return dict(schema_version=1, browser=browser, version='26.6.2', profile='通常プロファイル',
                    observed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                    source='native-ui', security_bypassed=False,
                    samples=[dict(url=url, result='loaded' if control else 'SAFARI_CERT_BLOCKED',
                                  observation='Example Domain' if control else '証明書はブロックされています')
                             for _,url,control in audit.TARGETS])

    def report(self, document):
        def execute(instance):
            instance.add('ブラウザ / 実際のプロファイル','INFO','fixture')
            instance.records[-1]['evidence']=[dict(check='Safari',kind='inventory',status='INFO',detail='installed',version='26.6.2')]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(audit.Audit,'execute',execute), contextlib.redirect_stdout(io.StringIO()):
            path=Path(tmp)/'browser.json'; path.write_text(json.dumps(document))
            code=audit.main(['--host-only','--only','browser','--browser-results',str(path),'--out',tmp])
            report=json.loads((Path(tmp)/'report.json').read_text(encoding='utf-8'))
            return code,report

    def test_native_browser_rejection_replaces_manual_and_retains_samples(self):
        code,report=self.report(self.document())
        self.assertEqual(code,0)
        measured=next(r for r in report['records'] if r['assessment_method']=='measured')
        self.assertEqual(measured['status'],'REJECTED')
        self.assertEqual(len(measured['samples']),5)
        self.assertIn('通常プロファイル',measured['scope'])
        self.assertFalse(any(r['status']=='MANUAL' for r in report['records']))

    def test_acceptance_without_chain_evidence_does_not_prove_target_acceptance(self):
        doc=self.document(); doc['samples'][1]['result']='loaded'
        code,report=self.report(doc)
        self.assertEqual(code,2)
        self.assertFalse(any(r['status']=='ACTION' for r in report['records']))

    def test_acceptance_with_matching_certificate_evidence_is_action(self):
        doc=self.document(); doc['samples'][1]['result']='loaded'
        refs=json.loads((audit.ROOT/'references/assessment.json').read_text())
        doc['samples'][1]['certificate_chain_sha256']=[refs['certificates'][0]['sha256']]
        code,report=self.report(doc)
        self.assertEqual(code,1)
        self.assertTrue(any(r['status']=='ACTION' for r in report['records']))

    def test_generic_warning_ct_and_expiry_are_not_trust_rejection(self):
        for result in ('privacy_warning','NET::ERR_CERT_DATE_INVALID','NET::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED'):
            with self.subTest(result=result):
                doc=self.document(); doc['samples'][1]['result']=result
                code,report=self.report(doc)
                self.assertEqual(code,2)
                self.assertFalse(any(r['status']=='REJECTED' for r in report['records']))

    def test_invalid_or_stale_observations_do_not_clear_manual(self):
        cases=[]
        for key,value in [('observed_at','2020-01-01T00:00:00+00:00'),('security_bypassed',True),
                          ('version','1.0'),('source','fetch'),('observed_at','2099-01-01T00:00:00+00:00')]:
            doc=self.document(); doc[key]=value; cases.append(doc)
        doc=self.document(); doc['samples'].pop(); cases.append(doc)
        doc=self.document(); doc['samples'][1]['url']='https://other.example/'; cases.append(doc)
        doc=self.document(); doc['samples'][1]=doc['samples'][2]; cases.append(doc)
        for doc in cases:
            with self.subTest(doc=doc):
                code,report=self.report(doc)
                self.assertEqual(code,2)
                self.assertTrue(any(r['status']=='MANUAL' for r in report['records']))
                self.assertFalse(any(r['status']=='REJECTED' for r in report['records']))

if __name__=='__main__': unittest.main(verbosity=2)
