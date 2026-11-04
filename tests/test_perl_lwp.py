"""Perl HTTP::Tiny and installed LWP are separate clients."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest import mock

import audit


class PerlClients(unittest.TestCase):
    @unittest.skipUnless(shutil.which('perl'), 'Perl unavailable')
    def test_lwp_internal_500_is_not_an_https_response(self):
        perl = shutil.which('perl')
        with tempfile.TemporaryDirectory() as tmp:
            rc,out,err = audit.run([perl,str(audit.PROBES/'perl_probe.pl'),'lwp','https://127.0.0.1:1/','2'],
                                    env={'PERL_LWP_SSL_CA_FILE':str(Path(tmp)/'missing.pem'),
                                         'HTTPS_PROXY':'','https_proxy':'','HTTP_PROXY':'','http_proxy':''})
            result = audit.parse_probe(out,err,rc)
            self.assertNotEqual(result['state'], 'accepted')
            self.assertNotEqual(audit.classify(result, True)[0], 'CONTROL_OK')

    def test_available_lwp_gets_its_own_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp)/'perl'; executable.write_text('fixture'); executable.chmod(0o755)
            calls = []
            def runner(command, **kwargs):
                calls.append(list(map(str, command)))
                if 'meta' in command:
                    return 0, 'EMUDHRA_JSON:'+json.dumps({'state':'meta','data':{'version':'5.40.0','mozilla_ca':'','lwp':'6.44'}}), ''
                return 0, 'EMUDHRA_JSON:'+json.dumps({'state':'error','detail':'certificate is revoked'}), ''
            with mock.patch.object(audit.Context, 'find', return_value=None), mock.patch.object(audit, 'run', side_effect=runner), \
                 mock.patch.object(audit.Audit, 'config_inventory'), contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only','perl','--perl',str(executable),'--out',str(Path(tmp)/'report')])
            report = json.loads((Path(tmp)/'report/report.json').read_text())
            self.assertTrue(any('HTTP::Tiny' in r['name'] and r['samples'] for r in report['records']))
            self.assertTrue(any('LWP' in r['name'] and r['samples'] for r in report['records']))
            self.assertTrue(any('lwp' in cmd for cmd in calls))
