"""Package results must be supported by the selected client's own connection."""
import contextlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock
from urllib.parse import urlsplit

import audit
import connection_evidence
import package_checks


class PackageConnectionEvidence(TestCase):
    def setUp(self):
        self.instance = audit.Audit(SimpleNamespace(project=None, offline=False, workers=1, timeout=2))
        self.addCleanup(self.instance.tmp.cleanup)

    def test_legacy_bundler_can_read_the_synthetic_gemfile_without_a_gemfile_switch(self):
        def legacy_cli(command, **options):
            if '--gemfile' in command:
                return 1, '', "Unknown switches '--gemfile'"
            source = Path(options['env']['BUNDLE_GEMFILE']).read_text()
            url = json.loads(source.splitlines()[0].removeprefix('source '))
            return 0, 'GEM\n  remote: '+url+'\n  specs:\n    emudhra-audit-fixture (0.0.0)\n', ''

        with contextlib.redirect_stdout(io.StringIO()):
            package_checks.bundler_source(self.instance, '/fixture/bundle', '/fixture/ruby',
                legacy_cli, audit.classify, audit.redact, [('control', 'https://fixture.invalid/', True)])
        sample = self.instance.records[0]['samples'][0]
        self.assertEqual(sample['observation'], 'connection')
        self.assertNotIn('Unknown switches', sample['detail'])

    def cargo(self, logs, code=101):
        def runner(command, **options):
            url = command[command.index('--index')+1].removeprefix('sparse+')
            return code, '', logs(url)
        with contextlib.redirect_stdout(io.StringIO()):
            package_checks.cargo_registry(self.instance, '/fixture/cargo', runner,
                audit.classify, audit.redact, [('control', 'https://control.invalid/', True)] +
                [('test', 'https://target.invalid/', False)]*4)
        return self.instance.records[0]

    @staticmethod
    def trace(url, *, status=404, error='', extra=''):
        parsed = urlsplit(url)
        messages = ['* Connected to '+parsed.hostname+' (127.0.0.1) port 443']
        if error:
            messages += ['* SSL certificate problem: '+error]
        else:
            messages += ['* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384',
                         '* SSL certificate verify ok.',
                         '> GET /config.json HTTP/1.1', '> Host: '+parsed.hostname,
                         '< HTTP/1.1 '+str(status)+' Fixture',
                         '< Set-Cookie: synthetic-secret-must-not-be-saved']
        return ('  0.01s DEBUG network::fetch: url="'+url+'config.json"\n' +
                ''.join('  0.02s DEBUG network: http-debug: '+s+'\n' for s in messages) + extra)

    def test_cargo_404_is_a_control_response_and_direct_trust_failure_is_rejected(self):
        row = self.cargo(lambda url: self.trace(url, error='' if 'control' in url else
                                             'unable to get local issuer certificate') +
                         'error: failed to update registry\nCaused by:\n  config.json not found\n')
        self.assertEqual([s['status'] for s in row['samples']], ['CONTROL_OK']+['REJECTED']*4)
        self.assertEqual(row['status'], 'REJECTED')
        self.assertNotIn('synthetic-secret', json.dumps(row))
        self.assertEqual(row['samples'][0]['connection_evidence']['http_status'], 404)

    def test_cargo_invalid_registry_json_still_records_the_actual_https_response(self):
        row = self.cargo(lambda url: self.trace(url, status=200) +
                         'error: expected value at line 1 column 1\n')
        self.assertEqual(row['samples'][0]['status'], 'CONTROL_OK')
        self.assertEqual(row['samples'][1]['observation'], 'connection')
        # A successful HTTP exchange alone does not prove the eMudhra chain.
        self.assertEqual(row['samples'][1]['status'], 'UNKNOWN')

    def test_cargo_does_not_attribute_a_redirect_destination_rejection_to_the_origin(self):
        row = self.cargo(lambda url: self.trace(url, status=302, extra=(
            '  0.03s DEBUG network: http-debug: < Location: https://other.invalid/\n' +
            self.trace('https://other.invalid/', error='unable to get local issuer certificate'))))
        self.assertEqual(row['samples'][0]['status'], 'CONTROL_OK')
        self.assertEqual(row['samples'][1]['status'], 'UNKNOWN')
        self.assertEqual(row['samples'][1]['connection_evidence']['http_status'], 302)

    def test_cargo_expiry_hostname_proxy_and_timeout_are_not_trust_rejections(self):
        for error in ('certificate has expired', 'certificate subject name does not match target hostname',
                      'proxy CONNECT aborted', 'SSL connection timeout'):
            with self.subTest(error=error):
                self.instance.records.clear()
                row = self.cargo(lambda url: self.trace(url, error=error))
                self.assertEqual([s['status'] for s in row['samples']], ['UNKNOWN']*5)
        self.instance.records.clear()
        row = self.cargo(lambda url: self.trace(url, error='unable to get local issuer certificate'), code=124)
        self.assertEqual([s['status'] for s in row['samples']], ['UNKNOWN']*5)

    def test_cargo_proxy_connect_response_is_not_a_control_response(self):
        def proxy_log(url):
            return ('  0.01s DEBUG network::fetch: url="'+url+'config.json"\n'
                    '  0.02s DEBUG network: http-debug: * Connected to proxy.invalid (127.0.0.1) port 443\n'
                    '  0.02s DEBUG network: http-debug: > CONNECT target.invalid:443 HTTP/1.1\n'
                    '  0.02s DEBUG network: http-debug: < HTTP/1.1 200 Connection established\n'
                    '  0.02s DEBUG network: http-debug: * SSL certificate problem: unable to get local issuer certificate\n')
        row = self.cargo(proxy_log)
        self.assertEqual([s['status'] for s in row['samples']], ['UNKNOWN']*5)

    def test_cargo_never_records_raw_debug_headers_on_timeout_or_excess_output(self):
        for code, padding in ((124, ''), (101, 'x'*(connection_evidence.MAX_TRACE+1))):
            with self.subTest(code=code):
                self.instance.records.clear()
                row = self.cargo(lambda url: padding+self.trace(url), code=code)
                self.assertEqual(row['samples'][0]['status'], 'UNKNOWN')
                self.assertNotIn('synthetic-secret', json.dumps(row))

    def test_cargo_a_trust_message_combined_with_a_transport_error_is_unknown(self):
        row = self.cargo(lambda url: self.trace(url, error='unable to get local issuer certificate; TLS handshake timeout'))
        self.assertEqual([s['status'] for s in row['samples']], ['UNKNOWN']*5)

    def test_cargo_configured_https_proxy_failure_is_not_origin_rejection(self):
        # HTTPS proxy TLS can fail before a CONNECT header is emitted, even
        # when proxy and requested origin happen to use the same host/port.
        for error in ('unable to get local issuer certificate', ''):
            with self.subTest(error=error), mock.patch.dict(os.environ,
                    {'CARGO_HTTP_PROXY': 'https://target.invalid:443'}):
                self.instance.records.clear()
                row = self.cargo(lambda url: self.trace(url, error=error))
                self.assertEqual([s['status'] for s in row['samples']], ['UNKNOWN']*5)
                self.assertFalse(row['samples'][1]['connection_evidence']['origin_verified'])

    def ruby(self, records, *, code=1, tool='bundler'):
        def runner(command, **options):
            env = options['env']
            target = env.get('EMUDHRA_TLS_TARGET', '')
            path = env.get('EMUDHRA_TLS_EVIDENCE')
            if path:
                Path(path).write_text('\n'.join(json.dumps(item) for item in records(target))+'\n')
            return code, '', 'synthetic package-format error'
        with contextlib.redirect_stdout(io.StringIO()):
            getattr(package_checks, tool+'_source')(self.instance, '/fixture/'+tool, '/fixture/ruby',
                runner, audit.classify, audit.redact, [('control', 'https://control.invalid/', True)] +
                [('test', 'https://target.invalid/', False)]*4)
        return self.instance.records[0]

    @staticmethod
    def socket_event(url, *, accepted=True, verify_code=0, port=443, name_ok=True, pin='a'*64):
        return dict(schema=1, source='ruby_ssl_socket', host=urlsplit(url).hostname, port=port,
                    state='accepted' if accepted else 'error', verify_code=verify_code,
                    verify_peer=True, hostname_verified=name_ok, chain_spki_sha256=[pin])

    def test_ruby_tools_use_their_own_socket_evidence_even_when_package_parsing_fails(self):
        for tool in ('bundler', 'rubygems'):
            self.instance.records.clear()
            with self.subTest(tool=tool):
                row = self.ruby(lambda url: [self.socket_event(url, accepted='control' in url,
                    verify_code=0 if 'control' in url else 20)], tool=tool)
                self.assertEqual([s['status'] for s in row['samples']], ['CONTROL_OK']+['REJECTED']*4)
                self.assertEqual(row['status'], 'REJECTED')
                self.assertEqual(row['samples'][1]['connection_evidence']['verify_code'], 20)

    def test_a_matched_peer_chain_is_actionable_and_an_unmatched_chain_remains_unknown(self):
        with mock.patch.object(connection_evidence, 'TLS_PINS', frozenset(['a'*64]), create=True):
            row = self.ruby(lambda url: [self.socket_event(url)])
        self.assertEqual([s['status'] for s in row['samples']], ['CONTROL_OK']+['ACTION']*4)
        self.assertEqual(row['status'], 'ACTION')
        self.assertTrue(row['samples'][1]['connection_evidence']['target_chain_verified'])
        self.instance.records.clear()
        with mock.patch.object(connection_evidence, 'TLS_PINS', frozenset(['b'*64]), create=True):
            row = self.ruby(lambda url: [self.socket_event(url)])
        self.assertEqual(row['samples'][1]['status'], 'UNKNOWN')

    def test_ruby_port_mismatch_name_failure_expiry_disabled_verification_and_incomplete_records(self):
        events = [self.socket_event('https://other.invalid/', accepted=False, verify_code=20),
                  self.socket_event('https://target.invalid/', accepted=False, verify_code=20, port=8443),
                  self.socket_event('https://target.invalid/', name_ok=False),
                  self.socket_event('https://target.invalid/', accepted=False, verify_code=10),
                  dict(self.socket_event('https://target.invalid/'), verify_peer=False),
                  {'schema': 1, 'state': 'accepted'}]
        for event in events:
            with self.subTest(event=event):
                self.instance.records.clear()
                row = self.ruby(lambda url: [event])
                self.assertEqual(row['samples'][1]['status'], 'UNKNOWN')

    def test_ruby_does_not_use_a_redirect_destinations_socket(self):
        row = self.ruby(lambda url: [self.socket_event(url),
                        self.socket_event('https://other.invalid/', accepted=False, verify_code=20)])
        self.assertEqual(row['samples'][0]['status'], 'CONTROL_OK')
        self.assertEqual(row['samples'][1]['status'], 'UNKNOWN')
        self.assertTrue(row['samples'][1]['connection_evidence']['tls_verified'])

    def test_ruby_proxy_certificate_failure_and_interrupted_observation_are_unknown(self):
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'https://proxy.invalid:443'}):
            row = self.ruby(lambda url: [self.socket_event(url, accepted=False, verify_code=20)])
        self.assertEqual(row['samples'][1]['status'], 'UNKNOWN')
        self.instance.records.clear()
        row = self.ruby(lambda url: [self.socket_event(url, accepted=False, verify_code=20)], code=124)
        self.assertEqual(row['samples'][1]['status'], 'UNKNOWN')

    def test_connection_evidence_and_action_survive_report_preparation(self):
        with mock.patch.object(connection_evidence, 'TLS_PINS', frozenset(['a'*64])):
            self.ruby(lambda url: [self.socket_event(url)])
        output = self.instance.work/'report'
        with contextlib.redirect_stdout(io.StringIO()):
            audit.write_reports(self.instance, output)
        report = json.loads((output/'report.json').read_text())
        measured = next(row for row in report['records'] if row['samples'])
        self.assertEqual(measured['status'], 'ACTION')
        self.assertEqual(report['summary']['tool_review_counts']['action'], 1)
        self.assertTrue(measured['samples'][1]['connection_evidence']['target_chain_verified'])
        self.assertIn('a'*64, (output/'report.html').read_text())
        self.assertTrue(any(row['status']=='MANUAL' and not row['samples'] for row in report['records']))
