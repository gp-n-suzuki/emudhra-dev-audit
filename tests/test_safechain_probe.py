"""Public report behavior for the isolated Safe Chain diagnostic."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import TestCase, mock

import audit
import safechain_probe
import verdicts


def installed(path):
    return verdicts.finish(dict(name='Safe Chain / 導入実体', status='MANUAL', detail='通信は未検査',
        metadata={'application': True, 'tool_id': 'safe-chain', 'tool_name': 'Safe Chain',
                  'path': str(path), 'discovered_paths': [str(path)], 'inspections': [],
                  'uninspected': ['実通信は未検査'],
                  'security_tool': {'version': '1.5.26'}}, samples=[]), 'inventory')


class SafeChainReportTests(TestCase):
    def test_offline_mode_does_not_launch_a_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'safe-chain'
            candidate.write_bytes(b'\xcf\xfa\xed\xfe synthetic executable')
            candidate.chmod(0o755)
            with mock.patch.object(audit.app_inventory, 'scan', return_value=[installed(candidate)]), \
                 mock.patch('subprocess.Popen', side_effect=AssertionError('offline must not start a probe')), \
                 contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only', 'packages', '--offline', '--out', str(root / 'out')])
            report = json.loads((root / 'out/report.json').read_text())
            row = next(r for r in report['records'] if r['name'] == 'Safe Chain / 証明書の接続テスト')
            self.assertIn('オフライン', row['detail'])
            self.assertEqual(row['review_state'], 'unverified')
            self.assertFalse(row['samples'])

    def test_unknown_binary_is_not_started_and_is_reported_as_unmeasured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'safe-chain'
            candidate.write_bytes(b'\xcf\xfa\xed\xfe synthetic unknown executable')
            candidate.chmod(0o755)
            with mock.patch.object(audit.app_inventory, 'scan', return_value=[installed(candidate)]), \
                 mock.patch('subprocess.Popen', side_effect=AssertionError('must not start an executable')), \
                 contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only', 'packages', '--out', str(root / 'out')])
            report = json.loads((root / 'out/report.json').read_text())
            row = next(r for r in report['records'] if r['name'] == 'Safe Chain / 証明書の接続テスト')
            self.assertEqual(row['review_state'], 'unverified')
            self.assertFalse(row['samples'])
            self.assertIn('未確認', row['detail'])

    def test_failed_sandbox_preflight_never_starts_the_candidate_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'bin' / 'safe-chain'
            candidate.parent.mkdir()
            candidate.write_bytes(b'\xcf\xfa\xed\xfe known synthetic binary')
            candidate.chmod(0o700)
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            commands = []
            mode = ['rejected']
            ports = iter(range(41000, 41020))

            class FixtureSocket:
                def __init__(self, *args): self.address = None
                def setsockopt(self, *args): pass
                def bind(self, address): self.address = (address[0], address[1] or next(ports))
                def listen(self, backlog): pass
                def getsockname(self): return self.address
                def close(self): pass

            def denied_sandbox(command, **kwargs):
                commands.append(list(command))
                if Path(command[0]).name == 'sandbox-exec':
                    if mode[0] == 'rejected':
                        return 71, '', 'sandbox_apply: Operation not permitted'
                    return 0, json.dumps(dict(safechain_probe.ISOLATED, other_port='allowed')), ''
                return 0, json.dumps({'file_read': 'allowed', 'alias_read': 'allowed',
                    'hardlink': 'allowed', 'outside_write': 'allowed', 'alias_write': 'allowed',
                    'scratch_write': 'allowed', 'unix_socket': 'allowed', 'allowed_port': 'allowed',
                    'other_port': 'allowed', 'other_loopback': 'allowed', 'mach_lookup': 0}), ''

            with mock.patch.dict(safechain_probe.SUPPORTED_HASHES, {digest: '1.5.26'}, clear=True), \
                 mock.patch.object(safechain_probe, 'platform_supported', return_value=True), \
                 mock.patch.object(safechain_probe, 'runtime_root', return_value=Path('/tmp')), \
                 mock.patch.object(safechain_probe.socket, 'socket', FixtureSocket):
                result = safechain_probe.probe(candidate, timeout=1, runner=denied_sandbox)
                mode[0] = 'unexpected-allow'
                second = safechain_probe.probe(candidate, timeout=1, runner=denied_sandbox)
            self.assertEqual(result['state'], 'skipped')
            self.assertIn('隔離', result['reason'])
            self.assertEqual(second['state'], 'skipped')
            self.assertIn('隔離', second['reason'])
            self.assertTrue(any(Path(c[0]).name == 'sandbox-exec' for c in commands))
            self.assertFalse(any(Path(argument).name == 'safe-chain' for c in commands for argument in c))

    def test_response_and_process_secrets_are_not_in_the_result(self):
        secret = 'synthetic-response-secret-987654321'
        observations = {
            'trusted': {'status': 200, 'tls_attempts': 1, 'http_requests': 1},
            'untrusted': {'status': 502, 'tls_attempts': 1, 'http_requests': 0},
            'mismatch': {'status': 502, 'tls_attempts': 1, 'http_requests': 0},
        }
        output = ('Error occurred while proxying request to /synthetic-untrusted for localhost: '
                  'unable to verify the first certificate ' + secret + '\n'
                  'Error occurred while proxying request to /synthetic-mismatch for localhost: '
                  'Hostname/IP does not match certificate ' + secret)
        result = safechain_probe.summarize_local_observations(observations, output)
        self.assertEqual(result['state'], 'measured')
        self.assertEqual(result['cases'], {'trusted': 'accepted', 'untrusted': 'rejected', 'mismatch': 'rejected'})
        self.assertNotIn(secret, json.dumps(result))

    def test_changed_candidate_is_not_started_after_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / 'bin' / 'safe-chain'
            candidate.parent.mkdir()
            candidate.write_bytes(b'original synthetic binary')
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            ports = iter(range(44000, 44020))
            commands = []
            class FixtureSocket:
                def __init__(self, *args): self.address = None
                def setsockopt(self, *args): pass
                def bind(self, address): self.address = (address[0], address[1] or next(ports))
                def listen(self, backlog): pass
                def getsockname(self): return self.address
                def close(self): pass
            def runner(command, **kwargs):
                commands.append(list(command))
                if Path(command[0]).name == 'sandbox-exec':
                    candidate.write_bytes(b'replaced synthetic binary')
                    return 0, json.dumps(safechain_probe.ISOLATED), ''
                return 0, json.dumps(safechain_probe.BASELINE), ''
            with mock.patch.dict(safechain_probe.SUPPORTED_HASHES, {digest: '1.5.26'}, clear=True), \
                 mock.patch.object(safechain_probe, 'platform_supported', return_value=True), \
                 mock.patch.object(safechain_probe, 'runtime_root', return_value=Path('/tmp')), \
                 mock.patch.object(safechain_probe.socket, 'socket', FixtureSocket):
                result = safechain_probe.probe(candidate, timeout=1, runner=runner)
            self.assertEqual(result['state'], 'skipped')
            self.assertIn('ハッシュ', result['reason'])
            self.assertFalse(any(Path(c[0]).name == 'openssl' for c in commands))

    def test_sandbox_denies_the_account_home_even_when_home_is_overridden(self):
        if os.name == 'nt':
            self.skipTest('the supported sandbox is macOS only')
        with mock.patch.dict(os.environ, {'HOME': '/tmp/synthetic-override-home'}), \
             mock.patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir='/tmp/synthetic-account-home')):
            policy = safechain_probe._policy(Path('/private/tmp/sandbox-test'), Path('/private/tmp/sandbox-test/work'),
                                             Path('/tmp/controller-runtime'), Path('/tmp/installed-safe-chain'), [43210])
        self.assertIn('subpath "' + str(Path('/tmp/synthetic-account-home').resolve()) + '"', policy)
        self.assertIn('subpath "' + str(Path('/tmp/synthetic-override-home').resolve()) + '"', policy)

    def test_candidate_through_an_env_symlink_is_not_opened(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / 'ordinary-fixture'
            fixture.write_text('synthetic-only')
            private = root / '.env.private'
            private.symlink_to(fixture)
            candidate = root / 'bin' / 'safe-chain'
            candidate.parent.mkdir()
            candidate.symlink_to(private)
            with mock.patch.object(safechain_probe, 'platform_supported', return_value=True), \
                 mock.patch.object(safechain_probe.os, 'open', side_effect=AssertionError('must not open')):
                result = safechain_probe.probe(candidate)
            self.assertEqual(result['state'], 'skipped')

    def test_proxy_port_is_not_used_until_the_complete_line_arrives(self):
        reader, writer = os.pipe()
        stream = os.fdopen(reader, 'rb')
        process = SimpleNamespace(stdout=stream)
        def send_chunks():
            os.write(writer, b'EMUDHRA_fixed_PROXY=http://127.0.0.1:1234')
            time.sleep(0.05)
            os.write(writer, b'5\n')
            os.close(writer)
        thread = threading.Thread(target=send_chunks)
        thread.start()
        try:
            port, _ = safechain_probe._wait_for_marker(process, 'fixed', 2)
            self.assertEqual(port, 12345)
        finally:
            thread.join()
            stream.close()

    def test_timeout_kills_a_probe_child_before_it_can_write(self):
        if os.name == 'nt':
            self.skipTest('process groups are exercised on POSIX')
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'child-survived'
            command = ['/bin/sh', '-c', '( /bin/sleep 0.8; /usr/bin/touch "$1" ) & wait', 'fixture', str(marker)]
            code, _, _ = safechain_probe.run_command(command, cwd=tmp,
                env={'PATH': '/usr/bin:/bin', 'HOME': tmp}, timeout=0.2)
            self.assertEqual(code, 124)
            time.sleep(1)
            self.assertFalse(marker.exists(), 'the timed-out child survived')

    @unittest.skipUnless(hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'), 'unreaped process status unavailable')
    def test_group_cleanup_occurs_once_while_leader_identity_is_still_reserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'detached-child-survived'
            original = safechain_probe._kill_group
            observed = []
            def cleanup(process):
                # A reaped leader no longer proves that the numeric process group
                # still belongs to this probe; never signal a recycled group.
                os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                observed.append(process.pid)
                original(process)
            command = ['/bin/sh', '-c', '( exec >/dev/null 2>&1; /bin/sleep 0.8; /usr/bin/touch "$1" ) & exit 0',
                       'fixture', str(marker)]
            with mock.patch.object(safechain_probe, '_kill_group', side_effect=cleanup):
                code, _, _ = safechain_probe.run_command(command, cwd=tmp,
                    env={'PATH':'/usr/bin:/bin', 'HOME':tmp}, timeout=2)
            self.assertEqual(code, 0)
            self.assertEqual(len(observed), 1)
            time.sleep(1)
            self.assertFalse(marker.exists(), 'a detached child survived successful cleanup')

    def test_supervised_marker_and_exit_keep_descendants_in_the_reserved_group(self):
        if os.name == 'nt':
            self.skipTest('process groups are exercised on POSIX')
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'proxy-child-survived'
            command = ['/bin/sh', '-c',
                       'printf "EMUDHRA_fixture_PROXY=http://127.0.0.1:12345\\n"; '
                       'read answer; [ "$answer" = done ] || exit 7; '
                       '( exec >/dev/null 2>&1; /bin/sleep 0.8; /usr/bin/touch "$1" ) & exit 0',
                       'fixture', str(marker)]
            process = safechain_probe._start_supervised(command, cwd=tmp,
                env={'PATH':'/usr/bin:/bin', 'HOME':tmp}, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                port, output = safechain_probe._wait_for_marker(process, 'fixture', 2)
                self.assertEqual(port, 12345)
                process.stdin.write(b'done\n'); process.stdin.flush(); process.stdin.close(); process.stdin = None
                code, _ = safechain_probe._finish_process(process, output, 2)
                self.assertEqual(code, 0)
            finally:
                safechain_probe._stop_supervised(process)
            time.sleep(1)
            self.assertFalse(marker.exists(), 'a proxy descendant survived cleanup')

    def test_supervised_command_preserves_nonzero_exit_and_output(self):
        if os.name == 'nt':
            self.skipTest('process groups are exercised on POSIX')
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = safechain_probe.run_command(
                ['/bin/sh', '-c', 'printf stdout; printf stderr >&2; exit 7'],
                cwd=tmp, env={'PATH':'/usr/bin:/bin', 'HOME':tmp}, timeout=2)
        self.assertEqual((code, out, err), (7, 'stdout', 'stderr'))

    def test_supervised_launch_failure_is_fail_closed(self):
        if os.name == 'nt':
            self.skipTest('process groups are exercised on POSIX')
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = safechain_probe.run_command(
                ['/nonexistent-emudhra-fixture'], cwd=tmp,
                env={'PATH':'/usr/bin:/bin', 'HOME':tmp}, timeout=2)
        self.assertEqual(code, 127)

    def test_group_permission_failure_is_not_treated_as_success(self):
        with mock.patch.object(safechain_probe.os, 'killpg', side_effect=PermissionError('fixture')):
            with self.assertRaises(PermissionError):
                safechain_probe._kill_group(SimpleNamespace(pid=1234))

    def test_key_generation_timeout_removes_the_private_working_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / 'bin' / 'safe-chain'
            candidate.parent.mkdir()
            candidate.write_bytes(b'\xcf\xfa\xed\xfe synthetic binary for timeout')
            candidate.chmod(0o700)
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            ports = iter(range(42000, 42020))
            key_directories = []

            class FixtureSocket:
                def __init__(self, *args): self.address = None
                def setsockopt(self, *args): pass
                def bind(self, address): self.address = (address[0], address[1] or next(ports))
                def listen(self, backlog): pass
                def getsockname(self): return self.address
                def close(self): pass

            def timeout_after_preflight(command, **kwargs):
                if Path(command[0]).name == 'sandbox-exec':
                    return 0, json.dumps(safechain_probe.ISOLATED), ''
                if Path(command[0]).name == 'openssl':
                    key_directories.append(Path(kwargs['cwd']))
                    (key_directories[-1] / 'generated.key').write_text('synthetic-secret-key')
                    return 124, '', 'synthetic-secret-key'
                return 0, json.dumps(safechain_probe.BASELINE), ''

            with mock.patch.dict(safechain_probe.SUPPORTED_HASHES, {digest: '1.5.26'}, clear=True), \
                 mock.patch.object(safechain_probe, 'platform_supported', return_value=True), \
                 mock.patch.object(safechain_probe, 'runtime_root', return_value=Path('/tmp')), \
                 mock.patch.object(safechain_probe.socket, 'socket', FixtureSocket):
                result = safechain_probe.probe(candidate, timeout=1, runner=timeout_after_preflight)
            self.assertTrue(key_directories, 'key generation was not attempted')
            self.assertTrue(all(not directory.exists() for directory in key_directories))
            self.assertEqual(result['state'], 'skipped')
            self.assertNotIn('synthetic-secret-key', json.dumps(result))

    def test_report_does_not_include_probe_output_and_keeps_real_tls_unconfirmed(self):
        secret = 'synthetic-response-secret-123456789'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'bin' / 'safe-chain'
            candidate.parent.mkdir()
            candidate.write_bytes(b'synthetic candidate')
            payload = {'state': 'measured', 'reason': secret, 'raw': secret,
                       'cases': {'trusted': 'accepted', 'untrusted': 'rejected', 'mismatch': 'rejected'}}
            with mock.patch.object(audit.app_inventory, 'scan', return_value=[installed(candidate)]), \
                 mock.patch.object(safechain_probe, 'probe', return_value=payload), \
                 contextlib.redirect_stdout(io.StringIO()):
                audit.main(['--only', 'packages', '--out', str(root / 'out')])
            data = (root / 'out/report.json').read_text()
            page = (root / 'out/report.html').read_text()
            self.assertNotIn(secret, data)
            self.assertNotIn(secret, page)
            report = json.loads(data)
            row = next(r for r in report['records'] if r['name'] == 'Safe Chain / 証明書の接続テスト')
            self.assertEqual(row['review_state'], 'unverified')
            self.assertIn('eMudhraへの対応状況は未確認', row['detail'])
            self.assertIn('テスト用の証明書を正しく判定', page)

    def test_generated_fixture_certificates_have_expected_chains_and_hostnames(self):
        if os.name == 'nt' or not Path('/usr/bin/openssl').is_file():
            self.skipTest('system OpenSSL is unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'tls'
            env = {'PATH': '/usr/bin:/bin', 'HOME': tmp, 'TMPDIR': tmp, 'LANG': 'C', 'LC_ALL': 'C'}
            self.assertTrue(safechain_probe._certificates(folder, env, safechain_probe.run_command, 10))
            self.assertTrue(safechain_probe._verify_certificates(folder, env, safechain_probe.run_command, 10))

    def _assert_signal_cleans_up(self, sent_signal):
        if os.name == 'nt':
            self.skipTest('POSIX signal and process group test')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'bin' / 'safe-chain'
            candidate.parent.mkdir()
            candidate.write_bytes(b'synthetic safe-chain executable')
            script = root / 'termination_fixture.py'
            script.write_text('''import hashlib, json, sys
from pathlib import Path
from unittest import mock
sys.path.insert(0, {source!r})
import safechain_probe as p
root=Path({root!r}); candidate=root/'bin'/'safe-chain'
digest=hashlib.sha256(candidate.read_bytes()).hexdigest()
ports=iter(range(43000,43020))
class Sock:
 def __init__(self,*args): self.address=None
 def setsockopt(self,*args): pass
 def bind(self,a): self.address=(a[0],a[1] or next(ports))
 def listen(self,n): pass
 def getsockname(self): return self.address
 def close(self): pass
def runner(command,**kw):
 if Path(command[0]).name=='sandbox-exec': return 0,json.dumps(p.ISOLATED),''
 if Path(command[0]).name=='openssl':
  folder=Path(kw['cwd']); (folder/'generated.key').write_text('synthetic-key')
  (root/'ready').write_text(str(folder))
  return p.run_command(['/bin/sh','-c','( /bin/sleep 1; /usr/bin/touch "$1" ) & wait',
                        'fixture',str(root/'child-survived')],cwd=folder,
                       env={{'PATH':'/usr/bin:/bin','HOME':str(folder)}},timeout=20)
 return 0,json.dumps(p.BASELINE),''
with mock.patch.dict(p.SUPPORTED_HASHES,{{digest:'1.5.26'}},clear=True), \\
 mock.patch.object(p,'platform_supported',return_value=True), \\
 mock.patch.object(p,'runtime_root',return_value=Path('/tmp')), \\
 mock.patch.object(p.socket,'socket',Sock):
 p.probe(candidate,timeout=5,runner=runner)
'''.format(source=str(Path(__file__).resolve().parents[1]), root=str(root)))
            process = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(script)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while not (root / 'ready').exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue((root / 'ready').exists(), 'probe did not reach synthetic key generation')
                key_dir = Path((root / 'ready').read_text())
                process.send_signal(sent_signal)
                process.wait(timeout=5)
                time.sleep(1.1)
                self.assertFalse(key_dir.exists(), 'temporary generated key directory survived')
                self.assertFalse((root / 'child-survived').exists(), 'a descendant survived termination')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_termination_stops_children_and_removes_generated_key(self):
        self._assert_signal_cleans_up(signal.SIGTERM)

    def test_interrupt_stops_children_and_removes_generated_key(self):
        self._assert_signal_cleans_up(signal.SIGINT)
