"""Fail-closed, synthetic Safe Chain checks that never use user settings."""
import contextlib
import errno
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import re
import secrets
import selectors
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

import evidence
import verdicts


ROOT = Path(__file__).resolve().parent
SANDBOX = '/usr/bin/sandbox-exec'
SUPPORTED_HASHES = {
    '9a162f410c74ebf27121ac44bf99097c06829a02bdf311f1b95f5c2bda66d088': '1.5.26',
}
BASELINE = dict(file_read='allowed', alias_read='allowed', hardlink='allowed', outside_write='allowed',
                alias_write='allowed', scratch_write='allowed', unix_socket='allowed', allowed_port='allowed',
                other_port='allowed', other_loopback='allowed', mach_lookup=0)
ISOLATED = dict(BASELINE, file_read='denied', alias_read='denied', hardlink='denied', outside_write='denied',
                alias_write='denied', unix_socket='denied', other_port='denied', other_loopback='denied',
                mach_lookup=1100)
REASON_LABELS = {
    '対応OS・CPUの隔離条件が未確認です。': 'このOS・機種で安全にテストできる条件は未確認です。',
    '対応する本体ハッシュが未確認です。': '対応するSafe Chain本体を確認できず、接続は未確認です。',
    '同梱ランタイムの隔離条件が未確認です。': '安全にテストするための実行環境は未確認です。',
    '隔離前の合成対照を確認できません。': '安全なテストの準備を確認できず、接続は未確認です。',
    'OS隔離の合成試験が成立せず、本体コピーは起動しませんでした。': '安全な実行環境が確認できず、本体のコピーを起動しませんでした。',
    '本体コピーのハッシュを確認できません。': '本体のコピーを確認できず、接続は未確認です。',
    '合成証明書の生成を確認できません。': 'テスト用の証明書を用意できず、接続は未確認です。',
    '合成証明書の検証を確認できません。': 'テスト用の証明書を確認できず、接続は未確認です。',
    '合成TLS検査の準備を確認できません。': 'このPC内の接続テストを準備できませんでした。',
    '隔離の準備または確認に失敗しました。': '安全な実行環境を用意できず、接続は未確認です。',
}


def platform_supported():
    return sys.platform == 'darwin' and platform.machine() == 'arm64'


def runtime_root():
    """Use only the app's bundled interpreter as a sandbox canary."""
    try:
        root = Path(sys.prefix).resolve(strict=True)
        executable = Path(sys.executable).resolve(strict=True)
        if (root.name != 'runtime' or root.parent.name != 'app' or root not in executable.parents or
                not evidence.public_path(root) or not evidence.public_path(executable)):
            return None
        return root
    except (OSError, RuntimeError, ValueError):
        return None


def _kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _start_supervised(command, *, cwd, env, stdin, stdout, stderr):
    """Reserve the group ID until all of the probe's descendants are stopped."""
    read_fd, write_fd = os.pipe()
    try:
        supervisor = [sys.executable, '-I', '-S', '-B', str(ROOT/'probes/safechain_supervisor.py'),
                      str(write_fd)] + list(map(str, command))
        process = subprocess.Popen(supervisor, cwd=str(cwd), env=env, stdin=stdin, stdout=stdout,
                                   stderr=stderr, start_new_session=True, pass_fds=(write_fd,))
        process._emudhra_status_fd = read_fd
        return process
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)


def _read_supervised(process, deadline, initial=b'', output_limit=None):
    """Collect output and the child status without reaping the group leader."""
    output = {'stdout':bytearray(initial), 'stderr':bytearray(), 'status':bytearray()}
    with selectors.DefaultSelector() as selector:
        if process.stdout is not None:
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
        if process.stderr is not None:
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
        selector.register(process._emudhra_status_fd, selectors.EVENT_READ, 'status')
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 124, '', ''
            ready = selector.select(remaining)
            if not ready:
                return 124, '', ''
            for key, _ in ready:
                chunk = os.read(key.fd, 65536)
                if chunk:
                    output[key.data].extend(chunk)
                    if key.data == 'status' and len(output['status']) > 32:
                        return 124, '', ''
                    if output_limit and len(output['stdout']) >= output_limit:
                        return 124, '', ''
                else:
                    selector.unregister(key.fileobj)
    status = bytes(output['status'])
    if not re.fullmatch(rb'-?\d+\n', status):
        return 124, '', ''
    return int(status), output['stdout'].decode('utf-8', 'replace'), output['stderr'].decode('utf-8', 'replace')


def _stop_supervised(process):
    _kill_group(process)
    process.wait()
    os.close(process._emudhra_status_fd)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()


@contextlib.contextmanager
def _block_start_signals():
    if hasattr(signal, 'pthread_sigmask'):
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    else:
        yield


@contextlib.contextmanager
def _termination_guard():
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError('signal cleanup unavailable')
    previous = signal.getsignal(signal.SIGTERM)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def run_command(command, *, cwd, env, timeout):
    """Always stop the process group, including after timeout or interruption."""
    process = None
    try:
        with _block_start_signals():
            process = _start_supervised(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return _read_supervised(process, time.monotonic()+timeout)
    finally:
        if process is not None:
            _stop_supervised(process)


def _hash_candidate(path):
    if path.name != 'safe-chain' or path.parent.name != 'bin' or not evidence.public_path(path):
        return ''
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 * 1024 * 1024:
                return ''
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
            return digest.hexdigest()
    except (OSError, ValueError):
        return ''


def _quote(value):
    value = str(value)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError('unsupported sandbox path')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _policy(root, work, runtime, install_root, ports):
    import pwd
    home = Path.home().resolve()
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    if home == Path('/') or account_home == Path('/') or install_root == Path('/'):
        raise ValueError('unsafe isolation boundary')
    blocked = ['/Users', '/System/Volumes/Data/Users', '/Library/Keychains',
               '/System/Library/Keychains', '/private/var/db', '/private/tmp', home, account_home, install_root]
    lines = ['(version 1)', '(allow default)',
        '(deny file-read* ' + ' '.join('(subpath ' + _quote(p) + ')' for p in blocked) + ')',
        '(allow file-read-metadata (literal "/private/tmp") (literal ' + _quote(root) + '))',
        '(allow file-read* (subpath ' + _quote(work) + ') (subpath ' + _quote(runtime) + '))',
        '(deny file-write*)', '(allow file-write* (subpath ' + _quote(work) + '))',
        '(deny mach-lookup)', '(deny mach-register)', '(deny ipc-posix-shm*)',
        '(deny ipc-posix-sem*)', '(deny iokit-open)', '(deny appleevent-send)',
        '(deny network*)', '(allow network-inbound (local ip "localhost:*"))']
    lines += ['(allow network-outbound (remote ip "localhost:' + str(p) + '"))' for p in ports]
    return '\n'.join(lines) + '\n'


def _listener(host, port=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        sock.listen(8)
        return sock
    except BaseException:
        sock.close()
        raise


def _listener_v6(port):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(('::1', port))
        sock.listen(8)
        return sock
    except BaseException:
        sock.close()
        raise


def _copy_verified(source, target, expected):
    """Copy only this executable and verify the exact copied bytes again."""
    descriptor = os.open(str(source), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as incoming:
        info = os.fstat(incoming.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 * 1024 * 1024:
            return False
        output = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        digest = hashlib.sha256()
        with os.fdopen(output, 'wb') as destination:
            for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                digest.update(chunk)
                destination.write(chunk)
    return digest.hexdigest() == expected


def _certificates(folder, env, runner, timeout):
    """Generate short-lived fixture keys locally; never return their contents."""
    folder.mkdir(mode=0o700)
    req = '''[req]
distinguished_name = dn
prompt = no
x509_extensions = ca_ext
[dn]
CN = NAME
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
'''
    (folder / 'localhost.ext').write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
    (folder / 'mismatch.ext').write_text('subjectAltName=DNS:fixture.invalid\nextendedKeyUsage=serverAuth\n')
    config = folder / 'request.cnf'
    for ca in ('trusted', 'other'):
        config.write_text(req.replace('NAME', 'synthetic-' + ca + '-ca'))
        command = ['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                   '-config', str(config), '-keyout', ca + '-ca.key', '-out', ca + '-ca.pem']
        rc, _, _ = runner(command, cwd=folder, env=env, timeout=timeout)
        if rc:
            return False
    for name, ca, extension in (('trusted', 'trusted', 'localhost'), ('untrusted', 'other', 'localhost'),
                                 ('mismatch', 'trusted', 'mismatch')):
        config.write_text(req.replace('NAME', 'synthetic-' + name))
        command = ['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', str(config),
                   '-keyout', name + '.key', '-out', name + '.csr']
        rc, _, _ = runner(command, cwd=folder, env=env, timeout=timeout)
        if rc:
            return False
        command = ['/usr/bin/openssl', 'x509', '-req', '-days', '1', '-in', name + '.csr',
                   '-CA', ca + '-ca.pem', '-CAkey', ca + '-ca.key', '-CAcreateserial',
                   '-out', name + '.pem', '-extfile', extension + '.ext']
        rc, _, _ = runner(command, cwd=folder, env=env, timeout=timeout)
        if rc:
            return False
    return True


def _verify_certificates(folder, env, runner, timeout):
    for ca, certificate, should_pass in (('trusted', 'trusted', True), ('other', 'untrusted', True),
                                         ('trusted', 'mismatch', True), ('trusted', 'untrusted', False)):
        command = ['/usr/bin/openssl', 'verify', '-CAfile', ca + '-ca.pem', certificate + '.pem']
        rc, _, _ = runner(command, cwd=folder, env=env, timeout=timeout)
        if (should_pass and rc != 0) or (not should_pass and rc not in (1, 2)):
            return False
    try:
        for name in ('trusted', 'untrusted', 'mismatch'):
            certificate = ssl._ssl._test_decode_cert(str(folder / (name + '.pem')))
            expected = (('DNS', 'fixture.invalid' if name == 'mismatch' else 'localhost'),)
            if certificate.get('subjectAltName') != expected:
                return False
        return True
    except (AttributeError, OSError, ValueError, ssl.SSLError):
        return False
    return False


class _FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, sock, handler, *, name, counter=None, tls_context=None):
        super().__init__(sock.getsockname(), handler, bind_and_activate=False)
        self.socket.close()
        self.socket = sock
        self.server_address = sock.getsockname()
        self.server_name = 'localhost'
        self.server_port = sock.getsockname()[1]
        self.fixture_name = name
        self.counter = counter
        self.tls_context = tls_context

    def get_request(self):
        connection, address = self.socket.accept()
        if self.tls_context is None:
            return connection, address
        self.counter['tls_attempts'] += 1
        connection.settimeout(5)
        try:
            return self.tls_context.wrap_socket(connection, server_side=True), address
        except (OSError, ssl.SSLError):
            connection.close()
            raise OSError('synthetic TLS handshake failed')


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        server = self.server
        if server.fixture_name == 'metadata':
            status, body = (200, b'[]') if self.path == '/safe_patches.json' else (404, b'')
        elif self.path == '/synthetic-' + server.fixture_name:
            server.counter['http_requests'] += 1
            # A fresh, synthetic value proves response bodies are never reported.
            body = ('{"name":"synthetic-fixture","opaque":"' + secrets.token_hex(24) + '"}').encode()
            status = 200
        else:
            status, body = 404, b''
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (OSError, ssl.SSLError):
            pass


def _start_servers(listeners, ipv6, certs):
    servers, threads = [], []
    counters = {name: {'tls_attempts': 0, 'http_requests': 0} for name in ('trusted', 'untrusted', 'mismatch')}
    try:
        for index, name in enumerate(('metadata', 'trusted', 'untrusted', 'mismatch')):
            context = None
            if name != 'metadata':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(certs / (name + '.pem')), str(certs / (name + '.key')))
            sockets = [listeners[index]] + ([ipv6[index]] if ipv6[index] is not None else [])
            for sock in sockets:
                server = _FixtureServer(sock, _FixtureHandler, name=name, counter=counters.get(name), tls_context=context)
                thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
                thread.start()
                servers.append(server)
                threads.append(thread)
        return servers, threads, counters
    except BaseException:
        _stop_servers(servers, threads)
        raise


def _stop_servers(servers, threads):
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(timeout=2)


def _http_via_proxy(proxy_port, target_port, ca_file, name, timeout):
    """Connect only to the proxy's loopback socket and discard all response bodies."""
    with socket.create_connection(('127.0.0.1', proxy_port), timeout=timeout) as connection:
        connection.sendall(('CONNECT localhost:' + str(target_port) + ' HTTP/1.1\r\nHost: localhost:' +
                            str(target_port) + '\r\n\r\n').encode('ascii'))
        header = b''
        while b'\r\n\r\n' not in header and len(header) < 8192:
            chunk = connection.recv(1024)
            if not chunk:
                return None
            header += chunk
        if not re.match(rb'^HTTP/1\.[01] 200\b', header):
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(ca_file))
        with context.wrap_socket(connection, server_hostname='localhost') as secure:
            secure.settimeout(timeout)
            secure.sendall(('GET /synthetic-' + name + ' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n').encode('ascii'))
            response = b''
            while b'\r\n' not in response and len(response) < 8192:
                chunk = secure.recv(1024)
                if not chunk:
                    return None
                response += chunk
            match = re.match(rb'^HTTP/1\.[01] (\d{3})\b', response)
            return int(match.group(1)) if match else None


def _wait_for_marker(process, token, timeout):
    marker = ('EMUDHRA_' + token + '_PROXY=').encode('ascii')
    output = bytearray()
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline and len(output) < 65536:
            ready = selector.select(max(0, deadline - time.monotonic()))
            if not ready:
                break
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            output.extend(chunk)
            for line in output.split(b'\n')[:-1]:
                if line.startswith(marker):
                    match = re.fullmatch(rb'http://127\.0\.0\.1:(\d{1,5})', line[len(marker):].strip())
                    if match and 1 <= int(match.group(1)) <= 65535:
                        return int(match.group(1)), bytes(output)
                    return None, bytes(output)
    return None, bytes(output)


def _finish_process(process, output, timeout):
    """Drain a bounded amount of untrusted output without printing it."""
    code, captured, _ = _read_supervised(process, time.monotonic()+timeout, output, 65536)
    return code, captured


def _exercise_copy(run, policy, listeners, ipv6, timeout):
    """Run only the pinned copy under the proven policy, using synthetic loopback."""
    fixture_bin = run / 'fixture-bin'
    fixture_bin.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    stub = fixture_bin / 'npm'
    stub.write_text('#!/bin/sh\nprintf "EMUDHRA_%s_PROXY=%s\\n" "$SAFECHAIN_TEST_TOKEN" "$HTTPS_PROXY"\n'
                    'IFS= read -r answer\n[ "$answer" = done ]\n')
    stub.chmod(0o700)
    ports = [sock.getsockname()[1] for sock in listeners[:4]]
    env = {'PATH': str(fixture_bin) + ':/usr/bin:/bin', 'HOME': str(run / 'home'),
           'TMPDIR': str(run / 'tmp'), 'LANG': 'C', 'LC_ALL': 'C',
           'NODE_EXTRA_CA_CERTS': str(run / 'tls' / 'trusted-ca.pem'),
           'NODE_OPTIONS': '--dns-result-order=ipv4first', 'SAFE_CHAIN_NPM_CUSTOM_REGISTRIES': 'localhost',
           'SAFE_CHAIN_MALWARE_LIST_BASE_URL': 'http://127.0.0.1:' + str(ports[0]),
           'SAFE_CHAIN_LOGGING': 'verbose', 'SAFECHAIN_TEST_TOKEN': token}
    command = [SANDBOX, '-f', str(policy), str(run / 'bin' / 'safe-chain'),
               'npm', 'view', 'synthetic-fixture', '--safe-chain-skip-minimum-package-age']
    servers, threads, counters = _start_servers(listeners, ipv6, run / 'tls')
    process = None
    try:
        with _block_start_signals():
            process = _start_supervised(command, cwd=run/'home', env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        proxy_port, output = _wait_for_marker(process, token, max(8, min(timeout + 5, 20)))
        if proxy_port is None or proxy_port in ports:
            return summarize_local_observations({}, '')
        ca = run / 'certs' / 'ca-cert.pem'
        for path in (ca, run / 'certs' / 'ca-key.pem'):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size < 65536:
                return summarize_local_observations({}, '')
        observations = {}
        for index, name in enumerate(('trusted', 'untrusted', 'mismatch'), 1):
            try:
                status = _http_via_proxy(proxy_port, ports[index], ca, name, max(1, min(timeout, 10)))
            except (OSError, ValueError, ssl.SSLError):
                status = None
            observations[name] = dict(counters[name], status=status)
        process.stdin.write(b'done\n')
        process.stdin.flush()
        process.stdin.close()
        process.stdin = None
        rc, captured = _finish_process(process, output, max(5, min(timeout + 5, 20)))
        if rc != 0:
            return summarize_local_observations({}, '')
        return summarize_local_observations(observations, captured)
    finally:
        if process is not None:
            _stop_supervised(process)
        _stop_servers(servers, threads)


def summarize_local_observations(observations, process_output):
    """Return fixed labels only; never carry response or process output into a report."""
    cases = dict.fromkeys(('trusted', 'untrusted', 'mismatch'), 'unknown')
    trusted = observations.get('trusted', {})
    if (trusted.get('status') == 200 and trusted.get('tls_attempts') == 1 and
            trusted.get('http_requests') == 1):
        cases['trusted'] = 'accepted'
    lines = process_output.splitlines()
    for case, reason in (('untrusted', 'unable to verify the first certificate'),
                         ('mismatch', 'Hostname/IP does not match certificate')):
        observed = observations.get(case, {})
        evidence_line = any('/synthetic-' + case in line and reason in line for line in lines)
        if (observed.get('status') == 502 and observed.get('tls_attempts') == 1 and
                observed.get('http_requests') == 0 and evidence_line):
            cases[case] = 'rejected'
    complete = cases == {'trusted': 'accepted', 'untrusted': 'rejected', 'mismatch': 'rejected'}
    return {'state': 'measured' if complete else 'partial', 'cases': cases,
            'reason': ('合成localhostへの上流TLSで、信頼済みの接続と未信頼CA・名前不一致の拒否を確認しました。'
                       if complete else '合成localhostへの上流TLSをすべて確認できませんでした。')}


def probe(executable, timeout=8, runner=run_command):
    """Probe a pinned binary only after the platform and sandbox pass controls."""
    executable = Path(executable)
    if not platform_supported():
        return {'state': 'skipped', 'reason': '対応OS・CPUの隔離条件が未確認です。'}
    digest = _hash_candidate(executable)
    if digest not in SUPPORTED_HASHES:
        return {'state': 'skipped', 'reason': '対応する本体ハッシュが未確認です。'}
    runtime = runtime_root()
    if not runtime:
        return {'state': 'skipped', 'reason': '同梱ランタイムの隔離条件が未確認です。'}
    listeners = []
    ipv6 = []
    try:
        install_root = executable.parent.parent.resolve()
        if runtime == install_root or install_root in runtime.parents:
            return {'state': 'skipped', 'reason': '同梱ランタイムの隔離条件が未確認です。'}
        with _termination_guard(), tempfile.TemporaryDirectory(prefix='emudhra-safechain-', dir='/private/tmp') as tmp:
            root = Path(tmp)
            work = root / 'work'
            for directory in (work, root / 'blocked', root / 'outside'):
                directory.mkdir(mode=0o700)
            (root / 'blocked' / 'data').write_text('synthetic fixture')
            (work / 'alias').symlink_to(root / 'blocked' / 'data')
            (work / 'write-alias').symlink_to(root / 'outside' / 'out')
            preflight = work / 'preflight.py'
            shutil.copyfile(ROOT / 'probes' / 'safechain_preflight.py', preflight)
            for _ in range(4):
                listeners.append(_listener('127.0.0.1'))
            for listener in listeners[:4]:
                try:
                    ipv6.append(_listener_v6(listener.getsockname()[1]))
                except OSError as exc:
                    if exc.errno not in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL):
                        raise
                    ipv6.append(None)
            allowed_port = listeners[0].getsockname()[1]
            other = _listener('127.0.0.1'); listeners.append(other)
            other_port = other.getsockname()[1]
            baseline = dict(BASELINE)
            try:
                listeners.append(_listener('127.0.0.2', allowed_port))
            except OSError as exc:
                if exc.errno != errno.EADDRNOTAVAIL:
                    raise
                # Some macOS hosts do not assign 127.0.0.2. The sandbox
                # must still reject it with EPERM, not an ordinary timeout.
                baseline['other_loopback'] = 'error'
            policy = root / 'policy.sb'
            policy.write_text(_policy(root, work, runtime, install_root,
                                      [item.getsockname()[1] for item in listeners[:4]]))
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'TMPDIR': str(work), 'LANG': 'C', 'LC_ALL': 'C'}
            python = str(Path(sys.executable).resolve())
            canary = [python, '-I', '-S', '-B', str(preflight), str(root), str(allowed_port), str(other_port)]
            rc, out, _ = runner(canary, cwd=work, env=env, timeout=max(5, timeout))
            if rc != 0 or json.loads(out) != baseline:
                return {'state': 'skipped', 'reason': '隔離前の合成対照を確認できません。'}
            rc, out, _ = runner([SANDBOX, '-f', str(policy)] + canary, cwd=work, env=env, timeout=max(5, timeout))
            if rc != 0 or json.loads(out) != ISOLATED:
                return {'state': 'skipped', 'reason': 'OS隔離の合成試験が成立せず、本体コピーは起動しませんでした。'}
            run = work / 'run'
            for directory in (run, run / 'bin', run / 'home', run / 'tmp'):
                directory.mkdir(mode=0o700)
            if not _copy_verified(executable, run / 'bin' / 'safe-chain', digest):
                return {'state': 'skipped', 'reason': '本体コピーのハッシュを確認できません。'}
            if not _certificates(run / 'tls', env, runner, max(5, min(timeout, 20))):
                return {'state': 'skipped', 'reason': '合成証明書の生成を確認できません。'}
            if not _verify_certificates(run / 'tls', env, runner, max(5, min(timeout, 20))):
                return {'state': 'skipped', 'reason': '合成証明書の検証を確認できません。'}
            return _exercise_copy(run, policy, listeners, ipv6, max(1, min(timeout, 10)))
    except Exception:
        return {'state': 'skipped', 'reason': '隔離の準備または確認に失敗しました。'}
    finally:
        for listener in listeners + ipv6:
            if listener is not None:
                listener.close()


def collect(audit):
    seen = set()
    for executable in audit.discovered.get('safe-chain', []):
        identity = verdicts.installation_identity('safe-chain', executable)
        if identity in seen:
            continue
        seen.add(identity)
        if audit.args.offline:
            detail = 'オフライン指定のため、このPC内の接続テストを見送りました。'
            result = {'state': 'skipped'}
        else:
            result = probe(executable, timeout=audit.args.timeout)
            if result.get('state') == 'measured':
                detail = 'このPC内のテストで、正常な証明書で接続し、未信頼の証明書と接続先の名前が違う証明書をブロックしました。eMudhraへの対応状況は未確認です。'
            elif result.get('state') == 'partial':
                detail = 'このPC内の接続テストをすべて確認できませんでした。eMudhraへの対応状況は未確認です。'
            else:
                reason = result.get('reason')
                detail = REASON_LABELS.get(reason, '安全に接続テストを行える条件は未確認です。')
        metadata = {'tool_id': 'safe-chain', 'tool_name': 'Safe Chain', 'executable': str(executable)}
        if result.get('state') in ('measured', 'partial'):
            values = result.get('cases', {})
            metadata['probe'] = 'safechain_synthetic_tls'
            metadata['synthetic_tls_state'] = result['state']
            metadata['synthetic_tls_cases'] = {key: values.get(key) if values.get(key) in ('accepted', 'rejected') else 'unknown'
                                               for key in ('trusted', 'untrusted', 'mismatch')}
        row = audit.add('Safe Chain / 証明書の接続テスト', 'MANUAL', detail, metadata,
                  action='普段の取得先や脅威情報への実際の接続を確認してください。', required=True)
        if result.get('state') in ('measured', 'partial'):
            row['assessment_method'] = 'measured'
            row['scope'] = 'このPC内でテスト用の証明書と一時設定を使用。eMudhraの検査先と普段の設定は未確認。'
