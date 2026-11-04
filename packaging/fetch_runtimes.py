"""Fetch pinned upstream archives; never invoked by an end-user launcher."""
import hashlib
import json
import ntpath
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def public_curl(cache, output, url, *, system=None, system_root=None):
    """Use system curl with no personal configuration or credential environment."""
    if (system or os.name) == 'nt':
        system_root = system_root or os.environ.get('SystemRoot', r'C:\Windows')
        system_bin = ntpath.join(system_root, 'System32')
        executable = ntpath.join(system_bin, 'curl.exe')
        env = {'SystemRoot':system_root, 'PATH':system_bin, 'HOME':str(cache.parent),
               'USERPROFILE':str(cache.parent)}
    else:
        executable = '/usr/bin/curl'
        env = {'PATH':'/usr/bin:/bin', 'HOME':str(cache.parent)}
    command = [executable, '-q', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
               '--silent', '--show-error', '--retry', '2', '--max-time', '180', '--output', str(output), url]
    return command, env


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    cache = ROOT / '.artifacts/runtime-cache'
    cache.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'packaging/runtimes.json').read_text())
    for asset in manifest['assets']:
        path = cache / asset['filename']
        if path.is_file() and sha256(path) == asset['sha256']:
            print(asset['platform'] + ': cached / SHA-256 verified', flush=True)
            continue
        partial = path.with_suffix(path.suffix + '.partial')
        # Do not load the operator's curl configuration, credentials, or proxy
        # environment while fetching public, hash-pinned release artifacts.
        command, env = public_curl(cache, partial, asset['url'])
        subprocess.run(command, check=True, env=env)
        if sha256(partial) != asset['sha256']:
            raise RuntimeError('SHA-256 mismatch: ' + asset['filename'])
        partial.replace(path)
        print(asset['platform'] + ': downloaded / SHA-256 verified', flush=True)


if __name__ == '__main__':
    main()
