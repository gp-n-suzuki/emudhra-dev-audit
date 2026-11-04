"""Release archives exclude local data and reject changed/unsafe runtimes."""
import io
from html.parser import HTMLParser
import json
from pathlib import Path
import posixpath
import subprocess
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
from urllib.parse import unquote, urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'packaging'))
import build_release
import verify_release
from fetch_runtimes import sha256
from fetch_runtimes import public_curl


@unittest.skipUnless(hasattr(tarfile,'data_filter'),'Maintainer packaging needs Python 3.12+')
class BuildReleaseTests(unittest.TestCase):
    def test_runtime_download_ignores_personal_curl_and_proxy_settings(self):
        command, env = public_curl(Path('/tmp/cache'), Path('/tmp/output'), 'https://example.invalid/file')
        self.assertEqual(command[1], '-q')
        self.assertIn('--proto-redir', command)
        self.assertNotIn('HTTPS_PROXY', env)
        self.assertNotIn('CURL_HOME', env)
        windows, win_env = public_curl(Path('/tmp/cache'), Path('/tmp/output'),
                                       'https://example.invalid/file', system='nt', system_root=r'C:\Windows')
        self.assertEqual(windows[0], r'C:\Windows\System32\curl.exe')
        self.assertEqual(windows[1], '-q')
        self.assertEqual(win_env['SystemRoot'], r'C:\Windows')
        self.assertNotIn('HTTPS_PROXY', win_env)

    def fixture(self,root,member='python/python.exe',platform='windows-x64'):
        cache=root/'.artifacts/runtime-cache';cache.mkdir(parents=True)
        archive=cache/'fixture.tar.gz'
        with tarfile.open(archive,'w:gz') as t:
            data=b'fixture runtime';info=tarfile.TarInfo(member);info.size=len(data)
            t.addfile(info,io.BytesIO(data))
        for name in build_release.FILES:
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture\n')
        for name in ('START-HERE.html', 'sample-report.html', 'verify_package.py', 'packaging/user-guide.html'):
            (root/name).write_text((build_release.ROOT/name).read_text())
        licenses=root/'packaging/upstream-licenses';licenses.mkdir(parents=True)
        (licenses/'LICENSE').write_text('fixture license')
        (root/'private-report.json').write_text('must never ship')
        (root/'fixture-ca-key.pem').write_text('synthetic-private-key-do-not-ship')
        (root/'fixture-response.json').write_text('synthetic-response-secret-do-not-ship')
        return dict(filename=archive.name,platform=platform,sha256=sha256(archive))

    def test_archive_contains_complete_runtime_manifest_and_no_local_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);asset=self.fixture(root)
            record=build_release.build(asset,dict(python='3.13.17',release='fixture',source='fixture'),root/'out',root)
            with zipfile.ZipFile(root/'out'/record['file']) as archive:
                names=archive.namelist()
                self.assertTrue(any(n.endswith('/runtime/python.exe') for n in names))
                self.assertFalse(any('private-report' in n for n in names))
                self.assertFalse(any('fixture-ca-key' in n or 'fixture-response' in n for n in names))
                for name in names:
                    if not name.endswith('/'):
                        content = archive.read(name)
                        self.assertNotIn(b'synthetic-private-key-do-not-ship', content)
                        self.assertNotIn(b'synthetic-response-secret-do-not-ship', content)
                for asset in ('診断を開始.cmd', 'desktop_entry.py', 'app_inventory.py', 'reporting.py', 'remediation.py', 'official_versions.py', 'safechain_supervisor.py', 'OFFICIAL-DECISIONS-ja.md', 'report-ui.js', 'ui.css'):
                    self.assertTrue(any(n.endswith('/'+asset) for n in names), asset)
                text=archive.read(next(n for n in names if n.endswith('/SHA256SUMS.txt'))).decode()
                self.assertIn('  app/runtime/python.exe\n',text)
                self.assertIn('  docs/licenses/python-build-standalone/LICENSE\n',text)

    def test_verifier_rejects_a_self_consistent_archive_missing_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); asset=self.fixture(root)
            runtime=root/'.artifacts/runtime-cache/fixture.tar.gz'
            header=bytearray(128); header[:2]=b'MZ'; struct.pack_into('<I',header,60,64)
            header[64:68]=b'PE\0\0'; struct.pack_into('<H',header,68,0x8664)
            with tarfile.open(runtime,'w:gz') as archive:
                info=tarfile.TarInfo('python/python.exe'); info.size=len(header)
                archive.addfile(info,io.BytesIO(header))
            asset['sha256']=sha256(runtime)
            files=tuple(name for name in build_release.APP_FILES if name != 'tool_catalog.py')
            with mock.patch.object(build_release,'APP_FILES',files):
                record=build_release.build(asset,dict(python='3.13.17',release='fixture',source='fixture'),root/'out',root)
            with self.assertRaisesRegex(AssertionError,'Required'):
                verify_release.verify(root/'out'/record['file'],record)

    def test_distribution_has_one_clickable_launcher_and_only_platform_relevant_files(self):
        for platform, executable, launcher, other, entry in (
                ('windows-x64', 'python/python.exe', 'run-checks.cmd', 'run-checks.sh', '診断を開始.cmd'),
                ('macos-arm64', 'python/bin/python3', 'run-checks.sh', 'run-checks.cmd', '診断を開始.command'),
                ('linux-arm64', 'python/bin/python3', 'run-checks.sh', 'run-checks.cmd', '診断を開始.sh')):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);asset=self.fixture(root,executable,platform)
                record=build_release.build(asset,dict(python='3.13.17',release='fixture',source='fixture'),root/'out',root)
                archive=root/'out'/record['file']
                if archive.suffix=='.zip':
                    with zipfile.ZipFile(archive) as z:
                        payload={'/'.join(n.split('/')[1:]):z.read(n) for n in z.namelist() if not n.endswith('/')}
                else:
                    with tarfile.open(archive) as t:
                        payload={'/'.join(m.name.split('/')[1:]):t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
                        self.assertTrue(next(m for m in t.getmembers() if m.name.endswith('/'+entry)).mode & 0o111)
                self.assertEqual({name.split('/')[0] for name in payload}, {entry, 'app', 'docs'})
                self.assertIn('app/'+launcher,payload)
                self.assertNotIn('app/'+other,payload)
                self.assertFalse(any('tests/' in name or name.endswith(('TESTING.md','run-checks.ps1','README-ja.md')) for name in payload))
                self.assertIn('docs/VALIDATION-ja.md',payload)
                self.assertIn('docs/使い方.html',payload)
                self.assertNotIn('app/quickstart.js',payload)
                self.assertNotIn('app/browser-check.html',payload)
                self.assertNotIn('app/browser-ui.js',payload)
                guide=payload['docs/使い方.html'].decode()
                self.assertIn(entry,guide)
                self.assertIn('ダブルクリック',guide)
                self.assertIn('自動で開きます',guide)
                self.assertNotIn('コマンドをコピー',guide)
                class Links(HTMLParser):
                    def handle_starttag(inner,tag,attrs):
                        for key,value in attrs:
                            if key not in ('href','src') or urlsplit(value).scheme: continue
                            path=unquote(urlsplit(value).path)
                            if path:
                                resolved=posixpath.normpath(posixpath.join(posixpath.dirname(inner.page),path))
                                self.assertIn(resolved,payload,(inner.page,value))
                for page in ('app/sample-report.html','docs/使い方.html'):
                    links=Links();links.page=page;links.feed(payload[page].decode())

    def test_extracted_verifier_covers_launcher_outside_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);asset=self.fixture(root)
            record=build_release.build(asset,dict(python='3.13.17',release='fixture',source='fixture'),root/'out',root)
            with zipfile.ZipFile(root/'out'/record['file']) as archive: archive.extractall(root/'extracted')
            package=next((root/'extracted').iterdir())
            verifier=package/'app/verify_package.py'
            result=subprocess.run([sys.executable,'-B',str(verifier)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            (package/'診断を開始.cmd').write_text('changed')
            result=subprocess.run([sys.executable,'-B',str(verifier)],capture_output=True,text=True)
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertIn('MISMATCH: 診断を開始.cmd',result.stdout)

    def test_changed_runtime_cannot_be_packaged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);asset=self.fixture(root);asset['sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'SHA-256'):
                build_release.build(asset,{},root/'out',root)

    def test_archive_cannot_write_outside_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);asset=self.fixture(root,'python/../../escape')
            with self.assertRaises(tarfile.FilterError):
                build_release.build(asset,{},root/'out',root)


if __name__=='__main__': unittest.main()
