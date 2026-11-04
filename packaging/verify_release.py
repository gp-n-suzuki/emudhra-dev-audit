"""Offline archive QA; checks every payload and the native executable's CPU."""
import argparse
import io
import json
from pathlib import Path
import struct
import tarfile
import zipfile
from build_release import APP_FILES, entry_name, regular_target, stream_hash
from fetch_runtimes import sha256


def verify(path,record):
    assert sha256(path)==record['sha256'], 'Outer archive hash mismatch'
    hashes={}; saved={}
    if path.suffix=='.zip':
        with zipfile.ZipFile(path) as archive:
            names=archive.namelist()
            for name in names:
                if name.endswith('/'): continue
                with archive.open(name) as stream: hashes[name]=stream_hash(stream)
                if name.endswith(('/SHA256SUMS.txt','/RUNTIME.json','/run-checks.cmd','/runtime/python.exe')):
                    with archive.open(name) as stream: saved[name]=stream.read(1024*1024)
    else:
        with tarfile.open(path) as archive:
            members={m.name:m for m in archive.getmembers()}; names=list(members)
            for member in members.values():
                if member.isfile():
                    with archive.extractfile(member) as stream: hashes[member.name]=stream_hash(stream)
                    if member.name.endswith(('/SHA256SUMS.txt','/RUNTIME.json','/runtime/bin/python3.13')):
                        with archive.extractfile(member) as stream: saved[member.name]=stream.read(1024*1024)
            for member in members.values():
                if member.issym() or member.islnk():
                    target=regular_target(member,members)
                    if target: hashes[member.name]=hashes[target.name]
    roots={n.split('/')[0] for n in names}
    assert len(roots)==1, 'Multiple archive roots'
    root=roots.pop()
    assert not any(p in ('.git','.artifacts','.env','report') or p.startswith('.env.') for n in names for p in n.split('/'))
    assert {n[len(root)+1:].split('/')[0] for n in names if n!=root}=={entry_name(record['platform']),'app','docs'}, 'Unexpected top-level entries'
    assert all(root+'/app/'+relative in names for relative in APP_FILES), 'Required application module or probe missing'
    assert root+'/docs/P2-COVERAGE-ja.md' in names, 'Target coverage notes missing'
    assert root+'/docs/OFFICIAL-DECISIONS-ja.md' in names, 'Official decision notes missing'
    assert root+'/docs/ACTION-PRESENTATION-ja.md' in names, 'Action/axis explanation missing'
    assert root+'/docs/VALIDATION-ja.md' in names, 'OS/CPU execution limits missing'
    assert not any(n.startswith(root+'/app/tests/') or n.endswith(('/TESTING.md','/run-checks.ps1','/browser-check.html','/browser-ui.js')) for n in names)
    manifest=saved[root+'/docs/SHA256SUMS.txt'].decode()
    expected={root+'/'+relative:digest for line in manifest.splitlines() for digest,relative in [line.split('  ',1)]}
    assert len(expected)==record['files']
    assert set(hashes)-{root+'/docs/SHA256SUMS.txt'}==set(expected), 'Missing/unlisted files'
    assert all(hashes[n]==digest for n,digest in expected.items()), 'Payload hash mismatch'
    runtime=json.loads(saved[root+'/app/RUNTIME.json'])
    assert runtime['platform']==record['platform'] and runtime['python']=='3.13.18'
    platform=record['platform']; arm=platform.endswith('arm64')
    if platform.startswith('windows'):
        assert root+'/app/run-checks.sh' not in names
        header=saved[root+'/app/runtime/python.exe']
        pe=struct.unpack_from('<I',header,0x3c)[0]
        assert header[:2]==b'MZ' and header[pe:pe+4]==b'PE\0\0'
        assert struct.unpack_from('<H',header,pe+4)[0]==(0xaa64 if arm else 0x8664)
        assert b'\r\n' in saved[root+'/app/run-checks.cmd']
    else:
        assert root+'/app/run-checks.cmd' not in names
        header=saved[root+'/app/runtime/bin/python3.13']
        if platform.startswith('linux'):
            assert header[:4]==b'\x7fELF'
            assert struct.unpack_from('<H',header,18)[0]==(183 if arm else 62)
        else:
            assert header[:4]==b'\xcf\xfa\xed\xfe'
            assert struct.unpack_from('<I',header,4)[0]==(0x100000c if arm else 0x1000007)
    return dict(platform=platform,files=len(expected),hashes='verified',cpu='verified')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    args=parser.parse_args()
    records=json.loads((args.directory/'release-manifest.json').read_text())['packages']
    assert {r['platform'] for r in records}=={'windows-x64','windows-arm64','macos-x64','macos-arm64','linux-x64','linux-arm64'}
    results=[verify(args.directory/r['file'],r) for r in records]
    (args.directory/'archive-verification.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__=='__main__': main()
