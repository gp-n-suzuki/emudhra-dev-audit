"""Verify extracted package files without inspecting any development environment."""
import hashlib
from pathlib import Path
import sys


def main():
    root=Path(__file__).resolve().parent
    manifest=root/'SHA256SUMS.txt'
    if root.name=='app':
        root=root.parent
        manifest=root/'docs/SHA256SUMS.txt'
    failed=[]; count=0
    for line in manifest.read_text(encoding='utf-8').splitlines():
        expected,relative=line.split('  ',1)
        path=root/relative
        if root not in path.resolve().parents or not path.is_file():
            failed.append(relative); continue
        digest=hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
        count+=1
        if digest.hexdigest()!=expected: failed.append(relative)
    for relative in failed: print('MISMATCH: '+relative)
    print('SHA-256 verified: {} files; failures: {}'.format(count,len(failed)))
    return 2 if failed else 0


if __name__=='__main__': sys.exit(main())
