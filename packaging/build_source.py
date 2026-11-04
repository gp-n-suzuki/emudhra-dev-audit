"""Create a current-source candidate from an explicit list, without Git history."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from distribution_version import VERSION, DISPLAY_VERSION, TAG


def build(output):
    names=(ROOT/'packaging/source-files.txt').read_text(encoding='utf-8').splitlines()
    assert len(names)==len(set(names)), 'Duplicate source paths'
    for name in names:
        path=PurePosixPath(name)
        assert not path.is_absolute() and '..' not in path.parts
        assert not set(path.parts)&{'.git','.artifacts','releases','結果','__pycache__'}
        source=ROOT/name
        assert source.is_file() and not source.is_symlink(),name
    for name in ('tests/fixtures/display-corrections-2.7.8.json','tests/fixtures/safechain-2.7.6.json'):
        for item in json.loads((ROOT/name).read_text(encoding='utf-8')):
            row=item.get('record',item)
            assert row['metadata'].get('fixture_origin')=='synthetic-v1', 'Non-synthetic fixture'
    output.mkdir(parents=True,exist_ok=False)
    target=output/'emudhra-dev-audit'
    records=[]
    for name in names:
        source=ROOT/name;dest=target/name
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,dest)
        digest=hashlib.sha256(dest.read_bytes()).hexdigest()
        records.append(dict(path=name,bytes=dest.stat().st_size,sha256=digest))
    result=dict(version=VERSION,display_version=DISPLAY_VERSION,tag=TAG,
                git_history_included=False,diagnostic_reports_included=False,
                files=records)
    (output/'source-manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(version=VERSION,files=len(records),git_history_included=False)))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=ROOT/'releases'/(VERSION+'-public-source'))
    build(parser.parse_args().out)
