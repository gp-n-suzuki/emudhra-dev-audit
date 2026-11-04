"""Exercise the shipped double-click launcher with a local fixture and recorded opener."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def verify(base):
    base=Path(base).resolve()
    entry=next(base.glob('診断を開始.*'))
    with tempfile.TemporaryDirectory(prefix='起動確認 日本語 & ') as tmp:
        root=Path(tmp).resolve(); app=root/'app'; app.mkdir()
        shutil.copyfile(base/'app/desktop_entry.py',app/'desktop_entry.py')
        shutil.copyfile(entry,root/entry.name)
        # Never modify the release payload or require a real desktop in a container.
        if os.name=='nt': shutil.copytree(base/'app/runtime',app/'runtime')
        else: (app/'runtime').symlink_to(base/'app/runtime',target_is_directory=True)
        (app/'audit.py').write_text('''import json, os, subprocess
from pathlib import Path
from types import SimpleNamespace

def record_open(path):
    report=Path(path)
    assert report.is_file(), 'opened before report existed'
    (report.parent/'opened.json').write_text(json.dumps(str(report)), encoding='utf-8')

def open_command(command, **kwargs):
    record_open(command[1])
    return SimpleNamespace(returncode=0)

os.startfile=record_open
subprocess.run=open_command

def main(arguments):
    assert '--project' not in arguments
    output=Path(arguments[arguments.index('--out')+1])
    (output/'report.html').write_text('<h1>Launcher test</h1>', encoding='utf-8')
    return 2
''',encoding='utf-8')
        if os.name=='nt':
            command=subprocess.list2cmdline([os.environ['COMSPEC']])+' /d /s /c "'+subprocess.list2cmdline([str(root/entry.name)])+'"'
        else: command=['/bin/bash',str(root/entry.name)]
        for _ in range(2):
            result=subprocess.run(command,cwd=base.parent,env=dict(os.environ,PATH=r'C:\no-python' if os.name=='nt' else '/no-python'),
                                  stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
            assert result.returncode==0,(result.returncode,result.stdout.decode('utf-8','replace'),result.stderr.decode('utf-8','replace'))
        reports=list((root/'結果').glob('*/report.html'))
        assert len(reports)==2
        for report in reports:
            assert json.loads((report.parent/'opened.json').read_text(encoding='utf-8'))==str(report)
        print('DESKTOP_LAUNCHER_SMOKE_OK: independent cwd, Unicode/spaces, verdict 2 opens, two reports retained',flush=True)


if __name__=='__main__': verify(sys.argv[1])
