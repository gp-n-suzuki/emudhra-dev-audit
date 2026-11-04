"""Run with the packaged Python on its target OS; no live scan or network test."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import subprocess
import sys
import tempfile
from desktop_smoke import verify as verify_desktop


def verify(base):
    base=Path(base).resolve()
    app=base/'app'
    version=runpy.run_path(str(app/'distribution_version.py'))['VERSION']
    runtime=app/('runtime/python.exe' if os.name=='nt' else 'runtime/bin/python3')
    env=dict(os.environ,PATH=r'C:\no-python' if os.name=='nt' else '/no-python',PYTHONDONTWRITEBYTECODE='1')

    def run(command):
        result=subprocess.run(command if isinstance(command,str) else [str(x) for x in command],env=env,cwd=base.parent,
                              capture_output=True,text=True,encoding='utf-8',timeout=90)
        assert result.returncode==0,(result.returncode,result.stdout[-2000:],result.stderr[-2000:])
        return result.stdout

    run([runtime,'-E','-s','-B',app/'verify_package.py'])
    if os.name=='nt':
        command=(subprocess.list2cmdline([os.environ['COMSPEC']])+' /d /s /c "'+
                 subprocess.list2cmdline([str(app/'run-checks.cmd'),'--help'])+'"')
        help_text=run(command)
    else:
        help_text=run(['/bin/bash',app/'run-checks.sh','--help'])
    assert 'eMudhra開発環境診断' in help_text
    with tempfile.TemporaryDirectory(prefix='保存済み合成データ 空白 ') as temporary:
        root=Path(temporary)
        source=root/'synthetic.json'
        source.write_text(json.dumps(dict(schema_version=3,tool_version=version,
            generated_at='synthetic fixture; no observation date',records=[
                dict(name='Go / バージョン',status='UPDATE',assessment_method='version',
                     detail='Synthetic old-version fixture',action='確認',samples=[],
                     metadata=dict(tool_id='go',tool_name='Go',executable='/fixture/go',
                                   version='1.23.0',reference_floor='1.26.10')),
                dict(name='Go / 普段の設定',status='MANUAL',assessment_method='manual',
                     detail='Synthetic unmeasured fixture',action='確認',samples=[],
                     metadata=dict(tool_id='go',tool_name='Go',executable='/fixture/go'))]),
            ensure_ascii=False),encoding='utf-8')
        before=hashlib.sha256(source.read_bytes()).hexdigest()
        run([runtime,'-E','-s','-B',app/'reassess_report.py',source,'--out',root/'output'])
        report=json.loads((root/'output/report.json').read_text(encoding='utf-8'))
        proof=json.loads((root/'output/reassessment.json').read_text(encoding='utf-8'))
        assert report['tool_version']==version
        assert report['schema_version']==3 and report['presentation']['schema_version']==1
        assert report['presentation']['primary_action_counts']['update']==1
        assert proof['new_observations']==0 and proof['communication_evidence_unchanged']
        assert hashlib.sha256(source.read_bytes()).hexdigest()==before
        assert all((root/'output'/n).is_file() for n in ('report.html','report.json','summary.txt'))
    verify_desktop(base)
    result=dict(version=version,os=platform.system(),machine=platform.machine(),python=platform.python_version(),
                hash_check=True,help=True,saved_synthetic_reassessment=True,launcher_fixture=True,
                new_live_scan=False,new_network_test=False,browser_ui_verified=False)
    print(json.dumps(result,ensure_ascii=False))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base',type=Path)
    verify(parser.parse_args().base)
