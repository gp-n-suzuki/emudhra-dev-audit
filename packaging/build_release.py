"""Build six offline distributions from checksum-pinned runtimes (Python 3.12+)."""
import argparse
import copy
import gzip
import hashlib
import html
import json
from pathlib import Path
import posixpath
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from fetch_runtimes import sha256

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from distribution_version import VERSION, DISPLAY_VERSION, TAG
EPOCH=1793577600  # 2026-11-02 00:00 UTC
APP_FILES=(
    'docker_registry.py',
    'report_actions.py','report_summary.py','ai_prompts.py','references/ai-answer-rules-ja.txt','references/ai-item-rules-ja.txt',
    'audit.py','distribution_version.py','evidence.py','verdicts.py','official_versions.py','version_inference.py','browser_results.py','php_diagnostics.py','reporting.py','remediation.py','desktop_entry.py','app_inventory.py','language_checks.py','tool_catalog.py','package_checks.py','p2_coverage.py','p2_settings.py','safechain_probe.py',
    'ui.css','report-ui.js','verify_package.py','research_rules.py','release_evidence.py','reassess_report.py','installed_metadata.py','references/official-research.json','connection_evidence.py','presentation.py',
    'sample-report.html',
    'references/assessment.json','references/java-blocklist.json',
    'probes/python_probe.py','probes/pipx_probe.py','probes/node_probe.cjs','probes/npm_probe.cjs','probes/safechain_preflight.py','probes/safechain_supervisor.py','probes/TLSProbe.java',
    'probes/go_probe.go','probes/ruby_probe.rb','probes/ruby_connection_observer.rb','probes/php_probe.php','probes/php_curl_probe.php',
    'probes/php_info.php','probes/macos_probe.swift','probes/dotnet_probe.ps1','probes/dotnet_http_probe.cs','probes/powershell_web_probe.ps1',
    'probes/fetch_probe.mjs','probes/dart_probe.dart','probes/perl_probe.pl','probes/beam_probe.erl','probes/beam_probe.exs','probes/poetry_probe.py','probes/azure_entry.py',
)
FILES=APP_FILES+('run-checks.cmd','run-checks.sh','packaging/start-diagnosis.cmd','packaging/start-diagnosis.sh',
                 'packaging/user-guide.html','THIRD-PARTY-NOTICES.txt','P2-COVERAGE-ja.md','OFFICIAL-DECISIONS-ja.md','ACTION-PRESENTATION-ja.md','VALIDATION-ja.md')
PLATFORMS={
    'windows-x64':('windows','Windows / Intel・AMD'),
    'windows-arm64':('windows','Windows / ARM'),
    'macos-arm64':('mac','macOS / Apple Silicon'),
    'macos-x64':('mac','macOS / Intel'),
    'linux-x64':('linux','Linux / Intel・AMD'),
    'linux-arm64':('linux','Linux / ARM'),
}


def entry_name(platform):
    extension='cmd' if platform.startswith('windows') else 'command' if platform.startswith('macos') else 'sh'
    return '診断を開始.'+extension


def stage_files(source, stage, platform):
    """One visible entry point; implementation and reference material stay below it."""
    os_key, label=PLATFORMS[platform]
    windows=os_key=='windows'
    launcher='run-checks.cmd' if windows else 'run-checks.sh'
    for relative in APP_FILES+(launcher,):
        target=stage/'app'/relative; target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source/relative,target)
    if windows:
        script=stage/'app'/launcher
        script.write_bytes(script.read_text().replace('\r\n','\n').replace('\n','\r\n').encode('ascii'))
    else:
        (stage/'app'/launcher).chmod(0o755)
    entry=entry_name(platform)
    start=(source/('packaging/start-diagnosis.cmd' if windows else 'packaging/start-diagnosis.sh')).read_text(encoding='utf-8')
    (stage/entry).write_bytes(start.replace('\n','\r\n').encode('utf-8') if windows else start.encode('utf-8'))
    if not windows: (stage/entry).chmod(0o755)
    sample=stage/'app/sample-report.html'
    sample.write_text(sample.read_text(encoding='utf-8').replace('"START-HERE.html"','"../docs/使い方.html"').replace('開始ページへ戻る','使い方を見る'),encoding='utf-8')
    docs=stage/'docs'; docs.mkdir()
    command="& '.\\app\\runtime\\python.exe' -E -s -B '.\\app\\audit.py'" if windows else "bash './app/run-checks.sh'"
    verifier=".\\app\\runtime\\python.exe -E -s -B .\\app\\verify_package.py" if windows else "./app/runtime/bin/python3 -E -s -B ./app/verify_package.py"
    guide=(source/'packaging/user-guide.html').read_text(encoding='utf-8')
    project='C:\\work\\my-project' if windows else '/Users/user/work/my-project' if os_key=='mac' else '/home/user/work/my-project'
    start_action='ダブルクリックして「実行」を選びます。' if os_key=='linux' else 'ダブルクリックします。'
    for key,value in (('COMMAND',command),('VERIFY',verifier),('PLATFORM',label),('PROJECT',project),('VERSION',DISPLAY_VERSION),('ENTRY',entry),('START_ACTION',start_action)):
        guide=guide.replace('{{'+key+'}}',html.escape(value))
    (docs/'使い方.html').write_text(guide,encoding='utf-8')
    shutil.copyfile(source/'P2-COVERAGE-ja.md',docs/'P2-COVERAGE-ja.md')
    shutil.copyfile(source/'OFFICIAL-DECISIONS-ja.md',docs/'OFFICIAL-DECISIONS-ja.md')
    shutil.copyfile(source/'ACTION-PRESENTATION-ja.md',docs/'ACTION-PRESENTATION-ja.md')
    shutil.copyfile(source/'VALIDATION-ja.md',docs/'VALIDATION-ja.md')
    shutil.copyfile(source/'THIRD-PARTY-NOTICES.txt',docs/'THIRD-PARTY-NOTICES.txt')
    shutil.copytree(source/'packaging/upstream-licenses',docs/'licenses/python-build-standalone')


def runtime_members(archive):
    members={}
    for member in archive.getmembers():
        name=member.name
        if ('\\' in name or name.startswith('/') or '..' in name.split('/') or
            (name!='python' and not name.startswith('python/')) or name in members):
            raise tarfile.FilterError('Unsafe runtime archive path: '+name)
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise tarfile.FilterError('Unsupported runtime archive entry: '+name)
        if member.issym() or member.islnk():
            target=posixpath.normpath(posixpath.join(posixpath.dirname(name),member.linkname)
                                     if member.issym() else member.linkname)
            if '\\' in target or (target!='python' and not target.startswith('python/')):
                raise tarfile.FilterError('External runtime link: '+name)
        members[name]=member
    return members


def regular_target(member,members):
    seen=set()
    while member.issym() or member.islnk():
        if member.name in seen: raise tarfile.FilterError('Cyclic runtime link')
        seen.add(member.name)
        target=posixpath.normpath(posixpath.join(posixpath.dirname(member.name),member.linkname)
                                 if member.issym() else member.linkname)
        member=members[target]
    return member if member.isfile() else None


def stream_hash(stream):
    digest=hashlib.sha256()
    for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
    return digest.hexdigest()


def build(asset, manifest, output, source=ROOT):
    cache=source/'.artifacts/runtime-cache'/asset['filename']
    if sha256(cache)!=asset['sha256']:
        raise ValueError('Runtime SHA-256 mismatch: '+asset['platform'])
    name='emudhra-dev-audit-'+VERSION+'-'+asset['platform']
    output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='emudhra-release-') as tmp, tarfile.open(cache) as runtime:
        stage=Path(tmp)/name; stage.mkdir()
        members=runtime_members(runtime)
        executable='python/python.exe' if asset['platform'].startswith('windows') else 'python/bin/python3'
        if executable not in members or not regular_target(members[executable],members):
            raise ValueError('Runtime executable missing')
        stage_files(source,stage,asset['platform'])
        info=dict(asset,python=manifest['python'],release=manifest['release'],source=manifest['source'],
                  purpose='Diagnostic controller only; never substitutes for installed development runtimes.')
        (stage/'app/RUNTIME.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        checks=[]
        hashes={}
        for member in members.values():
            if member.isfile():
                with runtime.extractfile(member) as stream: hashes[member.name]=stream_hash(stream)
        for member in members.values():
            target=regular_target(member,members)
            if target:
                checks.append(hashes[target.name]+'  app/runtime/'+member.name[len('python/'):])
        for path in sorted(stage.rglob('*')):
            if path.is_file(): checks.append(sha256(path)+'  '+path.relative_to(stage).as_posix())
        (stage/'docs/SHA256SUMS.txt').write_text('\n'.join(sorted(checks,key=lambda s:s.split('  ',1)[1]))+'\n',encoding='utf-8')
        if asset['platform'].startswith('windows'):
            dest=output/(name+'.zip')
            with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
                for path in sorted(stage.rglob('*')):
                    if path.is_file():
                        info=zipfile.ZipInfo(name+'/'+path.relative_to(stage).as_posix(),time.gmtime(EPOCH)[:6])
                        info.compress_type=zipfile.ZIP_DEFLATED
                        info.external_attr=path.stat().st_mode << 16
                        with path.open('rb') as original, archive.open(info,'w') as target:
                            shutil.copyfileobj(original,target)
                for member in members.values():
                    target=regular_target(member,members)
                    if target:
                        info=zipfile.ZipInfo(name+'/app/runtime/'+member.name[len('python/'):],time.gmtime(EPOCH)[:6])
                        info.compress_type=zipfile.ZIP_DEFLATED
                        info.external_attr=(0o100000 | member.mode) << 16
                        with runtime.extractfile(target) as original, archive.open(info,'w') as deststream:
                            shutil.copyfileobj(original,deststream)
        else:
            dest=output/(name+'.tar.gz')
            def normalize(info):
                info.uid=info.gid=0; info.uname=info.gname=''; info.mtime=EPOCH
                return info
            with dest.open('wb') as stream, gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=EPOCH) as compressed:
                with tarfile.open(fileobj=compressed,mode='w') as archive:
                    archive.add(stage,arcname=name,filter=normalize)
                    # Stream Linux's case-sensitive terminfo entries and links without
                    # extracting them onto a potentially case-insensitive macOS volume.
                    for member in members.values():
                        info=copy.copy(member)
                        info.name=name+'/app/runtime'+member.name[len('python'):]
                        if info.islnk(): info.linkname=name+'/app/runtime'+info.linkname[len('python'):]
                        normalize(info)
                        if member.isfile():
                            with runtime.extractfile(member) as original: archive.addfile(info,original)
                        else: archive.addfile(info)
        return dict(file=dest.name,sha256=sha256(dest),bytes=dest.stat().st_size,platform=asset['platform'],
                    files=len(checks))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',action='append')
    parser.add_argument('--out',type=Path,default=ROOT/'releases'/VERSION)
    args=parser.parse_args()
    manifest=json.loads((ROOT/'packaging/runtimes.json').read_text())
    assets=[a for a in manifest['assets'] if not args.platform or a['platform'] in args.platform]
    if not assets or (args.platform and set(args.platform)-{a['platform'] for a in assets}):
        parser.error('Unknown platform')
    results=[]
    for asset in assets:
        record=build(asset,manifest,args.out)
        results.append(record)
        print(json.dumps(record),flush=True)
    (args.out/'release-manifest.json').write_text(json.dumps(dict(version=VERSION,display_version=DISPLAY_VERSION,tag=TAG,runtimes=manifest,packages=results),indent=2)+'\n',encoding='utf-8')
    (args.out/'SHA256SUMS.txt').write_text(''.join(r['sha256']+'  '+r['file']+'\n' for r in results))


if __name__=='__main__': main()
