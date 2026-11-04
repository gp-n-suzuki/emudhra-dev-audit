"""Scoped checks of installed package-manager transports."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from urllib.parse import urlsplit

import app_inventory
import connection_evidence
import evidence
import verdicts


TOOLS = {'go': ('Go', 'Go Modules'), 'uv': ('uv', 'パッケージ管理'),
         'cargo': ('Cargo', 'registry'), 'rubygems': ('RubyGems', 'gem source'),
         'bundler': ('Bundler', 'gem source'),
         'composer': ('Composer', 'repository'), 'pnpm': ('pnpm', 'registry'),
         'yarn': ('Yarn', 'registry'),
         'kubectl': ('kubectl', '診断用API'), 'aws': ('AWS CLI', '診断用API'),
         'helm': ('Helm', 'repository'),
         'rustup': ('rustup', '更新情報'),
         'git-lfs': ('Git LFS', 'ロックAPI'),
         'pipx': ('pipx', '共有pip'),
         'poetry': ('Poetry', 'HTTP transport'),
         'azure': ('Azure CLI', '診断用REST'),
         'mamba': ('Mamba', 'channel'),
         'rclone': ('rclone', 'HTTP backend'),
         'osv-scanner': ('OSV-Scanner', '公式API')}
AMBIGUOUS_TRANSPORT = re.compile(
    r'proxyconnect|proxy\s+(?:connect|returned|error|failed|handshake)|'
    r'time.?out|timed out|context deadline|no such host|name resolution|'
    r'connection (?:refused|reset|closed|aborted|error)|failed to connect|could not resolve|'
    r'network error|error sending request|hostname|'
    r'certificate (?:has )?expired|not yet valid|redirect', re.I)
ANY_TLS_OR_TRANSPORT_FAILURE = re.compile(
    r'certificate|x509|\btls\b|\bssl\b|proxyconnect|proxy\s+(?:connect|returned|error|failed|handshake)|'
    r'time.?out|timed out|context deadline|no such host|name resolution|'
    r'connection (?:refused|reset|closed|aborted|error)|failed to connect|could not resolve|'
    r'network error|error sending request|hostname|redirect', re.I)


def native(path):
    try:
        path = Path(path)
        if not app_inventory.safe(path) or '/shims/' in str(path).replace('\\','/').lower():
            return False
        with path.open('rb') as stream: return stream.read(16).startswith(app_inventory.NATIVE_MAGIC)
    except (OSError, ValueError):
        return False


def safe_target(url):
    try:
        parsed=urlsplit(url)
        return (parsed.scheme == 'https' and bool(parsed.hostname) and parsed.port != 0 and '@' not in parsed.netloc and
                not parsed.username and not parsed.password and not parsed.fragment and
                not any(c in url for c in '\r\n\t "\'\\{}'))
    except (TypeError, ValueError):
        return False


def withheld(tool):
    truthy=lambda name: os.environ.get(name,'').strip().lower() in ('1','true','yes','on')
    proxy_names=('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy','CARGO_HTTP_PROXY')
    if any('@' in os.environ.get(name,'') for name in proxy_names):
        return '認証情報を含むproxy設定があるため、診断用の通信を見送りました。'
    if tool == 'go' and os.environ.get('GOPROXY','').strip().lower().split(',')[0] == 'off':
        return 'GOPROXYがオフのため通信検査を見送りました。'
    if tool == 'uv' and truthy('UV_OFFLINE'):
        return 'uvのオフライン設定により通信検査を見送りました。'
    if tool == 'uv' and os.environ.get('UV_INSECURE_HOST'):
        return 'uvに検証を緩めるホスト設定があるため通信検査を見送りました。'
    if tool == 'cargo' and truthy('CARGO_NET_OFFLINE'):
        return 'Cargoのオフライン設定により通信検査を見送りました。'
    if tool == 'cargo' and os.name == 'nt' and os.environ.get('CARGO_HTTP_CHECK_REVOKE','').lower() == 'false':
        return 'Cargoの失効確認が無効のため通信検査を見送りました。'
    if tool == 'rclone' and truthy('RCLONE_NO_CHECK_CERTIFICATE'):
        return 'rcloneの証明書検証が無効のため通信検査を見送りました。'
    if tool in ('pnpm','yarn') and os.environ.get('NODE_TLS_REJECT_UNAUTHORIZED') == '0':
        return 'Node.jsの証明書検証が無効のため通信検査を見送りました。'
    if tool == 'yarn' and truthy('YARN_ENABLE_OFFLINE_MODE'):
        return 'Yarnのオフライン設定により通信検査を見送りました。'
    if tool == 'yarn' and os.environ.get('YARN_ENABLE_STRICT_SSL','').lower() in ('false','0'):
        return 'Yarnの証明書検証が無効のため通信検査を見送りました。'
    if tool == 'bundler' and os.environ.get('BUNDLE_SSL_VERIFY_MODE','').strip() == '0':
        return 'Bundlerの証明書検証が無効のため通信検査を見送りました。'
    if tool == 'azure' and os.environ.get('AZURE_CLI_DISABLE_CONNECTION_VERIFICATION'):
        return 'Azure CLIの証明書検証を無効にする環境変数があるため通信検査を見送りました。'
    if tool == 'pipx' and (os.environ.get('PIP_TRUSTED_HOST') or os.environ.get('PIP_CLIENT_CERT')):
        return 'pipの検証緩和またはクライアント証明書が指定されているため通信検査を見送りました。'
    if tool == 'mamba' and (truthy('CONDA_OFFLINE') or truthy('MAMBA_OFFLINE')):
        return 'Mambaのオフライン設定により通信検査を見送りました。'
    if tool == 'mamba' and any(os.environ.get(key,'').strip().lower() in ('false','0','no','off')
                               for key in ('CONDA_SSL_VERIFY','MAMBA_SSL_VERIFY')):
        return 'Mambaの証明書検証を無効にする設定があるため通信検査を見送りました。'
    return ''


def isolated_environment(work):
    """Only TLS/proxy and OS bootstrap settings cross into the diagnostic child."""
    allowed = ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy',
               'NO_PROXY','no_proxy','SSL_CERT_FILE','SSL_CERT_DIR','UV_SYSTEM_CERTS',
               'CARGO_HTTP_CAINFO','CARGO_HTTP_PROXY_CAINFO','CARGO_HTTP_PROXY','CARGO_HTTP_CHECK_REVOKE',
               'COMPOSER_CAFILE','NODE_EXTRA_CA_CERTS','NODE_USE_SYSTEM_CA','BUNDLE_SSL_CA_CERT','AWS_CA_BUNDLE',
               'SYSTEMROOT','WINDIR','SYSTEMDRIVE')
    env = {name:os.environ[name] for name in allowed if name in os.environ}
    env.update(HOME=str(work), USERPROFILE=str(work), APPDATA=str(work),
               XDG_CONFIG_HOME=str(work), XDG_CACHE_HOME=str(work), PATH=os.defpath)
    return env


def transport_data(rc, detail, success):
    """Do not let a 404 or other success marker hide an independent failure."""
    if AMBIGUOUS_TRANSPORT.search(detail):
        return {'state':'unknown','detail':detail}
    if success and not ANY_TLS_OR_TRANSPORT_FAILURE.search(detail):
        return {'state':'accepted','detail':detail}
    return {'state':'error','detail':detail}


def scoped_classify(data, control, classify):
    if data.get('state')=='error' and AMBIGUOUS_TRANSPORT.search(data.get('detail','')):
        data=dict(data,state='unknown')
    status,detail=classify(data,control)
    observed=('connection' if data.get('state') == 'accepted' else 'connection_error'
              if (data.get('state')=='error' and data.get('origin_verified')) or
              ANY_TLS_OR_TRANSPORT_FAILURE.search(detail) or 'Bad CPU type in executable' in detail else 'unknown')
    if status == 'CONTROL_OK' and control and not data.get('origin_verified'):
        status='UNKNOWN'
        detail='通信応答を観測しましたが、proxyやリダイレクト先の応答と区別できません。 '+detail
    if status == 'REJECTED' and not control and not data.get('origin_verified'):
        status='UNKNOWN'
        detail='信頼エラーを観測しましたが、proxyやリダイレクト先のエラーと区別できません。 '+detail
    return status,detail,observed


def record_limited(audit, name, metadata, samples, scope, action):
    """Keep the observed diagnostic and the untested real configuration separate."""
    blocked=(len(samples) == 5 and samples[0]['status'] == 'CONTROL_OK' and
             all(sample['status'] == 'REJECTED' for sample in samples[1:]))
    accepted=any(not sample['control'] and sample['status']=='ACTION' for sample in samples)
    metadata=dict(metadata)
    proofs=[dict(target=sample['target'], **sample['connection_evidence'])
            for sample in samples if sample.get('connection_evidence')]
    if proofs:
        metadata['connection_evidence']=proofs
    if any(sample.get('observation') == 'connection_error' for sample in samples):
        metadata['diagnostic_observation']='connection_error'
    elif any(sample.get('observation') == 'connection' for sample in samples):
        metadata['diagnostic_observation']='response'
    row=audit.add(name+'（診断用設定）','ACTION' if accepted else 'REJECTED' if blocked else 'UNKNOWN',
        '診断用の設定で参照対象の証明書チェーンを受け入れました。' if accepted else
        '診断用の設定で検査用サイトへの接続をブロックしました。' if blocked else
        '診断用の設定での接続結果をすべて確認できませんでした。',
        metadata,samples,action='検査データの接続結果と、この実行環境の設定を確認してください。',required=not blocked)
    row['assessment_method']='measured'
    row['scope']='診断用設定: '+scope+(' 接続先・TLS判定の証拠と未確認範囲を検査データに記録。' if proofs else
                                     ' リダイレクト先のエラーかは特定できません。')
    audit.add(name+'（普段の設定）','MANUAL',
              '認証情報の送信を避けるため、普段使う設定での通信は確認していません。',
              dict(metadata),action=action,required=True)
    return row


def go_modules(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control = target
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='go-modules-', dir=str(audit.work)) as temporary:
            work=Path(temporary)
            env=isolated_environment(work)
            env.update(GOPROXY=url.rstrip('/'), GOAUTH='off', GOSUMDB='off',
                       GOENV='off', GOWORK='off', GO111MODULE='on', GOTOOLCHAIN='local',
                       GOPATH=str(work/'gopath'), GOMODCACHE=str(work/'modcache'), GOCACHE=str(work/'cache'))
            cmd=[path,'list','-m','-json','example.invalid/emudhra-audit-fixture@v0.0.0']
            rc,out,err=run(cmd, timeout=audit.args.timeout+5, env=env, cwd=work, inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            requested=url.rstrip('/')+'/example.invalid/emudhra-audit-fixture/@v/v0.0.0.info'
            response=re.search(r'\breading\s+'+re.escape(requested)+r':\s*(?:404\s+Not Found|410\s+Gone)(?:\s|$)',detail,re.I)
            try:
                result=json.loads(out)
                valid_result=(result.get('Path') == 'example.invalid/emudhra-audit-fixture' and result.get('Version') == 'v0.0.0')
            except (ValueError,TypeError,AttributeError):
                valid_result=False
            data=transport_data(rc,detail,rc != 124 and (bool(response) or (rc == 0 and valid_result)))
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Go / Go Modules',
        {'tool_id':'go','tool_name':'Go','executable':path,
         'source':'https://go.dev/ref/mod','probe':'synthetic_module_metadata'},samples,
        '選択したGo実行体と合成モジュール。ユーザー設定・認証・VCSへの直接接続は含みません。',
        '利用するGOPROXY・CA・proxyと、その環境での接続を確認してください。')


def uv_packages(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control = target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='uv-metadata-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            requirements=work/'requirements.in'
            requirements.write_text('emudhra-audit-fixture==0.0.0\n',encoding='utf-8')
            env=isolated_environment(work)
            env.update(UV_NO_ENV_FILE='1', UV_PYTHON_DOWNLOADS='never')
            cmd=[path,'pip','compile',str(requirements),'--index-url',url,
                 '--no-config','--no-cache','--no-build','--no-deps',
                 '--no-python-downloads','--python',sys.executable,'--no-progress','--keyring-provider','disabled']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            no_package='no solution found' in detail.lower() and 'not found in the package registry' in detail.lower()
            data=transport_data(rc,detail,rc != 124 and (rc == 0 or no_package))
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'uv / パッケージ管理',
        {'tool_id':'uv','tool_name':'uv','executable':path,
         'source':'https://docs.astral.sh/uv/reference/cli/','probe':'synthetic_package_metadata'},samples,
        '選択したuv実行体と合成要件のみ。利用者の設定・認証・パッケージの導入は含みません。',
        '利用するuvのindex・CA・proxy設定と、その環境での接続を確認してください。')


def cargo_is_shim(path):
    try:
        target=Path(path).resolve()
        sibling=Path(path).parent/('rustup.exe' if os.name == 'nt' else 'rustup')
        return target.stem.lower() == 'rustup' or (sibling.exists() and os.path.samefile(path,sibling))
    except (OSError, ValueError):
        return True


def gem_ruby(path):
    """Resolve only a Ruby shebang or a sibling Ruby; do not run shell shims."""
    try:
        if not app_inventory.safe(Path(path)): return None
        script=Path(path).resolve()
        if not app_inventory.safe(script) or '/shims/' in str(path).replace('\\','/').lower(): return None
        with script.open('rb') as stream: header=stream.readline(512).decode('utf-8','replace').strip()
        match=re.fullmatch(r'#!\s*(/[^\s]+)(?:\s+(ruby(?:[0-9.]*)?))?\s*',header)
        if not match: return None
        interpreter, argument=match.groups()
        if Path(interpreter).name == 'env' and argument:
            ruby=script.parent/('ruby.exe' if os.name == 'nt' else 'ruby')
        elif argument is None and re.fullmatch(r'ruby(?:[0-9.]*)?(?:\.exe)?',Path(interpreter).name,re.I):
            ruby=Path(interpreter)
        else:
            return None
        return str(ruby) if native(ruby) else None
    except (OSError, ValueError, RuntimeError):
        return None


def composer_php(path):
    try:
        if not app_inventory.safe(Path(path)): return None
        script=Path(path).resolve()
        if not app_inventory.safe(script) or '/shims/' in str(path).replace('\\','/').lower(): return None
        with script.open('rb') as stream: header=stream.readline(512).decode('utf-8','replace').strip()
        match=re.fullmatch(r'#!\s*(/[^\s]+)(?:\s+(php(?:[0-9.]*)?))?\s*',header)
        if not match: return None
        interpreter, argument=match.groups()
        if Path(interpreter).name == 'env' and argument:
            sibling=script.parent/('php.exe' if os.name == 'nt' else 'php')
            php=sibling if sibling.is_file() else Path(shutil.which(argument) or '')
        elif argument is None and re.fullmatch(r'php(?:[0-9.]*)?(?:\.exe)?',Path(interpreter).name,re.I):
            php=Path(interpreter)
        else:
            return None
        return str(php) if native(php) else None
    except (OSError, ValueError, RuntimeError):
        return None


def safe_module_tree(site):
    """Bound imports to a tree whose paths never pass through excluded env files."""
    def onerror(error): raise error
    count=0
    try:
        for folder,dirs,files in os.walk(site,followlinks=False,onerror=onerror):
            for name in dirs+files:
                candidate=Path(folder)/name; count+=1
                if count > 50000 or not app_inventory.safe(candidate) or (candidate.is_symlink() and candidate.is_dir()):
                    return False
        return True
    except (OSError,ValueError):
        return False


def isolated_python_site(prefix,required):
    try:
        prefix=Path(prefix)
        if not app_inventory.safe(prefix/'pyvenv.cfg'): return None
        sites=list((prefix/'lib').glob('python*/site-packages'))+[prefix/'Lib/site-packages']
        matches=[p for p in sites if app_inventory.safe(p) and all((p/x).is_file() and app_inventory.safe(p/x) for x in required)]
        if len(matches)!=1 or not safe_module_tree(matches[0]): return None
        return str(matches[0])
    except (OSError,ValueError,RuntimeError):
        return None


def poetry_python(path):
    """Recognize a Poetry console entry in its own Python virtual environment."""
    try:
        if not app_inventory.safe(Path(path)): return None
        script=Path(path).resolve()
        if not app_inventory.safe(script) or '/shims/' in str(path).replace('\\','/').lower(): return None
        raw=evidence.read_public_file(script,65536)
        if raw is None or b'from poetry.console.application import main' not in raw: return None
        bindir=script.parent
        if bindir.name.lower() not in ('bin','scripts') or not (bindir.parent/'pyvenv.cfg').is_file(): return None
        python=bindir/('python.exe' if bindir.name.lower() == 'scripts' else 'python')
        site=isolated_python_site(bindir.parent,('poetry/utils/authenticator.py','requests/__init__.py'))
        return (str(python),site,str(bindir.parent)) if site and native(python) else None
    except (OSError, ValueError, RuntimeError):
        return None


def azure_python(path):
    try:
        if not app_inventory.safe(Path(path)): return None
        script=Path(path).resolve()
        if not app_inventory.safe(script) or '/shims/' in str(path).replace('\\','/').lower(): return None
        raw=evidence.read_public_file(script,65536)
        if raw is None or b'azure.cli' not in raw: return None
        bindir=script.parent
        if bindir.name.lower() not in ('bin','scripts') or not (bindir.parent/'pyvenv.cfg').is_file(): return None
        python=bindir/('python.exe' if bindir.name.lower() == 'scripts' else 'python')
        site=isolated_python_site(bindir.parent,('azure/cli/__main__.py',))
        return (str(python),site,str(bindir.parent)) if site and native(python) else None
    except (OSError, ValueError, RuntimeError):
        return None


def pipx_pairs(path):
    """Find bounded managed environments whose .pth explicitly links pipx shared pip."""
    try:
        if not app_inventory.safe(Path(path)): return [],True
        home_setting=os.environ.get('PIPX_HOME')
        if home_setting:
            home=Path(home_setting).expanduser()
        else:
            resolved=Path(path).resolve()
            inferred=resolved.parent.parent
            if inferred.name == 'pipx' and inferred.parent.name == 'venvs':
                home=inferred.parent.parent
            else:
                user=Path.home(); legacy=user/'.local/pipx'
                if legacy.is_dir(): home=legacy
                elif os.name == 'nt' and (user/'pipx').is_dir(): home=user/'pipx'
                elif os.environ.get('XDG_DATA_HOME'): home=Path(os.environ['XDG_DATA_HOME'])/'pipx'
                elif sys.platform == 'darwin': home=user/'Library/Application Support/pipx'
                elif os.name == 'nt': home=Path(os.environ.get('LOCALAPPDATA') or user/'AppData/Local')/'pipx/pipx'
                else: home=user/'.local/share/pipx'
        shared_root=Path(os.environ.get('PIPX_SHARED_LIBS') or home/'shared').expanduser()
        if not app_inventory.safe(home) or not app_inventory.safe(shared_root): return [],True
        venvs=home/'venvs'; pairs=[]; limited=False
        if not venvs.is_dir(): return [],False
        if not app_inventory.safe(venvs): return [],True
        for index,venv in enumerate(sorted(venvs.iterdir())):
            if index >= 64 or len(pairs) >= 8:
                limited=True; break
            if not app_inventory.safe(venv) or not venv.is_dir() or not app_inventory.safe(venv/'pyvenv.cfg') or not (venv/'pyvenv.cfg').is_file(): continue
            python=venv/('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
            if not native(python): continue
            links=list(venv.glob('lib/python*/site-packages/pipx_shared.pth'))
            links+=list(venv.glob('Lib/site-packages/pipx_shared.pth'))
            if len(links) != 1: continue
            raw=evidence.read_public_file(links[0],4096)
            if raw is None: limited=True; continue
            lines=[line.strip() for line in raw.decode('utf-8').splitlines() if line.strip() and not line.lstrip().startswith('#')]
            if len(lines) != 1 or lines[0].startswith(('import ','import\t')): continue
            site=Path(lines[0]); site=site if site.is_absolute() else links[0].parent/site
            if not app_inventory.safe(site) or not app_inventory.safe(site/'pip/__init__.py'): continue
            if shared_root.resolve() not in site.resolve().parents or not (site/'pip/__init__.py').is_file(): continue
            # Python will import pip modules; reject excluded aliases anywhere in that tree.
            if not safe_module_tree(site/'pip'):
                limited=True; continue
            pairs.append((str(python),str(site),str(venv)))
        return pairs,limited
    except (OSError,UnicodeError,ValueError,RuntimeError):
        return [],True


def node_manager(path, tool):
    """Use only identified direct Node CLIs; Corepack and download wrappers stay unexecuted."""
    try:
        if not app_inventory.safe(Path(path)): return None
        script=Path(path).resolve()
        if not app_inventory.safe(script) or '/shims/' in str(path).replace('\\','/').lower(): return None
        with script.open('rb') as stream: header=stream.readline(512).decode('utf-8','replace').strip()
        match=re.fullmatch(r'#!\s*(/[^\s]+)(?:\s+(node))?\s*',header)
        if not match: return None
        executable, argument=match.groups()
        if Path(executable).name == 'env' and argument:
            node=shutil.which('node')
        elif argument is None and Path(executable).name == 'node':
            node=executable
        else: return None
        if not node or '/.volta/bin/' in node.replace('\\','/').lower() or not native(node): return None
        for parent in list(script.parents)[:5]:
            raw=evidence.read_public_file(parent/'package.json',65536)
            if raw is None: continue
            data=json.loads(raw)
            name,version=data.get('name',''),str(data.get('version',''))
            if name == 'corepack': return None
            if name != tool and not (tool == 'yarn' and name == '@yarnpkg/cli-dist'): continue
            match=re.fullmatch(r'(\d+)\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?',version)
            if not match: return None
            major=int(match.group(1))
            if tool == 'pnpm' and major != 11: return None
            return str(node),version
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError):
        pass
    return None


def node_registry(audit, path, node, version, tool, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix=tool+'-registry-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            (work/'package.json').write_text(json.dumps({'name':'emudhra-audit-project','private':True}),encoding='utf-8')
            config=work/'npmrc'; config.write_text('',encoding='utf-8')
            env=isolated_environment(work)
            env.update(COREPACK_ENABLE_NETWORK='0',CI='true',YARN_CACHE_FOLDER=str(work/'cache'),
                       npm_config_userconfig=str(config),npm_config_globalconfig=str(config),
                       NPM_CONFIG_USERCONFIG=str(config),NPM_CONFIG_GLOBALCONFIG=str(config),
                       npm_config_registry=url,pnpm_config_registry=url)
            berry=tool == 'yarn' and int(version.split('.',1)[0]) >= 2
            if berry:
                env.update(YARN_NPM_REGISTRY_SERVER=url,YARN_ENABLE_TELEMETRY='0',
                           YARN_ENABLE_SCRIPTS='0',YARN_IGNORE_PATH='1')
                cmd=[node,path,'npm','info','emudhra-audit-fixture','--json']
            else:
                cmd=[node,path,'view' if tool=='pnpm' else 'info','emudhra-audit-fixture',
                     '--registry',url,'--json']
                if tool=='yarn': cmd.extend(['--non-interactive','--no-progress'])
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            valid=False
            for line in out.splitlines():
                try:
                    value=json.loads(line)
                    if isinstance(value,dict):
                        item=value.get('data') if tool=='yarn' and not berry else value
                        if isinstance(item,dict) and item.get('name')=='emudhra-audit-fixture': valid=True
                except (ValueError,TypeError): pass
            data=transport_data(rc,detail,rc == 0 and valid)
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    label='pnpm' if tool=='pnpm' else 'Yarn'
    record_limited(audit,label+' / registry',
        {'tool_id':tool,'tool_name':label,'executable':path,'runtime_executable':node,'version':version,
         'source':'https://pnpm.io/blog/releases/11.0' if tool=='pnpm' else
                  'https://yarnpkg.com/cli/npm/info' if int(version.split('.',1)[0]) >= 2 else 'https://classic.yarnpkg.com/en/docs/cli/info',
         'probe':'synthetic_node_registry'},samples,
        '選択したCLIとNode、合成registryのみ。利用者の設定・認証・パッケージの導入は含みません。',
        'このCLIのregistry・CA・proxy設定と、普段の環境での接続を確認してください。')


def composer_repository(audit, path, php, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='composer-repo-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            manifest={'name':'emudhra/audit-fixture','version':'0.0.0','require':{},
                      'repositories':[{'type':'composer','url':url},{'packagist.org':False}]}
            (work/'composer.json').write_text(json.dumps(manifest),encoding='utf-8')
            env=isolated_environment(work)
            env.update(COMPOSER_HOME=str(work/'home'),COMPOSER_CACHE_DIR=str(work/'cache'),
                       COMPOSER_NO_INTERACTION='1',COMPOSER_DISABLE_XDEBUG_WARN='1')
            cmd=[php,'-d','auto_prepend_file=','-d','auto_append_file=',path,'search',
                 'emudhra-audit-fixture','--only-name','--format=json','--no-interaction',
                 '--no-plugins','--no-scripts','--no-cache']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            # Composer can return an empty search without showing which source replied.
            data={'state':'unknown','detail':detail} if rc == 0 and not ANY_TLS_OR_TRANSPORT_FAILURE.search(detail) else transport_data(rc,detail,False)
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Composer / repository',
        {'tool_id':'composer','tool_name':'Composer','executable':path,'runtime_executable':php,
         'source':'https://getcomposer.org/doc/03-cli.md','probe':'synthetic_composer_search'},samples,
        '選択したComposerとPHP、一時的な合成repositoryのみ。利用者設定・認証・plugin・パッケージ導入は含みません。',
        '利用するComposerのrepository・CA・proxy設定と、その環境での接続を確認してください。')


def rubygems_source(audit, path, ruby, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='rubygems-source-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            env=isolated_environment(work)
            env.update(GEM_HOME=str(work/'gems'),GEM_PATH=str(work/'gems'),GEM_SPEC_CACHE=str(work/'cache'),RUBYOPT='')
            proof=work/'tls-evidence.jsonl'
            env.update(EMUDHRA_TLS_EVIDENCE=str(proof),EMUDHRA_TLS_TARGET=url)
            observer=Path(__file__).resolve().parent/'probes/ruby_connection_observer.rb'
            cmd=[ruby,'-r',str(observer),path,'search','^emudhra-audit-fixture$','--remote','--clear-sources',
                 '--source',url,'--norc','--verbose']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            origin=re.escape(url.rstrip('/')+'/')
            response=re.search(r'(?m)^GET\s+'+origin+r'(?:latest_)?specs\.\d+\.\d+\.gz\s*\n200\s+OK\b',detail,re.I)
            data=transport_data(rc,detail,rc == 0 and bool(response))
            observed=connection_evidence.ruby_socket(proof,url,rc,proxy_possible=any(
                env.get(key) for key in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy')))
            if observed:
                data=observed
            status,detail,observation=scoped_classify(data,control,classify)
            sample=dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
            if data.get('connection_evidence'):
                sample['connection_evidence']=data['connection_evidence']
            return sample
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'RubyGems / gem source',
        {'tool_id':'rubygems','tool_name':'RubyGems','executable':path,'runtime_executable':ruby,
         'source':'https://guides.rubygems.org/command-reference/','probe':'synthetic_gem_search'},samples,
        'このgemとそのRuby、合成sourceのみ。利用者設定・認証・gem導入は含みません。',
        '利用するRubyGemsのsource・CA・proxy設定と、その環境での接続を確認してください。')


def bundler_source(audit, path, ruby, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='bundler-source-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            gemfile=work/'Gemfile'
            gemfile.write_text('source '+json.dumps(url)+'\ngem "emudhra-audit-fixture", "= 0.0.0"\n',encoding='utf-8')
            env=isolated_environment(work)
            env.update(BUNDLE_IGNORE_CONFIG='1',BUNDLE_USER_HOME=str(work/'bundle'),
                       BUNDLE_APP_CONFIG=str(work/'bundle-config'),BUNDLE_PLUGINS='false',
                       BUNDLE_AUTO_INSTALL='false',BUNDLE_GEMFILE=str(gemfile),RUBYOPT='')
            proof=work/'tls-evidence.jsonl'
            env.update(EMUDHRA_TLS_EVIDENCE=str(proof),EMUDHRA_TLS_TARGET=url)
            observer=Path(__file__).resolve().parent/'probes/ruby_connection_observer.rb'
            # Older Bundler releases reject --gemfile on `lock`; the environment
            # variable selects the same isolated fixture across supported versions.
            cmd=[ruby,'-r',str(observer),path,'lock','--print']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            valid=rc == 0 and url in out and 'emudhra-audit-fixture' in out
            data=transport_data(rc,detail,valid)
            observed=connection_evidence.ruby_socket(proof,url,rc,proxy_possible=any(
                env.get(key) for key in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy')))
            if observed:
                data=observed
            status,detail,observation=scoped_classify(data,control,classify)
            sample=dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
            if data.get('connection_evidence'):
                sample['connection_evidence']=data['connection_evidence']
            return sample
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Bundler / gem source',
        {'tool_id':'bundler','tool_name':'Bundler','executable':path,'runtime_executable':ruby,
         'source':'https://bundler.io/man/bundle-lock.1.html','probe':'synthetic_bundle_lock'},samples,
        'このBundlerとRuby、合成Gemfileのみ。利用者設定・認証・gem導入・実プロジェクトのlockfileは含みません。',
        '利用するBundlerのsource・CA・proxy設定と、その環境での接続を確認してください。')


def cargo_registry(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='cargo-registry-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            env=isolated_environment(work)
            env.update(CARGO_HOME=str(work/'cargo'),CARGO_NET_RETRY='0',
                       CARGO_HTTP_TIMEOUT=str(int(audit.args.timeout)),RUSTUP_AUTO_INSTALL='0',
                       CARGO_HTTP_DEBUG='true',CARGO_LOG='network=debug',CARGO_TERM_COLOR='never')
            index='sparse+'+url.rstrip('/')+'/'
            cmd=[path,'search','--index',index,'--limit','1','emudhra-audit-fixture']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            config_url=url.rstrip('/')+'/config.json'
            response=re.search(r'failed to get (?:a 200|successful HTTP) response from\s*[`\'"]?'+
                               re.escape(config_url)+r'[`\'"]?[^\n]{0,120}\b(?:404|410)\b',detail,re.I)
            data=transport_data(rc,detail,rc != 124 and (rc == 0 or bool(response)))
            observed=connection_evidence.cargo_trace(err,url,rc,proxy_possible=any(
                env.get(key) for key in ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy',
                                        'ALL_PROXY','all_proxy','CARGO_HTTP_PROXY')))
            if observed:
                data=observed
            status,detail,observation=scoped_classify(data,control,classify)
            sample=dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
            if data.get('connection_evidence'):
                sample['connection_evidence']=data['connection_evidence']
            return sample
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Cargo / registry',
        {'tool_id':'cargo','tool_name':'Cargo','executable':path,
         'source':'https://doc.rust-lang.org/cargo/commands/cargo-search.html','probe':'synthetic_sparse_registry'},samples,
        '選択したCargo実行体と合成registryのみ。利用者の設定・認証・crateの導入は含みません。',
        '利用するCargoのregistry・CA・proxy設定と、その環境での接続を確認してください。')


def rclone_http(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='rclone-http-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            config=work/'rclone.conf'; config.write_text('',encoding='utf-8')
            cmd=[path,'lsd','--config',str(config),'--ask-password=false','--http-url',url,':http:',
                 '--max-depth','1','--retries','1','--low-level-retries','1',
                 '--contimeout',str(int(audit.args.timeout))+'s','--timeout',str(int(audit.args.timeout))+'s']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=isolated_environment(work),cwd=work,inherit_env=False)
            combined=redact((out+'\n'+err).strip())
            data=transport_data(rc,combined,rc == 0)
            data['detail']=redact(err) if err else ('一覧取得が完了しました。' if data['state']=='accepted' else '一覧取得を確認できません。')
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'rclone / HTTP backend',
        {'tool_id':'rclone','tool_name':'rclone','executable':path,
         'source':'https://rclone.org/http/','probe':'synthetic_http_listing'},samples,
        '選択したrclone実行体の一時HTTP remoteのみ。実remote・認証・ファイル転送は含みません。',
        '利用するrclone remoteのCA・proxy設定と、その環境での接続を確認してください。')


def osv_api(audit, path, run, classify, redact):
    with tempfile.TemporaryDirectory(prefix='osv-fixture-',dir=str(audit.work)) as temporary:
        work=Path(temporary)
        fixture=work/'osv-scanner.json'
        package={'name':'emudhra-audit-fixture','version':'0.0.0','ecosystem':'PyPI'}
        fixture.write_text(json.dumps({'results':[{'packages':[{'package':package}]}]}),encoding='utf-8')
        config=work/'osv-scanner.toml'; config.write_text('',encoding='utf-8')
        cmd=[path,'scan','source','--lockfile','osv-scanner:'+str(fixture),
             '--config',str(config),'--format','json','--all-packages','--no-resolve']
        started=time.monotonic()
        rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=isolated_environment(work),cwd=work,inherit_env=False)
        try:
            result=json.loads(out)
            seen=any(all(item.get('package',{}).get(key) == value for key,value in package.items())
                     for group in result.get('results',[]) for item in group.get('packages',[]))
        except (ValueError,TypeError,AttributeError):
            seen=False
        ok=rc == 0 and seen and not ANY_TLS_OR_TRANSPORT_FAILURE.search(err)
        detail=('合成データの照会結果を受け取りました。リダイレクト先を含む接続経路は特定できません。' if ok else
                '公式APIへの合成データ照会を確認できません。 '+redact(err or out))
        sample=dict(target='OSV公式API',url='https://api.osv.dev/',control=True,
                    status='UNKNOWN',detail=detail,
                    seconds=round(time.monotonic()-started,2))
    metadata={'tool_id':'osv-scanner','tool_name':'OSV-Scanner','executable':path,
              'source':'https://google.github.io/osv-scanner/supported-languages-and-lockfiles/',
              'probe':'synthetic_osv_query'}
    row=audit.add('OSV-Scanner / 合成データの照会','CHECKED' if ok else 'UNKNOWN',
        '本体で公式APIへの合成照会を試し、結果を受け取りました。接続経路と検査用サイトは未確認です。' if ok else
        '本体から公式APIへの合成データ照会を確認できません。代表検査用サイトの接続も未確認です。',
        metadata,[sample],action='公式APIへの接続とCA・proxy設定を確認してください。',required=not ok)
    row['assessment_method']='measured'
    row['scope']='合成依存1件の公式API照会のみ。利用者のプロジェクトと、検査用サイトへの接続は含みません。'
    audit.add('OSV-Scanner / 普段の設定・検査用サイト','MANUAL',
              '公式APIへの合成照会では、普段の設定と検査用サイトへの接続を確認できません。',
              dict(metadata),action='OSV-Scanner本体のGo版と配布元の対応、利用するCA・proxy設定を確認してください。',required=True)


def kubectl_api(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='kubectl-api-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            config=work/'kubeconfig.json'
            config.write_text(json.dumps({'apiVersion':'v1','kind':'Config',
                'clusters':[{'name':'diagnostic','cluster':{'server':url}}],
                'contexts':[{'name':'diagnostic','context':{'cluster':'diagnostic'}}],
                'current-context':'diagnostic','users':[]}),encoding='utf-8')
            env=isolated_environment(work)
            env['KUBECTL_KUBERC']='false'
            cmd=[path,'--kubeconfig',str(config),'--cache-dir',str(work/'cache'),
                 '--request-timeout',str(int(audit.args.timeout))+'s','get','--raw','/']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            data=transport_data(rc,detail,rc == 0)
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    row=record_limited(audit,'kubectl / 診断用API',
        {'tool_id':'kubectl','tool_name':'kubectl','executable':path,
         'source':'https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/','probe':'synthetic_kubectl_raw'},samples,
        '選択したkubectl、認証設定のない一時kubeconfigと診断用GETのみ。実clusterや利用者設定は含みません。',
        '普段使うkubeconfigのcluster・CA・proxy設定と、その環境での接続を確認してください。')
    if all('Please enter Username' in sample['detail'] for sample in samples):
        row['detail']='このkubectlは匿名設定でも対話認証を要求したため、通信を確認できません。認証情報は入力していません。'
        row['scope']+=' この実行体は対話認証を要求し、通信前に終了しました。'


def aws_api(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='aws-api-',dir=str(audit.work)) as temporary:
            work=Path(temporary)
            config=work/'config'; credentials=work/'credentials'
            config.write_text('',encoding='utf-8'); credentials.write_text('',encoding='utf-8')
            env=isolated_environment(work)
            env.update(AWS_CONFIG_FILE=str(config),AWS_SHARED_CREDENTIALS_FILE=str(credentials),
                       AWS_EC2_METADATA_DISABLED='true',AWS_MAX_ATTEMPTS='1',AWS_RETRY_MODE='standard',
                       AWS_DEFAULT_REGION='us-east-1',AWS_PAGER='')
            cmd=[path,'sts','get-caller-identity','--no-sign-request','--no-paginate','--endpoint-url',url,
                 '--region','us-east-1','--output','json','--cli-connect-timeout',str(int(audit.args.timeout)),
                 '--cli-read-timeout',str(int(audit.args.timeout))]
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            try:
                result=json.loads(out)
                valid=isinstance(result,dict) and all(isinstance(result.get(key),str) for key in ('UserId','Account','Arn'))
            except (ValueError,TypeError):
                valid=False
            detail=redact((out+'\n'+err).strip())
            data=transport_data(rc,detail,rc == 0 and valid)
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'AWS CLI / 診断用API',
        {'tool_id':'aws','tool_name':'AWS CLI','executable':path,
         'source':'https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html','probe':'synthetic_unsigned_sts_query'},samples,
        '選択したAWS CLIと診断先への署名なしの照会のみ。利用者の資格情報・設定・実AWS環境は含みません。',
        '普段使うAWS CLIのCA・proxy・資格情報設定と、利用サービスへの接続を確認してください。')


def helm_repository(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='helm-repository-',dir=str(audit.work)) as temporary:
            work=Path(temporary); plugins=work/'plugins'; plugins.mkdir()
            env=isolated_environment(work)
            env.update(HELM_CONFIG_HOME=str(work/'config'),HELM_CACHE_HOME=str(work/'cache'),
                       HELM_DATA_HOME=str(work/'data'),HELM_PLUGINS=str(plugins),
                       HELM_REPOSITORY_CONFIG=str(work/'repositories.yaml'),
                       HELM_REPOSITORY_CACHE=str(work/'repositories-cache'))
            cmd=[path,'repo','add','diagnostic',url,'--repository-config',env['HELM_REPOSITORY_CONFIG'],
                 '--repository-cache',env['HELM_REPOSITORY_CACHE']]
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            success=rc == 0 and 'has been added to your repositories' in out
            data=transport_data(rc,detail,success)
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Helm / repository',
        {'tool_id':'helm','tool_name':'Helm','executable':path,
         'source':'https://helm.sh/docs/helm/helm_repo_add/','probe':'synthetic_helm_index'},samples,
        '選択したHelmと一時repository設定・合成indexのみ。認証、既存repository、plugin、clusterは使用しません。',
        '普段使うHelm repositoryとCA・proxy設定を確認してください。')


def rustup_metadata(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='rustup-check-',dir=str(audit.work)) as temporary:
            work=Path(temporary); rustup_home=work/'rustup'; rustup_home.mkdir()
            (rustup_home/'settings.toml').write_text('version = "12"\nauto-self-update = "check-only"\n',encoding='utf-8')
            env=isolated_environment(work)
            for key in ('RUSTUP_USE_CURL','RUSTUP_USE_RUSTLS','CURL_CA_BUNDLE'):
                if key in os.environ: env[key]=os.environ[key]
            env.update(RUSTUP_HOME=str(rustup_home),CARGO_HOME=str(work/'cargo'),
                       RUSTUP_UPDATE_ROOT=url.rstrip('/'),RUSTUP_DIST_SERVER=url.rstrip('/'),
                       RUSTUP_AUTO_INSTALL='0',RUSTUP_CONCURRENT_DOWNLOADS='1')
            rc,out,err=run([path,'check'],timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            success=rc in (0,2) and bool(re.search(r'\brustup\s*-\s*(?:up to date|update available)',out,re.I))
            data=transport_data(rc,detail,success)
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'rustup / 更新情報',
        {'tool_id':'rustup','tool_name':'rustup','executable':path,
         'source':'https://rust-lang.github.io/rustup/basics.html','probe':'synthetic_rustup_release'},samples,
        '空の一時RUSTUP_HOMEで本体の更新情報のみ取得。ツールチェーンと実設定は使わず、更新・導入はしません。',
        '普段のrustup配布先とCA・proxy設定を確認してください。')


def git_lfs_locks(audit, path, git, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='git-lfs-',dir=str(audit.work)) as temporary:
            work=Path(temporary); gitdir=work/'.git'
            (gitdir/'objects').mkdir(parents=True); (gitdir/'refs/heads').mkdir(parents=True)
            (gitdir/'HEAD').write_text('ref: refs/heads/diagnostic\n',encoding='utf-8')
            (gitdir/'config').write_text('[core]\n\trepositoryformatversion = 0\n\tbare = false\n'
                '[lfs]\n\turl = '+url+'\n[credential]\n\thelper =\n[http]\n\tfollowRedirects = false\n',encoding='utf-8')
            global_config=work/'gitconfig'; global_config.write_text('',encoding='utf-8')
            env=isolated_environment(work)
            env.update(PATH=str(Path(git).parent)+os.pathsep+os.defpath,
                       GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=str(global_config),
                       GIT_TERMINAL_PROMPT='0',GIT_ASKPASS='',SSH_ASKPASS='',GIT_LFS_SKIP_SMUDGE='1')
            # Do not use --json: some Git LFS versions print JSON and return
            # before propagating a failed SearchLocks operation.
            cmd=[path,'locks','--limit=1']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            data=transport_data(rc,err,rc == 0)
            status,_,observation=scoped_classify(data,control,classify)
            detail=('診断用ロックAPIから通信応答を観測しました。リダイレクト後の接続先は未確定です。'
                    if data['state']=='accepted' else
                    '診断用ロックAPIの通信を確認できません。リダイレクト先やエラーの内容は未確定です。')
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Git LFS / ロックAPI',
        {'tool_id':'git-lfs','tool_name':'Git LFS','executable':path,'git_executable':git,
         'source':'https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-locks.adoc','probe':'synthetic_lfs_locks'},samples,
        '一時Gitリポジトリと診断用LFS APIの読取のみ。実remote・認証・objectsは使用しません。',
        '普段使うGit LFS remoteとCA・proxy・認証設定を確認してください。')


def poetry_transport(audit, path, python, site, prefix, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='poetry-http-',dir=str(audit.work)) as temporary:
            work=Path(temporary); env=isolated_environment(work)
            for key in ('REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE'):
                if key in os.environ: env[key]=os.environ[key]
            env['POETRY_KEYRING_ENABLED']='false'
            probe=Path(__file__).resolve().parent/'probes/poetry_probe.py'
            rc,out,err=run([python,'-I','-S','-B',str(probe),site,prefix,url,str(audit.args.timeout)],
                           timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            try:
                value=json.loads(out)
                data={'state':value.get('state','unknown'),'detail':redact(str(value.get('detail','')))}
                if err:
                    data['detail'] += '\n'+redact(err)
                if rc == 0 and data['state'] == 'accepted':
                    data=transport_data(rc,data['detail'],True)
                elif rc != 0 or data['state'] not in ('unknown','error'):
                    data={'state':'unknown','detail':redact(err or out)}
            except (ValueError,TypeError,AttributeError):
                data={'state':'unknown','detail':redact(err or out)}
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Poetry / HTTP transport',
        {'tool_id':'poetry','tool_name':'Poetry','executable':path,'runtime_executable':python,
         'source':'https://github.com/python-poetry/poetry/blob/main/src/poetry/utils/authenticator.py',
         'probe':'poetry_authenticator'},samples,
        'このPoetry環境内のAuthenticatorとrequestsを一時設定・無認証で使用。実repositoryやユーザー設定は含みません。',
        '普段使うPoetry repositoryのCA・proxy・認証設定を確認してください。')


def pipx_transport(audit,path,python,shared,venv,run,classify,redact,targets):
    def one(target):
        label,url,control=target; started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='pipx-http-',dir=str(audit.work)) as temporary:
            work=Path(temporary); env=isolated_environment(work)
            for key in ('PIP_CERT','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE'):
                if key in os.environ: env[key]=os.environ[key]
            env.update(PIP_CONFIG_FILE=os.devnull,PIP_KEYRING_PROVIDER='disabled',
                       PIP_NO_INPUT='1',PIP_DISABLE_PIP_VERSION_CHECK='1')
            probe=Path(__file__).resolve().parent/'probes/pipx_probe.py'
            rc,out,err=run([python,'-I','-S','-B',str(probe),shared,url,str(audit.args.timeout)],
                           timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            try:
                line=next(line[len('EMUDHRA_JSON:'):] for line in out.splitlines() if line.startswith('EMUDHRA_JSON:'))
                data=json.loads(line); data['detail']=redact(data.get('detail',''))
                if err: data['detail']+='\n'+redact(err)
                if rc: data={'state':'unknown','detail':redact(err or out)}
                elif data.get('state')=='accepted': data=transport_data(rc,data['detail'],True)
            except (StopIteration,ValueError,TypeError,AttributeError):
                data={'state':'unknown','detail':redact(err or out)}
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'pipx / 共有pip ('+Path(venv).name+')',
        {'tool_id':'pipx','tool_name':'pipx','executable':path,'runtime_executable':python,
         'managed_environment':venv,'source':'https://pipx.pypa.io/stable/explanation/how-pipx-works.html',
         'probe':'pipx_shared_pip'},samples,
        'pipx管理環境のPythonと明示的に関連付けられた共有pipを使用。アプリ依存と.pthは実行せず、一時設定・無認証で照会します。',
        '普段使うpipx環境のbackend・index・CA・proxy設定を確認してください。')


def azure_rest(audit, path, prefix, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='azure-rest-',dir=str(audit.work)) as temporary:
            work=Path(temporary); env=isolated_environment(work)
            for key in ('REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE'):
                if key in os.environ: env[key]=os.environ[key]
            env.update(AZURE_CONFIG_DIR=str(work/'azure'),AZURE_CORE_COLLECT_TELEMETRY='no',
                       AZURE_EXTENSION_USE_DYNAMIC_INSTALL='no',AZURE_CORE_NO_COLOR='yes')
            cmd=prefix+['rest','--method','get','--url',url,'--skip-authorization-header',
                        '--only-show-errors','--output','json']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            data=transport_data(rc,detail,rc == 0)
            if data['state']=='accepted': data['detail']='診断用GETの応答を受け取りました。'
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Azure CLI / 診断用REST',
        {'tool_id':'azure','tool_name':'Azure CLI','executable':path,
         'source':'https://learn.microsoft.com/en-us/cli/azure/reference-index#az-rest','probe':'synthetic_azure_rest'},samples,
        'このAzure CLIの署名・認証ヘッダーなしの診断用GET。一時設定のみを使い、実クラウド資源は操作しません。',
        '普段使うAzure CLIのCA・proxy設定と、利用サービスへの接続を確認してください。')


def mamba_channel(audit, path, run, classify, redact, targets):
    def one(target):
        label,url,control=target
        started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='mamba-channel-',dir=str(audit.work)) as temporary:
            work=Path(temporary); env=isolated_environment(work)
            cmd=[path,'--no-rc','--no-env','--root-prefix',str(work/'root'),
                 'repoquery','search','emudhra-audit-fixture','--channel',url,
                 '--override-channels','--json']
            rc,out,err=run(cmd,timeout=audit.args.timeout+5,env=env,cwd=work,inherit_env=False)
            detail=redact((out+'\n'+err).strip())
            try:
                value=json.loads(out)
                valid=isinstance(value,dict) and value.get('result',{}).get('status') == 'OK'
            except (ValueError,TypeError,AttributeError):
                valid=False
            data=transport_data(rc,detail,rc == 0 and valid)
            status,detail,observation=scoped_classify(data,control,classify)
            return dict(target=label,url=url,control=control,status=status,detail=detail,
                        observation=observation,seconds=round(time.monotonic()-started,2))
    with ThreadPoolExecutor(max_workers=audit.args.workers) as pool:
        samples=list(pool.map(one,targets))
    record_limited(audit,'Mamba / channel',
        {'tool_id':'mamba','tool_name':'Mamba','executable':path,
         'source':'https://mamba.readthedocs.io/en/latest/user_guide/micromamba.html',
         'probe':'synthetic_mamba_search'},samples,
        'ネイティブMambaの合成channel照会。設定・認証・実環境・packageの導入は含みません。',
        '普段使うMamba channelとCA・proxy設定を確認してください。')


def collect(audit, run, classify, redact, targets):
    for tool, (label, component) in TOOLS.items():
        seen = set()
        for path in audit.discovered.get(tool, []):
            key = verdicts.installation_identity(tool, path)
            if key in seen: continue
            seen.add(key)
            metadata = {'tool_id':tool, 'tool_name':label, 'executable':path}
            if tool == 'azure' and os.environ.get('AZURE_CLI_DISABLE_CONNECTION_VERIFICATION'):
                row=audit.add('Azure CLI / REST証明書検証','ACTION',
                    '現在の環境でaz restの証明書検証を無効にする環境変数が設定されています。',
                    dict(metadata,setting_names=['AZURE_CLI_DISABLE_CONNECTION_VERIFICATION'],
                         source='https://github.com/Azure/azure-cli/blob/dev/src/azure-cli-core/azure/cli/core/util.py'),
                    action='この環境変数を設定した起動環境を確認してください。',required=True)
                row['scope']='現在の環境変数とAzure CLIのaz restに適用される検証設定。ほかの認証処理への適用は未確認。'
            if audit.args.offline:
                audit.add(label+' / '+component, 'SKIP', 'オフライン指定: パッケージ管理の通信は未検査です。',
                          metadata, required=True)
            elif any(not safe_target(target[1]) for target in targets):
                audit.add(label+' / '+component,'SKIP','検査先が安全なHTTPS URLではないため通信を見送りました。',
                          metadata,required=True)
            elif tool in getattr(audit,'package_protected',set()):
                audit.add(label+' / '+component, 'SKIP',
                          'Safe Chainのシェル連携候補があるため、保護を迂回する可能性のある直接通信は見送りました。',
                          metadata, required=True)
            elif withheld(tool):
                audit.add(label+' / '+component, 'SKIP', withheld(tool), metadata, required=True)
            elif tool in ('pnpm','yarn'):
                manager=node_manager(path,tool)
                if manager:
                    node_registry(audit,path,manager[0],manager[1],tool,run,classify,redact,targets)
                else:
                    audit.add(label+' / '+component,'MANUAL',
                              'Corepackや導入処理を起動せず、対応するCLI本体とNodeの組合せを特定できません。pnpm旧版のviewはnpmへ委譲します。',
                              metadata,required=True)
            elif tool == 'rubygems' and gem_ruby(path):
                rubygems_source(audit,path,gem_ruby(path),run,classify,redact,targets)
            elif tool == 'bundler' and gem_ruby(path):
                bundler_source(audit,path,gem_ruby(path),run,classify,redact,targets)
            elif tool == 'composer' and composer_php(path):
                composer_repository(audit,path,composer_php(path),run,classify,redact,targets)
            elif tool == 'poetry':
                runtime=poetry_python(path)
                if runtime:
                    poetry_transport(audit,path,*runtime,run,classify,redact,targets)
                else:
                    audit.add(label+' / '+component,'MANUAL',
                              'このPoetry本体に対応するPython環境を安全に特定できません。',metadata,required=True)
            elif tool == 'pipx':
                pairs,limited=pipx_pairs(path)
                for python,shared,venv in pairs:
                    pipx_transport(audit,path,python,shared,venv,run,classify,redact,targets)
                if limited or not pairs:
                    audit.add(label+' / '+component,'MANUAL',
                              '対応する管理環境と共有pipをすべて安全に特定できません。uv backendや探索上限は別確認です。',metadata,required=True)
            elif tool == 'azure':
                runtime=None if native(path) else azure_python(path)
                if native(path) or runtime:
                    prefix=([path] if not runtime else
                            [runtime[0],'-I','-S','-B',str(Path(__file__).resolve().parent/'probes/azure_entry.py'),runtime[1],runtime[2]])
                    azure_rest(audit,path,prefix,run,classify,redact,targets)
                else:
                    audit.add(label+' / '+component,'MANUAL',
                              'このAzure CLI本体とPython環境の組合せを安全に特定できません。',metadata,required=True)
            elif tool == 'git-lfs':
                git=shutil.which('git')
                if native(path) and git and native(git):
                    git_lfs_locks(audit,path,git,run,classify,redact,targets)
                else:
                    audit.add(label+' / '+component,'MANUAL',
                              'Git LFSと、そのローカル設定読取に使うGitの実行体を安全に特定できません。',
                              metadata,required=True)
            elif not native(path) or (tool == 'cargo' and cargo_is_shim(path)):
                audit.add(label+' / '+component, 'MANUAL', '管理ツールのshimや非ネイティブ実体は自動導入を避けるため起動しません。', metadata, required=True)
            elif tool == 'go':
                go_modules(audit,path,run,classify,redact,targets)
            elif tool == 'uv':
                uv_packages(audit,path,run,classify,redact,targets)
            elif tool == 'cargo':
                cargo_registry(audit,path,run,classify,redact,targets)
            elif tool == 'rclone':
                rclone_http(audit,path,run,classify,redact,targets)
            elif tool == 'osv-scanner':
                osv_api(audit,path,run,classify,redact)
            elif tool == 'kubectl':
                kubectl_api(audit,path,run,classify,redact,targets)
            elif tool == 'aws':
                aws_api(audit,path,run,classify,redact,targets)
            elif tool == 'helm':
                helm_repository(audit,path,run,classify,redact,targets)
            elif tool == 'rustup':
                rustup_metadata(audit,path,run,classify,redact,targets)
            elif tool == 'mamba':
                mamba_channel(audit,path,run,classify,redact,targets)
