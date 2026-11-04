"""Bounded, value-free evidence for selected package-manager settings."""
import os
from pathlib import Path
import re
import sys

import app_inventory
import evidence
import tool_catalog
import verdicts


ENV_NAMES = {
    'conda':('CONDA_SSL_VERIFY','CONDA_OFFLINE','CONDARC','REQUESTS_CA_BUNDLE','HTTPS_PROXY','https_proxy'),
    'mamba':('MAMBA_SSL_VERIFY','MAMBA_OFFLINE','MAMBA_CACERT_PATH','CONDARC','HTTPS_PROXY','https_proxy'),
    'pipx':('PIPX_HOME','PIPX_SHARED_LIBS','PIPX_DEFAULT_PYTHON','PIPX_DEFAULT_BACKEND','PIP_TRUSTED_HOST','PIP_CERT','HTTPS_PROXY','https_proxy'),
    'poetry':('POETRY_CONFIG_DIR','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','HTTPS_PROXY','https_proxy'),
    'rustup':('RUSTUP_DIST_SERVER','RUSTUP_UPDATE_ROOT','RUSTUP_USE_CURL','RUSTUP_USE_RUSTLS','SSL_CERT_FILE','HTTPS_PROXY','https_proxy'),
    'helm':('HELM_REPOSITORY_CONFIG','HELM_REPOSITORY_CACHE','HELM_REGISTRY_CONFIG','SSL_CERT_FILE','HTTPS_PROXY','https_proxy'),
    'homebrew':('HOMEBREW_CURLRC','HOMEBREW_CURL_PATH','HOMEBREW_API_DOMAIN','HOMEBREW_ARTIFACT_DOMAIN','HTTPS_PROXY','https_proxy'),
    'apt':('APT_CONFIG','HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy'),
    'dnf':('HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy'),
    'pacman':('HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy'),
    'zypper':('HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy'),
    'apk':('HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy'),
}
SOURCES = {
    'conda':'https://docs.conda.io/projects/conda/en/latest/user-guide/configuration/settings.html',
    'mamba':'https://mamba.readthedocs.io/en/latest/user_guide/configuration.html',
    'pipx':'https://pipx.pypa.io/stable/reference/environment-variables.html',
    'poetry':'https://python-poetry.org/docs/configuration/',
    'rustup':'https://rust-lang.github.io/rustup/environment-variables.html',
    'helm':'https://helm.sh/docs/helm/helm_repo_add/',
    'homebrew':'https://docs.brew.sh/Manpage#environment',
    'apt':'https://manpages.debian.org/apt/apt.conf.5.en.html',
    'dnf':'https://dnf.readthedocs.io/en/latest/conf_ref.html',
    'pacman':'https://man.archlinux.org/man/pacman.conf.5',
    'zypper':'https://en.opensuse.org/SDB:Zypper_manual',
    'apk':'https://wiki.alpinelinux.org/wiki/Apk',
}


def directory_files(directory, suffix=None, limit=64):
    try:
        directory=Path(directory)
        if not directory.is_dir(): return [], False
        if not app_inventory.safe(directory): return [], True
        found=[]
        for path in directory.iterdir():
            if suffix and path.suffix.lower() != suffix: continue
            if not path.is_file(): continue
            found.append(path)
            if len(found) > limit: return found[:limit], True
        return sorted(found), False
    except (OSError, ValueError):
        return [], True


def candidate_files(tool,executable=None):
    home=Path.home(); files=[]; limited=False
    def add(path, explicit=False):
        if path: files.append((Path(path).expanduser(),explicit))
    if tool in ('conda','mamba'):
        roots=[Path('/etc/conda'),Path('/var/lib/conda'),home/'.conda',
               Path(os.environ.get('XDG_CONFIG_HOME') or home/'.config')/'conda']
        if os.name == 'nt' and os.environ.get('PROGRAMDATA'): roots.append(Path(os.environ['PROGRAMDATA'])/'conda')
        for key in ('CONDA_ROOT','CONDA_PREFIX'):
            if os.environ.get(key): roots.append(Path(os.environ[key]).expanduser())
        if executable:
            candidate=Path(executable)
            if candidate.parent.name.lower() in ('bin','scripts','condabin'): roots.append(candidate.parent.parent)
        for root in roots:
            add(root/'.condarc'); add(root/'condarc')
            extra,partial=directory_files(root/'condarc.d','.yaml')
            more,other=directory_files(root/'condarc.d','.yml')
            files.extend((p,False) for p in extra+more); limited |= partial or other
        add(home/'.condarc')
        add(os.environ.get('CONDARC'),True)
        if tool == 'mamba': add(home/'.mambarc')
    elif tool == 'helm':
        explicit=os.environ.get('HELM_REPOSITORY_CONFIG')
        add(explicit,True) if explicit else add(Path(os.environ.get('XDG_CONFIG_HOME') or home/'.config')/'helm/repositories.yaml')
    elif tool == 'poetry':
        config=os.environ.get('POETRY_CONFIG_DIR')
        if config: directory=Path(config).expanduser()
        elif sys.platform == 'darwin': directory=home/'Library/Application Support/pypoetry'
        elif os.name == 'nt': directory=Path(os.environ.get('APPDATA') or home/'AppData/Roaming')/'pypoetry'
        else: directory=Path(os.environ.get('XDG_CONFIG_HOME') or home/'.config')/'pypoetry'
        add(directory/'config.toml',bool(config))
    elif tool == 'homebrew':
        rc=os.environ.get('HOMEBREW_CURLRC')
        if rc: add(rc,True) if Path(rc).is_absolute() else add(home/'.curlrc')
    elif tool == 'apt':
        add(os.environ.get('APT_CONFIG'),True); add('/etc/apt/apt.conf')
        extra,limited=directory_files('/etc/apt/apt.conf.d'); files.extend((p,False) for p in extra)
    elif tool == 'dnf':
        add('/etc/dnf/dnf.conf'); add('/etc/yum.conf')
        extra,limited=directory_files('/etc/yum.repos.d','.repo'); files.extend((p,False) for p in extra)
    elif tool == 'pacman': add('/etc/pacman.conf')
    elif tool == 'zypper':
        add('/etc/zypp/zypp.conf')
        extra,limited=directory_files('/etc/zypp/repos.d','.repo'); files.extend((p,False) for p in extra)
    elif tool == 'apk': add('/etc/apk/repositories')
    seen=set(); unique=[]
    for path,explicit in files:
        key=str(path)
        if key not in seen: seen.add(key); unique.append((path,explicit))
    return unique,limited


def setting_names(tool, raw):
    names=set(); uncertain=False
    for line in raw.decode('utf-8','replace').splitlines():
        text=line.strip()
        if tool == 'apt' and text.lower().startswith('#include'): uncertain=True
        if not text or text.startswith(('#',';')): continue
        if tool in ('conda','mamba'):
            match=re.match(r'^(ssl_verify|proxy_servers|client_ssl_cert|client_ssl_cert_key)\s*:',text,re.I)
            if match: names.add(match.group(1).lower())
        elif tool == 'poetry':
            if re.match(r'^\[certificates(?:\.|\])',text,re.I): names.add('certificates')
            if re.match(r'^certificates\.[^=]+\s*=',text,re.I): names.add('certificates')
        elif tool == 'helm':
            match=re.match(r'^(?:-\s*)?(insecure_skip_tls_verify|caFile|certFile|keyFile|pass_credentials_all)\s*:',text,re.I)
            if match:
                key=match.group(1)
                if key.lower() != 'insecure_skip_tls_verify' or re.match(r'^(?:-\s*)?insecure_skip_tls_verify\s*:\s*true\s*(?:#.*)?$',text,re.I):
                    names.add('insecure_skip_tls_verify' if key.lower() == 'insecure_skip_tls_verify' else key)
        elif tool == 'homebrew':
            if re.fullmatch(r'(?:insecure|--insecure|-k)\s*(?:#.*)?',text,re.I): names.add('insecure')
            match=re.match(r'^(?:--)?(cacert|capath|proxy|config)\b',text,re.I)
            if match:
                names.add(match.group(1).lower())
                if match.group(1).lower() == 'config': uncertain=True
        elif tool == 'apt':
            match=re.match(r'^Acquire::https(?:::[^\s:;]+)?::(Verify-Peer|Verify-Host|CaInfo|Proxy)\b',text,re.I)
            if match: names.add(match.group(1))
            if text.lower().startswith('#include'): uncertain=True
        elif tool in ('dnf','zypper'):
            match=re.match(r'^(sslverify|proxy_sslverify|sslcacert|ssl_verify|ssl_ca_cert|proxy)\s*=',text,re.I)
            if match: names.add(match.group(1).lower())
        elif tool == 'pacman':
            if re.match(r'^XferCommand\s*=',text,re.I): names.add('XferCommand')
            if re.match(r'^Include\s*=',text,re.I): uncertain=True
        elif tool == 'apk':
            if re.match(r'^(?:@\S+\s+)?http://',text,re.I): names.add('HTTP repository')
    return names,uncertain


def setting_observations(tool,raw):
    """Return fixed facts only, never the contents or effective precedence."""
    facts=set(); poetry_certificates=False
    for line in raw.decode('utf-8','replace').splitlines():
        text=line.strip()
        if not text or text.startswith(('#',';')): continue
        if tool == 'poetry' and text.startswith('['):
            poetry_certificates=bool(re.match(r'^\[certificates\.[^\]]+\]\s*(?:#.*)?$',text,re.I))
            continue
        if tool in ('conda','mamba') and re.match(r'^ssl_verify\s*:\s*["\']?false["\']?\s*(?:#.*)?$',text,re.I):
            facts.add('ssl_verify=false')
        elif tool == 'poetry' and poetry_certificates and re.match(r'^cert\s*=\s*false\s*(?:#.*)?$',text,re.I):
            facts.add('certificates cert=false')
        elif tool == 'helm' and re.match(r'^(?:-\s*)?insecure_skip_tls_verify\s*:\s*true\s*(?:#.*)?$',text,re.I):
            facts.add('insecure_skip_tls_verify=true')
        elif tool == 'homebrew' and re.fullmatch(r'(?:insecure|--insecure|-k)\s*(?:#.*)?',text,re.I):
            facts.add('curl insecure')
        elif tool == 'apt' and re.match(r'^Acquire::https(?:::[^\s:;]+)?::Verify-(?:Peer|Host)\s+["\']?(?:false|0)["\']?\s*;',text,re.I):
            facts.add('https Verify-Peer/Host disabled')
        elif tool in ('dnf','zypper') and re.match(r'^(?:sslverify|ssl_verify)\s*=\s*(?:false|0|no)\s*(?:[#;].*)?$',text,re.I):
            facts.add('ssl verification disabled')
    return facts


def collect(audit):
    for tool,env_names in ENV_NAMES.items():
        spec=tool_catalog.BY_ID.get(tool)
        if not spec: continue
        seen=set()
        for executable in audit.discovered.get(tool,[]):
            identity=verdicts.installation_identity(tool,executable)
            if identity in seen: continue
            seen.add(identity)
            metadata={'tool_id':tool,'tool_name':spec['name'],'executable':executable,
                      'p2_settings':True,'source':SOURCES.get(tool)}
            env_present={key for key in env_names if os.environ.get(key)}
            files,limited=candidate_files(tool,executable)
            names=set(env_present); observations=set(); unread=False; configured_files=0; uncertain=limited
            for path,explicit in files:
                try:
                    if not path.exists():
                        unread |= explicit
                        continue
                except OSError:
                    unread=True; continue
                raw=evidence.read_public_file(path,128*1024)
                if raw is None:
                    unread=True; continue
                configured_files+=1
                found,partial=setting_names(tool,raw)
                names.update(found); uncertain |= partial
                observations.update(setting_observations(tool,raw))
            metadata['setting_names']=sorted(names)
            metadata['setting_observations']=sorted(observations)
            detail=('関連する環境変数名と既知の設定ファイルを読み取り、設定名のみを記録しました。値・URL・認証情報は記録しません。'
                    if names or configured_files else
                    '既知の場所で対象設定を確認できません。設定の不在だけでは実効設定や通信を判断できません。')
            if unread: detail+=' 読取不能または除外対象の設定があります。'
            if uncertain: detail+=' include・外部設定または探索上限のため全設定を確認できません。'
            if observations: detail+=' 設定ファイルに検証を無効にする候補の記述がありますが、優先順位と適用先は未確定です。'
            row=audit.add(spec['name']+' / CA・proxy設定','UNKNOWN' if unread else 'MANUAL',detail,metadata,
                          action='実際の起動引数・設定の継承と使用する接続先を確認してください。',required=True)
            row['assessment_method']='static'
            row['scope']='既知の環境変数名と限定した設定ファイル。値は記録せず、優先順位・全接続先の実効値は未確定。'
            disabled=(tool == 'conda' and os.environ.get('CONDA_SSL_VERIFY','').strip().lower() == 'false')
            disabled |= (tool == 'mamba' and os.environ.get('MAMBA_SSL_VERIFY','').strip().lower() in ('false','0','<false>'))
            if disabled:
                name='CONDA_SSL_VERIFY' if tool == 'conda' else 'MAMBA_SSL_VERIFY'
                action=audit.add(spec['name']+' / 証明書検証','ACTION',
                    '現在の環境で'+name+'による証明書検証の無効化が指定されています。',
                    dict(metadata,setting_names=[name]),action='この環境変数を設定した起動環境を確認してください。',required=True)
                action['assessment_method']='static'
                action['scope']='現在の環境変数が指定する'+spec['name']+'のHTTPS検証。個別コマンド側の上書きは別途確認。'
