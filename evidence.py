"""Bounded, read-only evidence collection; never substitutes for a TLS probe."""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import official_versions
import stat
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
DOCKER_SOURCE = 'https://docs.docker.com/desktop/release-notes/#4962'
RUSTUP_SOURCE = 'https://blog.rust-lang.org/2026/10/20/Rustup-1.29.2/'
CRLSET_SOURCE = 'https://www.chromium.org/Home/chromium-security/crlsets/'
EXCLUDED = {'.git', '.artifacts', 'node_modules', 'target', 'vendor', 'dist', 'build', '__pycache__', 'runtime', 'releases'}


def finding(check, kind, status, detail, **fields):
    return dict(check=check, kind=kind, status=status, detail=detail, **fields)


def public_path(path):
    """Reject env names in every component and every symlink hop, without opening files."""
    try:
        path=Path(path).absolute()
        pending=list(path.parts[1:]); current=Path(path.anchor); hops=0
        while pending:
            part=pending.pop(0)
            if part == '.env' or part.startswith('.env.'): return False
            if part == '..':
                current=current.parent
                continue
            current=current/part
            try:
                mode=current.lstat().st_mode
            except (FileNotFoundError,NotADirectoryError):
                continue
            if stat.S_ISLNK(mode):
                hops+=1
                if hops > 40: return False
                target=Path(os.readlink(current))
                if target.is_absolute():
                    current=Path(target.anchor); pending=list(target.parts[1:])+pending
                else:
                    current=current.parent; pending=list(target.parts)+pending
        return True
    except (OSError,RuntimeError,ValueError):
        return False


def read_public_file(path, limit=16*1024*1024):
    """Read only caller-selected public configuration, never an env file/alias."""
    path = Path(path)
    try:
        if not public_path(path):
            return None
        if not path.is_file() or path.stat().st_size > limit:
            return None
        with path.open('rb') as stream:
            value = stream.read(limit+1)
        return value if len(value) <= limit else None
    except (OSError, ValueError):
        return None


def version_evidence(name, version, floor, source):
    result = finding(name, 'version', 'UNKNOWN', '版を比較できません。', source=source, version=version, reference_floor=floor)
    if not re.fullmatch(r'\d+\.\d+\.\d+', version or ''):
        return result
    current, baseline = [tuple(map(int, text.split('.'))) for text in (version, floor)]
    if current[0] != baseline[0]:
        result['detail'] = '参照と異なるメジャー系列です。配布元の確認が必要です。'
        return result
    if current > baseline and current[:2] != baseline[:2]:
        result['detail'] = '新しい系列の修正状況は未照合です。'
        return result
    result['status'] = 'UPDATE' if current < baseline else 'REFERENCE_OK'
    result['detail'] = '{} {} / 参考修正版 {} {}。版に基づく推定で、実通信の確認とは別です。'.format(
        name, version, floor, '未満' if current < baseline else '以上')
    return result


def crlset_evidence(raw, pins, now=None):
    result = finding('保存済みCRLSet', 'static', 'UNKNOWN', '既知のCRLSet形式を確認できません。', source=CRLSET_SOURCE)
    try:
        pins = {bytes.fromhex(pin) for pin in pins}
        if not pins or any(len(pin) != 32 for pin in pins): return result
        size = struct.unpack('<H', raw[:2])[0]
        header = json.loads(raw[2:2+size])
        if not isinstance(header,dict): return result
        if header.get('Version') != 0 or header.get('ContentType') != 'CRLSet': return result
        if type(header.get('Sequence')) is not int or header['Sequence'] < 0 or header.get('DeltaFrom',0) != 0: return result
        expiry = header.get('NotAfter',0)
        if not isinstance(expiry,(int,float)) or not math.isfinite(expiry) or expiry < 0: return result
        if expiry and expiry <= (time.time() if now is None else now):
            result['detail'] = '保存済みCRLSetの有効期限を過ぎています。適用中の状態は未確認です。'
            return result
        # Validate the entire body so a valid header on a truncated file cannot pass.
        offset = 2+size
        while offset < len(raw):
            if len(raw)-offset < 36: return result
            count = struct.unpack('<I',raw[offset+32:offset+36])[0]; offset += 36
            for _ in range(count):
                if offset >= len(raw): return result
                length = raw[offset]; offset += 1+length
                if offset > len(raw): return result
        blocked = {base64.b64decode(pin,validate=True) for pin in header.get('BlockedSPKIs',[])}
        if any(len(pin) != 32 for pin in blocked): return result
        matched = len(blocked & pins)
        result.update(matched=matched, total=len(pins), sequence=header['Sequence'])
        result['status'] = 'REFERENCE_OK' if matched == len(pins) else 'UNKNOWN'
        result['detail'] = '保存ファイルのBlockedSPKIsに対象TLS鍵 {}/{} 件を確認。適用中のデータ・組込ブロックリスト・各プロファイルの実通信は別確認。コード署名鍵は対象外。'.format(matched,len(pins))
    except (ValueError, TypeError, KeyError, struct.error, UnicodeError):
        pass
    return result


def bundle_evidence(text, fingerprints):
    result = finding('CAファイル照合', 'static', 'UNKNOWN', '証明書ファイルを解析できません。')
    try:
        blocks = re.findall(r'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----',text,re.S)
        hashes = {hashlib.sha256(base64.b64decode(re.sub(r'\s','',block),validate=True)).hexdigest() for block in blocks}
        targets = {pin.lower() for pin in fingerprints}
        if not hashes or not targets: return result
        matched = len(hashes & targets)
        result.update(certificates=len(hashes), matched=matched, total=len(targets))
        result['detail'] = 'この証明書ファイル内の参照対象証明書は {} 件。'.format(matched)
        result['detail'] += '含まれているかどうかだけでは、問題の証明書を使った接続を拒否できるか判断できません。'
        result['detail'] += '実際の通信、または使用中の実行環境・ライブラリの対応を確認してください。'
    except (ValueError, TypeError):
        pass
    return result


def project_inventory(root, max_dirs=2000, max_depth=4):
    """Names only; no application startup, lock refresh, or symlink traversal."""
    root = Path(root)
    pending = [(root,0)]; found = []; visited = 0; truncated = False
    while pending:
        if visited >= max_dirs:
            truncated = True; break
        folder, depth = pending.pop(); visited += 1
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            truncated = True; continue
        for path in entries:
            if path.is_symlink() or path.name in EXCLUDED or path.name == '.env' or path.name.startswith('.env.'):
                continue
            if path.is_dir():
                if depth < max_depth: pending.append((path,depth+1))
                else: truncated = True
            elif path.name in ('Cargo.lock','pyvenv.cfg') or path.name.endswith(('.runtimeconfig.json','.csproj')):
                found.append(path)
    return sorted(found), truncated


def mac_bundles():
    result = []
    if sys.platform != 'darwin': return result
    for name in ('Docker','Google Chrome','Microsoft Edge','Firefox','Safari','Visual Studio Code','IntelliJ IDEA','Android Studio'):
        for base in (Path('/Applications'),Path('/System/Applications'),Path.home()/'Applications'):
            path = base/(name+'.app')/'Contents/Info.plist'
            raw = read_public_file(path,1024*1024)
            if raw is None: continue
            try: version = plistlib.loads(raw).get('CFBundleShortVersionString','')
            except (ValueError,plistlib.InvalidFileException): continue
            result.append({'name':name,'version':str(version),'path':str(path)})
    return result


def php_evidence(audit, refs):
    p = audit.host.find('php')
    if not p: return []
    rc,out,_ = audit.host.call([p,str(ROOT/'probes/php_info.php')])
    try: info = json.loads(out) if not rc else {}
    except ValueError: info = {}
    if not info: return [finding('PHP設定取得','inventory','UNKNOWN','PHPのCA設定を取得できません。')]
    findings = [finding('PHP / OpenSSL','inventory','INFO', '{} / {}。PHP本体の版だけではCAの更新状態を判定できません。'.format(info.get('php','?'),info.get('openssl','?')))]
    locations = info.get('locations',{})
    file_path = locations.get('ini_cafile') or os.environ.get(locations.get('default_cert_file_env','SSL_CERT_FILE')) or locations.get('default_cert_file')
    directory = locations.get('ini_capath') or os.environ.get(locations.get('default_cert_dir_env','SSL_CERT_DIR')) or locations.get('default_cert_dir')
    pins = [r['sha256'] for r in refs['certificates']]
    if file_path:
        raw = read_public_file(file_path)
        value = bundle_evidence(raw.decode('ascii',errors='replace'),pins) if raw is not None else finding('CAファイル照合','static','UNKNOWN','参照先ファイルを安全に読み取れません。')
        value.update(path=str(file_path),source=refs['certificate_source'])
        findings.append(value)
    findings.append(finding('CA参照先','inventory','INFO','CAディレクトリも候補です。ファイルの照合結果だけでストリームの拒否原因を確定しません。', cafile=file_path,capath=directory))
    return findings


def rust_evidence(audit, files, reference):
    findings = []
    rustup = audit.host.find('rustup')
    if rustup:
        rc,out,_ = audit.host.call([rustup,'--version'],env={'RUSTUP_AUTO_INSTALL':'0'})
        match = re.search(r'^rustup (\S+)',out)
        if not rc and match:
            value = version_evidence('rustup',match.group(1),'1.29.2',RUSTUP_SOURCE)
            value.update(tool_id='rustup', tool_name='rustup', executable=rustup)
            value['detail'] += ' rustup自身の通信に対する基準で、Rust製アプリ全体の判定ではありません。'
            findings.append(value)
    locks = [path for path in files if path.name == 'Cargo.lock']
    findings.append(finding('Cargo.lock探索','inventory','INFO','指定プロジェクト内で {} 件を検出。対象外のプロジェクトや既存バイナリの依存関係は未確認。'.format(len(locks)),files=[str(path) for path in locks],count=len(locks)))
    for path in locks:
        raw = read_public_file(path)
        if raw is None: continue
        for block in re.split(r'(?m)^\[\[package\]\]\s*$',raw.decode('utf-8',errors='replace'))[1:]:
            name = re.search(r'(?m)^name\s*=\s*"([^"]+)"',block)
            version = re.search(r'(?m)^version\s*=\s*"([^"]+)"',block)
            if not name or not version or name[1] not in ('rustls-webpki','webpki-roots','webpki-root-certs'): continue
            status, detail, floor = reference(name[1],version[1])
            findings.append(finding(name[1],'version',status,detail,path=str(path),version=version[1],
                                    reference_floor=floor,source=official_versions.COMPONENT_SOURCES[name[1]]))
    return findings


def docker_evidence(audit, bundles):
    findings = []
    for bundle in bundles:
        if bundle['name'] == 'Docker':
            value = finding('Docker Desktop','version','MANUAL',
                            'Docker Desktopは部品ごとの段階的修正です。CLI・Engine・BuildKitを個別に照合します。',
                            version=bundle['version'],source=DOCKER_SOURCE)
            findings.append(value)
    if audit.args.offline:
        findings.append(finding('Docker Engine','inventory','SKIP','オフライン指定のためデーモンへの問い合わせを省略。'))
        return findings
    p = audit.host.find('docker')
    if not p: return findings
    rc,out,_ = audit.host.call([p,'version','--format','{{json .Server}}'],timeout=10)
    try: server = json.loads(out) if not rc else None
    except ValueError: server = None
    if isinstance(server,dict):
        findings.append(finding('接続中のDocker Engine','inventory','INFO','Engineと組込Goの版を取得。CA・バックポートの反映は版だけでは断定できません。',
                                version=server.get('Version'),go_version=server.get('GoVersion'),platform=server.get('Os')))
    else:
        findings.append(finding('接続中のDocker Engine','inventory','UNKNOWN','デーモンの情報を取得できません。停止・接続設定・権限などの可能性があります。'))
    rc,out,_ = audit.host.call([p,'info','--format','{{json .RegistryConfig.IndexConfigs}}'],timeout=10)
    try: registries = json.loads(out) if not rc else None
    except ValueError: registries = None
    if isinstance(registries,dict):
        count = sum(v.get('Secure') is False for v in registries.values() if isinstance(v,dict))
        names = sorted(name for name, value in registries.items()
                       if isinstance(value, dict) and value.get('Secure') is False and
                       isinstance(name, str) and len(name) <= 253 and
                       re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?', name))
        findings.append(finding('registryのTLS設定','configuration','ACTION' if count else 'INFO',
                                'TLSを安全としない設定のregistry {} 件を検出。CIDR指定や独自BuildKitは別確認。'.format(count),
                                count=count, insecure_registries=names, redacted_registry_count=count-len(names)))
    else:
        findings.append(finding('registryのTLS設定','configuration','UNKNOWN','registryの設定を取得できませんでした。接続先デーモン・権限を確認してください。'))
    return findings


def browser_evidence(bundles, refs):
    findings = [finding(b['name'],'inventory','INFO','導入版 {}。本体の版だけでは別配信の失効情報を判定できません。'.format(b['version']),version=b['version'])
                for b in bundles if b['name'] in ('Google Chrome','Microsoft Edge','Firefox','Safari')]
    if sys.platform != 'darwin':
        findings.append(finding('ブラウザ探索','inventory','UNKNOWN','保存CRLSetの既定配置探索は現在macOSのみ対応。'))
        return findings
    pins = refs['tls_spki_sha256']
    for name, relative in (('Chrome','Google/Chrome'),('Edge','Microsoft Edge')):
        root = Path.home()/'Library/Application Support'/relative/'CertificateRevocation'
        try: versions = [p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and re.fullmatch(r'\d+(?:\.\d+)*',p.name)]
        except FileNotFoundError: versions = []
        except OSError:
            findings.append(finding(name+' / 保存済みCRLSet','static','UNKNOWN',
                                    '保存済みCRLSetを読み取れません（権限・OSの保護設定等）。鍵の有無や適用状態は判定していません。',source=CRLSET_SOURCE))
            continue
        if not versions: continue
        newest = max(versions,key=lambda p:tuple(map(int,p.name.split('.'))))
        raw = read_public_file(newest/'crl-set')
        value = crlset_evidence(raw or b'',pins)
        value.update(check=name+' / 保存済みCRLSet',component_version=newest.name)
        findings.append(value)
    return findings


def dotnet_evidence(audit, files):
    roots = [Path.home()/'.dotnet',Path('/usr/local/share/dotnet'),Path('/usr/local/share/dotnet/x64'),
             Path('/usr/share/dotnet'),Path('/usr/lib/dotnet')]
    for key in ('DOTNET_ROOT','DOTNET_ROOT_X64','DOTNET_ROOT_ARM64','ProgramFiles','ProgramFiles(x86)'):
        if os.environ.get(key): roots.append(Path(os.environ[key])/('dotnet' if key.startswith('ProgramFiles') else ''))
    known = [p/('dotnet.exe' if os.name=='nt' else 'dotnet') for p in roots]
    found = sorted({str(p) for p in known if p.is_file()})
    on_path = audit.host.find('dotnet')
    if on_path and on_path not in found: found.append(on_path)
    value = finding('.NET配置探索','inventory','INFO',
                    'PATH・標準配置・DOTNET_ROOT指定から {} 件を検出。自己完結型アプリ内の.NETや別ユーザーの配置は対象外。'.format(len(found)),executables=found)
    configs = [str(p) for p in files if p.name.endswith(('.runtimeconfig.json','.csproj'))]
    value['project_markers'] = configs
    value['detail'] += ' 指定プロジェクトの.NET関連ファイルは {} 件。'.format(len(configs))
    return [value]


def collect(audit, reference):
    """Enrich the six unresolved rows without rewriting their probe outcomes."""
    files, truncated = project_inventory(audit.args.project) if audit.args.project else ([],False)
    bundles = mac_bundles()
    refs = json.loads((ROOT/'references/assessment.json').read_text(encoding='utf-8'))
    for row in audit.records:
        name = row['name']
        try:
            if 'PHP OpenSSL streams' in name and name.startswith('ホスト'):
                row['evidence'] = php_evidence(audit,refs)
            elif name in ('Rust', 'Rust / Cargo.lock'):
                row['evidence'] = rust_evidence(audit,files,reference)
            elif name == 'Docker Engine / Desktop / BuildKit / registry':
                row['evidence'] = docker_evidence(audit,bundles)
            elif name == 'ブラウザ / 実際のプロファイル':
                row['evidence'] = browser_evidence(bundles,refs)
            elif name.startswith('.NET HttpClient'):
                row['evidence'] = dotnet_evidence(audit,files)
            elif name == '対象範囲の確認':
                if not audit.args.project:
                    row['evidence'] = [finding('ホストのみの検査','inventory','SKIP',
                        '--host-only指定: プロジェクトのGit/npm設定、依存関係、仮想環境は探索していません。必要なプロジェクトを--projectで指定して再実行してください。')]
                    continue
                row['evidence'] = [finding('指定プロジェクト探索','inventory','INFO',
                    '深さ4・最大2000ディレクトリの範囲で環境識別ファイル {} 件。{} ホーム全体・VM・CI・アプリの実際の利用状況は対象外。'.format(len(files),'探索上限または読取制限あり。' if truncated else '設定した探索範囲を確認。'),
                    project=str(audit.args.project),files=[str(p) for p in files[:100]],truncated=truncated),
                    finding('既知アプリの配置','inventory','INFO','既知のアプリ配置を確認。内蔵ランタイムの起動・網羅性の判定は行いません。',applications=bundles)]
        except (OSError, ValueError, TypeError, KeyError):
            row['evidence'] = [finding('補助情報取得','inventory','UNKNOWN','設定・保存データの形式を安全に確認できませんでした。')]
