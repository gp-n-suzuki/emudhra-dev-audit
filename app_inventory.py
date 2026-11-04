"""Bounded, non-executing inspection of installed applications.

Static observations never establish which trust configuration an application
uses at runtime. No imports from discovered packages, subprocesses or network.
"""
import json
import hashlib
import os
from pathlib import Path
import plistlib
import re
import ssl
import stat
import struct
import sys
import time

import evidence
import verdicts
import official_versions
import research_rules
import tool_catalog
import installed_metadata

ROOT = Path(__file__).resolve().parent
GO_SOURCE = official_versions.COMPONENT_SOURCES['go']
ELECTRON_SOURCE = 'https://github.com/electron/electron/security/advisories/GHSA-jr5w-w6x2-84p9'
ELECTRON_FLOORS = {42: '42.11.16', 43: '43.8.1', 44: '44.9.1'}
GO_MAGIC = b'\xff Go buildinf:'
NATIVE_MAGIC = (b'\x7fELF', b'MZ', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf')
SKIP_DIRS = {'.git', '.svn', '__pycache__', 'Cache', 'Caches', 'logs', 'Logs',
             'test', 'tests', 'testdata', 'docs', 'examples', '.Trash'}
CA_NAMES = {'cacert.pem', 'ca-bundle.crt', 'ca-certificates.crt', 'cert.pem'}
SCOPE = '検出したファイルの静的照合のみ。実効CA・独自検証設定・実通信は未検査。PC全体の安全性は示しません。'


def safe(path):
    return evidence.public_path(path)


def default_locations():
    """Return bounded discovery roots, not recursive filesystem search roots."""
    home = Path.home()
    paths = [Path(p) for p in os.environ.get('PATH', '').split(os.pathsep) if p]
    if sys.platform == 'darwin':
        installs = [Path('/Applications'), Path('/System/Applications'), home/'Applications', Path('/opt/homebrew/opt'), Path('/usr/local/opt'), Path('/opt/homebrew/Cellar'), Path('/usr/local/Cellar')]
        paths += [Path('/opt/homebrew/bin'), Path('/usr/local/bin'), home/'.local/bin', home/'go/bin', home/'.cargo/bin', home/'.safe-chain/bin']
    elif os.name == 'nt':
        installs = [Path(os.environ[k]) for k in ('ProgramFiles', 'ProgramFiles(x86)') if os.environ.get(k)]
        if os.environ.get('LOCALAPPDATA'):
            installs.append(Path(os.environ['LOCALAPPDATA'])/'Programs')
        installs.append(home/'scoop/apps')
        paths += [home/'go/bin', home/'.cargo/bin', home/'scoop/shims', home/'.safe-chain/bin']
    else:
        installs = [Path('/opt'), Path('/usr/local/lib')]
        paths += [Path('/usr/local/bin'), home/'.local/bin', home/'go/bin', home/'.cargo/bin', home/'.safe-chain/bin']
    return paths, installs


class Reader:
    def __init__(self, max_bytes, deadline):
        self.remaining = max_bytes
        self.deadline = deadline
        self.exhausted = False
        self.go_cache = {}
        self.go_modules = {}

    def read(self, path, limit=2*1024*1024, offset=0, whole=True):
        if not safe(path):
            raise ValueError('秘密設定ファイルは除外')
        if time.monotonic() >= self.deadline:
            raise ValueError('検査時間の上限')
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError('通常ファイル以外は未検査')
        size = max(0, path.stat().st_size-offset)
        if whole and size > limit:
            raise ValueError('ファイルサイズの上限')
        size = min(size, limit)
        if size > self.remaining:
            self.exhausted = True
            raise ValueError('総読取量の上限')
        self.remaining -= size
        with path.open('rb') as stream:
            stream.seek(offset)
            return stream.read(size)


def go_versions(path, reader):
    """Read inline Go 1.18+ build info from writable ELF/PE/Mach-O segments.

    Limit each data segment to its first 64 KiB. Unknown/legacy formats are not
    inferred from printable version strings. Fat Mach-O slices are all checked.
    """
    if path in reader.go_cache:
        return reader.go_cache[path]
    versions = []
    modules = []
    def parse(base=0, fat_allowed=True):
        data = reader.read(path, 4096, base, whole=False)
        segments = []
        if data.startswith(b'\x7fELF'):
            endian = {1: '<', 2: '>'}.get(data[5])
            if not endian or data[4] not in (1, 2):
                raise ValueError('ELF形式を解析できません')
            wide = data[4] == 2
            offset = struct.unpack_from(endian+('Q' if wide else 'I'), data, 32 if wide else 28)[0]
            size, count = struct.unpack_from(endian+'HH', data, 54 if wide else 42)
            if count > 512 or size < (56 if wide else 32):
                raise ValueError('ELFヘッダーの上限・破損')
            for i in range(count):
                values = struct.unpack_from(endian+('IIQQQQQQ' if wide else 'IIIIIIII'), data, offset+i*size)
                kind, flags, start, length = (values[0], values[1], values[2], values[5]) if wide else (values[0], values[6], values[1], values[4])
                if kind == 1 and flags & 2 and length:
                    segments.append((start, length))
        elif data.startswith(b'MZ'):
            offset = struct.unpack_from('<I', data, 60)[0]
            if data[offset:offset+4] != b'PE\0\0':
                return
            count = struct.unpack_from('<H', data, offset+6)[0]
            optional = struct.unpack_from('<H', data, offset+20)[0]
            if count > 512:
                raise ValueError('PEセクション数の上限')
            for i in range(count):
                section = offset+24+optional+i*40
                length, start = struct.unpack_from('<II', data, section+16)
                flags = struct.unpack_from('<I', data, section+36)[0]
                if flags & 0x80000000 and length:
                    segments.append((start, length))
        elif data[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') and fat_allowed:
            wide = data[3] == 0xbf
            count = struct.unpack_from('>I', data, 4)[0]
            if not 0 < count <= 16:
                raise ValueError('Mach-Oスライス数の上限')
            for i in range(count):
                offset = struct.unpack_from('>'+('Q' if wide else 'I'), data, 8+i*(32 if wide else 20)+8)[0]
                parse(base+offset, False)
            return
        elif data[:4] in NATIVE_MAGIC[2:6]:
            endian = '<' if data[0] in (0xce, 0xcf) else '>'
            wide = data[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf')
            count = struct.unpack_from(endian+'I', data, 16)[0]
            offset = 32 if wide else 28
            needed = offset+struct.unpack_from(endian+'I',data,20)[0]
            if needed > len(data):
                data = reader.read(path,min(needed,65536),base,whole=False)
            build_sections = []
            if count > 1024:
                raise ValueError('Mach-Oロードコマンド数の上限')
            for _ in range(count):
                cmd, size = struct.unpack_from(endian+'II', data, offset)
                if size < 8 or offset+size > len(data):
                    raise ValueError('Mach-Oヘッダーの上限・破損')
                if cmd in (1, 0x19):
                    is64 = cmd == 0x19
                    start, length = struct.unpack_from(endian+('QQ' if is64 else 'II'), data, offset+(40 if is64 else 32))
                    flags = struct.unpack_from(endian+'I', data, offset+(60 if is64 else 44))[0]
                    sections = struct.unpack_from(endian+'I',data,offset+(64 if is64 else 48))[0]
                    section_size = 80 if is64 else 68
                    section_start = offset+(72 if is64 else 56)
                    if section_start+sections*section_size > offset+size:
                        raise ValueError('Mach-Oセクションが破損しています')
                    for index in range(sections):
                        section = section_start+index*section_size
                        if data[section:section+16].rstrip(b'\0') == b'__go_buildinfo':
                            length = struct.unpack_from(endian+('Q' if is64 else 'I'),data,section+(40 if is64 else 36))[0]
                            start = struct.unpack_from(endian+'I',data,section+(48 if is64 else 40))[0]
                            build_sections.append((start,length))
                offset += size
            # Supported modern Go binaries have this named section. Do not
            # scan every unrelated native application's large writable data.
            segments = build_sections
        for start, length in segments:
            chunk = reader.read(path, min(length, 65536), base+start, whole=False)
            offset = chunk.find(GO_MAGIC)
            if offset < 0:
                continue
            if offset % 16 or len(chunk)-offset < 32 or chunk[offset+14] not in (4, 8):
                raise ValueError('Goビルド情報が破損しています')
            if chunk[offset+15] not in (2, 3):
                raise ValueError('Goビルド情報が旧形式または未対応です')
            # A valid Go version fits in one uvarint byte; do not decode modules
            # or build settings, which may contain private paths and flags.
            length = chunk[offset+32]
            version = chunk[offset+33:offset+33+length].decode('ascii')
            if not 0 < length < 128 or not re.fullmatch(r'go\d+\.\d+\.\d+', version):
                raise ValueError('Goの開発版・未知の版または破損した情報です')
            versions.append(version[2:])
            # Go inline build info stores a second length-prefixed string. Only
            # retain the scanner's module and public TLS dependencies; build
            # flags and arbitrary module paths can contain private information.
            position = offset+33+length
            size = shift = 0
            while position < len(chunk) and shift < 64:
                byte = chunk[position]; position += 1
                size |= (byte & 127) << shift
                if byte < 128: break
                shift += 7
            else: continue
            if size < 32 or size > len(chunk)-position: continue
            info = chunk[position+16:position+size-16].decode('utf-8', errors='replace')
            for line in info.splitlines():
                fields = line.split('\t')
                if len(fields) < 3 or fields[0] not in ('mod', 'dep'): continue
                name, value = fields[1:3]
                if (re.fullmatch(r'github\.com/google/osv-scanner(?:/v\d+)?', name) or
                    name in ('golang.org/x/crypto', 'golang.org/x/net', 'github.com/refraction-networking/utls')):
                    if re.fullmatch(r'v[0-9A-Za-z.+-]+', value):
                        record = {'module':name, 'version':value}
                        if record not in modules: modules.append(record)
    parse()
    reader.go_modules[path] = modules
    reader.go_cache[path] = sorted(set(versions))
    return reader.go_cache[path]


def version_check(reference, component, version, path):
    if component == 'electron':
        match = re.fullmatch(r'(\d+)\.\d+\.\d+', version)
        floor = ELECTRON_FLOORS.get(int(match[1])) if match else None
        # The official advisory explicitly covers every version below 42.11.16.
        if match and int(match[1]) < 42:
            floor = ELECTRON_FLOORS[42]
        status, detail = 'MANUAL', 'このElectron系列の修正版は未照合です。'
        if floor:
            status = 'UPDATE' if tuple(map(int, version.split('.'))) < tuple(map(int, floor.split('.'))) else 'INFERRED_OK'
            detail = '同梱Electronの参考修正版 '+floor+' と照合。'
        source = ELECTRON_SOURCE
    else:
        status, detail, floor = reference(component, version)
        status = 'INFERRED_OK' if status == 'REFERENCE_OK' else status
        source = (GO_SOURCE if component == 'go' else 'https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/' if component == 'nss' else official_versions.COMPONENT_SOURCES.get(component, 'https://emudhra.we-have-a-problem.com/'))
    return dict(component=component, status=status, method='version', version=version,
                reference_floor=floor, source=source, path=str(path), detail=detail)


def embedded_safe_chain_info(path, reader):
    """Read only an exact embedded package manifest; never start the program."""
    before = path.stat()
    if before.st_size > 128 * 1024 * 1024:
        return {}
    if not reader.read(path, 16, whole=False).startswith(NATIVE_MAGIC):
        return {}
    pattern = re.compile(rb'"name"\s*:\s*"@aikidosec/safe-chain"\s*,\s*'
                         rb'"version"\s*:\s*"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)"')
    versions, tail, digest = set(), b'', hashlib.sha256()
    size = before.st_size
    for offset in range(0, size, 1024 * 1024):
        chunk = reader.read(path, min(1024 * 1024, size-offset), offset=offset, whole=False)
        if len(chunk) != min(1024 * 1024, size-offset):
            return {}
        digest.update(chunk)
        window = tail + chunk
        versions.update(match.group(1).decode('ascii') for match in pattern.finditer(window))
        tail = window[-256:]
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        return {}
    return dict(version=next(iter(versions)) if len(versions) == 1 else '', binary_sha256=digest.hexdigest())


def embedded_safe_chain_version(path, reader):
    return embedded_safe_chain_info(path, reader).get('version', '')


def security_tool_evidence(candidate, reader):
    """Inspect the named installed tool without starting it or its shell wrappers."""
    path = candidate['path']
    tool = candidate.get('tool_id')
    if tool == 'osv-scanner':
        try:
            versions = go_versions(path, reader)
            modules = reader.go_modules.get(path, [])
        except (OSError, ValueError, TypeError, IndexError, struct.error, UnicodeError):
            versions, modules = [], []
        main = next((item['version'] for item in modules if item['module'].startswith('github.com/google/osv-scanner')), '')
        version_source = 'Goビルド情報' if main else ''
        if not main:
            parts = path.parts
            for index, part in enumerate(parts[:-2]):
                if part == 'Cellar' and parts[index+1] == 'osv-scanner' and re.fullmatch(r'\d+\.\d+\.\d+(?:_\d+)?',parts[index+2]):
                    main = parts[index+2]; version_source = 'Homebrewの導入配置'; break
        deps = [item for item in modules if not item['module'].startswith('github.com/google/osv-scanner')]
        return dict(version=main, version_source=version_source, go_versions=versions, tls_dependencies=deps,
                    limitation='実行ファイル内のGoビルド情報のみ。配布元の独自修正と実通信は未確認。',
                    source='https://github.com/google/osv-scanner')
    if tool != 'safe-chain': return None
    wrappers = sorted({match.group(1) for name in candidate['aliases']
                       for match in [re.match(r'aikido-([a-z0-9]+)', Path(name).name, re.I)] if match})
    version, runtime, version_source, binary = '', '不明', '', {}
    try:
        header = reader.read(path, 512, whole=False).decode('utf-8', errors='replace').splitlines()[0]
        if header.startswith('#!') and re.search(r'(?:^|[ /])node(?:\s|$)', header):
            runtime = 'node (PATH)' if '/env ' in header else 'node (指定パス)'
    except (OSError, ValueError, IndexError): pass
    for parent in [path.parent] + list(path.parents)[:4]:
        manifest = parent/'package.json'
        try:
            data = json.loads(reader.read(manifest, 65536).decode('utf-8'))
            if data.get('name') == '@aikidosec/safe-chain':
                value = str(data.get('version', ''))
                if re.fullmatch(r'[0-9A-Za-z.+-]+', value):
                    version, version_source = value, 'package.json'
                break
        except (OSError, ValueError, TypeError, AttributeError, UnicodeError): pass
    if not version and path.name.lower() in ('safe-chain', 'safe-chain.exe'):
        try:
            binary = embedded_safe_chain_info(path, reader)
            version = binary.get('version', '')
            if version: version_source = '本体内のパッケージ情報'
        except (OSError, ValueError, UnicodeError): pass
    links, shell_sources, configured = set(), set(), set()
    # Collect only recognized alias names; never store or output shell contents.
    for rcfile in (Path.home()/'.zshrc', Path.home()/'.bashrc', Path.home()/'.bash_profile',
                   Path.home()/'.profile', Path.home()/'.config/fish/config.fish'):
        try:
            contents = reader.read(rcfile, 128*1024).decode('utf-8', errors='replace')
            for line in contents.splitlines():
                if re.match(r'\s*(?:source|\.)\s+[^\n#]*safe-chain',line,re.I):
                    shell_sources.add(str(rcfile.relative_to(Path.home())))
                match = re.match(r"\s*alias\s+(npm|npx|yarn|pnpm|pnpx|bun|bunx|pip|pip3|python|python3|uv|uvx|poetry|pipx|rush|rushx|pdm)\s*=\s*['\"]?[^\r\n]*aikido-", line)
                if match and not line.lstrip().startswith('#'): links.add(match.group(1))
        except (OSError, ValueError, UnicodeError): pass
    base = path.parent.parent if path.parent.name == 'bin' else Path.home()/'.safe-chain'
    for script in ('init-posix.sh','init-fish.fish','init-pwsh.ps1'):
        try:
            contents = reader.read(base/'scripts'/script,128*1024).decode('utf-8',errors='replace')
            for name in ('npm','npx','yarn','pnpm','pnpx','bun','bunx','pip','pip3','python','python3','uv','uvx','poetry','pipx','rush','rushx','pdm'):
                if re.search(r'(?<![\w-])'+re.escape(name)+r'(?![\w-])',contents): configured.add(name)
        except (OSError, ValueError, UnicodeError): pass
    return dict(version=version, version_source=version_source, runtime=runtime, wrappers=wrappers, shell_links=sorted(links),
                **{k:v for k,v in binary.items() if k != 'version'},
                shell_sources=sorted(shell_sources), configured_wrappers=sorted(configured),
                local_proxy_ca_present=(base/'certs/ca-cert.pem').is_file(),
                limitation='設定ファイルの文字列上の候補であり、稼働中の連携は未確認。内部CAの有無は外部TLS対策の証拠ではありません。ネイティブ版の組込実行環境を安全に識別できない場合は不明。npm/pip→ローカルproxyとproxy→外部通信は別経路。外部通信は未確認。',
                source='https://github.com/AikidoSec/safe-chain')


def inspect(candidate, reference, reader, max_entries, max_depth, fingerprints):
    checks, gaps = [], []
    root = candidate['path']
    boundary = root if root.is_dir() else root.parent
    visited = set()
    entries = [0]
    app_deadline = min(reader.deadline, time.monotonic()+0.5)
    app_start_bytes = reader.remaining
    exhausted = [False]

    def observe(path):
        name = path.name
        lower = name.lower()
        component = None
        try:
            if name == 'METADATA' and path.parent.name.lower().startswith('certifi-') and path.parent.name.endswith('.dist-info'):
                text = reader.read(path).decode('utf-8')
                if re.search(r'^Name: certifi\s*$', text, re.M | re.I):
                    match = re.search(r'^Version: ([^\r\n]+)', text, re.M)
                    if match:
                        checks.append(version_check(reference, 'certifi', match[1], path))
                        return
                raise ValueError('certifiの版を解析できません')
            if name == 'Info.plist' and 'Electron Framework.framework' in path.parts:
                data = plistlib.loads(reader.read(path))
                if data.get('CFBundleIdentifier') in ('com.github.Electron.framework', 'org.electronjs.framework'):
                    version = data.get('CFBundleVersion') or data.get('CFBundleShortVersionString', '')
                    checks.append(version_check(reference, 'electron', str(version), path))
                    return
            if lower in CA_NAMES:
                text = reader.read(path).decode('ascii')
                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=text)
                result = evidence.bundle_evidence(text, fingerprints)
                checks.append(dict(component='CAファイル', status='MANUAL',
                                   method='static', path=str(path), detail=result['detail'],
                                   matched=result.get('matched'), certificates=result.get('certificates')))
                return
            if name in ('sbom.cdx.json', 'bom.json'):
                data = json.loads(reader.read(path))
                if data.get('bomFormat') != 'CycloneDX' or not isinstance(data.get('components'), list):
                    raise ValueError('対応するCycloneDX SBOMではありません')
                for item in data['components'][:10000]:
                    if not isinstance(item, dict):
                        continue
                    match = re.fullmatch(r'pkg:cargo/(rustls-webpki|webpki-roots|webpki-root-certs)@([^?#]+)', str(item.get('purl', '')))
                    if match:
                        checks.append(version_check(reference, match[1], match[2], path))
                gaps.append('SBOMと使用中の実行ファイルの対応は未確認')
                if len(data['components']) > 10000:
                    gaps.append('SBOMのコンポーネント数の上限')
                return
            if name == 'release':
                text = reader.read(path, 32768).decode('utf-8')
                match = re.search(r'^JAVA_VERSION="([^"\r\n]+)"', text, re.M)
                if match:
                    component = 'Java '+match[1]
                    vendor = re.search(r'^IMPLEMENTOR="([A-Za-z0-9 .,_+()&/-]{1,128})"', text, re.M)
                    runtime = re.search(r'^JAVA_RUNTIME_VERSION="([A-Za-z0-9.+_-]{1,128})"',text,re.M)
                    result=research_rules.java(dict(version=match[1],vendor=vendor[1] if vendor else '',runtime_version=runtime[1] if runtime else ''))
                    checks.append(dict(result, component=component, status='INFERRED_OK' if result['status']=='REFERENCE_OK' else result['status'],
                                       method='version',path=str(path),vendor=vendor[1] if vendor else ''))
                    gaps.append('同梱JREの実効truststore・独自TrustManager・配布元修正版は未確認')
                    return
            elif name in ('blocked.certs', 'blacklisted.certs'):
                text = reader.read(path).decode('ascii')
                pins = {x.replace(':', '').lower() for x in re.findall(r'(?m)^\s*([0-9a-fA-F:]{64,95})\s*(?:=|$)', text)}
                # Only report stored contents. Runtime use, algorithm and vendor
                # support are deliberately not inferred from this file alone.
                checks.append(dict(component='Java拒否リスト', status='MANUAL', method='static', path=str(path),
                                   detail='拒否リストの保存データを確認。参照対象の証明書指紋 {} 件。適用状態・配布元の対策は未確認。'.format(len(pins & fingerprints))))
                return
            elif name.endswith('.runtimeconfig.json'):
                data = json.loads(reader.read(path))
                runtime = data.get('runtimeOptions', {})
                frameworks = runtime.get('includedFrameworks') or runtime.get('frameworks') or [runtime.get('framework', {})]
                versions = [str(x.get('version', '')) for x in frameworks if isinstance(x, dict)]
                component = '.NET '+', '.join(versions)
            elif re.fullmatch(r'lib(?:ssl|crypto|curl)(?:[-.][\w-]+)*\.(?:dll|dylib|a|so(?:\.\d+)*)', lower):
                component = 'ネイティブTLSライブラリ '+name
            if component:
                checks.append(dict(component=component, status='MANUAL', method='inventory', path=str(path),
                                   detail='同梱ファイルを検出。使用中の版・実効CA・修正版の照合は未完了。'))
                return
            if (path == root or os.access(path, os.X_OK) or lower.endswith(('.exe', '.dll', '.so', '.dylib'))):
                header = reader.read(path, 16, whole=False)
                if header.startswith(NATIVE_MAGIC):
                    for version in go_versions(path, reader):
                        checks.append(version_check(reference, 'go', version, path))
        except (OSError, ValueError, TypeError, AttributeError, IndexError, struct.error, UnicodeError, RuntimeError):
            gaps.append('読取・解析不可または上限: '+str(path))
            if lower in CA_NAMES or name in ('release','blocked.certs','blacklisted.certs','METADATA','sbom.cdx.json','bom.json') or name.endswith('.runtimeconfig.json') or 'Electron Framework.framework' in path.parts:
                checks.append(dict(component='同梱メタデータ '+name,status='MANUAL',method='inventory',
                                   path=str(path),detail='TLS関連情報の読取・解析を完了できません。'))

    def walk(path, depth):
        if not safe(path):
            return
        if exhausted[0]:
            return
        if time.monotonic() >= app_deadline or reader.remaining <= 0 or app_start_bytes-reader.remaining >= 8*1024*1024:
            gaps.append('アプリの検査時間または読取量の上限')
            exhausted[0] = True
            return
        try:
            resolved = path.resolve()
            if resolved in visited:
                return
            if path != root and boundary.resolve() not in resolved.parents:
                gaps.append('アプリ外を指すリンクは未検査: '+str(path))
                return
            visited.add(resolved)
            if path.is_dir():
                if path.name in SKIP_DIRS:
                    return
                if depth > max_depth:
                    gaps.append('探索の深さの上限: '+str(path))
                    return
                with os.scandir(path) as children:
                    bounded = []
                    for entry in children:
                        entries[0] += 1
                        if entries[0] > max_entries:
                            gaps.append('アプリ内探索件数の上限')
                            break
                        bounded.append(Path(entry.path))
                    # Runtime metadata before large resources/dependency trees.
                    priority = {'Info.plist', 'release', 'METADATA', 'Contents', 'Frameworks', 'Resources',
                                'bin', 'jre', 'runtime', 'sbom.cdx.json', 'bom.json'}
                    for child in sorted(bounded, key=lambda p:(p.name not in priority, p.name)):
                        if entries[0] > max_entries and child.is_dir():
                            continue
                        walk(child, depth+1)
            elif path.is_file():
                observe(path)
        except (OSError, ValueError, RuntimeError):
            gaps.append('読取不可: '+str(path))

    if candidate.get('tool_id') == 'nss' and re.fullmatch(r'\d+\.\d+(?:\.\d+)?(?:_\d+)?', root.name):
        checks.append(version_check(reference, 'nss', root.name, root))
        gaps.append('HomebrewのNSSパッケージ版。利用アプリ・適用中の証明書ストアは未確認')
    else:
        # Inspect the conventional framework first, before a large Resources
        # tree can exhaust the per-app traversal budget.
        if root.suffix.lower() == '.app':
            framework = root/'Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist'
            if framework.is_file() and safe(framework) and root.resolve() in framework.resolve().parents:
                observe(framework)
                visited.add(framework.resolve())
        walk(root, 0)
    inspected = [c for c in checks if c['status'] in ('UPDATE', 'INFERRED_OK', 'STATIC_OK')]
    unresolved = [c for c in checks if c not in inspected]
    coverage = 'partial' if inspected and (unresolved or gaps) else 'static_checked' if inspected else 'uninspected'
    status = 'UPDATE' if any(c['status']=='UPDATE' for c in checks) else 'MANUAL' if coverage!='static_checked' else 'INFERRED_OK' if any(c['method']=='version' for c in inspected) else 'STATIC_OK'
    # Discovery proves installation, not the outcome of this app's TLS.
    if candidate.get('tool_id') or '明示指定' in candidate['sources']:
        status = 'UPDATE' if any(c['status'] == 'UPDATE' for c in checks) else 'MANUAL'
    label = {'partial':'一部のみ静的照合', 'static_checked':'静的照合あり', 'uninspected':'未照合'}[coverage]
    gaps = list(dict.fromkeys(gaps))
    if not inspected:
        gaps.insert(0, 'TLS構成と修正版の照合に必要な情報を取得できません（通信の有無も未確認）')
    gaps.append('アプリの実効CA・独自検証設定・実通信は未検査')
    detail = 'このツールの通信は未確認。'+(' / '.join(c['component']+': '+c['detail'] for c in checks) if checks else '導入を確認しました。')
    metadata = dict(application=True, path=str(root), discovered_paths=candidate['aliases'],
                    discovery_sources=candidate['sources'], coverage_state=coverage, inspections=checks,
                    uninspected=gaps, reference_date=official_versions.AS_OF,
                    tool_id=candidate.get('tool_id'), tool_name=candidate.get('tool_name'),
                    catalog_features=list(tool_catalog.BY_ID.get(candidate.get('tool_id'),{}).get('features', ())))
    if candidate.get('tool_id') == 'python':
        identity = verdicts.installation_identity('python', root)
        if identity: metadata['python_identity'] = list(identity)
    elif candidate.get('tool_id') == 'pip':
        # Absolute Python shebangs bind pip to an interpreter without executing
        # wrappers or guessing which Python /usr/bin/env would select.
        try:
            header = reader.read(root, 4096, whole=False).split(b'\n', 1)[0].decode('utf-8')
            match = re.fullmatch(r'#!(/[^\r\n]+/python(?:\d+(?:\.\d+)*)?)\s*', header)
            if match and safe(Path(match[1])):
                identity = verdicts.installation_identity('python', match[1])
                if identity: metadata['python_identity'] = list(identity)
        except (OSError, ValueError, UnicodeError):
            pass
    if candidate.get('tool_id') in ('poetry','pip'):
        environment = installed_metadata.python_environment(root,reader)
        if environment: metadata['python_environment'] = environment
    if root.is_dir() and root.suffix.lower() == '.app':
        info_path = root/'Contents/Info.plist'
        try:
            info = plistlib.loads(reader.read(info_path,1024*1024))
            version = info.get('CFBundleShortVersionString') or info.get('CFBundleVersion')
            if isinstance(version, str) and len(version) <= 100:
                metadata['application_version'] = version
            bundle = info.get('CFBundleIdentifier')
            if isinstance(bundle, str) and len(bundle) <= 200:
                metadata['bundle_identifier'] = bundle
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
            metadata['uninspected'].append('アプリ本体のバージョンを取得できません')
    security = security_tool_evidence(candidate, reader)
    if security is not None:
        metadata['security_tool'] = security
        if candidate['tool_id'] == 'safe-chain':
            detail = 'Safe Chainの外部通信は未確認。ローカルproxyと外部への通信を分けて確認してください。'
        else:
            detail = ('OSV-Scannerの通信は未確認。実行ファイル自身のGoビルド情報を確認しました。' if security['go_versions'] else
                      'OSV-Scannerの通信は未確認。実行ファイルのGoビルド情報を取得できません。')
    primary = next((c for c in checks if c['status']=='UPDATE'), None)
    if primary:
        metadata.update({key:primary.get(key) for key in ('version', 'reference_floor', 'source')})
    display_name = candidate.get('tool_name') or Path(candidate['aliases'][0]).name
    return verdicts.finish(dict(name='アプリ / '+display_name+' ['+str(root)+']', status=status, detail=detail,
                                metadata=metadata, samples=[], scope=SCOPE,
                                action='このツールの配布元で対応状況・同梱ランタイムを確認してください。'),
                           'version' if any(c['method']=='version' for c in checks) else 'static' if inspected else 'manual')


def managed_locations(max_dirs=300):
    """Known manager layouts only; do not traverse projects or arbitrary homes."""
    home = Path.home()
    groups = [
        (home/'.pyenv/versions', ('bin', 'Scripts')),
        (home/'.nvm/versions/node', ('bin',)), (home/'.rbenv/versions', ('bin',)),
        (home/'.local/share/fnm/node-versions', ('installation/bin',)),
        (home/'.volta/tools/image/node', ('bin',)),
        (home/'fvm/versions', ('bin',)), (home/'.fvm/versions', ('bin',)),
        (home/'.conda/envs', ('bin', 'Scripts')),
        (home/'miniconda3/envs', ('bin', 'Scripts')),
        (home/'anaconda3/envs', ('bin', 'Scripts')),
        (home/'.rustup/toolchains', ('bin',)),
        (home/'.sdkman/candidates/java', ('bin',)),
        (home/'.sdkman/candidates/gradle', ('bin',)), (home/'.sdkman/candidates/maven', ('bin',)),
        (home/'.sdkman/candidates/kotlin', ('bin',)), (home/'.sdkman/candidates/scala', ('bin',)),
        (Path('/Library/Java/JavaVirtualMachines'), ('Contents/Home/bin',)),
        (Path('/usr/lib/jvm'), ('bin',)),
    ]
    # mise/asdf use a tool/version layout. Only known runtime names are opened.
    for base in (home/'.asdf/installs', home/'.local/share/mise/installs'):
        for name in ('python', 'node', 'nodejs', 'java', 'ruby', 'golang', 'go', 'rust', 'bun', 'deno', 'dart', 'erlang', 'elixir'):
            groups.append((base/name, ('bin', 'Scripts')))
    for cellar in (Path('/opt/homebrew/Cellar'), Path('/usr/local/Cellar')):
        formulae = ['python', 'node', 'ruby', 'openjdk', 'go', 'php', 'curl', 'wget', 'rust',
                    'bun', 'deno', 'dart', 'perl']
        formulae += ['python@3.'+str(n) for n in range(8, 21)]
        formulae += ['node@'+str(n) for n in (18,20,22,24,26)]
        formulae += ['openjdk@'+str(n) for n in (8,11,17,21,25)]
        groups.extend((cellar/name, ('bin', 'libexec/bin')) for name in formulae)
    scoop = home/'scoop/apps'
    groups.extend((scoop/name, ('', 'bin', 'Scripts')) for name in
                  ('python','nodejs','nodejs-lts','openjdk','temurin','go','rustup','ruby','php','dart','flutter','bun','deno','perl'))
    paths, incomplete = [], []
    for direct in (home/'miniconda3/bin', home/'miniconda3/Scripts', home/'anaconda3/bin', home/'anaconda3/Scripts'):
        if direct.is_dir(): paths.append(direct)
    for base, suffixes in groups:
        try:
            if not base.is_dir():
                continue
            with os.scandir(base) as children:
                for child in children:
                    if len(paths) >= max_dirs:
                        incomplete.append('管理ツールの環境数の上限')
                        return paths, incomplete
                    if child.name.startswith('.') or not child.is_dir():
                        continue
                    paths.extend(Path(child.path)/suffix for suffix in suffixes)
        except OSError:
            incomplete.append('管理ツールの環境を探索できません: '+str(base))
    return paths, incomplete


def known_installations(platform=None, environ=None, home=None, system_root=None):
    """Specific nested installation paths, without recursively scanning applications."""
    platform = platform or sys.platform
    environ = os.environ if environ is None else environ
    home = Path.home() if home is None else Path(home)
    system_root = Path('/') if system_root is None else Path(system_root)
    paths = []
    if platform == 'win32':
        bases = [Path(environ[k]) for k in ('ProgramFiles','ProgramFiles(x86)') if environ.get(k)]
        for base in bases:
            for relative, tool in (
                ('Google/Chrome/Application/chrome.exe','chrome'), ('Microsoft/Edge/Application/msedge.exe','edge'),
                ('Mozilla Firefox/firefox.exe','firefox'), ('BraveSoftware/Brave-Browser/Application/brave.exe','brave'),
                ('Git/cmd/git.exe','git'), ('Docker/Docker/resources/bin/docker.exe','docker'),
                ('PowerShell/7/pwsh.exe','powershell'), ('dotnet/dotnet.exe','dotnet'),
                ('FileZilla FTP Client/filezilla.exe','filezilla'), ('WinSCP/WinSCP.exe','winscp')):
                paths.append((base/relative,tool))
            java = base/'Java'
            try:
                if java.is_dir():
                    with os.scandir(java) as children:
                        for child in children:
                            if re.match(r'^(?:jdk|jre)',child.name,re.I): paths.append((Path(child.path)/'bin/java.exe','java'))
            except OSError: pass
        if environ.get('LOCALAPPDATA'):
            local = Path(environ['LOCALAPPDATA'])
            for relative, tool in (
                ('Google/Chrome/Application/chrome.exe','chrome'), ('Microsoft/Edge/Application/msedge.exe','edge'),
                ('Programs/Microsoft VS Code/Code.exe','vscode'), ('Programs/cursor/Cursor.exe','cursor'),
                ('Programs/Windsurf/Windsurf.exe','windsurf'), ('Programs/Postman/Postman.exe','postman'),
                ('Programs/Bruno/Bruno.exe','bruno'), ('Programs/Insomnia/Insomnia.exe','insomnia'),
                ('GitHubDesktop/GitHubDesktop.exe','github-desktop')):
                paths.append((local/relative,tool))
            python = local/'Programs/Python'
            try:
                if python.is_dir():
                    with os.scandir(python) as children:
                        for child in children:
                            if re.fullmatch(r'Python3\d+',child.name,re.I): paths.append((Path(child.path)/'python.exe','python'))
            except OSError: pass
        if environ.get('SystemRoot'):
            paths.append((Path(environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe','windows-powershell'))
    elif platform.startswith('linux'):
        for relative, tool in (
            ('opt/google/chrome/google-chrome','chrome'), ('opt/microsoft/msedge/msedge','edge'),
            ('opt/brave.com/brave/brave','brave'), ('opt/Postman/Postman','postman'),
            ('opt/Insomnia/insomnia','insomnia'), ('usr/share/code/code','vscode'),
            ('usr/lib/firefox/firefox','firefox'), ('opt/visual-studio-code/code','vscode')):
            paths.append((system_root/relative,tool))
    return [(path, tool) for path,tool in paths if safe(path) and path.is_file()]


def windows_registrations(max_entries=5000):
    """Read only recognized uninstall registrations; no command or registry edits."""
    if sys.platform != 'win32': return [], []
    try:
        import winreg
    except ImportError:
        return [], ['Windowsの登録情報を取得できません']
    names = {
        'Google Chrome':'chrome', 'Microsoft Edge':'edge', 'Mozilla Firefox':'firefox',
        'Brave':'brave', 'Microsoft Visual Studio Code':'vscode', 'Visual Studio Code':'vscode',
        'Cursor':'cursor', 'Windsurf':'windsurf', 'Antigravity':'antigravity',
        'Kiro':'kiro', 'Postman':'postman', 'Insomnia':'insomnia', 'Bruno':'bruno',
        'GitHub Desktop':'github-desktop', 'Sourcetree':'sourcetree', 'Fork':'fork',
        'Docker Desktop':'docker', 'Android Studio':'android-studio',
        'Microsoft Visual Studio':'visual-studio', 'IntelliJ IDEA':'jetbrains',
        'PyCharm':'jetbrains', 'WebStorm':'jetbrains', 'GoLand':'jetbrains',
        'CLion':'jetbrains', 'Rider':'jetbrains', 'FileZilla':'filezilla', 'WinSCP':'winscp',
    }
    registrations, gaps, seen, total = [], [], set(), 0
    branch = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (getattr(winreg,'KEY_WOW64_64KEY',0),getattr(winreg,'KEY_WOW64_32KEY',0)):
            try:
                with winreg.OpenKey(hive,branch,0,winreg.KEY_READ | view) as root:
                    count = winreg.QueryInfoKey(root)[0]
                    for index in range(count):
                        total += 1
                        if total > max_entries:
                            gaps.append('Windows登録情報の件数の上限'); return registrations,gaps
                        try:
                            keyname = winreg.EnumKey(root,index)
                            with winreg.OpenKey(root,keyname) as key:
                                def value(field):
                                    try: return winreg.QueryValueEx(key,field)[0]
                                    except OSError: return ''
                                display = value('DisplayName')
                                if not isinstance(display,str): continue
                                matched = next(((label,tool) for label,tool in names.items()
                                    if re.match(r'^'+re.escape(label)+r'(?:$|[ (\d])',display,re.I)),None)
                                if not matched: continue
                                label, match = matched
                                version,location = value('DisplayVersion'),value('InstallLocation')
                                version = version if isinstance(version,str) and re.fullmatch(r'[0-9A-Za-z.+_ -]{1,80}',version) else ''
                                location = location if isinstance(location,str) and len(location)<=1024 else ''
                                identity = (match,version,location.casefold())
                                if identity in seen: continue
                                seen.add(identity)
                                registrations.append(dict(tool_id=match,display_name=label,version=version,location=location))
                        except OSError: continue
            except FileNotFoundError: continue
            except OSError: gaps.append('Windowsのアプリ登録情報を一部取得できません')
    return registrations,list(dict.fromkeys(gaps))


def managed_metadata(max_entries=300):
    """Locate manager scripts and installed modules without executing them."""
    home = Path.home()
    found, gaps = [], []
    fixed = [('nvm', home/'.nvm/nvm.sh'), ('sdkman', home/'.sdkman/bin/sdkman-init.sh')]
    for tool, path in fixed:
        if path.is_file(): found.append((path, tool))
    module_roots = [home/'.local/share/powershell/Modules', home/'Documents/PowerShell/Modules',
                    home/'Documents/WindowsPowerShell/Modules', Path('/usr/local/share/powershell/Modules'),
                    Path('/usr/share/powershell/Modules'), Path('/opt/microsoft/powershell/7/Modules')]
    if os.name == 'nt':
        for key in ('ProgramFiles', 'ProgramFiles(x86)', 'SystemRoot'):
            if os.environ.get(key):
                base = Path(os.environ[key])
                module_roots += [base/'PowerShell/Modules', base/'WindowsPowerShell/Modules',
                                 base/'System32/WindowsPowerShell/v1.0/Modules']
    for base in module_roots:
        for name, tool in (('PowerShellGet', 'powershellget'),
                           ('Microsoft.PowerShell.PSResourceGet', 'psresourceget')):
            path = base/name
            if path.is_dir(): found.append((path, tool))
    base = home/'.mix/archives'
    try:
        if base.is_dir():
            with os.scandir(base) as children:
                for child in children:
                    if len(found) >= max_entries:
                        gaps.append('管理ツールのメタデータ件数の上限'); break
                    if re.fullmatch(r'hex-.*', child.name, re.I) and child.is_dir():
                        found.append((Path(child.path), 'hex'))
    except OSError:
        gaps.append('Hexのメタデータを探索できません: '+str(base))
    return found, gaps


def scan(reference, path_dirs=None, install_dirs=None, extra_paths=(), max_candidates=4096,
         max_entries=20000, max_seconds=90, max_bytes=512*1024*1024, max_app_entries=1000, max_depth=8):
    use_managed = path_dirs is None
    if path_dirs is None or install_dirs is None:
        default_paths, default_installs = default_locations()
        path_dirs = default_paths if path_dirs is None else path_dirs
        install_dirs = default_installs if install_dirs is None else install_dirs
    incomplete = []
    metadata_locations, known_locations, registrations = [], [], []
    if use_managed:
        managed, gaps = managed_locations()
        path_dirs = list(path_dirs) + managed
        incomplete.extend(gaps)
        metadata_locations, gaps = managed_metadata()
        incomplete.extend(gaps)
        known_locations = known_installations()
        registrations, gaps = windows_registrations()
        incomplete.extend(gaps)
    reader = Reader(max_bytes, time.monotonic()+max_seconds)
    candidates, searched, excluded = {}, [], []
    seen_roots = set()
    total = [0]
    commands, apps = {}, {}
    for spec in tool_catalog.CATALOG:
        for name in spec['commands']:
            commands.setdefault(name.casefold(), []).append(spec)
        for name in spec['apps']:
            apps.setdefault(name.casefold(), []).append(spec)

    def add(path, source, spec=None):
        if not safe(path):
            if source == '明示指定':
                incomplete.append('明示対象は除外規則に該当するため未検査: '+str(path))
            return
        try:
            if not path.exists():
                incomplete.append('対象が存在しません: '+str(path))
                return
            actual = path.resolve()
            # A known app's CLI symlink identifies the enclosing bundle even
            # when it is installed outside the usual Applications directories.
            if spec and actual.is_file():
                names = {name.casefold() for name in spec['apps'] if name.lower().endswith('.app')}
                enclosing = next((p for p in actual.parents if p.name.casefold() in names), None)
                if enclosing and safe(enclosing):
                    actual = enclosing
            # A venv executable can symlink to the same base interpreter as other venvs.
            venv = spec and spec['id'] == 'python' and (path.parent.parent/'pyvenv.cfg').is_file()
            identity = (path.parent.parent.absolute(), actual) if venv else actual
            key = (spec['id'] if spec else 'explicit', identity)
            if key in candidates:
                item = candidates[key]
                if str(path) not in item['aliases']: item['aliases'].append(str(path))
                if source not in item['sources']: item['sources'].append(source)
            elif len(candidates) < max_candidates:
                candidates[key] = dict(path=path.absolute() if venv else actual, aliases=[str(path)],
                                       sources=[source], tool_id=spec['id'] if spec else None,
                                       tool_name=spec['name'] if spec else None)
            else:
                incomplete.append('アプリ件数の上限')
        except (OSError, RuntimeError, ValueError):
            incomplete.append('対象を解決できません: '+str(path))

    for path, tool_id in metadata_locations:
        spec = tool_catalog.BY_ID[tool_id]
        if sys.platform in spec['platforms']:
            add(path, '管理ツールのメタデータ', spec)
    for path, tool_id in known_locations:
        spec = tool_catalog.BY_ID[tool_id]
        if sys.platform in spec['platforms']:
            add(path, '既知の配置', spec)
    for value in extra_paths:
        path = Path(value).expanduser().absolute()
        key = re.sub(r'\.(?:exe|cmd|bat|ps1|com|appimage)$', '', path.name, flags=re.I).casefold()
        matches = commands.get(key) or apps.get(path.name.casefold()) or []
        add(path, '明示指定', matches[0] if matches else None)
    for source, directories in (('既知の配置', install_dirs), ('PATH/標準bin', path_dirs)):
        for value in directories:
            root = Path(value).expanduser()
            if not root.is_absolute() or not safe(root):
                excluded.append(str(root)); continue
            try:
                key = (root.resolve(), source)
                if key in seen_roots: continue
                seen_roots.add(key)
                if not root.exists():
                    searched.append(dict(path=str(root), source=source, status='not_found')); continue
                if time.monotonic() >= reader.deadline:
                    incomplete.append('探索時間の上限: '+str(root)); continue
                searched.append(dict(path=str(root), source=source, status='searched'))
                with os.scandir(root) as children:
                    for child in children:
                        total[0] += 1
                        if total[0] > max_entries or time.monotonic() >= reader.deadline:
                            incomplete.append('探索件数または時間の上限: '+str(root)); break
                        path = Path(child.path)
                        if child.name.startswith('.') or not safe(path): continue
                        if source == '既知の配置':
                            matches = apps.get(child.name.casefold(), [])
                        else:
                            name = re.sub(r'\.(?:exe|cmd|bat|ps1|com)$', '', child.name, flags=re.I).casefold()
                            matches = commands.get(name, [])
                        if not matches: continue
                        try:
                            if source == '既知の配置' and not (path.is_dir() or path.is_file()): continue
                            if source != '既知の配置' and not (path.is_file() and (os.name == 'nt' or os.access(path, os.X_OK))): continue
                            for spec in matches:
                                if sys.platform not in spec['platforms']: continue
                                if spec['id'] == 'nss' and path.parent.name == 'Cellar' and path.is_dir():
                                    with os.scandir(path) as versions:
                                        for child_version in versions:
                                            if re.fullmatch(r'\d+\.\d+(?:\.\d+)?(?:_\d+)?', child_version.name) and child_version.is_dir():
                                                add(Path(child_version.path), 'Homebrew登録情報', spec)
                                else:
                                    add(path, source, spec)
                        except (OSError, ValueError, RuntimeError):
                            incomplete.append('対象を確認できません: '+str(path))
            except (OSError, RuntimeError, ValueError):
                incomplete.append('探索できません: '+str(root))
    discovery_incomplete = bool(incomplete)
    try:
        refs = json.loads((ROOT/'references/assessment.json').read_text(encoding='utf-8'))
        fingerprints = {c['sha256'].lower() for c in refs['certificates']}
    except (OSError, ValueError, KeyError, TypeError):
        fingerprints = set()
        incomplete.append('参照証明書データを読み込めません')
    ordered = sorted(candidates.values(), key=lambda item:('明示指定' not in item['sources'], item['path'].is_dir()))
    records = [inspect(item, reference, reader, max_app_entries, max_depth, fingerprints) for item in ordered]
    if time.monotonic() >= reader.deadline or reader.remaining <= 0 or reader.exhausted:
        incomplete.append('静的検査の時間または総読取量の上限')
    found = {item['tool_id'] for item in ordered}
    for registration in registrations:
        spec = tool_catalog.BY_ID[registration['tool_id']]
        found.add(spec['id'])
        records.append(verdicts.finish(dict(name=spec['name']+' / Windows登録情報',status='MANUAL',
            detail='Windowsの登録情報を確認しました。このツールの通信と現在の導入実体は未確認です。',
            metadata=dict(tool_id=spec['id'],tool_name=spec['name'],discovery_state='registry_only',
                          version=registration['version'],registration_name=registration['display_name'],
                          path=registration['location']),samples=[],
            scope='現在のユーザーとマシンのアンインストール登録情報。'), 'inventory'))
    for spec in tool_catalog.CATALOG:
        if spec['id'] in found: continue
        applicable = sys.platform in spec['platforms']
        status = 'NOT_APPLICABLE' if not applicable else 'UNKNOWN' if discovery_incomplete else 'NOT_FOUND'
        detail = ('このOSの標準対象ではありません。' if not applicable else
                  '探索に制限があり、導入状況を確認できません。' if discovery_incomplete else
                  '探索した配置では見つかりませんでした。')
        records.append(verdicts.finish(dict(name=spec['name'], status=status, detail=detail,
            metadata=dict(tool_id=spec['id'], tool_name=spec['name'], discovery_state=status.lower(),
                          catalog_features=list(spec['features'])),
            samples=[], scope='PATH・既知の配置と管理ツールの環境のみ。'), 'inventory'))
    summary = verdicts.finish(dict(name='アプリ / 探索範囲', status='UNKNOWN' if incomplete else 'CHECKED',
        detail='標準対象から{}件の導入実体を検出。'.format(len(ordered)),
        metadata=dict(application_scan=True, searched=searched, incomplete=list(dict.fromkeys(incomplete)),
                      excluded=excluded, limits=dict(candidates=max_candidates, entries=max_entries,
                      seconds=max_seconds, bytes=max_bytes, app_entries=max_app_entries, depth=max_depth)),
        samples=[], scope='探索した配置のみ。プロジェクト・コンテナ・別ユーザーは明示指定時のみ。'), 'inventory')
    return [summary]+records
