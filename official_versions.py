"""Version evidence for narrowly identified upstream distributions.

The version text and recorded installation layout are not an authenticity check.
An unknown vendor build, suffix, preview, or unreviewed release stays unknown.
"""
import re

AS_OF = '2026-11-02'
CODEX_SOURCE = 'https://github.com/openai/codex/releases/tag/rust-v0.164.0'
CODEX_DETAIL = 'https://github.com/openai/codex/pull/55616'
PYTHON_SOURCE = 'https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576'
COMPONENT_SOURCES = {
    'node':'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
    'certifi':'https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2',
    'go':'https://pkg.go.dev/vuln/GO-2026-6809',
    'rustls-webpki':'https://github.com/rustls/webpki/releases/tag/v%2F0.103.16',
    'webpki-roots':'https://github.com/rustls/webpki-roots/releases',
    'webpki-root-certs':'https://github.com/rustls/webpki-roots/releases',
}
FLOORS = {'nss':'3.131.1', 'pip':'26.2.2', 'certifi':'2026.10.18', 'uv':'0.13.5',
          'rustls-webpki':'0.103.16', 'webpki-roots':'1.0.10', 'webpki-root-certs':'1.0.10'}
FAMILY_FLOORS = {'node':{(22,):'22.23.4',(24,):'24.22.1',(26,):'26.12.1'},
                 'go':{(1,26):'1.26.10',(1,27):'1.27.3'}}


# A release manifest establishes only that release's published dependencies.
# Do not extend exact dependency mappings to unreviewed later releases.
MISE_SOURCE = 'https://github.com/jdx/mise/releases/tag/v2026.10.17'
ZED_SOURCE = 'https://github.com/zed-industries/zed/blob/v1.26.2/Cargo.lock'
ZED_TLS_SOURCE = 'https://github.com/zed-industries/zed/blob/v1.26.2/crates/http_client_tls/src/http_client_tls.rs'


def published(tool, text, bundle=None):
    """Reviewed upstream release facts, not installed files or dependency ranges."""
    dependencies = [('rustls-webpki', '0.103.16'), ('webpki-roots', '1.0.10')]
    if tool == 'mise':
        match = re.fullmatch(r'(?:mise )?(2026\.\d+\.\d+)(?: (?:macos|linux|windows)-(?:arm64|x64|x86_64|aarch64) \(\d{4}-\d{2}-\d{2}\))?', text or '')
        if not match: return None
        version = match[1]
        status = 'UPDATE' if tuple(map(int,version.split('.'))) < (2026,10,17) else 'REFERENCE_OK'
        return dict(status=status, version=version, reference_floor='2026.10.17', source=MISE_SOURCE,
                    version_basis='official-release', as_of=AS_OF,
                    detail='miseの組込npmバックエンドを公式の対策版2026.10.17と照合。',
                    scope='miseの組込npmバックエンドの標準CA・TLS依存。OSストアを使うビルド、外部ツール・プラグインは別の判定。')
    if tool == 'zed' and text == '1.26.2' and bundle == 'dev.zed.Zed':
        return dict(status='REFERENCE_OK', version=text, reference_floor=None, source=ZED_SOURCE,
                    version_basis='published-dependencies', as_of=AS_OF,
                    published_dependencies=[dict(component=c,version=v,reference_floor=v,
                        source=COMPONENT_SOURCES[c]) for c,v in dependencies],
                    dependency_sources=[ZED_SOURCE,ZED_TLS_SOURCE],
                    detail='Zed 1.26.2の公開依存関係には対策版のRust TLS・証明書データが含まれます。',
                    scope='公式1.26.2の組込Rust TLS・CA部品からの推定。通常の通信はOSの証明書検証を使い、その検証機能を初期化できない場合に組込CAへ切り替えます。OS側の適用状況は別の判定。')
    return None


def reference(name, text):
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z0-9.+_~-]*)', text or '')
    if not match or match.group(4) or re.search(r'\d(?:[-._]?(?:rc|alpha|beta|dev|ea|pre|nightly))', text or '', re.I):
        return 'MANUAL', 'バージョンを一意に比較できません', None
    version = tuple(int(x or 0) for x in match.groups()[:3])
    floor = FLOORS.get(name)
    if name in FAMILY_FLOORS:
        floor = next((f for key, f in FAMILY_FLOORS[name].items() if version[:len(key)] == key), None)
    # GO-2026-6809 explicitly includes all earlier stable Go 1 releases.
    # This is the runtime embedded in the inspected binary, not another compiler.
    if name == 'go' and version[0] == 1 and version < (1,26,10): floor = '1.26.10'
    if name == 'certifi' and version < (2019,3,9): floor = None
    if name == 'nss' and version[0] != 3: floor = None
    if name == 'pip' and version[0] > 26: floor = None
    if name == 'uv' and version[0] != 0: floor = None
    if name == 'rustls-webpki' and version[:2] != (0,103): floor = None
    if name in ('webpki-roots','webpki-root-certs') and version[:2] != (1,0): floor = None
    if not floor:
        return 'MANUAL', 'この系列の修正版は配布元で確認してください', None
    baseline = tuple(int(x) for x in floor.split('.'))
    if version < baseline:
        return 'UPDATE', '参考修正版 {} 未満。配布元のバックポート有無も確認'.format(floor), floor
    return 'REFERENCE_OK', '参考修正版 {} 以上。実通信の結果とは別の判定'.format(floor), floor


def assess(tool, text, distribution='unknown'):
    result = dict(status='MANUAL', floor=None, source='', scope='', as_of=AS_OF,
                  detail='この配布形式・版の公式対策は判定できません。')
    text = (text or '').strip()
    if tool == 'codex' and distribution == 'npm':
        match = re.fullmatch(r'codex-cli (\d+\.\d+\.\d+)', text)
        version = tuple(map(int, match.group(1).split('.'))) if match else None
        if version and version[0] == 0:
            result.update(status='UPDATE' if version < (0, 164, 0) else 'REFERENCE_OK',
                          floor='0.164.0', source=CODEX_SOURCE,
                          detail='公式 npm 版の版番号と配置に基づく照合。実体の真正性・変更の有無は未検証。',
                          scope='公式 Codex の Rust TLS 依存に関する版照合。別の通信・独自設定は未確認。')
    elif tool == 'python' and distribution == 'official':
        match = re.fullmatch(r'(?:Python )?(\d+)\.(\d+)\.(\d+)', text)
        floors = {(3,11):18, (3,12):16, (3,13):18, (3,14):10, (3,15):2}
        if match:
            version = tuple(map(int, match.groups()))
            floor = floors.get(version[:2])
            if floor is not None:
                result.update(status='UPDATE' if version[2] < floor else 'REFERENCE_OK',
                              floor='{}.{}.{}'.format(*version[:2], floor), source=PYTHON_SOURCE,
                              detail='公式 CPython の標準 TLS 検証について版番号を照合。',
                              scope='公式 CPython の標準 TLS 検証のみ。独自配布・別のライブラリーは別。')
    return result


def codex_distribution(snapshot_path):
    """Recognize the npm entry point from recorded evidence, never from a version path."""
    path = (snapshot_path or '').replace('\\', '/').lower()
    if path.endswith('/node_modules/@openai/codex/bin/codex.js'):
        return 'npm'
    return 'unknown'


def python_distribution(snapshot_path):
    """Recognize standard python.org installer layouts; this does not verify signatures."""
    path = (snapshot_path or '').replace('\\', '/').lower()
    if re.fullmatch(r'/library/frameworks/python\.framework/versions/3\.\d+/(?:bin/python(?:3(?:\.\d+)?)?|resources/python\.app/contents/macos/python)', path):
        return 'official'
    if re.fullmatch(r'[a-z]:/(?:users/[^/]+/appdata/local/programs/python|program files)/python3\d+/python(?:w)?\.exe', path):
        return 'official'
    return 'unknown'
