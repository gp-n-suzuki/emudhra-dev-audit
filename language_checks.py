"""Installed language runtimes: scoped version evidence and isolated TLS probes."""
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

import evidence

ROOT = Path(__file__).resolve().parent
KINDS = ('bun', 'deno', 'dart', 'flutter', 'perl', 'erlang', 'elixir')
LABELS = dict(bun='Bun', deno='Deno', dart='Dart', flutter='Flutter', perl='Perl', erlang='Erlang', elixir='Elixir')
REFERENCES = {
    'bun': ('1.4.4', 'https://github.com/oven-sh/bun/security/advisories/GHSA-26q8-h657-pf84'),
    'deno': ('2.9.8', 'https://github.com/denoland/deno/releases/tag/v2.9.8'),
    'dart': ('3.13.7', 'https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp'),
    'flutter': ('3.47.8', 'https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp'),
    'mozilla_ca': ('20261020', 'https://metacpan.org/release/LWP/Mozilla-CA-20261020'),
    'certifi': ('2.18.0', 'https://certifi.hexdocs.pm/2.18.0/changelog.html'),
    'castore': ('1.0.22', 'https://hex.pm/packages/castore/1.0.22'),
}
SDK_SCOPE = 'Android・Windows・Linux向けにビルドするSDKの版。macOS・iOS・Webの通信はこのSDK版による影響判定の対象外。既存アプリは再ビルドが別途必要。'


def version_result(kind, text):
    floor, source = REFERENCES[kind]
    if kind == 'mozilla_ca':
        match = re.fullmatch(r'\d{8}', text.strip())
        observed = current = match.group(0) if match else ''
        preview = False
    else:
        # Reject the complete prerelease token, including vendor/nightly suffixes.
        match = re.search(r'(?<![\w.])(\d+\.\d+\.\d+[^\s()]*)', text)
        observed = current = match.group(1) if match else ''
        preview = bool(current and (not re.fullmatch(r'\d+\.\d+\.\d+', current) or
                       re.search(r'\b(?:alpha|beta|rc|dev|canary|nightly|preview)\b', text, re.I)))
        if preview:
            current = ''
    status, detail = 'MANUAL', '安定版のバージョンを確認できません。'
    if current:
        value = tuple(map(int, current.split('.')))
        baseline = tuple(map(int, floor.split('.')))
        if kind in ('bun','dart','flutter') and value[0] != baseline[0]:
            detail = 'このメジャー系列の修正版やバックポートを配布元で確認してください。'
        elif kind in ('deno','certifi','castore') and value[:2] != baseline[:2]:
            detail = 'この系列の修正版やバックポートを配布元で確認してください。'
        elif kind != 'mozilla_ca' and value[0] > baseline[0]:
            detail = 'この新しいメジャー系列の対策状況は未照合です。'
        else:
            status = 'UPDATE' if value < baseline else 'INFERRED_OK'
            detail = '検出した版 {} / 参考対策版 {}。実通信の結果とは別の版照合です。'.format(current, floor)
    return status, detail, dict(version=observed, preview=preview, reference_floor=floor,
                                source=source, reference_date='2026-10-29')


def candidates(audit, kind):
    """Explicit locations, PATH and a small list of common installations; no recursive scan."""
    explicit = getattr(audit.args, kind, [])
    if explicit: paths = list(map(Path, explicit))
    else:
        command = 'erl' if kind == 'erlang' else kind
        found = audit.host.find(command)
        paths = [Path(found)] if found else []
        paths.extend(Path(p) for p in getattr(audit, 'discovered', {}).get(kind, []))
        home = Path.home()
        names = [command+'.exe', command+'.bat', command] if os.name == 'nt' else [command]
        dirs = [home/'.bun/bin'] if kind == 'bun' else [home/'.deno/bin'] if kind == 'deno' else []
        if kind in ('dart', 'flutter'):
            dirs += [home/'flutter/bin', home/'development/flutter/bin', Path('/opt/homebrew/share/flutter/bin'),
                     Path('/opt/flutter/bin'), Path('C:/src/flutter/bin')]
        if kind == 'dart': dirs += [Path('/opt/homebrew/opt/dart/libexec/bin'), Path('/usr/local/opt/dart/libexec/bin')]
        for directory in dirs:
            paths.extend(directory/name for name in names)
    result, seen = [], set()
    for path in paths:
        try:
            if not evidence.public_path(path.expanduser()): continue
            real = path.expanduser().resolve()
            if real.is_file() and real not in seen:
                seen.add(real); result.append(real)
        except (OSError, ValueError): pass
    return result


def collect(audit, selected, run, parse_probe):
    env = {'DENO_NO_UPDATE_CHECK':'1', 'DENO_NO_PROMPT':'1', 'DENO_DIR':str(audit.work/'deno-cache'),
           'DART_SUPPRESS_ANALYTICS':'true', 'CI':'true', 'PUB_CACHE':str(audit.work/'pub-cache')}
    def call(command, timeout=12):
        return run(list(map(str, command)), timeout=timeout, cwd=audit.work, env=env)
    def add_version(kind, label, version, path, scope=None):
        status, detail, meta = version_result(kind, version)
        meta['executable'] = str(path)
        action = '配布元の対応状況とバックポートの有無を確認してください。' if status == 'UPDATE' else '対象の実行環境が使うバージョン・CAライブラリを確認してください。'
        row = audit.add(label, status, detail, meta, action=action)
        row['assessment_method'] = 'version'
        if scope: row['scope'] = scope
    def probe(kind, path, label, perl_mode='probe'):
        source = ROOT/'probes'/({'bun':'fetch_probe.mjs','deno':'fetch_probe.mjs','dart':'dart_probe.dart','perl':'perl_probe.pl'}[kind])
        copied = audit.work/source.name
        if not copied.exists(): shutil.copyfile(source, copied)
        def request(url):
            if kind == 'bun': command = [path, '--no-env-file', '--no-install', copied, url, str(audit.args.timeout)]
            elif kind == 'deno':
                host = urlsplit(url).netloc
                command = [path,'run','--no-config','--no-lock','--cached-only','--no-prompt','--allow-net='+host,copied,url,str(audit.args.timeout)]
            elif kind == 'dart': command = [path,'--disable-dart-dev',copied,url,str(audit.args.timeout)]
            else: command = [path,copied,perl_mode,url,str(audit.args.timeout)]
            rc,out,err = call(command, audit.args.timeout+8)
            return parse_probe(out,err,rc)
        audit.sample(label,request,{'executable':str(path)},
                     note='この実行環境の標準HTTPクライアントを検査。アプリ独自のCA設定・既存の配布バイナリは別対象。',
                     action='対象の実行環境とCAライブラリ、配布元の対応を確認してください。')
    for kind in KINDS:
        if kind not in selected: continue
        found = candidates(audit, kind)
        if not found:
            status = 'MANUAL' if getattr(audit.args, kind, []) else 'NOT_FOUND'
            audit.add(LABELS[kind],status,'指定した場所・PATH・既知の配置で実行環境を確認できません。')
        for path in found:
            label = LABELS[kind]
            if kind == 'flutter':
                cache = path.parent/'cache'
                raw = evidence.read_public_file(cache/'flutter.version.json', 32768)
                try: info = json.loads(raw) if raw else {}
                except (ValueError, TypeError): info = {}
                if not isinstance(info, dict): info = {}
                version = str(info.get('frameworkVersion',''))
                if info.get('channel') not in ('stable',None): version += '-'+str(info['channel'])
                add_version('flutter','Flutter SDK',version,path,SDK_SCOPE)
                dart = cache/'dart-sdk/bin'/('dart.exe' if os.name == 'nt' else 'dart')
                if dart.is_file():
                    rc,out,err = call([dart,'--version'])
                    add_version('dart','Flutter / 同梱Dart SDK',out or err if rc == 0 else '',dart,SDK_SCOPE)
                    probe('dart',dart,'Flutter / Dart HttpClient')
                else: audit.add('Flutter / 同梱Dart SDK','MANUAL','キャッシュ済みのDart SDKがないため検査できません。Flutterの更新・ダウンロードは実行しません。')
                continue
            # Flutter's dart wrapper may download its SDK; execute the cached VM only.
            if kind == 'dart' and any((path.parent/'internal'/name).is_file() for name in ('shared.sh','shared.bat')):
                path = path.parent/'cache/dart-sdk/bin'/('dart.exe' if os.name == 'nt' else 'dart')
                if not path.is_file():
                    audit.add('Dart','MANUAL','Flutter同梱のDart SDKが未取得です。'); continue
            if kind in ('bun','deno','dart'):
                rc,out,err = call([path] + (['--no-env-file'] if kind == 'bun' else []) + ['--version'])
                add_version(kind,label+' SDK' if kind == 'dart' else label+' バージョン',
                            (out or err) if rc == 0 else '',path,SDK_SCOPE if kind == 'dart' else None)
                probe(kind,path,label+(' HttpClient' if kind == 'dart' else ' fetch'))
            elif kind == 'perl':
                source = ROOT/'probes/perl_probe.pl'
                rc,out,err = call([path,source,'meta'])
                data = parse_probe(out,err,rc).get('data',{})
                audit.add('Perl バージョン','INFO',str(data.get('version','取得できません')),{'executable':str(path)})
                add_version('mozilla_ca','Perl / Mozilla::CA',str(data.get('mozilla_ca','')),path)
                probe(kind,path,'Perl HTTP::Tiny（証明書検証あり）')
                if data.get('lwp'):
                    probe(kind,path,'Perl LWP::UserAgent（証明書検証あり）','lwp')
            else:
                source = ROOT/'probes'/('beam_probe.erl' if kind == 'erlang' else 'beam_probe.exs')
                # No Mix/Rebar invocation, dependency fetching, or project startup.
                if kind == 'erlang':
                    script = source.read_text(encoding='utf-8')
                    command = [path,'-noshell','-noinput','-eval',script]
                else: command = [path,source]
                rc,out,err = call(command)
                runtime = re.search(r'^EMUDHRA_RUNTIME:(.+)$',out,re.M)
                audit.add(label+' バージョン','INFO' if runtime else 'MANUAL',runtime.group(1) if runtime else '実行環境の情報を取得できません。',{'executable':str(path)})
                libs = dict(re.findall(r'^EMUDHRA_LIB:(certifi|castore):([^\r\n]+)$',out,re.M)) if rc == 0 else {}
                for library in ('certifi','castore'):
                    if library in libs: add_version(library,label+' / '+library,libs[library],path)
                audit.add(label+' / アプリの通信','MANUAL',
                          '起動した実行環境から見えるCAライブラリを照合しました。プロジェクト固有の依存関係と実通信は未確認です。' if libs else
                          'この実行環境からcertifi・castoreの導入版を確認できません。アプリが使うCAとTLS設定は未確認です。',
                          {'executable':str(path)},action='対象アプリが使うcertifi・castoreの版とTLS設定を確認し、対応する依存関係を更新してください。')
