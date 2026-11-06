#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eMudhra development-environment audit, reference date 2026-11-02.
Python 3.8+ standard library only. No remediation, installs, pulls or CA edits.
Writes only reports and temporary probe build files. See README-ja.md.
"""
from __future__ import annotations
import argparse
import concurrent.futures as futures
import datetime as dt
import json
import netrc
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import evidence
import verdicts
import browser_results
import php_diagnostics
import reporting
import remediation
import app_inventory
import language_checks
import package_checks
import p2_settings
import p2_coverage
import safechain_probe
import official_versions
import version_inference
import research_rules
from distribution_version import VERSION as TOOL_VERSION, DISPLAY_VERSION

ROOT = Path(__file__).resolve().parent
PROBES = ROOT / 'probes'
AS_OF = '2026-11-02'
SOURCE = 'https://emudhra.we-have-a-problem.com/'
TARGETS = [
    ('通常サイト', 'https://example.com/', True),
    ('emSign / CTあり', 'https://dv-g3b-emudhra.we-have-a-problem.com/', False),
    ('AAA経路 / CTあり', 'https://dv-g3b-aaa-emudhra.we-have-a-problem.com/', False),
    ('emSign / CTなし', 'https://dv-g3b-noct-emudhra.we-have-a-problem.com/', False),
    ('AAA経路 / CTなし', 'https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/', False),
]
LABEL = reporting.STATUS_LABELS
REFERENCE_URLS = {
    'pip':'https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576',
    'certifi':'https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576',
    'uv':'https://github.com/astral-sh/uv/releases/tag/0.13.5',
    'node':'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
    'nss':'https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/',
    **official_versions.COMPONENT_SOURCES,
}
FLOORS = official_versions.FLOORS
FAMILY_FLOORS = official_versions.FAMILY_FLOORS
CONFIG_ENVS = ('CURL_CA_BUNDLE','SSL_CERT_FILE','SSL_CERT_DIR','REQUESTS_CA_BUNDLE','PIP_CERT',
 'PIP_CLIENT_CERT','PIP_TRUSTED_HOST','GIT_SSL_NO_VERIFY','GIT_SSL_CAINFO','GIT_SSL_CAPATH',
 'NODE_TLS_REJECT_UNAUTHORIZED','NODE_EXTRA_CA_CERTS','NODE_OPTIONS','NODE_USE_SYSTEM_CA','NODE_USE_ENV_PROXY',
 'PERL_LWP_SSL_CA_FILE','PERL_LWP_SSL_VERIFY_HOSTNAME',
 'JAVA_HOME','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS',
 'HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy','NO_PROXY','no_proxy',
 'DOCKER_HOST','DOCKER_CONTEXT','CONDA_PREFIX','VIRTUAL_ENV')

# Only recognized trust/chain errors count as rejection. Expiry, hostname, CT,
# pinning, protocol and generic handshake failures never count as remediation.
AMBIGUOUS = re.compile(r'expir|not yet valid|not valid yet|validity check failed|certificateexpired|certificatenotyetvalid|'
    r'hostname|host name|ip address mismatch|does not match|did not match|no alternative certificate subject|'
    r'no subject alternative|no name matching|cert_e_cn_no_match|cert_e_expired|'
    r'certificate transparency|ct_required|pinned|pinning|pubkeypin|bad_certificate|certificate_required|'
    r'purpose|NotValidForUsage|signature failure|key too weak|digest.*too weak|invalid ca|path length|'
    r'有効期限|期限切れ|名前.{0,12}一致しません', re.I)
TRUST_ERROR = re.compile(r'unable to get (?:local )?issuer|unable to verify (?:the )?(?:first|leaf) certificate|'
    r'self[- ]signed certificate|certificate (?:is )?revoked\b|cert(?:ificate)?_revoked|explicit.distrust|untrusted.?root|'
    r'unknown (?:certificate )?authority|unknown ca|certificate (?:is )?not trusted|cert_e_untrustedroot|'
    r'sec_e_untrusted_root|cert_e_chaining|cert_e_untrustedtestroot|unable to find valid certification path|'
    r'pkix path building failed|trust anchor|certification path|certificate is blacklisted|'
    r'certificate is blocked|certificate signer not trusted|certificate.s issuer is unknown|'
    r'certificate of .{1,255} is not trusted|'
    r'certificate chain was issued by an authority that is not trusted|PartialChain|UntrustedRoot|'
    r'self_signed_cert_in_chain|depth_zero_self_signed_cert|unable_to_get_issuer_cert_locally|'
    r'unable_to_verify_leaf_signature|invalid peer certificate: (?:UnknownIssuer|Revoked)\b|証明書は信頼されていません', re.I)


def redact(value):
    s = str(value)
    s = re.sub(r'(https?://)[^/\s@]+@', r'\1[認証情報省略]@', s)
    s = re.sub(r'(?i)((?:proxy-)?authorization\s*:)[^\r\n]+', r'\1 [省略]', s)
    s = re.sub(r'(?i)((?:password|token|secret|api[_-]?key)=)[^\s&]+', r'\1[省略]', s)
    for name, val in os.environ.items():
        if len(val) >= 8 and re.search(r'TOKEN|PASSWORD|SECRET|API_KEY|ACCESS_KEY|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS', name, re.I):
            s = s.replace(val, '[環境変数値省略]')
    return s[:3000]


def run(command, timeout=12, env=None, cwd=None, inherit_env=True):
    """Bound subprocess lifetime, including probe children. Never shell=True."""
    e = os.environ.copy() if inherit_env else {}
    e.update({'LC_ALL':'C','LANG':'C','PYTHONDONTWRITEBYTECODE':'1',
              'HOMEBREW_NO_AUTO_UPDATE':'1','GOTOOLCHAIN':'local'})
    if env:
        e.update(env)
    # The invoked tool may itself open configured files. Fail closed before
    # launching it when an explicitly configured file is an .env or alias.
    file_settings = {'SSL_CERT_FILE','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','PIP_CONFIG_FILE',
                     'PIP_CERT','PIP_CLIENT_CERT','GIT_SSL_CAINFO','GIT_CONFIG_GLOBAL',
                     'GIT_CONFIG_SYSTEM','NODE_EXTRA_CA_CERTS','NPM_CONFIG_USERCONFIG',
                     'NPM_CONFIG_GLOBALCONFIG','DENO_CERT','PERL_LWP_SSL_CA_FILE','WGETRC','OPENSSL_CONF',
                     'CARGO_HTTP_CAINFO','CARGO_HTTP_PROXY_CAINFO','COMPOSER_CAFILE','BUNDLE_SSL_CA_CERT','AWS_CA_BUNDLE'}
    for name, value in e.items():
        if value and name.upper() in file_settings and not app_inventory.safe(Path(value).expanduser()):
            return 126, '', name.upper()+' が除外対象の設定ファイルを参照するため実行を見送りました。'
    for value in e.get('SSL_CERT_DIR','').split(os.pathsep):
        if value:
            directory=Path(value).expanduser()
            if not app_inventory.safe(directory):
                return 126, '', 'SSL_CERT_DIR が除外対象のディレクトリを参照するため実行を見送りました。'
            try:
                if directory.is_dir():
                    for index,child in enumerate(directory.iterdir()):
                        if index >= 4096 or (re.fullmatch(r'[0-9a-fA-F]{8}\.\d+',child.name) and not app_inventory.safe(child)):
                            return 126, '', 'SSL_CERT_DIR の参照先を安全に確認できないため実行を見送りました。'
            except OSError:
                return 126, '', 'SSL_CERT_DIR を安全に確認できないため実行を見送りました。'
    for name in ('NODE_OPTIONS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):
        if re.search(r'(?:^|[=/\\\s])\.env(?:[.\\/\s\"\']|$)',e.get(name,''),re.I):
            return 126, '', name+' に除外対象の設定ファイルが含まれるため実行を見送りました。'
    kw = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
              env=e, cwd=str(cwd) if cwd else None)
    if os.name == 'nt':
        kw['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw['start_new_session'] = True
    try:
        p = subprocess.Popen([str(x) for x in command], **kw)
        try:
            out, err = p.communicate(timeout=timeout)
            return p.returncode, out.decode('utf-8','replace'), err.decode('utf-8','replace')
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                try:
                    subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                except Exception:
                    p.kill()
            else:
                try: os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            out, err = p.communicate()
            return 124, out.decode('utf-8','replace'), 'TIMEOUT: ' + err.decode('utf-8','replace')
    except (OSError, ValueError) as e:
        return 127, '', str(e)


def parse_probe(out, err='', rc=0):
    for line in reversed(out.splitlines()):
        if line.startswith('EMUDHRA_JSON:'):
            try:
                data = json.loads(line[len('EMUDHRA_JSON:'):])
                if isinstance(data, dict):
                    return data
            except ValueError:
                pass
    return {'state':'unknown', 'detail':'probe終了コード={} {}'.format(rc, redact(err or out))}


def classify(data, control=False):
    state = data.get('state','unknown')
    detail = redact(data.get('detail',''))
    if state == 'accepted':
        if control: return 'CONTROL_OK', detail
        if data.get('target_chain_verified') is True: return 'ACTION', detail
        return 'UNKNOWN', 'HTTPS接続は成立しましたが、提示された証明書の経路は未確認です。 ' + detail
    if state == 'skipped':
        return 'SKIP', detail
    if state == 'inferred_rejection' and not control:
        return 'INFERRED_REJECTED', detail
    if state == 'error' and not control and not AMBIGUOUS.search(detail) and 'verify_code' in data:
        code = data['verify_code']
        # truststore may attach negative native OS status values instead of OpenSSL codes.
        # Those still need a specific trust reason in the native error message below.
        if type(code) is not int or code >= 0:
            return ('REJECTED' if type(code) is int and code in (2,18,19,20,21,23,27,28) else 'UNKNOWN'), detail
    if state == 'error' and not control and not AMBIGUOUS.search(detail) and TRUST_ERROR.search(detail):
        return 'REJECTED', detail
    return 'UNKNOWN', detail


def client_result(client, rc, out, err):
    """Do not treat a proxy CONNECT response or an HTTP failure as origin TLS."""
    combined = out+'\n'+err
    combined = '\n'.join(line for line in combined.splitlines()
                         if not re.search(r'--no-check-certificate|--verify=no|insecurely', line, re.I))
    if rc == 0:
        for line in combined.splitlines():
            match = re.match(r'\s*HTTP/\d(?:\.\d)?\s+(\d{3})(.*)$', line, re.I)
            if match and 'connection established' not in match.group(2).lower():
                return {'state':'accepted', 'detail':'HTTP '+match.group(1)}
    if AMBIGUOUS.search(combined) or TRUST_ERROR.search(combined):
        return {'state':'error', 'detail':redact(combined)}
    messages = [line.strip() for line in combined.splitlines() if re.search(r'error|certificate|ssl|tls',line,re.I)]
    detail = ' / '.join(messages[:4])
    return {'state':'unknown', 'detail':client+' 終了コード='+str(rc)+'。HTTPS応答を確認できません。 '+redact(detail)}


def git_result(trace, rc):
    """An HTTPS GET response counts even when ls-remote reports not-a-repository.
    A proxy CONNECT response alone NEVER proves origin TLS completed.
    """
    sent_get = False
    for line in trace.splitlines():
        if ('=> Send header:' in line and re.search(r'\bGET\s', line)) or re.search(r'\[:method: GET\]', line):
            sent_get = True
        if sent_get and '<= Recv header:' in line and re.search(r'HTTP/[\d.]+\s+\d{3}', line):
            if 'connection established' not in line.lower():
                status = re.search(r'HTTP/[\d.]+\s+(\d{3})',line).group(1)
                return {'state':'accepted','detail':'origin HTTP '+status+' (Git終了コード='+str(rc)+')'}
    if AMBIGUOUS.search(trace) or TRUST_ERROR.search(trace):
        return {'state':'error', 'detail':next((s.strip() for s in trace.splitlines() if AMBIGUOUS.search(s) or TRUST_ERROR.search(s)), 'TLS error')}
    return {'state':'unknown', 'detail':'GitのTLS完了を確認できません; 終了コード='+str(rc)}


def reference(name, text):
    return official_versions.reference(name, text)


def netrc_targets(paths):
    """Return host names only. Never return credentials or parser error text."""
    hosts=set()
    for path in paths:
        if not path.exists(): continue
        if not evidence.public_path(path):
            return set(), True
        try: hosts.update(netrc.netrc(str(path)).hosts)
        except (OSError, netrc.NetrcParseError, UnicodeError): return set(), True
    return hosts, False


def git_target_blocker(url, credential_hosts, rewrite_prefixes, client_identity=False):
    host=urlsplit(url).hostname
    credential_hosts={name.lower().rstrip('.') for name in credential_hosts}
    if 'default' in credential_hosts or host.lower().rstrip('.') in credential_hosts:
        return 'この検証先に適用されるnetrc認証設定があります。'
    if any(url.startswith(prefix) for prefix in rewrite_prefixes):
        return 'この検証先に適用されるURL書換えがあります。'
    if client_identity:
        return 'この検証先に適用されるクライアント証明書設定があります。'
    return None


def java_blocklist(home, fingerprints):
    """Check the vendor's known Java blocklist format without altering it."""
    for name in ('blocked.certs','blacklisted.certs'):
        path=Path(home)/'lib'/'security'/name
        if not path.is_file(): continue
        try: text=path.read_text(encoding='utf-8')
        except (OSError, UnicodeError): return 'MANUAL','ブロックリストを読み取れません。'
        lines={line.strip() for line in text.splitlines() if not line.lstrip().startswith('#')}
        if text.startswith('\ufeff') or 'Algorithm=SHA-256' not in lines:
            return 'MANUAL','ブロックリストの形式・ハッシュ方式を確認できません。'
        missing=set(fingerprints)-lines
        if missing:
            return 'UPDATE','参照対象{}証明書のうち{}件がブロックリストにありません。配布元の更新・対処を確認。'.format(len(fingerprints),len(missing))
        return 'REFERENCE_OK','参照対象{}証明書のSHA-256がブロックリストにあります。実通信・独自TrustManagerは別確認。'.format(len(fingerprints))
    return 'MANUAL','既知の配置にJavaブロックリストがありません。'


class Context:
    def __init__(self, prefix=None, label='ホスト', project=None):
        self.prefix = prefix or []
        self.label = label
        self.project = project if not self.prefix else None
    def call(self, command, **kwargs):
        if self.prefix:
            # docker exec does not inherit host CLI environment variables.
            # Pass only diagnostic controls, never the host's CA/proxy/secret environment.
            e = {'LC_ALL':'C', 'LANG':'C', 'PYTHONDONTWRITEBYTECODE':'1'}
            e.update(kwargs.pop('env', None) or {})
            flags = []
            for key, value in e.items():
                flags.extend(['-e', key+'='+str(value)])
            cmd = self.prefix[:-1] + flags + self.prefix[-1:] + list(command)
            return run(cmd, **kwargs)
        return run(list(command), cwd=self.project, **kwargs)
    def find(self, name):
        if self.prefix:
            rc,out,_ = self.call(['sh','-c','command -v '+name], timeout=10)
            return out.strip().splitlines()[0] if rc == 0 and out.strip() else None
        return shutil.which(name)


class Audit:
    def __init__(self, args):
        self.args = args
        self.records = []
        self.discovered = {}
        self.package_protected = set()
        self.tmp = tempfile.TemporaryDirectory(prefix='emudhra-dev-audit-')
        self.work = Path(self.tmp.name)
        self.host = Context(project=args.project or self.work)
    def add(self, name, status, detail, meta=None, samples=None, action='', required=False):
        row = {'name':name,'status':status,'detail':redact(detail),'action':action,
               'metadata':meta or {},'samples':samples or [],'required':required}
        self.records.append(row)
        print('[{}] {}\n  {}'.format(LABEL.get(status,status),name,row['detail']),flush=True)
        return row
    def ref(self, name, version, label=None, identity=None):
        if version is None: return
        status,detail,floor = reference(name,version)
        metadata = {'version':version,'reference_floor':floor,'as_of':AS_OF,'source':REFERENCE_URLS.get(name,SOURCE)}
        metadata.update(identity or {})
        self.add(label or name, status, '{} / {}'.format(version,detail), metadata,
                 action='配布元の対応状況とバックポートの有無を確認し、必要に応じて同じ環境で再診断。独自CA・設定も確認。' if status in ('UPDATE','MANUAL') else '')
    def sample(self, name, probe, meta=None, note='', action=''):
        if self.args.offline:
            return self.add(name,'SKIP','オフライン指定: 実通信は未検査。'+note,meta,action=action,required=True)
        if any('@' in os.environ.get(key,'') for key in
               ('HTTPS_PROXY','https_proxy','HTTP_PROXY','http_proxy','ALL_PROXY','all_proxy','CARGO_HTTP_PROXY')):
            return self.add(name,'SKIP','認証情報を含むproxy設定があるため、診断用の通信を見送りました。',
                            meta,action=action,required=True)
        def one(target):
            label,url,control = target
            started = time.monotonic()
            try:
                data = probe(url)
            except Exception as e:
                data = {'state':'unknown','detail':type(e).__name__+': '+str(e)}
            status,detail = classify(data, control)
            sample={'target':label,'url':url,'control':control,'status':status,'detail':detail,
                    'seconds':round(time.monotonic()-started,2)}
            if data.get('corroboration'): sample['corroboration']=data['corroboration']
            if 'verify_code' in data: sample['verify_code']=data['verify_code']
            if data.get('optional_missing'): sample['optional_missing']=True
            return sample
        with futures.ThreadPoolExecutor(max_workers=self.args.workers) as pool:
            samples = list(pool.map(one, TARGETS))
        tests = samples[1:]
        if any(s['status']=='ACTION' for s in tests):
            status = 'ACTION'
            message = '検証先へのHTTPS接続が成立。対象CAの受入れ、TLS検査プロキシ、検証無効化を調査。'
        elif samples[0]['status']=='CONTROL_OK' and all(s['status']=='REJECTED' for s in tests):
            status = 'REJECTED'
            message = '通常サイトに接続し、検査用サイトへの接続をブロックしました。全体の安全性を保証するものではありません。'
        elif samples[0]['status']=='CONTROL_OK' and all(s['status'] in ('REJECTED','INFERRED_REJECTED') for s in tests):
            status='INFERRED_REJECTED'
            message='通常サイトに接続し、検査用サイトへの接続が失敗しました。別の接続結果からブロックしたと推定します。'
        elif all(s['status']=='SKIP' for s in samples):
            status = 'SKIP'; message = 'この構成の実通信は実施できません。'
        else:
            status = 'UNKNOWN'; message = '通信・期限・名前・未対応API等のため、今回の対策の効果を確定できません。'
        row = self.add(name,status,message+' '+note,meta,samples,action,
                       required=status=='SKIP')
        if any(s['status']=='INFERRED_REJECTED' for s in samples):
            row['assessment_method']='corroborated'
            row['scope']='PHPの接続失敗は実測。拒否原因は同じOpenSSL版・CA設定の別接続から推定。配信チェーンの差・PHP内部設定・独自stream_contextは未確定。'
        for s in samples:
            print('    [{}] {}: {}'.format(LABEL.get(s['status'],s['status']),s['target'],s['detail'][:180]),flush=True)
        return row
    def json_probe(self, ctx, command, env=None):
        rc,out,err = ctx.call(command, timeout=self.args.timeout+5, env=env)
        return parse_probe(out,err,rc)
    def config_inventory(self):
        target = ('このPCの開発環境 ＋ プロジェクト: '+str(self.args.project)) if self.args.project else 'このPCにインストールされている開発環境'
        self.add('検査対象','INFO',target,{'project':str(self.args.project) if self.args.project else None,
                 'host_only':self.args.project is None},action='')
        present = [n for n in CONFIG_ENVS if os.environ.get(n)]
        self.add('OS / 環境設定','INFO','値は保存せず、関連環境変数の名前だけを記録します。',
                 {'platform':sys.platform,'python_controller':sys.version.split()[0], 'set_environment_names':present})
        if os.environ.get('NODE_TLS_REJECT_UNAUTHORIZED') == '0':
            self.add('Node.js 証明書検証無効化','ACTION','NODE_TLS_REJECT_UNAUTHORIZED=0 が設定されています。',action='値を無効化して回避せず、CAと接続先を修正。設定元を確認。')
        if os.environ.get('PERL_LWP_SSL_VERIFY_HOSTNAME') == '0':
            self.add('Perl LWP 証明書検証無効化','ACTION','PERL_LWP_SSL_VERIFY_HOSTNAME=0 が設定されています。')
        if os.environ.get('GIT_SSL_NO_VERIFY','').lower() not in ('','0','false','no','off'):
            self.add('Git 証明書検証無効化','ACTION','GIT_SSL_NO_VERIFY が設定されています。',action='設定元を確認し、TLS検証を有効な状態へ戻す。')
        if any('PROXY' in n.upper() for n in present):
            self.add('プロキシ','MANUAL','プロキシ関連設定があります。クライアントごとの経路と証明書差し替えを確認。設定を迂回しません。')
        if sys.platform.startswith('linux'):
            commands = [('dpkg-query',['-W','-f=${Package} ${Version}\n','ca-certificates','libnss3']),
                        ('rpm',['-q','ca-certificates','nss']),('apk',['info','-v','ca-certificates']),
                        ('pacman',['-Q','ca-certificates','ca-certificates-mozilla'])]
            for tool, argv in commands:
                if self.host.find(tool):
                    rc,out,err = self.host.call([tool]+argv)
                    self.add('Linux CAパッケージ','INFO',out.strip() or 'パッケージ情報を取得できません',action='ディストリビューションの修正アドバイザリと照合。')
                    break
        elif os.name == 'nt':
            self.add('Windows CTL','MANUAL','Windows Updateとは別にDisallowed CTLの反映を管理者と確認。自動インポートはしません。')
        elif sys.platform == 'darwin' and 'native' in self.args.only.split(','):
            self.macos_trust()
    def macos_trust(self):
        name='macOS / URLSession・SecTrust'
        if self.args.offline:
            self.add(name,'SKIP','オフライン指定: OS標準の実通信は未検査。',required=True); return
        # Do not invoke the /usr/bin shim when Command Line Tools are absent.
        rc,developer,_=run(['xcode-select','-p'])
        developer=Path(developer.strip())
        compiler=next((p for p in (developer/'usr/bin/swiftc',
                      developer/'Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc') if p.is_file()),None)
        if rc or compiler is None:
            self.add(name,'MANUAL','既存のSwiftコンパイラがありません。自動導入しません。'); return
        build=self.work/'macos'; build.mkdir()
        exe=build/'probe'
        # xcrun supplies the SDK for the selected Xcode/CLT installation.
        rc,_,err=run(['/usr/bin/xcrun','--sdk','macosx','swiftc','-module-cache-path',str(build/'cache'),str(PROBES/'macos_probe.swift'),'-o',str(exe)],timeout=90)
        if rc:
            self.add(name,'UNKNOWN','診断プログラムのビルド失敗: '+err); return
        self.sample(name,lambda url:self.json_probe(self.host,[str(exe),url,str(self.args.timeout)]),
                    note='OS標準の信頼評価とシステムのプロキシ設定を使用。各ブラウザ・CLIの独自CAは別対象。',
                    action='OSの信頼情報と実際に使うアプリの結果を確認。')
    def paths(self, ctx, tool, extra=None, all_paths=False):
        result=[]
        seen=set()
        def add(p):
            if not p: return
            key = verdicts.installation_identity(tool, p) if not ctx.prefix else p
            if key not in seen:
                seen.add(key); result.append(p)
        add(ctx.find(tool))
        if not ctx.prefix:
            discovery_id = {'pwsh':'powershell','powershell.exe':'windows-powershell'}.get(tool,tool)
            for p in self.discovered.get(discovery_id, []):
                add(p)
            for p in extra or []:
                add(str(Path(p).expanduser().absolute()))
            if all_paths:
                for d in os.environ.get('PATH','').split(os.pathsep):
                    if not d: continue
                    for ext in (['.exe'] if os.name=='nt' else ['']):
                        p = Path(d)/(tool+ext)
                        if p.is_file() and os.access(str(p),os.X_OK): add(str(p.absolute()))
        return result
    def curl(self, ctx):
        paths=self.paths(ctx,'curl',self.args.curl,all_paths=True)
        if not ctx.prefix:
            for p in (['C:/Windows/System32/curl.exe'] if os.name=='nt' else ['/usr/bin/curl','/opt/homebrew/opt/curl/bin/curl','/usr/local/opt/curl/bin/curl']):
                if Path(p).is_file() and p not in paths: paths.append(p)
        if not paths: self.add(ctx.label+' / curl','NOT_FOUND','探索した配置では見つかりません。'); return
        seen=set()
        for path in paths:
            key=os.path.realpath(path) if not ctx.prefix else path
            if key in seen: continue
            seen.add(key)
            rc,out,err=ctx.call([path,'-q','--version'])
            version=(out or err).splitlines()[:2]
            def probe(url,p=path):
                rc,out,err=ctx.call([p,'-q','--silent','--show-error','--proto','=https',
                    '--connect-timeout',str(self.args.timeout),'--max-time',str(self.args.timeout),
                    '--output','NUL' if os.name=='nt' and not ctx.prefix else '/dev/null',
                    '--write-out','%{http_code}',url],timeout=self.args.timeout+3)
                if rc==0: return {'state':'accepted','detail':'HTTP '+out.strip()}
                return {'state':'error' if rc in (60,51,35) else 'unknown','detail':'curl '+str(rc)+': '+err.strip()}
            self.sample(ctx.label+' / curl: '+path,probe,{'tool_id':'curl','executable':path,'version':version},
                        note='.curlrcは読まない診断。CA・プロキシ環境変数は維持。',
                        action='この実行ファイルのTLSバックエンド・参照CA・プロキシ設定を確認。')
    def network_client(self, ctx, kind):
        commands = ('wget', 'wget2') if kind == 'wget' else ('http',)
        paths = []
        for command in commands:
            for path in self.paths(ctx, command, getattr(self.args, kind, []), all_paths=True):
                if path not in paths: paths.append(path)
        if not paths:
            self.add(ctx.label+' / '+('wget' if kind == 'wget' else 'HTTPie'), 'NOT_FOUND', '探索した配置では見つかりませんでした。')
            return
        seen = set()
        for path in paths:
            identity = os.path.realpath(path) if not ctx.prefix else path
            if identity in seen: continue
            seen.add(identity)
            safe_env = {'HTTPIE_CONFIG_DIR':str(self.work/'httpie-config')} if kind == 'httpie' else {}
            rc, out, err = ctx.call([path, '--version'], timeout=12, env=safe_env)
            if rc != 0:
                self.add(ctx.label+' / '+kind, 'UNKNOWN', '実行ファイルの版を取得できません。', {'executable':path}, required=True)
                continue
            version = (out or err).splitlines()[:2]
            def probe(url, executable=path):
                if kind == 'wget':
                    command = [executable, '--no-config', '--no-netrc', '--no-hsts', '--max-redirect=0',
                               '--tries=1', '--timeout='+str(int(self.args.timeout)), '--server-response',
                               '--output-document='+('NUL' if os.name == 'nt' and not ctx.prefix else '/dev/null'), url]
                else:
                    command = [executable, '--ignore-stdin', '--ignore-netrc', '--headers',
                               '--timeout='+str(self.args.timeout), 'GET', url]
                rc, out, err = ctx.call(command, timeout=self.args.timeout+5, env=safe_env)
                return client_result(kind, rc, out, err)
            self.sample(ctx.label+' / '+('wget' if kind == 'wget' else 'HTTPie')+' ['+path+']',
                        probe, {'tool_id':kind, 'executable':path, 'version':version},
                        note='認証情報とリダイレクトを使用せず、ツール固有の設定ファイルは読みません。CA・proxy環境変数は維持。',
                        action='このツールのTLSライブラリ・CA・プロキシ設定を確認してください。')

    def git(self,ctx):
        paths=self.paths(ctx,'git',self.args.git)
        if not paths: self.add(ctx.label+' / Git','NOT_FOUND','探索した配置では見つかりません。'); return
        for path in paths:
            _,version,_=ctx.call([path,'--version'])
            meta={'tool_id':'git','executable':path,'version':version.strip(),'repository':str(ctx.project or '(container workdir)')}
            for key in ('http.sslBackend','http.sslCAInfo','http.sslVerify','http.schannelCheckRevoke','http.schannelUseSSLCAInfo'):
                _,out,_=ctx.call([path,'config','--get',key]); meta[key]=redact(out.strip()) or '(未設定)'
            if meta['http.sslVerify'].lower() in ('false','0','no','off'):
                self.add(ctx.label+' / Git sslVerify','ACTION','http.sslVerify=false が設定されています。')
            if ctx.prefix:
                rc,netrc,_=ctx.call(['sh','-c','test ! -f "$HOME/.netrc" && test ! -f "$HOME/_netrc"'])
                has_netrc=(rc!=0)
            else:
                netrc_paths=[Path.home()/n for n in ('.netrc','_netrc')]
                if os.environ.get('NETRC'): netrc_paths.append(Path(os.environ['NETRC']).expanduser())
                credential_hosts,netrc_failed=netrc_targets(netrc_paths)
                has_netrc=False
            rewrite_rc,rewrites,_=ctx.call([path,'config','--null','--get-regexp',r'^url\..*\.insteadof$'])
            rewrite_entries=[entry.split('\n',1) for entry in rewrites.split('\0') if entry]
            rewrite_failed=rewrite_rc not in (0,1) or any(len(entry)!=2 for entry in rewrite_entries)
            rewrite_prefixes=[entry[1] for entry in rewrite_entries if len(entry)==2]
            suppressed={'extraheader':'','cookiefile':'','savecookies':'false',
                        'followredirects':'false','emptyauth':'false','proactiveauth':'none','delegation':'none'}
            keys_rc,keys,_=ctx.call([path,'config','--name-only','--get-regexp',
                                    r'^http\..*('+ '|'.join(suppressed)+r'|sslcert|sslkey)$'])
            keylist=keys.splitlines()
            client_identity=False
            if not ctx.prefix:
                client_identity = client_identity or bool(os.environ.get('GIT_SSL_CERT') or os.environ.get('GIT_SSL_KEY'))
            else:
                rc,_,_ = ctx.call(['sh','-c','test -z \"$GIT_SSL_CERT$GIT_SSL_KEY\"'])
                client_identity = client_identity or rc != 0
            if has_netrc or rewrite_failed or keys_rc not in (0,1) or (not ctx.prefix and netrc_failed):
                self.add(ctx.label+' / Git TLS','SKIP','認証設定・URL書換えの適用範囲を安全に確認できないため、実通信を見送ります。',meta,
                         action='設定を管理者と確認。netrc等を勝手に削除しないでください。',required=True)
                continue
            safe=['-c','credential.helper=','-c','credential.interactive=false']
            # URL-scoped HTTP options override global ones, so suppress both.
            for key in ['http.'+name for name in suppressed]+keylist:
                name=key.rsplit('.',1)[-1].lower()
                if name in suppressed: safe.extend(['-c',key+'='+suppressed[name]])
            def probe(url,p=path,safe=safe):
                identity=client_identity
                for key in ('http.sslCert','http.sslKey'):
                    rc,value,_=ctx.call([p,'config','--get-urlmatch',key,url])
                    if rc not in (0,1): return {'state':'skipped','detail':'GitのURL別設定を確認できません。'}
                    identity=identity or bool(value.strip())
                reason=git_target_blocker(url, set() if ctx.prefix else credential_hosts,
                                          rewrite_prefixes, identity)
                if reason: return {'state':'skipped','detail':reason+' 認証情報を送信せず検査を見送ります。'}
                # Read URL-specific flags without changing them.
                _,verify,_=ctx.call([p,'config','--get-urlmatch','http.sslVerify',url])
                rc,out,err=ctx.call([p]+safe+['ls-remote',url],timeout=self.args.timeout+5,
                    env={'GIT_TRACE_CURL':'1','GIT_TRACE_CURL_NO_DATA':'1','GIT_TRACE_REDACT':'1',
                         'GIT_TERMINAL_PROMPT':'0','GCM_INTERACTIVE':'Never','GIT_ASKPASS':'','SSH_ASKPASS':'',
                         'GIT_HTTP_LOW_SPEED_LIMIT':'1','GIT_HTTP_LOW_SPEED_TIME':str(int(self.args.timeout))})
                data=git_result(err+'\n'+out,rc)
                if verify.strip().lower() in ('false','0','no','off'):
                    data['detail']=data.get('detail','')+'; URL-specific sslVerify=false'
                return data
            self.sample(ctx.label+' / Git TLS: '+path,probe,meta,
                        note='接続先ごとにnetrc・URL書換え・クライアント証明書の適用を確認。認証・Cookie・追加ヘッダーを抑制したls-remote。',
                        action='このGitのTLSバックエンド・参照CAとリポジトリ固有設定を確認。')
    def python(self,ctx):
        paths=[]
        # The bundled controller is not an installed development environment.
        if not ctx.prefix and ROOT/'runtime' not in Path(sys.executable).absolute().parents:
            paths.append(sys.executable)
        for name in ('python3','python'):
            p=ctx.find(name)
            if p and p not in paths: paths.append(p)
        if not ctx.prefix:
            for p in self.discovered.get('python', []):
                if p not in paths: paths.append(p)
            for p in self.args.python:
                p=str(Path(p).expanduser().absolute())
                if p not in paths: paths.append(p)
            for name in (('.venv','venv') if self.args.project else ()):
                p=Path(self.args.project)/name/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
                if p.is_file() and str(p) not in paths: paths.append(str(p))
            if self.args.scan_venvs:
                for base in self.args.scan_venvs:
                    for folder,dirs,files in os.walk(str(Path(base).expanduser()),followlinks=False):
                        dirs[:]=[d for d in dirs if d not in ('.git','node_modules','.cache','site-packages')]
                        if 'pyvenv.cfg' in files:
                            p=Path(folder)/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
                            if p.is_file() and str(p) not in paths: paths.append(str(p))
                            dirs[:]=[]
                        if len(paths)>=100:
                            self.add('venv探索','MANUAL','100環境で探索を打ち切りました。'); break
        if not paths: self.add(ctx.label+' / Python','NOT_FOUND','探索した配置では見つかりません。'); return
        source=(PROBES/'python_probe.py').read_text(encoding='utf-8')
        seen=set()
        for path in paths:
            metaresult=self.json_probe(ctx,[path,'-B','-c',source,'meta','-',str(self.args.timeout)])
            if metaresult.get('state')!='meta':
                failed = {'tool_id':'python','tool_name':'Python','executable':path,'execution_context':ctx.label}
                identity = verdicts.installation_identity('python', path) if not ctx.prefix else None
                if identity: failed['python_identity'] = list(identity)
                self.add(ctx.label+' / Python: '+path,'UNKNOWN',metaresult.get('detail','メタデータ取得失敗'),failed); continue
            meta=metaresult['data']
            meta['tool_id']='python'
            meta['tool_name']='Python'
            if not ctx.prefix:
                identity = verdicts.installation_identity('python', path)
                if identity: meta['python_identity'] = list(identity)
            if ctx.prefix: meta['execution_context']=ctx.label
            # Do NOT deduplicate virtualenvs by symlink target; their CA packages differ.
            key=(meta.get('prefix'),meta.get('version'))
            if key in seen: continue
            seen.add(key)
            label=ctx.label+' / Python '+meta['version']+' ['+meta['prefix']+']'
            python_identity = {'tool_id':'python','tool_name':'Python','executable':path,
                               'prefix':meta['prefix'],'python_version':meta['version'],
                               'execution_context':ctx.label}
            if meta.get('python_identity'): python_identity['python_identity'] = meta['python_identity']
            self.add(label,'INFO','このPython環境を検査します。',meta)
            for pkg in ('pip','certifi'):
                self.ref(pkg,meta['packages'].get(pkg),label+' / '+pkg+' バージョン',
                         python_identity)
            if meta.get('ensurepip_bundled_pip'):
                self.ref('pip',meta['ensurepip_bundled_pip'],label+' / ensurepip同梱pip（新規venv用）',
                         python_identity)
            modes=['urllib']
            if meta['packages'].get('certifi'): modes.append('certifi')
            for pkg in ('requests','httpx','pip'):
                if meta['packages'].get(pkg): modes.append(pkg)
            for mode in modes:
                if mode == 'pip' and not ctx.prefix and self.package_protected.intersection({'pip','pip3','python','python3'}):
                    self.add(label+' / pip実通信セッション（内部API）','SKIP',
                             'Safe Chainの連携候補があるため、保護を迂回する可能性のある直接通信は見送りました。',
                             dict(python_identity,mode='pip'),required=True)
                    continue
                def probe(url,p=path,m=mode):
                    return self.json_probe(ctx,[p,'-B','-c',source,m,url,str(self.args.timeout)])
                description={'urllib':'標準urllib / SSLContext','certifi':'certifi単独CAバンドル',
                             'requests':'requests','httpx':'httpx','pip':'pip実通信セッション（内部API）'}[mode]
                self.sample(label+' / '+description,probe,{'tool_id':'python','tool_name':'Python','executable':path,
                            'prefix':meta['prefix'],'execution_context':ctx.label,'mode':mode},
                            note='実アプリ固有のSSLContextや起動引数は含みません。'+('認証を無効化し、既存CA・プロキシ設定は維持。' if mode=='pip' else ''),
                            action='このPython環境のpip・certifi・CA参照先と配布元の対応を確認。')
    def node(self,ctx):
        paths=self.paths(ctx,'node',self.args.node)
        if not paths: self.add(ctx.label+' / Node.js','NOT_FOUND','探索した配置では見つかりません。'); return
        source=(PROBES/'node_probe.cjs').read_text(encoding='utf-8')
        for path in paths:
            data=self.json_probe(ctx,[path,'-e',source,'meta','-',str(self.args.timeout)])
            meta=data.get('data',{'executable':path})
            meta['tool_id']='node'
            meta['resolved_executable']=meta.get('executable') if data.get('data') else None
            meta['executable']=path
            meta['execution_context']=ctx.label
            self.ref('node',meta.get('version',''),ctx.label+' / Node.js '+path,
                     {'tool_id':'node','tool_name':'Node.js','executable':path,'execution_context':ctx.label,
                      'resolved_executable':meta.get('resolved_executable')})
            if meta.get('validationDisabled'):
                self.add(ctx.label+' / Node.js TLS設定','ACTION','NODE_TLS_REJECT_UNAUTHORIZED=0 が設定されています。',meta)
            for mode in ('https','fetch'):
                def probe(url,p=path,m=mode): return self.json_probe(ctx,[p,'-e',source,m,url,str(self.args.timeout)])
                self.sample(ctx.label+' / Node.js '+mode+' ['+path+']',probe,meta,
                            note='選択したランタイムの既定動作。npmやアプリ固有Agent/CAは別対象。',
                            action='Node.js本体・NODE_EXTRA_CA_CERTS・起動設定を確認。')
    def java(self,ctx):
        paths=self.paths(ctx,'java',self.args.java)
        if not paths: self.add(ctx.label+' / Java','NOT_FOUND','探索した配置では見つかりません。'); return
        for i,path in enumerate(paths):
            rc,out,err=ctx.call([path,'-version'])
            self.add(ctx.label+' / Java: '+path,'INFO',(out+err).strip(),
                     dict(research_rules.java_output(out+err),tool_id='java',tool_name='Java',executable=path,execution_context=ctx.label))
            if ctx.prefix:
                self.add(ctx.label+' / Java TLS','MANUAL','コンテナ内Javaはこの自動検査ではバージョン確認のみ。JDK/JSSEで別途検査。'); continue
            build=self.work/('java'+str(i)); build.mkdir(exist_ok=True)
            # Prefer a compiler belonging to the selected Java, not another PATH JDK.
            p=Path(path).resolve()
            javac=p.parent/('javac.exe' if os.name=='nt' else 'javac')
            if not javac.is_file():
                self.add('Java TLS: '+path,'SKIP','同じJDKのjavacが見つかりません。JRE単体は自動コンパイルできません。',required=True); continue
            source=build/'TLSProbe.java'; shutil.copyfile(PROBES/'TLSProbe.java',source)
            rc,out,err=run([str(javac),'-encoding','UTF-8','-d',str(build),str(source)],timeout=30)
            if rc:
                self.add('Java TLS: '+path,'UNKNOWN','診断クラスのコンパイル失敗: '+err); continue
            meta=self.json_probe(ctx,[path,'-cp',str(build),'TLSProbe','--meta']).get('data',{})
            meta.update(tool_id='java', tool_name='Java', executable=path, execution_context=ctx.label)
            def probe(url,p=path,b=build): return self.json_probe(ctx,[p,'-cp',str(b),'TLSProbe',url,str(self.args.timeout)])
            self.sample('Java JSSE ['+path+']',probe,meta,note='標準JSSE・現在のJVM環境変数を利用。アプリ独自TrustManagerは未検査。',
                        action='JDK配布元の対策を適用。独自truststore、IDE/Maven/Gradleが使う別JDKも確認。')
            if 'Azul' in meta.get('vendor','') and meta.get('java_home'):
                reference_data=json.loads((ROOT/'references/java-blocklist.json').read_text(encoding='utf-8'))
                status,detail=java_blocklist(meta['java_home'],{r['sha256'] for r in reference_data['certificates']})
                self.add('Java / Azulブロックリスト',status,detail,
                         {'tool_id':'java','tool_name':'Java','java_home':meta['java_home'],
                          'execution_context':ctx.label,'source':reference_data['source'],'reference_date':AS_OF},
                         action='配布元の更新または公式対処を適用した後、同じJDKで再診断。')
    def other_languages(self,ctx,selected):
        if 'ruby' in selected:
            paths = self.paths(ctx,'ruby',all_paths=True)
            if not paths: self.add(ctx.label+' / Ruby','NOT_FOUND','探索した配置では見つかりません。')
            for p in paths:
                src=(PROBES/'ruby_probe.rb').read_text(encoding='utf-8')
                _,out,err=ctx.call([p,'--version'])
                self.sample(ctx.label+' / Ruby Net::HTTP ['+p+']',lambda u,p=p:self.json_probe(ctx,[p,'-e',src,u,str(self.args.timeout)]),
                            {'tool_id':'ruby','executable':p,'version':out.strip()},
                            action='Rubyが参照するOpenSSL/CAと、Bundler・Gemの個別設定を確認。')
        if 'php' in selected:
            paths = self.paths(ctx,'php',all_paths=True)
            if not paths: self.add(ctx.label+' / PHP','NOT_FOUND','探索した配置では見つかりません。')
            for p in paths:
                src=(PROBES/'php_probe.php').read_text(encoding='utf-8').replace('<?php','',1)
                _,out,err=ctx.call([p,'--version'])
                def stream_probe(url,p=p):
                    data=self.json_probe(ctx,[p,'-r',src,url,str(self.args.timeout)])
                    return php_diagnostics.corroborate(data,url,self.args.timeout,run) if not ctx.prefix else data
                self.sample(ctx.label+' / PHP OpenSSL streams ['+p+']',stream_probe,
                            {'tool_id':'php','executable':p,'version':out.splitlines()[:1]},
                            note='汎用エラーは同じOpenSSL版・CA設定で再検証できた場合のみ拒否推定。curl拡張とは別。Composer・個別stream_contextは未検査。',action='openssl.cafile等とOS/独自CAバンドルを確認。')
                curl_src=(PROBES/'php_curl_probe.php').read_text(encoding='utf-8').replace('<?php','',1)
                self.sample(ctx.label+' / PHP curl拡張 ['+p+']',lambda u,p=p:self.json_probe(ctx,[p,'-r',curl_src,u,str(self.args.timeout)]),
                            {'tool_id':'php','executable':p},
                            note='curl.cainfoとcurlの既定CAを使用。OpenSSLの検証結果コードで判定。PHP streamsの判定を置き換えません。')
        if 'go' in selected:
            paths = self.paths(ctx,'go',all_paths=True)
            if not paths: self.add(ctx.label+' / Go','NOT_FOUND','探索した配置では見つかりません。')
            for index,p in enumerate(paths):
                _,out,_=ctx.call([p,'version'])
                meta = {'tool_id':'go','tool_name':'Go','executable':p,'execution_context':ctx.label}
                self.ref('go',out.strip(),ctx.label+' / Goバージョン ['+p+']',meta)
                if not ctx.prefix and not self.args.offline:
                    build=self.work/('go'+str(index)); build.mkdir(exist_ok=True)
                    exe=build/('probe.exe' if os.name=='nt' else 'probe')
                    env={'GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GO111MODULE':'off','GOWORK':'off','GOCACHE':str(build/'cache'),'GOTELEMETRY':'off'}
                    rc,_,err=run([p,'build','-o',str(exe),str(PROBES/'go_probe.go')],timeout=75,env=env,cwd=build)
                    if rc: self.add('Go TLS ['+p+']','UNKNOWN','標準ライブラリの診断プログラムをビルドできません: '+err,meta)
                    else:
                        self.sample('Go net/http ['+p+']',lambda u,exe=exe:self.json_probe(ctx,[str(exe),u,str(self.args.timeout)]),meta,
                                    note='既存のGo製バイナリは未検査。修正版への置換/再ビルドが別途必要。',action='ツールチェーンと対象アプリを確認。')
                else: self.add(ctx.label+' / Go TLS ['+p+']','SKIP','コンテナ内・オフラインではGo診断のビルドを実施しません。',meta,required=True)
        if 'dotnet' in selected and not ctx.prefix:
            found_shell = False
            for shell, label, tool_id in (('pwsh','PowerShell 7','powershell'),
                                          ('powershell.exe','Windows PowerShell','windows-powershell')):
                for p in self.paths(ctx, shell, all_paths=True):
                    found_shell = True
                    def probe(u,p=p):
                        return self.json_probe(ctx,[p,'-NoProfile','-NonInteractive','-File',str(PROBES/'dotnet_probe.ps1'),'-Url',u,'-Seconds',str(self.args.timeout)])
                    self.sample(label+' / HttpClient ['+p+']',probe,
                                {'tool_id':tool_id,'executable':p},
                                note='このPowerShellの.NET環境のみ。別のPowerShell・.NETランタイム・アプリは別対象。',
                                action='このPowerShellのOS信頼情報・ランタイム・独自CAを確認。')
                    def web_probe(u,p=p):
                        return self.json_probe(ctx,[p,'-NoProfile','-NonInteractive','-File',str(PROBES/'powershell_web_probe.ps1'),'-Url',u,'-Seconds',str(self.args.timeout)])
                    self.sample(label+' / Invoke-WebRequest ['+p+']',web_probe,
                                {'tool_id':tool_id,'executable':p},
                                note='このPowerShellのWebコマンド。プロファイルを読み込まず、リダイレクトを追跡しません。',
                                action='このPowerShellの通信とCA設定を確認してください。')
            if not found_shell:
                self.add('PowerShell / HttpClient','NOT_FOUND','探索した配置ではPowerShellが見つかりません。')
            p=ctx.find('dotnet')
            if p:
                self.dotnet_runtimes(ctx, p)
    def dotnet_runtimes(self, ctx, executable):
        build = self.work/'dotnet'; build.mkdir(exist_ok=True)
        env = {'DOTNET_CLI_HOME':str(build), 'DOTNET_CLI_TELEMETRY_OPTOUT':'1',
               'DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1', 'DOTNET_NOLOGO':'1',
               'NUGET_PACKAGES':str(build/'packages'), 'DOTNET_STARTUP_HOOKS':'',
               'DOTNET_ADDITIONAL_DEPS':''}
        rc, out, err = ctx.call([executable,'--list-runtimes'], env=env)
        self.add('.NETランタイム一覧','INFO' if rc == 0 else 'UNKNOWN',out or err,
                 {'tool_id':'dotnet','executable':executable})
        runtimes = re.findall(r'^Microsoft\.NETCore\.App\s+(\d+\.\d+\.\d+)\s+\[', out, re.M)
        if not runtimes:
            self.add('.NET / 各ランタイムの通信','MANUAL','対応する.NETランタイム一覧を取得できません。',
                     {'tool_id':'dotnet','executable':executable}, required=True)
            return
        sdk_rc, sdks, _ = ctx.call([executable,'--list-sdks'], env=env)
        sdk_available = sdk_rc == 0 and bool(re.search(r'^\d+\.\d+\.\d+', sdks, re.M))
        shutil.copyfile(PROBES/'dotnet_http_probe.cs',build/'Program.cs')
        (build/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>',encoding='utf-8')
        (build/'probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>$(ProbeTarget)</TargetFramework><RestoreConfigFile>NuGet.Config</RestoreConfigFile></PropertyGroup></Project>',encoding='utf-8')
        builds = {}
        for version in runtimes:
            meta = {'tool_id':'dotnet','executable':executable,'runtime_version':version}
            if self.args.offline:
                self.add('.NET / HttpClient '+version,'SKIP','オフライン指定のため、このランタイムの通信は未検査。',meta,required=True)
                continue
            if not sdk_available:
                self.add('.NET / HttpClient '+version,'MANUAL','対応する診断プログラムをビルドできる.NET SDKが見つかりません。SDKの導入はしません。',meta,required=True)
                continue
            major = version.split('.')[0]
            if major not in builds:
                output = build/('out-'+major)
                command = [executable,'build',str(build/'probe.csproj'),'--configuration','Release','--output',str(output),
                           '-p:ProbeTarget=net'+major+'.0','-p:RestoreConfigFile='+str(build/'NuGet.Config')]
                build_rc, _, _ = run(command,timeout=75,env=env,cwd=build)
                builds[major] = output/'probe.dll' if build_rc == 0 else None
            assembly = builds[major]
            if not assembly:
                self.add('.NET / HttpClient '+version,'MANUAL','オフラインのSDK参照パックで診断プログラムをビルドできません。追加のパッケージ取得はしません。',meta,required=True)
                continue
            def probe(url, runtime=version, dll=assembly):
                return self.json_probe(ctx,[executable,'exec','--fx-version',runtime,str(dll),url,str(self.args.timeout)],env=env)
            self.sample('.NET / HttpClient '+version,probe,meta,
                        note='指定した.NETランタイムの既定HttpClient。別アプリの独自設定は未検査。',
                        action='このランタイムと使用するCA設定を確認してください。')
    def safe_chain_version(self):
        """Identify a Node runtime without executing Safe Chain or its shims."""
        for row in self.records:
            meta = row.get('metadata', {})
            info = meta.get('security_tool')
            if meta.get('tool_id') != 'safe-chain' or not info: continue
            env={'HOME':str(self.work), 'USERPROFILE':str(self.work), 'APPDATA':str(self.work),
                 'XDG_CONFIG_HOME':str(self.work), 'NODE_OPTIONS':'', 'NODE_PATH':'', 'NO_COLOR':'1'}
            if info.get('runtime') == 'node (PATH)':
                node=self.host.find('node')
                if node and '/shims/' not in node.replace('\\','/').lower():
                    rc,out,err=self.host.call([node,'--version'],timeout=12,env=env)
                    match=re.fullmatch(r'v?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)',(out or err).strip())
                    if rc == 0 and match:
                        info['runtime_version']=match.group(1)
                        info['runtime_executable']=node
                else:
                    info['runtime_reason']='PATHのNodeを安全に特定できません。'
            if not info.get('version'):
                info['version_reason']='本体を起動せずに版を確認できません。'

    def homebrew_packages(self):
        """Retain the exact queried installation; packages do not prove effective CA."""
        brew=self.host.find('brew')
        if not brew: return
        rc,out,err=self.host.call([brew,'list','--versions','ca-certificates','curl','openssl@3'],timeout=20)
        packages={}
        if rc==0:
            for line in out.splitlines():
                match=re.fullmatch(r'(ca-certificates|curl|openssl@3)((?: [0-9][A-Za-z0-9._+-]*)+)',line)
                if match: packages[match[1]]=match[2].split()
        self.add('Homebrew CAパッケージ','INFO',out or err,
                 dict(tool_id='homebrew',tool_name='Homebrew',executable=brew,execution_context='ホスト',
                      packages=packages,package_query_succeeded=rc==0,effective_ca_verified=False),
                 action='同じHomebrewの使用curl・実効CAを確認してください。パッケージ導入版だけでは通信を判定しません。')

    def configuration_checks(self):
        """Read version metadata for installed build tools without project execution."""
        if sys.platform.startswith('linux'):
            package_queries = [('dpkg-query',['-W','-f=${Package}\t${Version}\n','libnss3','nss']),
                               ('rpm',['-q','--qf','%{NAME}\t%{VERSION}-%{RELEASE}\n','nss','nss3'])]
            for manager, arguments in package_queries:
                executable = self.host.find(manager)
                if not executable: continue
                _, out, _ = self.host.call([executable]+arguments, timeout=12)
                packages = []
                for line in out.splitlines():
                    fields = line.split('\t')
                    if len(fields) == 2 and fields[0] in ('libnss3','nss','nss3') and re.fullmatch(r'[0-9A-Za-z.+:~_-]+',fields[1]):
                        packages.append(fields)
                if packages:
                    self.records[:] = [r for r in self.records if not (r.get('status') == 'NOT_FOUND' and r.get('metadata',{}).get('tool_id') == 'nss')]
                    for name,version in packages:
                        self.add('NSS / システムパッケージ','MANUAL',
                                 '導入版を確認しました。配布元の修正・バックポートと利用するアプリを確認してください。',
                                 {'tool_id':'nss','tool_name':'NSS','package':name,'version':version,'package_manager':manager})
                    break
        labels = {'rust':'Rust', 'cargo':'Cargo', 'rustup':'rustup', 'swift':'Swift',
                  'cc':'C/C++', 'conan':'Conan', 'vcpkg':'vcpkg',
                  'uv':'uv', 'pipx':'pipx', 'poetry':'Poetry', 'conda':'Conda', 'mamba':'Mamba',
                  'maven':'Maven', 'gradle':'Gradle',
                  'kotlin':'Kotlin', 'scala':'Scala', 'nuget':'NuGet', 'composer':'Composer',
                  'rubygems':'RubyGems', 'bundler':'Bundler', 'rebar3':'Rebar3', 'buildkit':'BuildKit', 'docker':'Docker',
                  'homebrew':'Homebrew', 'winget':'WinGet', 'chocolatey':'Chocolatey', 'scoop':'Scoop',
                  'mise':'mise', 'asdf':'asdf', 'pyenv':'pyenv', 'fnm':'fnm', 'volta':'Volta',
                  'corepack':'Corepack', 'rbenv':'rbenv', 'fvm':'FVM', 'git-lfs':'Git LFS', 'gh':'GitHub CLI',
                  'codex':'Codex', 'claude-code':'Claude Code', 'gemini-cli':'Gemini CLI', 'kiro-cli':'Kiro CLI',
                  'aws':'AWS CLI', 'azure':'Azure CLI', 'gcloud':'gcloud', 'firebase':'Firebase CLI',
                  'vercel':'Vercel CLI', 'netlify':'Netlify CLI', 'heroku':'Heroku CLI',
                  'supabase':'Supabase CLI', 'wrangler':'Wrangler', 'podman':'Podman', 'helm':'Helm',
                  'terraform':'Terraform', 'opentofu':'OpenTofu', 'pulumi':'Pulumi', 'rclone':'rclone'}
        hex_rows=research_rules.hex_archives(Path(os.environ.get('MIX_ARCHIVES') or Path(os.environ.get('MIX_HOME') or Path.home()/'.mix')/'archives'))
        if hex_rows:
            self.records[:]=[r for r in self.records if not (r['status']=='NOT_FOUND' and r.get('metadata',{}).get('tool_id')=='hex')]
            self.records.extend(hex_rows)
        env = {'RUSTUP_AUTO_INSTALL':'0', 'CARGO_NET_OFFLINE':'true',
               'HOME':str(self.work), 'USERPROFILE':str(self.work), 'APPDATA':str(self.work),
               'XDG_CONFIG_HOME':str(self.work/'config'), 'XDG_CACHE_HOME':str(self.work/'cache'),
               'CONAN_HOME':str(self.work/'conan'), 'CONAN_USER_HOME':str(self.work/'conan'),
               'CLOUDSDK_CONFIG':str(self.work/'gcloud'), 'CLOUDSDK_CORE_DISABLE_PROMPTS':'1',
               'CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK':'1', 'AZURE_CONFIG_DIR':str(self.work/'azure'),
               'AWS_EC2_METADATA_DISABLED':'true', 'AWS_CONFIG_FILE':str(self.work/'aws-config'),
               'CHECKPOINT_DISABLE':'1', 'PULUMI_SKIP_UPDATE_CHECK':'1', 'NO_UPDATE_NOTIFIER':'1',
               'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1', 'DISABLE_AUTOUPDATER':'1', 'CI':'true',
               'GRADLE_USER_HOME':str(self.work/'gradle'), 'PUB_CACHE':str(self.work/'pub-cache'),
               'DART_SUPPRESS_ANALYTICS':'true', 'COREPACK_ENABLE_NETWORK':'0', 'PIP_DISABLE_PIP_VERSION_CHECK':'1',
               'PIP_NO_CACHE_DIR':'1'}
        for tool, label in labels.items():
            seen = set()
            for path in self.discovered.get(tool, []):
                key = verdicts.installation_identity(tool,path)
                if key in seen: continue
                seen.add(key)
                if '/shims/' in path.replace('\\','/').lower():
                    self.add(label+' / バージョン','MANUAL','管理ツールのshimは自動導入を避けるため起動しません。',
                             {'tool_id':tool,'tool_name':label,'executable':path})
                    continue
                argument = '/Bv' if os.name == 'nt' and Path(path).stem.lower() == 'cl' else '-version' if tool in ('kotlin','scala') else 'version' if tool in ('terraform','opentofu','pulumi','git-lfs','rclone') else '--version'
                local_env = dict(env)
                if tool in ('rust','cargo','rustup'):
                    local_env['HOME'] = str(Path.home())
                    if os.environ.get('USERPROFILE'): local_env['USERPROFILE'] = os.environ['USERPROFILE']
                rc, out, err = self.host.call([path,argument], timeout=12, env=local_env)
                line = (out or err).splitlines()[:1]
                detail = redact(line[0]) if rc == 0 and line else 'バージョンを取得できません。'
                self.add(label+' / バージョン', 'INFO' if rc == 0 and line else 'UNKNOWN', detail,
                         {'tool_id':tool,'tool_name':label,'executable':path,'version':detail if rc == 0 and line else ''})
        if self.discovered.get('cargo'):
            home = Path(os.environ.get('CARGO_HOME') or Path.home()/'.cargo').expanduser()
            keys, failed, unknown_verify = set(), False, False
            filenames = ('config',) if (home/'config').is_file() else ('config.toml',)
            for filename in filenames:
                path = home/filename
                if not path.exists(): continue
                raw = evidence.read_public_file(path,128*1024)
                if raw is None:
                    failed = True; continue
                section = ''
                for line in raw.decode('utf-8', errors='replace').splitlines():
                    text = line.strip()
                    if text.startswith('#'): continue
                    group = re.match(r'^\[([^]]+)\]',text)
                    if group:
                        section = group.group(1); continue
                    setting = re.match(r'^([a-z-]+)\s*=',text)
                    if setting and section == 'http' and setting.group(1) in ('cainfo','proxy-cainfo','proxy','check-revoke','ssl-verify'):
                        keys.add('http.'+setting.group(1))
                        if setting.group(1) == 'ssl-verify' and re.match(r'^ssl-verify\s*=\s*false(?:\s*(?:#.*)?)?$',text,re.I):
                            unknown_verify = True
            self.add('Cargo / 設定','UNKNOWN' if failed else 'INFO',
                     'Cargoの利用者設定にあるCA・proxy関連の設定名を確認しました。値とプロジェクト固有設定は記録しません。',
                     {'tool_id':'cargo','tool_name':'Cargo','setting_names':sorted(keys),
                      'source':'https://doc.rust-lang.org/cargo/reference/config.html'})
            if unknown_verify or os.environ.get('CARGO_HTTP_SSL_VERIFY','').lower() == 'false':
                self.add('Cargo / 未確認の検証設定','INFO',
                         'http.ssl-verify=false 相当の指定を検出しましたが、標準Cargoでの適用は未確認です。',
                         {'tool_id':'cargo','tool_name':'Cargo','setting_names':['http.ssl-verify']})
            if sys.platform == 'win32' and os.environ.get('CARGO_HTTP_CHECK_REVOKE','').lower() == 'false':
                self.add('Cargo / 失効確認','ACTION',
                         '現在の環境変数でCargoの失効確認を無効にしています。',
                         {'tool_id':'cargo','tool_name':'Cargo','setting_names':['CARGO_HTTP_CHECK_REVOKE']})

    def tools(self):
        for name in ('uv','conda','pipx','poetry','docker','openssl'):
            p=self.host.find(name)
            if not p: continue
            if name in self.package_protected:
                self.add(name+' バージョン','SKIP','Safe Chainの連携候補があるため直接起動を見送りました。',
                         {'tool_id':name,'executable':p})
                continue
            flag='version' if name=='openssl' else '--version'
            rc,out,err=self.host.call([p,flag]); text=(out or err).strip()
            if name=='uv': self.ref('uv',text,'uvバージョン',{'tool_id':'uv','tool_name':'uv','executable':p})
            else: self.add(name+' バージョン','INFO',text,action='この行は通信試験ではありません。ツール固有CA・配布元アドバイザリを確認。')
        self.homebrew_packages()
        npm_env={'npm_config_cache':str(self.work/'npm-cache'), 'npm_config_update_notifier':'false',
                 'npm_config_fund':'false', 'npm_config_audit':'false'}
        for npm in self.paths(self.host,'npm',all_paths=True):
            if 'npm' in self.package_protected:
                self.add('npm / 通信','SKIP','Safe Chainの連携候補があるため直接起動と通信を見送りました。',
                         {'tool_id':'npm','executable':npm},required=True)
                continue
            # Windows .cmd scripts need a shell; invoke the installed npm-cli.js through its Node.
            command=[npm]
            if npm.lower().endswith(('.cmd','.bat')):
                cli=Path(npm).parent/'node_modules/npm/bin/npm-cli.js'
                local_node=Path(npm).parent/'node.exe'
                node=str(local_node) if local_node.is_file() else self.host.find('node')
                command=[node,str(cli)] if node and cli.is_file() else None
            if not command:
                self.add('npm / 通信','MANUAL','このnpmの実行方法を安全に確認できません。',{'tool_id':'npm','executable':npm})
                continue
            rc,out,_=self.host.call(command+['--version'],env=npm_env)
            meta={'tool_id':'npm','executable':npm,'version':out.strip() if rc == 0 else ''}
            if rc:
                self.add('npm / バージョン','UNKNOWN','npmの版を取得できません。',meta)
                continue
            for k in ('strict-ssl','cafile'):
                _,v,_=self.host.call(command+['config','get',k],env=npm_env); meta[k]=redact(v.strip())
            if meta.get('strict-ssl')=='false':
                self.add('npm設定','ACTION','npmのstrict-ssl=falseを検出。',meta)
            self.npm_transport(command,meta)
        lock=Path(self.args.project)/'Cargo.lock' if self.args.project else None
        if lock and lock.is_file():
            self.add('Rust / Cargo.lock','INFO','依存バージョンとrustupを自動照合します。既存Rust製CLIの実通信は対象外。')
        elif self.host.find('cargo') or self.host.find('rustc'):
            self.add('Rust','INFO','Rustコマンドを検出。rustupの版と対象プロジェクトのCargo.lockを自動照合します。')
    def npm_transport(self,command,meta):
        node=command[0] if len(command)>1 else self.host.find('node')
        env={'npm_config_cache':str(self.work/'npm-cache'), 'npm_config_update_notifier':'false', 'npm_config_fund':'false', 'npm_config_audit':'false'}
        rc,root,_=self.host.call(command+['root','-g'],env=env)
        package=Path(root.strip())/'npm'
        try: installed=json.loads(evidence.read_public_file(package/'package.json',65536) or b'{}')
        except (OSError,ValueError,TypeError): installed={}
        if rc or not node or installed.get('version')!=meta.get('version'):
            self.add('npm HTTP transport','MANUAL','選択されたnpmと同じ版の同梱ライブラリを確認できません。',meta); return
        source=str(PROBES/'npm_probe.cjs')
        self.sample('npm HTTP transport',lambda url:self.json_probe(self.host,[node,source,str(package),'probe',url,str(self.args.timeout)],env=env),
                    meta, note='選択したnpmと同じ版の設定ローダー・HTTP transport。CA・proxy設定を使用し、認証・Cookie・リダイレクトを抑制。',
                    action='npm本体・cafile・strict-sslを確認。npm lifecycleやinstallは実行しません。')
    def docker(self):
        p=self.host.find('docker')
        if not p:
            self.add('Docker','SKIP','見つかりません'); return
        _,out,err=self.host.call([p,'--version'])
        self.add('Docker CLI','INFO',out or err)
        self.add('Docker Engine / Desktop / BuildKit / registry','INFO',
                 'Docker本体のTLS経路はコンテナ内と別。バージョン、レジストリCA、BuildKit、insecure-registry設定を確認。pull/login/buildは実行しません。',
                 action='Desktop/Engine配布元の対策を適用。コンテナは --container で個別検査。')
        for name in self.args.container:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name):
                self.add('Dockerコンテナ','UNKNOWN','不正なコンテナ名/ID'); continue
            rc,out,err=self.host.call([p,'inspect','--type','container','--format','{{.State.Running}}',name])
            if rc or out.strip()!='true':
                self.add('Docker / '+name,'SKIP','稼働中と確認できません。起動・作成・pullはしません。'); continue
            ctx=Context([p,'exec',name],'コンテナ '+name)
            if not ctx.find('sh'):
                self.add('Docker / '+name,'SKIP','shがありません。distroless/Windowsコンテナはこの自動検査の対象外。'); continue
            for method in (self.curl,self.git,self.python,self.node,self.java): method(ctx)
            self.add('コンテナ '+name+' / 検査範囲','MANUAL','exec時の既定PATH/作業ディレクトリのみ。アプリのプロセス固有env・起動引数・別venvは未検査。')
    def execute(self):
        self.config_inventory()
        selected=set(self.args.only.split(','))
        if selected.intersection({'apps','packages','python','tools'}):
            print('標準対象の導入場所を検査します。', flush=True)
            installed = app_inventory.scan(reference, extra_paths=getattr(self.args, 'app', []))
            if 'apps' in selected: self.records.extend(installed)
            for row in installed:
                meta = row.get('metadata', {})
                security = meta.get('security_tool') or {}
                if meta.get('tool_id') == 'safe-chain':
                    candidate = Path(meta.get('path') or '')
                    shim_dir = candidate.parent.parent/'shims' if candidate.parent.name.lower() == 'bin' else None
                    path_dirs = [os.path.normcase(os.path.realpath(x)) for x in os.environ.get('PATH','').split(os.pathsep) if x]
                    shims_active = bool(shim_dir and os.path.normcase(os.path.realpath(shim_dir)) in path_dirs)
                    if security.get('shell_sources') or security.get('shell_links') or shims_active:
                        # Shell source/shim detection cannot prove that the read wrapper list is complete.
                        self.package_protected.update({'npm','npx','pnpm','yarn','pip','pip3','python','python3','uv','poetry','pipx'})
                if meta.get('application') and meta.get('tool_id') and selected.intersection({'apps','packages'}):
                    path = (meta.get('discovered_paths') or [meta.get('path')])[0]
                    self.discovered.setdefault(meta['tool_id'], []).append(path)
        for k,method in [('curl',self.curl),('git',self.git),('python',self.python),('node',self.node),('java',self.java)]:
            if k in selected: method(self.host)
        for kind in ('wget','httpie'):
            if kind in selected: self.network_client(self.host, kind)
        self.other_languages(self.host,selected)
        language_checks.collect(self, selected, run, parse_probe)
        if 'packages' in selected:
            p2_settings.collect(self)
            package_checks.collect(self,run,classify,redact,TARGETS)
            safechain_probe.collect(self)
            p2_coverage.collect(self)
        if 'apps' in selected:
            self.safe_chain_version()
            self.configuration_checks()
        if selected.intersection({'apps','packages','tools'}): version_inference.collect(self)
        if 'tools' in selected: self.tools()
        if 'docker' in selected: self.docker()
        if 'browser' in selected:
            self.add('ブラウザ / 実際のプロファイル','INFO','導入版と保存済みの失効情報を自動照合し、未確認のブラウザを分けて表示します。',
                     action='各ブラウザの配布元の対応情報と、保存済み失効情報の検査結果を確認してください。')
        self.add('対象範囲の確認','INFO','指定範囲を探索し、検出した未検査の環境を個別に表示します。')
        evidence.collect(self, reference)


def render_report(records, generated, source_observation=None):
    return reporting.render(records, generated, LABEL, AS_OF, source_observation)


def write_reports(audit, outdir):
    outdir.mkdir(parents=True,exist_ok=True)
    generated=dt.datetime.now().astimezone().isoformat(timespec='seconds')
    audit.records=verdicts.prepare(audit.records)
    for row in audit.records:
        remedy=remediation.plan(row)
        if remedy: row['remediation']=remedy
    summary=verdicts.summarize(audit.records)
    summary['tool_review_counts'] = reporting.tool_counts(audit.records)
    summary['tool_total'] = len(reporting.group_tools(audit.records)[0])
    display = reporting.action_model(audit.records)
    summary['primary_action_counts'] = display['primary_action_counts']
    summary['action_counts'] = display['action_counts']
    summary['presentation_tool_total'] = display['tool_total']
    report={'schema_version':3,'tool_version':TOOL_VERSION,'reference_date':AS_OF,'generated_at':generated,
            'reference_site':SOURCE,'scope':'代表的なTLS検査。全8鍵・コード署名・全アプリの保証ではない。',
            'summary':summary,'records':audit.records,'presentation':display}
    if getattr(audit, 'source_observation', None):
        report['source_observation'] = audit.source_observation
    (outdir/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (outdir/'report.html').write_text(render_report(audit.records,generated,getattr(audit,'source_observation',None)),encoding='utf-8')
    state=reporting.action_overview(display)
    lines=['eMudhra 開発環境診断 '+generated,'参考基準: '+AS_OF,'',
           state['title'],state['next_step'],state['counting_note']]+state['facts']+['', '対象ごとの結果', '']
    if getattr(audit, 'source_observation', None):
        lines.insert(2, reporting.observation_notice(audit.source_observation))
    context = [(i, audit.records[i]) for i in display['context_record_indices']]
    def append_record(r):
        lines.append('  [{} / {}] {}\n    {}\n    判定範囲: {}'.format(reporting.result_label(r, LABEL),
                     verdicts.METHOD_LABELS[r['assessment_method']],r['name'],r['detail'],r['scope']))
        for sample in r['samples']:
            lines.append('    [{}] {}: {}'.format(LABEL.get(sample['status'],sample['status']),sample['target'],sample['detail']))
        lines.extend('    '+line for line in reporting.application_lines(r))
        if r.get('action'):
            lines.append('    取得済み記録の案内（原文）: '+r['action'])
    for tool in display['tools']:
        lines.extend(reporting.action_text(tool))
        for index in tool['record_indices']:
            append_record(audit.records[index])
        lines.append('')
    if context:
        lines.append('検査情報')
        for _, row in context:
            append_record(row)
    (outdir/'summary.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('\n結果: '+str(outdir/'report.html'))
    shutil.copyfile(ROOT/'ui.css',outdir/'ui.css')
    print('report.html を開いてください。')
    print(state['title'])
    print(state['next_step'])
    for fact in state['facts']: print('  '+fact)
    print(state['counting_note'])
    for tool in display['tools']:
        if any(key in reporting.presentation.NEEDS_ACTION for key in tool['actions']):
            print('\n'+'\n'.join(reporting.action_text(tool)))
        elif tool['primary_action'] in ('version_complete', 'complete', 'scoped_complete', 'checked'):
            print('\n'+'\n'.join(reporting.action_text(tool)))
    for row in audit.records:
        if row['status'] in ('ACTION','UPDATE'):
            print('\n[{}] {}'.format(reporting.result_label(row, LABEL),row['name']))
            for line in remediation.text_lines(row): print('  '+line)
    print('調査用JSON: '+str(outdir/'report.json')+'（ローカルパスを含むため共有前に確認）')
    print('主分類: '+' / '.join(label+' '+str(display['primary_action_counts'][key])
                               for key, label in reporting.presentation.GROUPS))


def main(argv=None):
    # Configure before argparse: --help and argument errors also contain Japanese.
    # Windows redirected streams otherwise use an ANSI code page such as cp1252.
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):
            stream.reconfigure(encoding='utf-8',errors='replace')
    start_page='docs/使い方.html' if (ROOT.parent/'docs/使い方.html').is_file() else 'START-HERE.html'
    p=argparse.ArgumentParser(description='eMudhra開発環境診断。このPCの開発ツールを調べ、要対応の対象と対応手順を表示します。',
        epilog='初めての方は '+start_page+' をブラウザで開いてください。プロジェクト指定は必要な場合だけ追加できます。')
    p.add_argument('--offline',action='store_true',help='バージョン/設定のみ。接続しない')
    scope=p.add_mutually_exclusive_group()
    scope.add_argument('--project',type=Path,help='必要な場合に追加: このプロジェクトのGit/npm/Cargo.lock/venvも検査')
    scope.add_argument('--host-only',action='store_true',help='このPCにインストールされている開発環境を検査（既定）')
    p.add_argument('--out',type=Path,help='結果出力先')
    for name in ('python','node','java','curl','git','wget','httpie') + language_checks.KINDS:
        p.add_argument('--'+name,action='append',default=[],metavar='PATH',help='追加で検査する実行ファイル（繰返し可）')
    p.add_argument('--scan-venvs',action='append',default=[],metavar='DIR',help='指定ディレクトリのpyvenv.cfgを探索（最大100環境）')
    p.add_argument('--container',action='append',default=[],metavar='NAME',help='指定した稼働中Linuxコンテナ内をdocker execで検査')
    p.add_argument('--app',type=Path,action='append',default=[],metavar='PATH',help='追加で検査するアプリの実行ファイルまたはフォルダー（繰返し可）')
    p.add_argument('--only',default='curl,wget,httpie,git,python,node,java,go,ruby,php,dotnet,tools,docker,browser,native,apps,packages,'+','.join(language_checks.KINDS),help='検査種類をカンマ区切りで指定')
    p.add_argument('--timeout',type=float,default=8,help='各接続のタイムアウト秒')
    p.add_argument('--workers',type=int,default=4,help='同じクライアントでの並列接続数 1..5')
    p.add_argument('--browser-results',type=Path,action='append',default=[],metavar='JSON',help='macOS限定: 24時間以内の通常ブラウザの実測記録を取込（繰返し可）')
    args=p.parse_args(argv)
    args.host_only=args.project is None
    if args.project:
        args.project=args.project.expanduser().absolute()
        if not args.project.is_dir(): p.error('--project は存在するディレクトリにしてください')
    if args.browser_results and sys.platform!='darwin':
        p.error('--browser-results は本配布版ではmacOSのみ対応です。Windows/Linuxの観測JSON取り込みには対応していません。')
    if not 1<=args.workers<=5: p.error('--workers は1..5')
    if not 1<=args.timeout<=60: p.error('--timeout は1..60')
    allowed={'curl','wget','httpie','git','python','node','java','go','ruby','php','dotnet','tools','docker','browser','native','apps','packages'}
    allowed.update(language_checks.KINDS)
    if set(args.only.split(','))-allowed: p.error('--only に未知の検査名があります')
    if args.offline and args.container: p.error('--offline と --container は併用できません')
    if args.container and 'docker' not in args.only.split(','): p.error('--container には --only にdockerを含めてください')
    if args.browser_results and 'browser' not in args.only.split(','): p.error('--browser-results には --only にbrowserを含めてください')
    if args.app and 'apps' not in args.only.split(','): p.error('--app には --only にappsを含めてください')
    print('eMudhra 開発環境診断 '+DISPLAY_VERSION+' / 内部版 '+TOOL_VERSION+' / 参考日 '+AS_OF,flush=True)
    print('検査対象: このPCの開発環境'+(' ＋ '+str(args.project) if args.project else ''),flush=True)
    print('通信: '+('オフライン（版・設定のみ確認）' if args.offline else '通常サイトと代表4つの検証先へHTTPS接続'),flush=True)
    print('検査を開始します。通常は数分程度です。終了後にreport.htmlの保存先を表示します。',flush=True)
    audit=Audit(args)
    try:
        audit.execute()
    except KeyboardInterrupt:
        audit.add('検査中断','UNKNOWN','ユーザーによって中断されました。取得済み結果を出力します。')
    except Exception as e:
        audit.add('診断ツール内のエラー','UNKNOWN',type(e).__name__+': '+str(e))
    try:
        out=args.out.expanduser().absolute() if args.out else Path.cwd()/('emudhra-report-'+dt.datetime.now().strftime('%Y%m%d-%H%M%S'))
        for path in args.browser_results:
            try:
                audit.records.append(browser_results.load(path,audit.records,TARGETS))
            except ValueError as exc:
                audit.add('ブラウザ / 実測記録の取込','UNKNOWN',str(exc),action='新しい正常な実測JSONを指定してください。')
        write_reports(audit,out)
    finally:
        audit.tmp.cleanup()
    display=reporting.action_model(audit.records)
    actions={key for tool in display['tools'] for key in tool['actions']}
    if actions & (reporting.presentation.NEEDS_ACTION - {'investigate'}): return 1
    # Keep 0/1/2 semantics consistent with the displayed action, including
    # a known fixed version whose communication remains untested.
    if 'investigate' in actions: return 2
    # Context-only failures are not tool cards, but still make diagnosis incomplete.
    if any(audit.records[i]['review_state'] in ('review','unverified') for i in display['context_record_indices']): return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
