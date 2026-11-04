"""Bound conclusions to the selected client's observed TLS connection.

Only allowlisted facts leave these parsers. Response bodies, headers, cookies,
and raw debug logs never become report evidence.
"""
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import evidence


MAX_TRACE = 256 * 1024
TRACE = re.compile(r'^\s*\d+(?:\.\d+)?s\s+DEBUG\s+network(?:::\w+)?:\s+(.*)$')
try:
    TLS_PINS = frozenset(json.loads((Path(__file__).resolve().parent/'references/assessment.json').read_text())['tls_spki_sha256'])
except (OSError, ValueError, KeyError, TypeError):
    TLS_PINS = frozenset()


def ruby_socket(path, url, returncode, *, proxy_possible=False):
    """Use socket facts recorded inside this exact RubyGems/Bundler process."""
    raw = evidence.read_public_file(path, limit=64*1024)
    if not raw or returncode in (124, 126) or returncode < 0:
        return None
    target = urlsplit(url)
    try:
        rows = [json.loads(line) for line in raw.decode('utf-8').splitlines()]
        if len(rows) > 64:
            return None
        matches = []
        for row in rows:
            if not isinstance(row, dict) or row.get('schema') != 1 or row.get('source') != 'ruby_ssl_socket':
                return None
            if row.get('host') != target.hostname or row.get('port') != (target.port or 443):
                continue
            code = row.get('verify_code')
            pins = row.get('chain_spki_sha256')
            if (type(code) is not int or not isinstance(pins, list) or len(pins) > 16 or
                    any(not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{64}', pin) for pin in pins) or
                    row.get('verify_peer') is not True or row.get('state') not in ('accepted', 'error')):
                return None
            matches.append(row)
        if not matches:
            return None
        # Successful evidence wins over a later retry/redirect error. Never use
        # a different host or port, or a generic/expired/name-mismatch failure.
        accepted = [r for r in matches if r['state'] == 'accepted' and r['verify_code'] == 0 and
                    r.get('hostname_verified') is True]
        if accepted:
            row = next((r for r in accepted if TLS_PINS.intersection(r['chain_spki_sha256'])), accepted[0])
            verified = bool(TLS_PINS.intersection(row['chain_spki_sha256']))
            state = 'accepted'
            detail = '対象ツール自身のTLSソケットで接続先名・証明書検証の成功を確認。'
            if verified:
                detail += ' 同じ接続の証明書チェーンの公開鍵指紋が参照対象と一致。'
        elif all(r['state'] == 'error' and r['verify_code'] in (2, 18, 19, 20, 21, 23, 27, 28) for r in matches):
            row = matches[0]
            state, verified = 'error', False
            detail = '対象ツール自身のTLSソケットで証明書の信頼拒否を確認（検証コード '+str(row['verify_code'])+'）。'
        else:
            row = matches[0]
            state, verified = 'unknown', False
            detail = '対象ツール自身のTLS検証は期限・接続先名・その他の理由で未判定（検証コード '+str(row['verify_code'])+'）。'
        origin_verified = not proxy_possible or verified
        facts = dict(source='ruby_ssl_socket', origin=url, origin_verified=origin_verified,
                     verify_code=row['verify_code'], tls_verified=state == 'accepted',
                     hostname_verified=row.get('hostname_verified') is True,
                     chain_spki_sha256=row['chain_spki_sha256'], target_chain_verified=verified)
        return dict(state=state, detail=detail, origin_verified=origin_verified, verify_code=row['verify_code'],
                    target_chain_verified=verified, connection_evidence=facts)
    except (ValueError, TypeError, UnicodeError):
        return None


def cargo_trace(output, url, returncode, *, proxy_possible=False):
    """Read Cargo/libcurl's first origin exchange, before any HTTP redirect.

    A registry-format error is not a TLS failure. A successful proxy CONNECT,
    or the certificate error at a later destination, is not origin evidence.
    A configured HTTPS proxy can fail before emitting a CONNECT log entry.
    Unsupported/incomplete log formats deliberately supply no such proof.
    """
    if len(output) > MAX_TRACE or returncode in (124, 126) or returncode < 0:
        return dict(state='unknown', detail='Cargoの通信観測が中断・上限・実行失敗のため未判定です。')
    parsed = urlsplit(url)
    expected = url.rstrip('/')+'/config.json'
    port = parsed.port or 443
    authority = parsed.netloc.lower()
    request_path = urlsplit(expected).path
    active = connected = tls_ok = request = host = proxy = False
    seen = False
    failures = []
    connections = 0
    facts = dict(source='cargo_http_debug', origin=url, request_path=request_path)
    for line in output.splitlines():
        # Cargo can include arbitrary server response text after its final error.
        if line.startswith('error:'):
            break
        match = TRACE.fullmatch(line)
        if not match:
            continue
        message = match[1]
        fetch = re.fullmatch(r'url="([^"]+)"', message)
        if fetch:
            seen = True
            active = fetch[1] == expected
            connected = tls_ok = request = host = False
            continue
        if not active or not message.startswith('http-debug: '):
            continue
        value = message[len('http-debug: '):]
        if value.startswith('> CONNECT ') or re.search(r'Establish HTTP proxy tunnel|CONNECT tunnel|Proxy certificate:', value, re.I):
            proxy = True
        connection = re.fullmatch(r'\* Connected to ([^ ]+) \([^\n]+\) port (\d+)(?:.*)', value)
        if connection:
            connections += 1
            connected = connection[1].lower().strip('[]') == parsed.hostname.lower() and int(connection[2]) == port
            tls_ok = request = host = False
        if value == '*  SSL certificate verify ok.' or value == '* SSL certificate verify ok.':
            tls_ok = True
        if re.fullmatch(r'> GET '+re.escape(request_path)+r' HTTP/(?:1\.[01]|2|3)', value):
            request = True
        if value.lower() == '> host: '+authority:
            host = True
        response = re.fullmatch(r'< HTTP/(?:1\.[01]|2|3) (\d{3})(?: .*)?', value)
        if response and connected and tls_ok and request and host and not proxy:
            code = int(response[1])
            if code < 200:
                continue
            return dict(state='accepted', origin_verified=not proxy_possible,
                        detail='Cargo自身の接続先・TLS検証・HTTP応答を確認: HTTP '+str(code),
                        connection_evidence=dict(facts, http_status=code, tls_verified=True,
                                                 origin_verified=not proxy_possible, target_chain_verified=False))
        failure = re.fullmatch(r'\* (SSL certificate problem: .+|SSL: .+|schannel: .+)', value)
        if failure and connected and not proxy:
            failures.append(failure[1])
    if len(failures) == 1 and connections == 1 and not proxy:
        return dict(state='error', origin_verified=not proxy_possible, detail=failures[0],
                    connection_evidence=dict(facts, origin_verified=not proxy_possible, tls_verified=False))
    if seen or 'http-debug:' in output:
        return dict(state='unknown', detail='Cargoのログから対象先のTLS結果を一意に確認できません。',
                    connection_evidence=dict(facts, origin_verified=False))
    return None
