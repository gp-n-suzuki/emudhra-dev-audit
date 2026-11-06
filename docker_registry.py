"""Classify saved registry settings without probing or changing observations.

Desktop identification is an inference from the same daemon's OS/name and a
bound local endpoint. It is not verification of outbound TLS or code signing.
"""
import ipaddress
import re

INTERNAL = 'hubproxy.docker.internal:5555'
SOURCES = ['https://docs.docker.com/desktop/features/networking/',
           'https://docs.docker.com/reference/cli/dockerd/#insecure-registries',
           'https://docs.docker.com/engine/manage-resources/contexts/']


def identifier(name):
    return isinstance(name, str) and len(name) <= 253 and bool(re.fullmatch(
        r'(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?', name))


def confirmation_facts(value):
    """Typed, explicitly user-reported facts; never synthesize daemon observations."""
    if not isinstance(value, dict) or value.get('schema_version') != 1 or value.get('source') != 'user-provided':
        return {}
    if any(not isinstance(value.get(k), str) or not re.fullmatch(r'[0-9a-f]{64}', value[k])
           for k in ('source_sha256', 'record_sha256')):
        return {}
    if not isinstance(value.get('provided_at'), str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value['provided_at']):
        return {}
    facts = value.get('facts')
    if not isinstance(facts, dict) or type(facts.get('local_docker_desktop')) is not bool:
        return {}
    if (not isinstance(facts.get('context'), str) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}', facts['context']) or
            facts.get('endpoint_type') not in ('unix', 'npipe', 'remote-or-unknown')):
        return {}
    names = facts.get('insecure_registries')
    cidrs = facts.get('insecure_registry_cidrs')
    if not isinstance(names, list) or not all(identifier(n) for n in names) or len(names) != len(set(names)):
        return {}
    if not isinstance(cidrs, list) or not all(isinstance(c, str) for c in cidrs):
        return {}
    try:
        for cidr in cidrs:
            ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return {}
    for key in ('user_added_insecure_registries', 'user_added_registry_mirrors', 'docker_hub_secure'):
        if key in facts and type(facts[key]) is not bool:
            return {}
    return facts


def assess(meta):
    captured_names = meta.get('insecure_registries')
    names = captured_names if isinstance(captured_names, list) else []
    names = [n for n in names if identifier(n)]
    count = meta.get('count')
    valid_count = type(count) is int and count >= len(names)
    redacted = meta.get('redacted_registry_count', 0)
    hidden = redacted if type(redacted) is int and redacted >= 0 else 0
    complete_names = isinstance(captured_names, list) and valid_count and count == len(names)+hidden
    connection = meta.get('docker_connection', {})
    connection = connection if isinstance(connection, dict) else {}
    bound = connection.get('bound') is True
    observed_desktop = (bound and connection.get('server_os') == 'Docker Desktop' and
               connection.get('server_name') == 'docker-desktop' and
               connection.get('endpoint_type') in ('unix', 'npipe'))
    # OS and registry values come from the same info response. A non-Desktop
    # daemon cannot gain the exception even when its endpoint lookup failed.
    non_desktop = bool(connection.get('server_os')) and connection['server_os'] != 'Docker Desktop'
    facts = confirmation_facts(meta.get('registry_user_confirmation'))
    matching = bool(facts) and complete_names and hidden == 0 and sorted(facts['insecure_registries']) == sorted(names)
    conflict = bool(facts) and (not matching or facts['local_docker_desktop'] is False or
        facts['endpoint_type'] not in ('unix', 'npipe') or non_desktop or
        connection.get('endpoint_type') not in (None, '', facts['endpoint_type']) or
        connection.get('context') not in (None, '', facts['context']) or
        connection.get('server_name') not in (None, '', 'docker-desktop') or
        connection.get('bound') is False)
    user_desktop = (matching and not conflict and facts['local_docker_desktop'] is True and
                    facts['endpoint_type'] in ('unix', 'npipe'))
    desktop = (observed_desktop or user_desktop) and not conflict
    internal, external, pending = [], [], []
    for name in names:
        if name.lower() != INTERNAL or non_desktop:
            external.append(name)
        elif desktop:
            internal.append(name)
        else:
            pending.append(name)
    unsafe_cidrs, unknown_cidrs = [], False
    cidrs = meta.get('insecure_registry_cidrs', [])
    if not isinstance(cidrs, list):
        cidrs, unknown_cidrs = [], True
    # Supplemented CIDRs are additional claims, not replacements for raw values.
    cidrs = cidrs + (facts['insecure_registry_cidrs'] if matching else [])
    for value in cidrs:
        try:
            network = ipaddress.ip_network(value, strict=False)
            if not network.is_loopback:
                unsafe_cidrs.append(str(network))
        except (ValueError, TypeError):
            unknown_cidrs = True
    observed = meta.get('registry_secure_observations')
    conflicting = observed is not None and (not isinstance(observed, dict) or
                    any(observed.get(name) is not False for name in names))
    incomplete = not complete_names or unknown_cidrs or bool(meta.get('registry_entries_incomplete')) or conflicting
    if incomplete:
        pending.extend(internal)
        internal = []
    status = ('ACTION' if external or hidden or unsafe_cidrs else
              'MANUAL' if pending or incomplete else 'CHECKED' if internal else 'INFO')
    return dict(rule='desktop-internal-registry-v1', status=status, internal=internal,
                external=external, pending=pending, redacted_external_count=hidden,
                unsafe_cidrs=sorted(set(unsafe_cidrs)), incomplete=incomplete,
                user_confirmation_state=('conflict' if conflict else 'accepted' if user_desktop else
                                         'insufficient' if meta.get('registry_user_confirmation') else 'absent'),
                basis='same-daemon-desktop-and-local-endpoint' if observed_desktop and not conflict else
                      'user-confirmed-desktop-and-local-endpoint' if user_desktop else
                      'same-daemon-non-desktop' if non_desktop else 'connection-evidence-insufficient',
                interpretation='configuration-only; outbound TLS and code signing not evaluated',
                sources=SOURCES)


def reassess(row):
    if (row.get('name') != 'Docker / registryのTLS設定' or row.get('samples') or
            row.get('assessment_method') not in (None, 'configuration')):
        return row
    meta = row.get('metadata', {})
    if 'count' not in meta:
        return row
    result = assess(meta)
    if result['status'] == 'CHECKED':
        basis = ('ユーザー提供の追加確認結果（ローカルDocker Desktopへの接続と実効registry設定）' if
                 result['basis'] == 'user-confirmed-desktop-and-local-endpoint' else
                 '同じEngineから取得したDocker Desktopの識別情報とローカル接続')
        detail = '対応不要。'+basis+'を根拠に、内部接続用設定と判断しました。この設定の変更は必要ありません。Secure=falseの元観測は保持しています。'
        action = ''
    elif result['status'] == 'ACTION':
        detail = 'Desktop内部例外とは区別して対応するinsecure registry設定があります。'
        if result['internal']:
            detail += ' Desktop内部用 {} 件は設定修正の対象に含めません。'.format(len(result['internal']))
        detail += ' 外部・非Desktop {} 件、名前を伏せた対象 {} 件、ループバック以外のCIDR {} 件。'.format(
            len(result['external']), result['redacted_external_count'], len(result['unsafe_cidrs']))
        action = '対象の外部registry・CIDRの用途とTLS・CA設定を確認してください。Desktop内部用の設定を一緒に削除しないでください。'
    elif result['status'] == 'MANUAL':
        detail = 'Secure=falseを記録しましたが、接続先がローカルのDocker Desktopかを確定する情報が不足しています。内部用かどうか判定保留です。' if result['pending'] else 'registry設定の取得情報が不完全なため、対応の要否は判定保留です。'
        action = '設定削除はまだ不要です。接続先の情報を含む新しい診断結果、または接続先・設定の追加確認結果で判断してください。'
        if result['user_confirmation_state'] == 'conflict':
            detail = 'ユーザー提供の追加確認結果と保存済みの接続先情報が一致しないため、内部用かどうか判定保留です。'
    else:
        detail = '取得したregistry一覧にSecure=falseはありません。CIDR・別BuildKit・外部TLS通信の未検査範囲とは区別します。'
        action = ''
    original = meta.get('registry_original_result') or {
        key:row.get(key) for key in ('status', 'detail', 'action')}
    value = dict(row, status=result['status'], detail=detail, action=action,
                 scope='取得したregistry設定の範囲。追加確認結果がある場合は自動観測と区別します。外部TLSやDocker全体の安全性は別です。',
                 metadata=dict(meta, registry_assessment=result, registry_original_result=original))
    value.pop('remediation', None)
    return value
