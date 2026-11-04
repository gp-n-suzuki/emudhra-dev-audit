"""Presentation vocabulary and reports; machine verdict codes stay in verdicts.py."""
import html
import json
import re
from collections import Counter
from pathlib import Path

import remediation
import verdicts
import presentation

ROOT = Path(__file__).resolve().parent
RESULT_GROUPS = (
    ('action', '対応が必要'),
    ('review', '確認が必要'),
    ('complete', '確認できた'),
    ('unverified', '未判定'),
    ('scope', '見つからなかった対象'),
    ('info', '環境情報'),
)
STATUS_LABELS = {
    'ACTION': '設定・接続を確認', 'REJECTED': '検査先の証明書を拒否できた',
    'UNKNOWN': '未判定', 'SKIP': '未検査', 'MANUAL': '未判定',
    'INFO': '検査情報', 'UPDATE': '更新が必要', 'REFERENCE_OK': '照合基準を満たす',
    'CONTROL_OK': '接続できた', 'INFERRED_OK': '対応版を使用中',
    'STATIC_OK': '保存済み拒否情報を照合', 'CHECKED': '設定・配置を確認済み',
    'NOT_FOUND': '見つからない', 'NOT_APPLICABLE': 'このOSでは対象外', 'INFERRED_REJECTED': '検査先の証明書を拒否できた（推定）',
}

# Names emitted by collectors, matched only at the start of the tool portion.
# A PHP curl extension, for example, belongs to PHP rather than the curl CLI.
TOOL_NAMES = (
    ('Java', ('Java',)), ('Python', ('Python', 'pip', 'certifi', 'venv探索')),
    ('Node.js', ('Node.js', 'Node')), ('Rust', ('Rust', 'rustup', 'Cargo')),
    ('Bun', ('Bun',)), ('Deno', ('Deno',)), ('Dart', ('Dart',)), ('Flutter', ('Flutter',)),
    ('Perl', ('Perl',)), ('Erlang', ('Erlang', 'erl')), ('Elixir', ('Elixir',)),
    ('Docker', ('Docker',)), ('Google Chrome', ('Google Chrome', 'Chrome')),
    ('Microsoft Edge', ('Microsoft Edge', 'Edge')), ('Safari', ('Safari',)),
    ('Firefox', ('Firefox',)), ('curl', ('curl',)), ('wget', ('wget',)), ('HTTPie', ('HTTPie', 'httpie')), ('Git', ('Git',)),
    ('Go', ('Go',)), ('Ruby', ('Ruby',)), ('PHP', ('PHP',)), ('.NET', ('.NET',)),
    ('PowerShell 7', ('PowerShell 7',)), ('Windows PowerShell', ('Windows PowerShell',)),
    ('uv', ('uv',)), ('npm', ('npm',)), ('Poetry', ('poetry',)),
    ('OpenSSL', ('openssl',)), ('Homebrew', ('Homebrew',)),
    ('macOS', ('macOS',)), ('Windows', ('Windows',)), ('Linux', ('Linux',)),
)
CONTEXT_NAMES = {'検査対象', 'OS / 環境設定', '検査範囲 / ホストのみの検査'}


def tool_name(row):
    name = row['name']
    meta = row.get('metadata', {})
    if meta.get('result_tool_name'):
        return meta['result_tool_name']
    if meta.get('tool_name'):
        return meta['tool_name']
    if meta.get('application_scan'):
        return '対象の探索' if row['review_state'] == 'review' else None
    if meta.get('application'):
        paths = meta.get('discovered_paths') or [meta.get('path', '')]
        name = paths[0].replace('\\', '/').rstrip('/').rsplit('/', 1)[-1] or name.replace('アプリ / ', '', 1)
        name = re.sub(r'\.(?:app|exe|cmd|bat|ps1|com|appimage)$', '', name, flags=re.IGNORECASE)
        if re.fullmatch(r'python(?:\d+(?:\.\d+)*)?', name, re.IGNORECASE):
            return 'Python'
    if name in CONTEXT_NAMES and row['review_state'] in ('info', 'scope', 'unverified'):
        return None
    if name == '検査範囲 / 未検査のPython仮想環境':
        return 'Python'
    name = re.sub(r'^(?:ホスト|ブラウザ|コンテナ [^/]+) / ', '', name)
    for tool, aliases in TOOL_NAMES:
        if any(re.match(re.escape(alias) + r'(?![a-zA-Z0-9])', name, re.IGNORECASE) for alias in aliases):
            return tool
    return name if meta.get('application') else row['name']


def group_tools(records, include_not_applicable=False):
    tools, context = {}, []
    aliases = verdicts.snapshot_targets(records)
    for index, row in enumerate(records):
        if row['status'] == 'NOT_APPLICABLE' and not include_not_applicable:
            continue
        name = tool_name(row)
        if name is None:
            context.append((index, row))
        else:
            tools.setdefault(name, []).append((index, row))
    result = []
    for name, rows in tools.items():
        units, keyed = [], {}
        for index, row in rows:
            identity = verdicts.snapshot_identity(row, aliases)
            if identity is None:
                units.append(dict(rows=[(index, row)], installation=False))
            else:
                if identity not in keyed:
                    unit = dict(rows=[], installation=True)
                    keyed[identity] = unit
                    units.append(unit)
                keyed[identity]['rows'].append((index, row))
        for unit in units:
            states = {row['review_state'] for _, row in unit['rows']}
            unit['state'] = min(states, key=verdicts.PRIORITY.get)
        counts = Counter(unit['state'] for unit in units)
        state = min(counts, key=verdicts.PRIORITY.get)
        # Every tool belongs to one primary group; installation states remain visible within it.
        filters = [state]
        result.append(dict(name=name, rows=rows, units=units, counts=counts, state=state, filters=filters))
    return sorted(result, key=lambda t: (verdicts.PRIORITY[t['state']], t['name'].casefold())), context


def tool_badges(tool):
    badges = [(key, '{} {}件'.format(dict(RESULT_GROUPS)[key], tool['counts'][key]))
              for key in ('action', 'review') if tool['counts'][key]]
    if not badges:
        statuses = {row['status'] for _, row in tool['rows']}
        if tool['state'] == 'complete':
            if 'REJECTED' in statuses:
                label = '検査先の証明書を拒否できた（推定を含む）' if 'INFERRED_REJECTED' in statuses else STATUS_LABELS['REJECTED']
            else:
                chosen = next(s for s in ('INFERRED_REJECTED', 'STATIC_OK', 'INFERRED_OK', 'CHECKED') if s in statuses)
                matches = [r for _, r in tool['rows'] if r['status'] == chosen]
                labels = {result_label(r, STATUS_LABELS) for r in matches}
                label = next(iter(labels)) if len(labels) == 1 else STATUS_LABELS[chosen]
            badges.append(('complete', label))
        elif tool['state'] == 'unverified':
            badges.append(('unverified', '未判定'))
        elif tool['state'] == 'info':
            badges.append(('info', '環境情報のみ'))
    if tool['counts']['scope']:
        badges.append(('scope', '見つからない {}件'.format(tool['counts']['scope'])))
    if tool['counts']['unverified'] and tool['state'] != 'unverified':
        badges.append(('unverified', '未判定 {}件'.format(tool['counts']['unverified'])))
    if tool['counts']['complete'] and tool['state'] in ('action', 'review'):
        badges.append(('complete', '確認できた {}件'.format(tool['counts']['complete'])))
    return ''.join('<span class="tool-status {}">{}</span>'.format(key, html.escape(label)) for key, label in badges)


def tool_counts(records):
    tools, _ = group_tools(records)
    return {key:sum(key in tool['filters'] for tool in tools) for key, _ in RESULT_GROUPS}


def action_model(records):
    """Additive UI contract; retain the legacy grouping API for JSON consumers."""
    return presentation.build(records, *group_tools(records, include_not_applicable=True))


def action_overview(model):
    counts = model['primary_action_counts']
    urgent = sum(counts[key] for key in presentation.NEEDS_ACTION if key != 'investigate')
    if urgent:
        title = '更新・設定修正などの対応が必要なツールが{}件あります'.format(urgent)
    elif counts['investigate']:
        title = '追加確認が必要なツールが{}件あります'.format(counts['investigate'])
    elif counts['checked']:
        title = '記載した検査範囲で問題を検出しませんでした'
    else:
        title = '探索結果・環境情報を記録しました' if model['tools'] else '検査結果がありません'
    facts = [label+': '+str(counts[key])+'ツール（主分類）' for key, label in presentation.GROUPS]
    facts += [label+': '+str(sum(any(e['state'] == key for e in t['communication']) for t in model['tools']))+'ツール（通信の根拠・重複あり）'
              for key, label in (('rejected', '検査先の証明書を拒否できた'), ('inferred_rejected', '検査用サイトのブロックを推定'))]
    return dict(title=title, next_step='必要な行動を確認し、版の判定と通信の結果を別々に確認してください。',
                facts=facts,
                counting_note=model['counting_note'])


def action_text(tool):
    """The CLI and text export use exactly the same claims as HTML/JSON."""
    lines = ['ツール: '+tool['name']+' / '+'・'.join(presentation.LABELS[key] for key in tool['actions'])]
    for reason in tool['action_reasons']:
        lines.extend(['  対応理由: '+reason['reason'], '  次の行動: '+reason['next_step']])
    for axis, label in (('version', '版'), ('communication', '通信'), ('configuration', '設定')):
        for entry in tool[axis]:
            version = str(entry.get('version') or '')
            current = ' / '+entry.get('component', '')+' '+version if version else ''
            lines.append('  '+label+': '+entry['label']+current+' / '+entry['scope'])
            if entry.get('reason'):
                lines.append('    根拠: '+entry['reason'])
    for gap in tool['gaps']:
        lines.extend(['  不足・未確認: '+gap['reason'], '  次の確認: '+gap['next_step']])
    return lines


def overview(records):
    counts = verdicts.summarize(records)
    states, review = counts['status_counts'], tool_counts(records)
    tools, _ = group_tools(records)
    rejected = sum(any(r['status']=='REJECTED' for _,r in tool['rows']) for tool in tools)
    inferred = sum(any(r['status']=='INFERRED_REJECTED' for _,r in tool['rows']) for tool in tools)
    reference = sum(any(r['status'] in ('INFERRED_OK','STATIC_OK') for _,r in tool['rows']) for tool in tools)
    fixed_versions = any(r['status']=='INFERRED_OK' and r['assessment_method']=='version' for r in records)
    if review['action']:
        title = '対応が必要なツールが{}件あります'.format(review['action'])
        next_step = '各項目の手順に沿って対応し、もう一度診断してください。'
    elif review['review']:
        title = '確認が必要なツールが{}件あります'.format(review['review'])
        next_step = '各項目に表示された操作を進めてください。'
    elif fixed_versions:
        title = '照合した版に更新が必要なものはありません'
        next_step = '未判定の対象と通信の詳細は検査データで確認できます。'
    elif rejected:
        title = '検査先の証明書を拒否できました'
        next_step = 'ツールごとの結果を確認してください。'
    elif records:
        title = '検査結果を記録しました'
        next_step = '各対象の結果と検査データを確認できます。'
    else:
        title = '検査結果がありません'
        next_step = '検査する環境を指定して再実行してください。'
    facts = [
        '対応が必要: {}ツール'.format(review['action']),
        '確認が必要: {}ツール'.format(review['review']),
        '未判定: {}ツール'.format(review['unverified']),
        '検査先の証明書を拒否できた: {}ツール'.format(rejected),
        '検査用サイトのブロックを推定: {}ツール'.format(inferred),
        'バージョン・証明書データを確認: {}ツール'.format(reference),
    ]
    return dict(title=title, next_step=next_step, facts=facts, review=review,
                rejected=rejected, inferred=inferred, reference=reference,
                tone='action' if review['action'] else 'review' if review['review'] else 'measured' if rejected else 'neutral')


COMPONENT_LABELS = {'go': '同梱Go', 'certifi': '同梱certifi', 'electron': '同梱Electron',
                    'ca_bundle': '同梱CA証明書', 'rust': '同梱Rust'}


def below_fixed_version(check):
    return check['status'] == 'UPDATE' and bool(check.get('reference_floor'))


def application_check_label(check):
    if check['component'] == 'CAファイル':
        return 'CAファイルを確認'
    return '対策版未満' if below_fixed_version(check) else STATUS_LABELS.get(check['status'], check['status'])


def component_label(row, check):
    return 'Go本体' if verdicts.is_go_toolchain_check(row, check) else COMPONENT_LABELS.get(check['component'], check['component'])


def application_lines(row):
    """Keep collected coverage in the human-readable text export."""
    meta = row.get('metadata', {})
    if meta.get('application_scan'):
        labels = {'searched': '探索済み', 'not_found': '見つからない'}
        return (['探索: '+p['path']+' / '+labels.get(p['status'], p['status']) for p in meta['searched']]
                + ['未探索・中断: '+reason for reason in meta['incomplete']]
                + ['探索対象外: '+path for path in meta.get('excluded', [])])
    if not meta.get('application'):
        return []
    security = meta.get('security_tool', {})
    security_lines = ([key+': '+str(security[field]) for key,field in (('本体バージョン','version'),('実行環境','runtime'),('組込Go','go_versions'),('連携候補','configured_wrappers')) if security.get(field)])
    env = meta.get('python_environment',{})
    environment_lines = ([env['scope']]+[p['name']+' '+p['version']+' / インストール記録のみ・実使用未確認'+
        (' / 参考対策版 '+str(p['reference_floor'])+' / '+p.get('detail','') if p.get('reference_floor') else '')
        for p in env.get('packages',[])]) if env else []
    return security_lines + environment_lines + ([component_label(row, c)+' '+str(c.get('version', ''))+
             ' / '+application_check_label(c)+
             (' / 対策版: '+str(c['reference_floor']) if c.get('reference_floor') else '')+
             ' / '+c['detail'] for c in meta['inspections']]
            + ['未検査: '+reason for reason in meta['uninspected']])


def application_details(row, only_ca=False):
    meta = row.get('metadata', {})
    esc = html.escape
    if not meta.get('application'):
        return ''
    groups = Counter((component_label(row, c), str(c.get('version') or '—'),
                      str(c.get('reference_floor') or '—'), c['status'], application_check_label(c))
                     for c in meta.get('inspections', []) if (c['component'] == 'CAファイル') == only_ca)
    checks = ''.join('<tr><td>{}</td><td>{}</td><td>{}</td><td><span class="tag {}">{}</span></td><td>{}</td></tr>'.format(
        esc(component), esc(version), esc(floor),
        'state-review' if status == 'UPDATE' else 'state-complete' if status in ('INFERRED_OK', 'STATIC_OK') else 'state-unverified',
        esc(label), count) for (component, version, floor, status, label), count in groups.items())
    version_label = '本体バージョン' if any(verdicts.is_go_toolchain_check(row, c) for c in meta.get('inspections', [])) else '同梱バージョン'
    table = ('<div class="scroll"><table class="component-table"><thead><tr><th>検査内容</th><th>'+version_label+'</th><th>対策版</th><th>結果</th><th>件数</th></tr></thead><tbody>'
             + checks+'</tbody></table></div>') if checks else ''
    version = None if only_ca else meta.get('application_version')
    security = {} if only_ca else meta.get('security_tool', {})
    facts = []
    if security.get('version'): facts.append(('本体バージョン',security['version']))
    if security.get('runtime'): facts.append(('実行環境',security['runtime']+(' '+security['runtime_version'] if security.get('runtime_version') else '')))
    if security.get('go_versions'): facts.append(('組込Go',', '.join(security['go_versions'])))
    wrappers = sorted(set(security.get('wrappers', [])) | set(security.get('configured_wrappers', [])))
    if wrappers: facts.append(('連携候補',', '.join(wrappers)))
    facts_html = ('<dl class="data-list">'+''.join('<dt>'+esc(label)+'</dt><dd>'+esc(value)+'</dd>' for label,value in facts)+'</dl>') if facts else ''
    env = meta.get('python_environment',{}) if not only_ca else {}
    environment_html = ('<p>'+esc(env['scope'])+'</p><ul>'+''.join('<li>'+esc(p['name']+' '+p['version']+
        (' / 参考対策版 '+str(p['reference_floor'])+' / '+p.get('detail','') if p.get('reference_floor') else ''))+'</li>'
        for p in env.get('packages',[]))+'</ul>') if env else ''
    scopes = list(dict.fromkeys(c['scope'] for c in meta.get('inspections',[]) if c.get('component_only') and c.get('scope')))
    return ('<p>導入バージョン: '+esc(str(version))+'</p>' if version else '') + facts_html + table + environment_html + ''.join('<p>'+esc(s)+'</p>' for s in scopes)


def application_diagnostics(row):
    """Discovery limits and paths belong to the collapsed inspection data."""
    meta = row.get('metadata', {})
    lines = application_lines(row) if meta.get('application_scan') else meta.get('uninspected', []) if meta.get('application') else []
    return '<ul>'+''.join('<li>'+html.escape(line)+'</li>' for line in lines)+'</ul>' if lines else ''


def record_name(row):
    # Keep the complete collector name and installation path in inspection data.
    name = re.sub(r' \[(?:/|[A-Za-z]:[\\/])[^\]]*\]', '', row['name'])
    executable = row.get('metadata', {}).get('executable')
    if isinstance(executable, str) and executable:
        name = name.replace(executable, '').rstrip(' /:')
    return name


def source_link(row):
    source = row['metadata'].get('source', '')
    if isinstance(source, str) and source.startswith('https://'):
        return '<a href="{}" target="_blank" rel="noopener noreferrer">配布元の対応情報 ↗</a>'.format(html.escape(source, quote=True))
    return ''


def result_label(row, labels):
    """Summarize observed failures without changing the underlying verdict."""
    status = row['status']
    basis = row.get('metadata', {}).get('version_basis')
    if status == 'UPDATE' and row.get('metadata', {}).get('product_release_evidence'):
        return '公式対策版未満・更新対象'
    if status == 'MANUAL' and row['metadata'].get('release_condition'):
        return row['metadata']['release_condition']
    if status == 'INFERRED_OK' and basis == 'published-dependencies': return '公開依存関係は対策版'
    if status == 'INFERRED_OK' and basis == 'official-release': return '公式の対策版'
    if row.get('metadata', {}).get('runtime_component') == 'node':
        if status == 'INFERRED_OK': return '使用するNode.jsは対策版'
        if status == 'UPDATE': return '使用するNode.jsが対策版未満'
    if status == 'INFERRED_OK' and row.get('metadata', {}).get('verified_components'):
        components = row['metadata']['verified_components']
        label = COMPONENT_LABELS.get(components[0], '同梱'+components[0]) if len(components) == 1 else '照合した同梱部品'
        return label+'は対策版'
    if row.get('metadata', {}).get('application') and status == 'UPDATE':
        if any(verdicts.is_go_toolchain_check(row, c) and below_fixed_version(c) for c in row['metadata'].get('inspections', [])):
            return 'Go本体が対策版未満'
        components = {c['component'] for c in row['metadata'].get('inspections', []) if below_fixed_version(c)}
        if components:
            component = next(iter(components)) if len(components) == 1 else None
            return (COMPONENT_LABELS.get(component, component) if component else '同梱ソフトウェア')+'が対策版未満'
        return '同梱ソフトウェアの対応を確認'
    if status == 'UPDATE' and row['review_state'] == 'review':
        return '配布元の対応を確認'
    if status == 'ACTION' and row['assessment_method'] in ('measured', 'corroborated'):
        return '問題の証明書に接続できた'
    if status == 'CHECKED' and row.get('metadata', {}).get('probe') == 'synthetic_osv_query':
        return '合成データの照会結果を確認'
    if status == 'UNKNOWN':
        if presentation.certificate_retry_timeouts(row):
            return '証明書エラー後の再試行でタイムアウト・検査未完了'
        evidence = row['detail'] + ' ' + ' '.join(sample['detail'] for sample in row['samples'])
        if 'Bad CPU type in executable' in evidence:
            return '起動できない（CPU形式）'
        if '読み取れません' in evidence:
            return '検査データを読めない'
        if row.get('metadata', {}).get('diagnostic_observation') == 'connection_error':
            return '診断用の通信で接続エラーを観測'
        if row.get('metadata', {}).get('diagnostic_observation') == 'response':
            return '診断用の通信応答を観測'
    if status == 'MANUAL':
        if row['metadata'].get('probe') == 'safechain_synthetic_tls':
            return ('テスト用の証明書を正しく判定' if row['metadata'].get('synthetic_tls_state') == 'measured'
                    else 'このPC内の接続を確認できない')
        if row['metadata'].get('tool_id') == 'safe-chain':
            return '外部通信は未確認'
        if row['metadata'].get('application'):
            return 'このツールの通信は未確認'
        if row['metadata'].get('version') == '':
            return 'バージョンを取得できない'
        if '実通信' in row['detail'] and '未取得' in row['detail']:
            return '接続テストが未実施'
    return labels.get(status, status)


def status_tag(row, labels):
    return '<span class="tag state-{}">{}</span>'.format(row['review_state'], html.escape(result_label(row, labels)))


def version_details(row):
    meta = row.get('metadata', {})
    runtime = meta.get('runtime_component') == 'node'
    if meta.get('release_condition') and not meta.get('version_basis'):
        return '<p>'+html.escape(row['detail'])+'</p>'
    if meta.get('version_basis'):
        esc = html.escape
        rows = meta.get('published_dependencies') or [dict(component=meta.get('tool_name',meta.get('tool_id','本体')),
                        version=meta.get('assessed_version',meta.get('version','')),reference_floor=meta.get('reference_floor') or '—')]
        table = ''.join('<tr><td>'+esc(r['component'])+'</td><td>'+esc(r['version'])+'</td><td>'+esc(r['reference_floor'])+'</td></tr>' for r in rows)
        return '<div class="scroll"><table><thead><tr><th>照合対象</th><th>バージョン</th><th>対策版</th></tr></thead><tbody>'+table+'</tbody></table></div><p>'+esc(row['scope'])+'</p>'
    if not runtime:
        return ''
    esc = html.escape
    return ('<div class="scroll"><table><thead><tr><th>通信部品</th><th>使用バージョン</th><th>対策版</th>'
            '</tr></thead><tbody><tr><td>Node.js</td><td>'+esc(meta.get('runtime_version') or '取得できない')+
            '</td><td>'+esc(meta.get('reference_floor') or '系列を確認できない')+'</td></tr></tbody></table></div>')


def record_action(row):
    esc = html.escape
    remedy = remediation.plan(row)
    if remedy:
        reference = '<p class="version-data">'+esc(remedy['reference'])+'</p>' if remedy['reference'] and not row['metadata'].get('application') else ''
        return '<div class="next-action"><h4>'+esc(remedy['title'])+'</h4>'+reference+'<ol>'+''.join('<li>'+esc(step)+'</li>' for step in remedy['steps'])+'</ol></div>'
    if row['requires_attention']:
        return '<div class="next-action"><p>'+esc(row['action'])+'</p></div>'
    return ''


def record_data(row, labels):
    """One evidence panel, without nested disclosures; retain each original observation."""
    esc = html.escape
    fact = row['metadata'].get('research', {})
    research = ('<h5>公式の対策版・判定基準</h5><p>'+esc(fact['fixed_version'])+'</p><p>'+esc(fact['notes'])+'</p>'+
                ''.join('<p><a href="'+esc(url,quote=True)+'" target="_blank" rel="noopener noreferrer">'+esc(url)+'</a></p>'
                        for url in fact.get('sources',[]) if url.startswith('https://'))) if fact else ''
    if fact.get('variants'):
        research += '<div class="scroll"><table><thead><tr><th>配布元</th><th>確認済みビルド</th><th>適用条件</th></tr></thead><tbody>'+''.join(
            '<tr><td>'+esc(v['vendor'])+'</td><td>'+esc(v['versions'])+'</td><td>'+esc(v['meaning'])+'</td></tr>' for v in fact['variants'])+'</tbody></table></div>'
    samples = ''.join('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
        esc(s['target']), esc('問題の証明書に接続できた' if s['status'] == 'ACTION' else labels.get(s['status'], s['status'])),
        esc(s['detail'])) for s in row['samples'])
    table = ('<div class="scroll"><table><thead><tr><th>接続先</th><th>結果</th><th>観測内容</th>'
             '</tr></thead><tbody>' + samples + '</tbody></table></div>') if samples else ''
    checks = row['metadata'].get('inspections', [])
    component_files = ('<h5>同梱部品の検査ファイル</h5><div class="scroll"><table><thead><tr><th>部品</th><th>バージョン</th><th>結果</th><th>ファイル・観測内容</th></tr></thead><tbody>' + ''.join(
        '<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code><p>{}</p></td></tr>'.format(
            esc(COMPONENT_LABELS.get(c['component'], c['component'])), esc(str(c.get('version', '—'))),
            esc(application_check_label(c)), esc(str(c.get('path', ''))), esc(c.get('detail', '')))
        for c in checks) + '</tbody></table></div>') if checks else ''
    remedy = remediation.plan(row)
    target = '<dt>対象の場所</dt><dd><code>'+esc(remedy['target'])+'</code></dd>' if remedy and remedy['target'] else ''
    return ('<p>'+esc(row['detail'])+'</p>'+application_details(row, only_ca=True)+application_diagnostics(row)+table+component_files+
            '<dl class="data-list"><dt>検査対象</dt><dd>'+esc(row['name'])+'</dd>'+target+
            '<dt>検査方法</dt><dd>'+esc(verdicts.METHOD_LABELS[row['assessment_method']])+'</dd><dt>検査範囲</dt><dd>'+esc(row['scope'])+'</dd></dl>'+source_link(row)+
            research+'<h5>設定・パス（JSON）</h5><pre>'+esc(json.dumps(row['metadata'], ensure_ascii=False, indent=2))+'</pre>')


def record_section(row, index, body):
    return '<section class="{}" data-review="{}" data-method="{}" id="item-{}">{}</section>'.format(
        row['status'], row['review_state'], row['assessment_method'], index, body)


def render_card(row, index, labels, inline=False):
    name = '<span class="record-name">記録'+str(index+1)+'：'+html.escape(record_name(row))+'</span>'
    finding = application_details(row)+version_details(row)+record_action(row)
    if inline:
        return record_section(row, index, '<div class="result-row">'+name+status_tag(row, labels)+'</div>'+finding)
    return record_section(row, index, '<details class="result-record"><summary class="result-row">'+name+status_tag(row, labels)+
        '</summary><div class="record-details">'+finding+'<details class="inspection-data"><summary>検査データ</summary>'+record_data(row, labels)+'</details></div></details>')


def installation_path(unit):
    for field in ('prefix', 'java_home', 'path', 'executable'):
        for _, row in unit['rows']:
            value = row.get('metadata', {}).get(field)
            if value:
                return str(value).replace(chr(92), '/')
    return ''


def installation_name(unit):
    rows = unit['rows']
    path = installation_path(unit)
    normalized = path.lower()
    # Labels describe recorded locations only, never resolve a shim on the current PC.
    kind = ('Xcode' if '/xcode.app/' in normalized else
            'Command Line Tools' if '/commandlinetools/' in normalized else
            'uv' if '/uv/python/' in normalized else
            'pyenv shim' if '/.pyenv/shims/' in normalized else
            'pyenv' if '/.pyenv/versions/' in normalized else
            'mise' if '/mise/' in normalized or normalized.endswith('/bin/mise') else
            'nvm' if '/.nvm/' in normalized else
            'Volta' if '/.volta/' in normalized else
            'npm' if '/node_modules/' in normalized else
            'Homebrew (Intel)' if normalized.startswith(('/usr/local/cellar/', '/usr/local/opt/')) else
            'Homebrew' if '/cellar/' in normalized or normalized.startswith('/opt/homebrew/') else
            'Conda' if any(x in normalized for x in ('/miniconda', '/anaconda', '/miniforge', '/mambaforge')) else
            'アプリ' if '.app/' in normalized or normalized.endswith('.app') else
            'OS標準' if normalized.startswith(('/usr/bin/', '/system/')) else '環境')
    if '/JavaVirtualMachines/' in path:
        kind = path.split('/JavaVirtualMachines/', 1)[1].split('/', 1)[0]
    python_version = next((str(m.get('python_version') or (m.get('version') if 'packages' in m else ''))
                           for _, row in rows for m in (row.get('metadata', {}),)
                           if m.get('python_version') or (m.get('tool_id') == 'python' and 'packages' in m and m.get('version'))), '')
    version = next((str(m.get('version')) for _, row in rows for m in (row.get('metadata', {}),)
                    if row['name'].endswith(' / バージョン') and m.get('version')), '')
    if python_version:
        version = 'Python '+python_version
    java_version = next((str(m['version']) for _, row in rows for m in (row.get('metadata', {}),)
                         if m.get('tool_id') == 'java' and m.get('version')), '')
    if java_version:
        version = 'Java '+java_version
    if not version:
        version = next((str(m.get('application_version') or m.get('security_tool', {}).get('version'))
                        for _, row in rows for m in (row.get('metadata', {}),)
                        if m.get('application_version') or m.get('security_tool', {}).get('version')), '')
    if not version:
        # Runtime version observations may use legacy collector names.
        version = next((str(m['version']) for _, row in rows for m in (row.get('metadata', {}),)
                        if row['assessment_method'] == 'version' and m.get('version') and
                        not m.get('application') and not any(x in row['name'] for x in ('pip', 'certifi', 'Cargo.lock'))), '')
    if kind == '環境' and path:
        leaf = path.rstrip('/').rsplit('/', 1)[-1]
        kind = leaf if leaf not in ('bin', 'python', 'python3', 'node', 'java') else '環境'
    context = next((str(row['metadata']['execution_context']) for _, row in rows
                    if row.get('metadata', {}).get('execution_context') not in (None, '', 'ホスト')), '')
    location = ' · …/'+'/'.join(path.rstrip('/').split('/')[-3:]) if path and not version else ''
    return (context+' / ' if context else '')+kind+(' / '+version if version else location)


def installation_names(units):
    names = [installation_name(u) if u['installation'] else '' for u in units]
    original = names[:]
    counts = Counter(names)
    for i, unit in enumerate(units):
        if unit['installation'] and counts[names[i]] > 1:
            paths = [installation_path(other).split('/') for other, name in zip(units, original) if name == names[i]]
            parts = installation_path(unit).split('/')
            # The shortest distinguishing suffix is visible; the full path stays in evidence.
            width = next((n for n in range(1, min(4, len(parts))+1) if sum(p[-n:] == parts[-n:] for p in paths) == 1), 3)
            names[i] += ' · …/'+'/'.join(parts[-width:])
    return names


def render_installation(unit, number, labels, name=None):
    rows = unit['rows']
    substantive = [(i, row) for i, row in rows if row['review_state'] in ('action', 'review', 'complete')]
    technical = [(i, row) for i, row in rows if (i, row) not in substantive]
    main = next(row for _, row in rows if row['review_state'] == unit['state'])
    if unit['state'] == 'unverified':
        failures = [row for _, row in rows if row['status'] == 'UNKNOWN']
        main = next((row for row in failures if result_label(row, labels) == '起動できない（CPU形式）'),
                    failures[0] if failures else main)
    findings = ''.join(render_card(row, index, labels, inline=True) for index, row in substantive)
    # Independent unverified checks stay visible, while inventory-only notes live in evidence.
    pending = [(i, row) for i, row in technical if row['review_state'] == 'unverified' and row['assessment_method'] != 'inventory'
               and not (substantive and not row.get('samples') and
                        (row['metadata'].get('p2_coverage') or row['metadata'].get('application') or row['assessment_method'] == 'unmeasured'))]
    findings += ''.join('<div class="pending-check"><span>'+html.escape(record_name(row))+'</span>'+status_tag(row, labels)+'</div>' for _, row in pending)
    evidence = ''
    for index, row in substantive+technical:
        body = '<h4>記録'+str(index+1)+'：'+html.escape(record_name(row))+'</h4>'+status_tag(row, labels)+record_data(row, labels)
        evidence += ('<div class="evidence-record">'+body+'</div>' if (index, row) in substantive else record_section(row, index, body))
    return ('<div class="installation-result" data-state="{state}"><details class="result-record"><summary class="result-row">'
            '<span class="record-name">{name}</span>{tag}</summary><div class="record-details">{findings}'
            '<details class="inspection-data"><summary>検査データ</summary>{evidence}</details></div></details></div>').format(
                state=unit['state'], name=html.escape(name or installation_name(unit)), tag=status_tag(main, labels), findings=findings, evidence=evidence)


def render_tool(tool, labels):
    actions = list(dict.fromkeys(plan['title'] for _, row in tool['rows']
                                if row['review_state'] in ('action', 'review')
                                for plan in [remediation.plan(row)] if plan))
    action = '<span class="tool-action">'+html.escape(' / '.join(actions[:2])+(' ほか{}件'.format(len(actions)-2) if len(actions)>2 else ''))+'</span>' if actions else ''
    return '''<article data-tool="{name}" data-state="{state}" data-states="{filters}">
<details class="tool-record"><summary class="tool-row"><span class="tool-heading"><span class="tool-name">{name}</span>{action}</span><span class="tool-statuses">{badges}</span></summary>
<div class="tool-checks"><h3>環境・検査対象 <span>{count}件</span></h3>{checks}</div></details></article>'''.format(
        name=html.escape(tool['name'], quote=True), state=tool['state'], filters=' '.join(tool['filters']),
        badges=tool_badges(tool), count=len(tool['units']), action=action,
        checks=''.join(render_installation(unit, number, labels, name) if unit['installation'] else
                       render_card(unit['rows'][0][1], unit['rows'][0][0], labels)
                       for number, (unit, name) in enumerate(zip(tool['units'], installation_names(tool['units'])), 1)))


def render_groups(tools, labels):
    groups = []
    for key, title in RESULT_GROUPS:
        members = [tool for tool in tools if tool['state'] == key]
        if not members:
            continue
        groups.append('<div class="result-group" data-result-group="{}" aria-labelledby="group-{}">'
                      '<h2 id="group-{}">{} <span>{}</span></h2><div class="result-list">{}</div></div>'.format(
                          key, key, key, title, str(len(members)) + 'ツール',
                          ''.join(render_tool(tool, labels) for tool in members)))
    return ''.join(groups)


def observation_notice(source):
    text = '取得済み記録の再判定。元の記録日時: '+str(source.get('generated_at','不明'))+'。'
    if source.get('new_network_requests') is False:
        text += '新規の通信検査は実施していません。'
    return text


def action_badges(value):
    return ''.join('<span class="action-badge action-{}">{}</span>'.format(key, html.escape(presentation.LABELS[key]))
                   for key in value['actions'])


def axis_summary(value):
    version = list(dict.fromkeys(x['label'] for x in value['version']))
    communication = list(dict.fromkeys(x['label'] for x in value['communication']))
    def short(items):
        return ' / '.join(items[:2])+(' ほか'+str(len(items)-2)+'種類' if len(items)>2 else '')
    return '<span class="axis-summary"><span>版：'+html.escape(short(version))+'</span><span>通信：'+html.escape(short(communication))+'</span></span>'


def render_axes(value):
    esc = html.escape
    sections = []
    for axis, title in (('version', '版の判定'), ('communication', '通信の検証'), ('configuration', '設定・保存データ')):
        if not value[axis]:
            continue
        entries = []
        for entry in value[axis]:
            details = ''
            if axis == 'version':
                version, floor = entry.get('version'), entry.get('reference_floor')
                details = '<p class="axis-version">'+esc(str(entry.get('component', '本体')))+'：'+esc(str(version or '未取得'))
                if floor:
                    kind = '確認済み対策版' if entry.get('conditions', {}).get('known_fixed_versions') else '照合基準'
                    details += ' / '+kind+' '+esc(str(floor))
                details += '</p>'
                source = entry.get('source')
                if isinstance(source, str) and source.startswith('https://'):
                    details += '<a href="'+esc(source, quote=True)+'" target="_blank" rel="noopener noreferrer">出典・適用条件 ↗</a>'
            else:
                details = '<p>'+esc(entry['reason'])+'</p>'
            refs = ' '.join('<a href="#item-{0}" onclick="revealRecord(\'item-{0}\')">記録{1}</a>'.format(i, i+1) for i in entry['record_indices'])
            entries.append('<div class="axis-finding"><strong>'+esc(entry['label'])+'</strong>'+details+
                           '<p class="axis-scope">対象範囲：'+esc(entry['scope'])+'</p><p class="evidence-links">'+refs+'</p></div>')
        sections.append('<section class="assessment-axis" data-axis="'+axis+'"><h4>'+title+'</h4>'+''.join(entries)+'</section>')
    return '<div class="assessment-axes">'+''.join(sections)+'</div>'


def render_action_unit(unit, records, name, labels):
    esc = html.escape
    rows = [(i, records[i]) for i in unit['record_indices']]
    remedies, seen = [], set()
    for _, row in rows:
        remedy = remediation.plan(row)
        if not remedy:
            continue
        key = json.dumps(remedy, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            remedies.append(record_action(row))
    needs = ''.join('<li><p>'+esc(gap['reason'])+'</p><p><strong>次の確認：</strong>'+esc(gap['next_step'])+'</p></li>' for gap in unit['gaps'])
    gaps = '<section class="missing-evidence"><h4>不足情報と次の確認</h4><ul>'+needs+'</ul></section>' if needs else ''
    actions = ''.join('<div class="action-reason action-'+item['code']+'"><h4>'+esc(item['label'])+'</h4><p>'+esc(' / '.join(dict.fromkeys(record_name(records[i]) for i in item['record_indices'])))+'</p><p>'+esc(item['reason'])+
                      '</p><p>'+esc(item['next_step'])+'</p></div>' for item in unit['action_reasons'])
    evidence = ''.join(record_section(row, i, '<h4>記録'+str(i+1)+'：'+esc(record_name(row))+'</h4><p>記録の判定：'+status_tag(row, labels)+
                       '</p>'+record_data(row, labels)) for i, row in rows)
    return ('<div class="installation-result" data-action="'+unit['primary_action']+'"><details class="result-record">'
            '<summary class="result-row"><span class="record-name">'+esc(name)+'</span><span class="tool-statuses">'+action_badges(unit)+
            '</span></summary><div class="record-details">'+actions+render_axes(unit)+''.join(remedies)+gaps+
            '<details class="inspection-data"><summary>検査データ・原記録</summary>'+evidence+'</details></div></details></div>')


def render_action_tool(tool, records, labels):
    grouped = [dict(rows=[(i, records[i]) for i in unit['record_indices']], installation=unit['installation']) for unit in tool['units']]
    names = installation_names(grouped)
    units = ''.join(render_action_unit(unit, records, name or record_name(records[unit['record_indices'][0]]), labels)
                    for unit, name in zip(tool['units'], names))
    return ('<article data-tool="'+html.escape(tool['name'], quote=True)+'" data-state="'+tool['primary_action']+
            '" data-states="'+tool['primary_action']+'" data-actions="'+' '.join(tool['actions'])+'">'
            '<details class="tool-record"><summary class="tool-row"><span class="tool-heading"><span class="tool-name">'+
            html.escape(tool['name'])+'</span>'+axis_summary(tool)+'</span><span class="tool-statuses">'+action_badges(tool)+
            '</span></summary><div class="tool-checks"><h3>導入先・検査対象 <span>'+str(len(tool['units']))+'件</span></h3>'+units+'</div></details></article>')


def render_action_groups(tools, records, labels):
    groups = []
    for key, title in presentation.GROUPS:
        members = [tool for tool in tools if tool['primary_action'] == key]
        if members:
            groups.append('<div class="result-group" data-result-group="'+key+'" aria-labelledby="group-'+key+'">'
                          '<h2 id="group-'+key+'">'+html.escape(title)+'（主分類） <span>'+str(len(members))+'ツール</span></h2>'
                          '<div class="result-list">'+''.join(render_action_tool(t, records, labels) for t in members)+'</div></div>')
    return ''.join(groups)


def render(records, generated, labels, reference_date, source_observation=None):
    records = verdicts.prepare(records)
    model = action_model(records)
    state = action_overview(model)
    tools = model['tools']
    context = [(i, records[i]) for i in model['context_record_indices']]
    esc = html.escape
    target = next((r['detail'] for r in records if r['name'] == '検査対象'), 'このPCの開発環境')
    filters = [('all', 'すべて', len(tools))] + [(key, label, model['action_counts'][key]) for key, label in presentation.GROUPS]
    buttons = ''.join('<button type="button" data-filter="{}" onclick="filterReports(\'{}\')" aria-pressed="{}">{} <span>{}</span></button>'.format(
        key, key, str(key == 'all').lower(), label, str(count) + 'ツール') for key, label, count in filters)
    stylesheet = (ROOT/'ui.css').read_text(encoding='utf-8')
    script = (ROOT/'report-ui.js').read_text(encoding='utf-8')
    return '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>診断結果 — eMudhra 開発環境診断</title><style>''' + stylesheet + '''</style></head><body><main class="results-page">
<header id="current-status" class="report-header">
<div class="section-heading"><h1>診断結果</h1><div class="report-actions"><button type="button" onclick="window.print()">印刷</button></div></div>
<p class="report-summary">''' + esc(state['title']) + '''</p>''' + ('<p class="notice">'+esc(observation_notice(source_observation))+'</p>' if source_observation else '') + '''<p>''' + esc('対象：このPCの開発環境' if target == 'このPCの開発環境' or 'ホストのみ' in target else '対象：'+target) + '''</p>
<p>''' + esc(state['next_step']) + '''</p><p class="counting-note">''' + esc(model['counting_note']) + '''</p>
<p id="filter-counting">行動別フィルター（重複を含む）。下の分類見出しの件数は主分類です。</p>
<div class="filters" aria-label="必要な行動で絞り込み" aria-describedby="filter-counting">''' + buttons + '''</div>
<details class="report-legend"><summary>判定軸・集計の読み方</summary><p>主表示は次の行動です。更新と設定修正が必要な場合は両方を表示します。問題の証明書を受け入れた実測結果は、独立した対応理由として表示します。</p>
<p>版：本体か同梱部品か、対応基準・出典・適用範囲を表示します。部品の対策版未満は、アプリの更新先や独自修正を配布元へ確認する場合があります。</p>
<p>通信：未実施、実行失敗、拒否確認、問題検出を区別します。通常接続の成功やローカル合成テストだけでは、eMudhraの問題の証明書を拒否したことになりません。</p>
<p>「検査した範囲で問題なし」は記載した導入先・接続先・設定に限ります。未確認事項のある対象、未導入、環境情報、対象外をこの分類に含めません。</p></details>
<details><summary>検査情報・主分類の内訳</summary><dl class="data-list"><dt>対象</dt><dd>''' + esc(target) + '''</dd><dt>結果生成日時</dt><dd>''' + esc(generated) + '''</dd><dt>観測日時</dt><dd>''' + esc(str(source_observation.get('generated_at', '不明')) if source_observation else generated) + '''</dd></dl>
<ul>''' + ''.join('<li>' + esc(fact) + '</li>' for fact in state['facts']) + '''</ul><p>照合基準日: ''' + esc(reference_date) + '''</p>''' + ''.join(render_card(row, index, labels) for index, row in context) + '''</details>
</header>
<div class="search-row"><label class="search" for="record-search">検索<input type="search" id="record-search" aria-label="ツール・検査結果を検索" oninput="filterReports(activeFilter)"></label>
<p id="result-count" role="status" aria-live="polite">''' + str(len(tools)) + '''ツールを表示</p></div>
<p id="empty-results" class="panel"''' + (' hidden' if tools else '') + '>' + ('該当するツールがありません。' if tools else '検査結果がありません') + '''</p>
<div id="records">''' + render_action_groups(tools, records, labels) + '''</div>
<footer class="report-files"><a href="summary.txt" download>テキストを保存</a><a href="report.json" download>検査データを保存（JSON）</a></footer>
</main><script>''' + script + '''</script></body></html>'''
