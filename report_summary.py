"""Prioritized, installation-scoped navigation over saved report evidence."""
import re

GROUPS = (
    ('action', '対応が必要', True),
    ('review', '対応方法を確認', True),
    ('conditional', '利用している場合に確認', True),
    ('unknown', '未確認の対象', False),
    ('done', '追加更新なし・確認済み', False),
    ('scope', '未検出・対象外・環境情報', False),
)
COMPONENTS = {'本体':'本体', 'electron':'同梱Electron', 'go':'同梱Go', 'node':'使用するNode.js',
              'certifi':'certifi', 'nss':'NSS', 'ensurepip同梱pip（新規venv用）':'ensurepipのpip'}


def version_text(value):
    text = str(value or '').strip()
    return re.sub(r'^(?:Bundler version |Homebrew |ruby |Python |v(?=\d))', '', text)[:100]


def versions(unit, records):
    values = []
    assessments = {}
    attention = {}
    for i in unit['record_indices']:
        meta = records[i].get('metadata', {})
        if meta.get('python_version'):
            values.append(('本体', version_text(meta['python_version'])))
    for fact in unit['version']:
        if fact.get('version'):
            key = (COMPONENTS.get(fact.get('component'), fact.get('component', '本体')), version_text(fact['version']))
            values.append(key)
            state = fact['state']
            label = ('基準未満'+('（'+version_text(fact['reference_floor'])+'）' if fact.get('reference_floor') else '')
                     if state in ('below_fixed', 'component_below_fixed') else
                     'バージョン基準を満たす' if state in ('fixed', 'component_fixed') else
                     '取得のみ・対応状況は未照合' if state == 'observed' else '対応状況が未確認')
            assessments.setdefault(key, []).append(label)
            emphasis = ('update' if state in ('below_fixed', 'update_required') else
                        'review' if state in ('component_below_fixed', 'component_update_review') else '')
            if emphasis and attention.get(key) != 'update':
                attention[key] = emphasis
    for i in unit['record_indices']:
        meta = records[i].get('metadata', {})
        if meta.get('tool_id') == 'homebrew' and meta.get('package_query_succeeded') is True:
            values.extend(('CAパッケージ', version_text(v)) for v in meta.get('packages', {}).get('ca-certificates', []))
    return [dict(component=c, version=v, assessment=' / '.join(dict.fromkeys(assessments.get((c, v), []))),
                 attention=attention.get((c, v), '')) for c, v in dict.fromkeys(values)]


def unit_priority(unit, tasks):
    if any(e['state'] == 'problem' for axis in ('communication', 'configuration') for e in unit[axis]):
        return 0
    if any(v['state'] in ('below_fixed', 'update_required') for v in unit['version']) or any(a['code'] in ('update', 'action_required') for a in unit['action_reasons']):
        return 1
    if any(v['state'] in ('component_below_fixed', 'component_update_review') for v in unit['version']):
        return 2
    if any(t['classification'] in ('conditional', 'required') for t in tasks):
        return 3
    if unit['primary_action'] in ('not_found', 'not_applicable', 'info'):
        return 6
    if unit.get('version_complete') or unit['primary_action'] in ('complete', 'checked', 'scoped_complete'):
        return 5
    if (unit['primary_action'] == 'investigate' and
            (unit.get('completed_versions') or unit.get('confirmed_communications')) and
            any(g.get('blocks_completion', True) for g in unit['gaps'])):
        return 4
    if tasks and all(t['classification'] == 'unneeded' for t in tasks):
        return 5
    return 4


def unknown_concern(tool, records):
    """Choose a specific observed gap, without inventing a security failure."""
    rows = [records[i] for i in tool['record_indices']]
    if any(r.get('metadata', {}).get('registry_assessment', {}).get('pending') for r in rows):
        return dict(title='内部registryかを判断する接続先情報が不足しています',
                    next_step='この表示だけを理由に設定を削除する必要はありません。ローカルDocker Desktopだと追加確認済みなら、その結果を下のAIプロンプトへ追記できます。',
                    evidence='Secure=falseの観測あり・接続先の判断は保留')
    failure = [r for r in rows if r['status'] == 'UNKNOWN']
    logs = ' '.join(str(r.get('detail', ''))+' '+' '.join(str(s.get('detail', '')) for s in r.get('samples', [])) for r in failure)
    if 'Bad CPU type' in logs or 'Exec format error' in logs:
        return dict(title='実行ファイルのCPU形式が合わず、起動できませんでした',
                    next_step='使うツールなら、OS・CPUに合う配布物を導入元で確認してください。更新済みでも起動形式の問題は残ります。', evidence='起動エラーを記録')
    if 'TIMEOUT' in logs or 'タイムアウト' in logs:
        return dict(title='接続テストがタイムアウトしました',
                    next_step='普段の操作でも接続エラーが出る場合は、操作内容とエラーを下のAIプロンプトへ追記してください。通常利用に問題がなければ、先に「対応が必要」の対象を進めてください。', evidence='通信検査が未完了')
    if any(c['state'] == 'indeterminate' for c in tool['communication']):
        return dict(title='通信テストを完了できませんでした',
                    next_step='使うツールなら、普段の操作で出るエラーと操作内容を下のAIプロンプトへ追記してください。', evidence='通信検査が未完了')
    if any(v['state'] in ('custom_unknown', 'component_below_fixed', 'component_update_review') for v in tool['version']):
        return dict(title='配布元の修正内容を確認する必要があります',
                    next_step='利用している導入方法とアプリのバージョンを下のAIプロンプトへ追記し、配布元の対応情報を確認してください。', evidence='配布条件・同梱部品の照合待ち')
    if any(v['state'] in ('missing', 'unknown', 'not_assessed') for v in tool['version']):
        return dict(title='本体の対応バージョンを照合する情報が不足しています',
                    next_step='使っている場合は、バージョンと導入方法を下のAIプロンプトへ追記し、その導入先の対応情報を確認してください。', evidence='バージョン・適用条件が未確認')
    return dict(title='普段使う接続先での通信は未検査です',
                next_step='普段の操作で証明書エラーが出る場合は、操作内容とエラーを下のAIプロンプトへ追記してください。', evidence='通常利用の通信は対象外')


def build(tool, records):
    rows = []
    for number, unit in enumerate(tool['units']):
        related = [t for t in tool['work']['tasks'] if set(t['record_indices']) & set(unit['record_indices'])]
        priority = unit_priority(unit, related)
        updates = {(v.get('component'), str(v.get('version')), str(v.get('reference_floor')))
                   for v in unit['version'] if v['state'] in ('below_fixed', 'update_required', 'component_below_fixed', 'component_update_review')}
        installed = unit['installation'] and unit['primary_action'] not in ('not_found', 'not_applicable')
        status = ('接続・設定の問題を検出' if priority == 0 else '更新が必要' if priority == 1 else
                  '同梱部品の対応を確認' if priority == 2 else '利用条件に応じて確認' if priority == 3 else
                  '対応状況が未確認' if priority == 4 else '照合した対象の追加更新なし' if priority == 5 else unit['primary_label'])
        if priority == 5 and unit['primary_action'] == 'scoped_complete':
            status = '確認した範囲は対応不要 / 別の範囲は未評価'
        elif priority == 5 and unit['primary_action'] == 'checked':
            status = '検査した通信経路は対応不要'
        if priority == 5 and unit['primary_action'] != 'scoped_complete' and any(c['state'] == 'indeterminate' for c in unit['communication']):
            status += ' / 通信検査は未完了'
        elif priority == 5 and unit['primary_action'] != 'scoped_complete' and any(c['state'] == 'not_run' for c in unit['communication']):
            status += ' / 未検査の通信あり'
        rows.append(dict(unit_index=number, installed=bool(installed), priority=priority, status=status,
                         versions=versions(unit, records), update_items=len(updates), record_indices=unit['record_indices']))
    priority = min((r['priority'] for r in rows), default=6)
    group = ('action' if priority < 2 else 'review' if priority == 2 else 'conditional' if priority == 3 else
             'unknown' if priority == 4 else 'done' if priority == 5 else 'scope')
    counts = dict(installations=sum(r['installed'] for r in rows),
                  affected_installations=sum(r['installed'] and r['priority'] < 2 for r in rows),
                  affected_checks=sum(not r['installed'] and r['priority'] < 2 for r in rows),
                  review_installations=sum(r['installed'] and r['priority'] in (2, 3) for r in rows),
                  unknown_installations=sum(r['installed'] and r['priority'] == 4 for r in rows),
                  update_items=sum(r['update_items'] for r in rows),
                  unlocated_checks=sum(not r['installed'] for r in rows))
    candidates = [t for t in tool['work']['tasks'] if t['classification'] in ('required', 'conditional')]
    candidates.sort(key=lambda t: (min((r['priority'] for r in rows if set(t['record_indices']) & set(r['record_indices'])), default=6), t['title']))
    if candidates:
        t = candidates[0]
        preferred = [s for s in t['steps'] if re.search('開き|入力|確認し|移行し|更新し|表示し|取り除|修正し', s['text'])]
        first = (preferred or t['steps'] or [dict(text=t.get('condition', ''))])[0]
        concern = dict(title=t['title'], next_step=first['text'], command=first.get('command'),
                       evidence=('接続・設定の問題を検出' if priority == 0 else
                                 ('対策バージョン未満' if any(v['state'] == 'below_fixed' for v in tool['version']) else '更新・対応の記録あり') if priority == 1 else
                                 '同梱部品の照合結果' if priority == 2 else '利用状況に応じた操作'))
    elif priority == 4:
        concern = unknown_concern(tool, records)
    elif priority == 5:
        concern = dict(title='確認した範囲への追加対応は不要です', next_step='確認済みの部品・通信経路を下に示しています。別の未評価の範囲は詳細に残しています。', evidence='記録の対象範囲で確認済み')
    else:
        concern = dict(title=tool['primary_label'], next_step='探索範囲と記録は詳細にあります。', evidence='探索結果・環境情報')
    body_versions = list(dict.fromkeys(v['version'] for r in rows for v in r['versions'] if v['component'] == '本体'))
    return dict(group=group, priority=priority, counts=counts, concern=concern,
                versions=body_versions, rows=sorted(rows, key=lambda r: (r['priority'], r['unit_index'])))
