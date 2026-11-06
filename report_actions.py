"""Operation guidance derived from saved evidence; never collects or changes it.

Work classification is separate from the canonical security verdict. In
particular, an unknown result does not establish a mandatory repair.
"""
import copy
import re
import shlex

import remediation

CLASS_LABELS = dict(required='必須', conditional='条件付き', unneeded='不要', unassigned='—（未決定）')
CERTAINTY_LABELS = dict(established='確定', provisional='暫定', deferred='判定保留')
KIND_LABELS = dict(local_read='ローカルの読み取り', network='通信による確認', change='更新・設定変更', review='手順・根拠の確認')


def step(text, kind='review', command=None):
    value = dict(text=text, kind=kind)
    if command:
        value['command'] = command
    return value


def task(title, indices, target='', classification='unassigned', certainty='deferred', **extra):
    return dict(title=title, record_indices=sorted(set(indices)), target=target,
                classification=classification, certainty=certainty, steps=[],
                correction_priority='保留：変更の必要性をまだ判断できません。',
                confirmation_priority='利用・影響範囲が分かってから判断します。', **extra)


def personal_text(text):
    """Keep legacy advice in evidence; active guidance is for the reader."""
    return (text.replace('IT担当', 'AI').replace('管理元へ確認', '導入元の情報で確認')
            .replace('管理元に、', 'AIへの質問用プロンプトに、')
            .replace('更新を依頼します', '具体的な更新方法を質問します')
            .replace('管理している人に、', 'AIへの質問用プロンプトに、')
            .replace('切り替えるよう依頼してください', '切り替える方法を質問してください'))


def target_of(rows):
    return next((str(row.get('metadata', {}).get(k)) for row in rows
                 for k in ('executable', 'prefix', 'java_home', 'path') if row.get('metadata', {}).get(k)), '')


def _has_problem(unit):
    return any(x['state'] == 'problem' for axis in ('communication', 'configuration') for x in unit[axis])


def _has_version_work(unit):
    return (any(a['code'] in ('update', 'action_required') for a in unit['action_reasons']) or
            any(v['state'] in ('below_fixed', 'update_required', 'component_below_fixed', 'component_update_review') for v in unit['version']))


def unit_work(unit, records, tool_name):
    indices = unit['record_indices']
    rows = [records[i] for i in indices]
    target = target_of(rows)
    tasks, details, notes = [], [], []
    ids = {r.get('metadata', {}).get('tool_id') for r in rows}
    system_ruby = [i for i in indices if records[i].get('metadata', {}).get('tool_id') in ('bundler', 'rubygems')
                   and (str(records[i]['metadata'].get('runtime_executable', '')).startswith('/System/Library/Frameworks/Ruby.framework/')
                        or records[i]['metadata'].get('runtime_executable') == '/usr/bin/ruby')]
    if system_ruby and not _has_version_work(unit) and any(x['state'] == 'problem' for x in unit['communication']) and not any(x['state'] == 'problem' for x in unit['configuration']):
        current = task('macOSの更新があれば適用する', system_ruby, target, 'conditional', 'provisional')
        current.update(condition='ソフトウェアアップデートに更新が表示される場合。すでに確認済みなら繰り返す必要はありません。',
                       fact='macOS付属Rubyを起動する経路で、問題の証明書を受け入れた記録があります。',
                       correction_priority='この経路を使う前に対応。macOS更新だけで解消するかは未確認です。',
                       confirmation_priority='この経路を使う作業・アプリがある場合は、更新後の問題解消を確認します。',
                       completion='更新の完了と、この接続問題の解消は別です。解消は同じ実行経路の検証で確認します。')
        current['steps'] = [step('「システム設定 → 一般 → ソフトウェアアップデート」を開きます。更新確認はAppleへの通信を伴います。', 'network'),
                            step('更新があれば内容を確認して適用します。更新の確認・取得はAppleへの通信、適用はOSの変更と再起動を伴います。', 'change')]
        tasks.append(current)
        command = 'type -a ruby '+('bundle' if 'bundler' in ids else 'gem')
        details = [step('bundle / gemを自分で使う場合、または利用するアプリがこのmacOS付属Rubyを使うと分かっている場合だけ、以下を確認します。'),
                   step('普段使うターミナルで起動候補を表示します。先頭が /usr/bin のRuby・コマンドか確認します。この結果からアプリ内部のRubyまでは分かりません。', 'local_read', command),
                   step('macOSに更新がない、または同じ経路で問題が残る場合は、対象と起動先Rubyの情報を個別プロンプトに追記し、使うアプリ・プロジェクトに合う切り替え方法を質問してください。OS付属Rubyを直接書き換えないでください。')]
        notes.append('検出した接続問題は解消未確認です。利用状況はこの診断では取得していません。')
    elif 'homebrew' in ids and not _has_problem(unit) and not _has_version_work(unit):
        package_rows = [i for i in indices if records[i].get('metadata', {}).get('tool_id') == 'homebrew'
                        and records[i]['metadata'].get('package_query_succeeded') is True
                        and records[i]['metadata'].get('executable')]
        # Exact known package release only. Do not order arbitrary vendor or
        # future versions, or borrow another brew installation's package query.
        fixed = package_rows if package_rows and all(records[i]['metadata'].get('packages', {}).get('ca-certificates') == ['2026-10-20'] for i in package_rows) else []
        if fixed:
            current = task('確認済みのCAパッケージを再更新する必要はありません', fixed, target, 'unneeded', 'established')
            current.update(fact='この導入先でca-certificates 2026-10-20を取得しました。保存済みの公式調査で確認した対策バージョンです。',
                           correction_priority='このCAパッケージの更新は不要です。', confirmation_priority='実際に使用したCAと通信の結果は別に扱います。',
                           completion='取得したCAパッケージのバージョンに限る完了。Homebrew全体の通信検証ではありません。')
        else:
            current = task('このHomebrewを使う場合だけ、CAパッケージを調べる', indices, target, 'conditional', 'provisional')
            current.update(condition='この導入先のHomebrewを使う場合。使わない導入先の更新はこの情報だけでは求めません。',
                           fact='この導入先で対策済みCAパッケージが入っているか、保存済みの記録では確定できません。',
                           correction_priority='更新の必要性は、取得したパッケージのバージョンを照合してから判断します。',
                           confirmation_priority='このHomebrewを使う場合は、更新の前に確認します。',
                           completion='同じ導入先のパッケージと対策情報を照合できたら確認完了。通信の成否は別です。')
            # Restrict supplied commands to the recorded standard host installs.
            if target in ('/usr/local/bin/brew', '/usr/local/Homebrew/bin/brew', '/opt/homebrew/bin/brew') and all(r.get('metadata', {}).get('execution_context') in (None, '', 'ホスト') for r in rows):
                current['steps'] = [step('普段のターミナルで使われるHomebrewの場所を表示します。別アプリや別ターミナルの経路までは確認できません。', 'local_read', 'command -v brew'),
                                    step('この導入先にインストールされたCAパッケージのバージョンを表示します。', 'local_read', shlex.quote(target)+' list --versions ca-certificates'),
                                    step('出力を個別プロンプトへ追記します。空欄・エラー・未知のバージョンを「古い」と決めつけず、この導入先に必要な対応を質問してください。')]
        tasks.append(current)
        if not any(records[i]['metadata'].get('effective_ca_verified') is True for i in package_rows):
            notes.append('Homebrewが実際に使ったCAは未確認です。CAパッケージの更新完了とは別です。')
        if not any(c['state'] == 'rejected' for c in unit['communication']):
            notes.append('Homebrewの実通信による拒否は未確認です。CAパッケージの更新完了とは別です。')
    elif tool_name == 'Google Chrome' and target and not _has_problem(unit) and not _has_version_work(unit):
        current = task('通常のChrome更新を済ませる', indices, target, 'conditional', 'provisional')
        current.update(condition='更新・再起動をまだ済ませていない場合。済ませている場合は、この未確認表示だけを理由に手動のCA調査をする必要はありません。',
                       fact='Chrome本体のバージョンと、CRLSetの取得・適用状態は別です。',
                       correction_priority='通常の更新が未完了なら実施します。この記録だけで古いとは断定しません。',
                       confirmation_priority='通常利用で証明書エラーなどがある場合は、その具体的な症状を確認します。',
                       completion='Chromeの更新画面で更新完了と必要な再起動を確認。eMudhra対策の適用確認とは別です。')
        current['steps'] = [step('Chromeのアドレス欄に chrome://settings/help を入力します。更新確認はGoogleへの通信を伴い、更新が自動適用される場合があります。', 'change'),
                            step('画面に更新・再起動が表示されたら案内に従います。', 'change')]
        tasks.append(current)
        if not any(c['state'] == 'rejected' for c in unit['communication']):
            notes.append('このChromeの実通信による拒否は未確認です。通常の更新だけで対策確認済みとは表示しません。')
    else:
        # Separate a proven version completion from independent issues.
        if unit.get('completed_versions'):
            current = task('対策バージョンを確認した対象の追加更新は不要です',
                           [i for v in unit['completed_versions'] for i in v['record_indices']], target, 'unneeded', 'established')
            current.update(fact='照合対象：'+'、'.join(str(v['component'])+' '+str(v['version']) for v in unit['completed_versions']),
                           correction_priority='照合した対象の追加更新は不要です。', confirmation_priority='通信と設定の独立した問題は別の作業です。',
                           completion='記録に示した導入先・部品・配布条件の範囲。ほかの部品や未検証の通信には広げません。')
            tasks.append(current)
        for confirmed in unit.get('confirmed_communications', []):
            logged = confirmed['state'] == 'rejected_before_send'
            current = task('記録した検査先への送信前拒否を確認しました' if logged else
                           '検査した通信経路への追加対応は不要です', confirmed['record_indices'],
                           target, 'unneeded', 'established')
            current.update(fact=confirmed['reason'] if logged else
                           '通常サイトへの接続と、記録した検査先の証明書拒否を確認済みです。',
                           correction_priority='確認済みの範囲への追加修正は不要です。',
                           confirmation_priority='別の導入先・設定・経路は、ここに記載した確認の対象外です。',
                           completion=confirmed['scope'])
            tasks.append(current)
        for version in unit['version']:
            if version['state'] not in ('component_below_fixed', 'component_update_review'):
                continue
            current = task('アプリの対応バージョンを調べる', version['record_indices'], target, 'conditional', 'provisional')
            current.update(condition='このアプリを使う場合。対応バージョンが提供されている場合に更新します。アプリの更新で同梱部品も対策済みになるかを確認します。',
                           fact=str(version.get('component', '同梱部品'))+' '+str(version.get('version') or '未取得')+' / 保存済み照合基準 '+str(version.get('reference_floor') or '未取得')+'。アプリ全体の対応と独自修正は未確認です。',
                           correction_priority='対応するアプリの更新が提供されていれば適用します。部品を直接置き換えません。',
                           confirmation_priority='利用するアプリは、更新の前に配布元の対応情報を確認します。',
                           completion='同じアプリの更新履歴・同梱部品・独自修正の根拠で対応を確認。実通信は別です。')
            current['steps'] = [step('アプリの更新画面・公式のリリース情報で、eMudhraへの対応と同梱部品の変更を確認します。提供元サイトの閲覧は通信を伴います。', 'network'),
                                step('対応バージョンが提供されている場合は、アプリを導入した方法で更新します。PC側の別のランタイムを更新しても同梱部品は変わりません。', 'change'),
                                step('対応情報が見つからない場合は、この項目のプロンプトで、導入先と部品の情報を元にAIへ質問できます。根拠が得られるまでは判定保留です。')]
            tasks.append(current)
        seen = set()
        for entry in unit['action_reasons']:
            if entry['code'] not in ('configure', 'update', 'connection_problem', 'action_required'):
                continue
            for i in entry['record_indices']:
                row = records[i]
                candidate = row
                if entry['code'] == 'configure' and row.get('assessment_method') != 'configuration':
                    candidate = dict(row, status='ACTION', assessment_method='configuration', detail=entry['reason'])
                remedy = remediation.plan(candidate)
                title = remedy['title'] if remedy else '記録で検出された問題への対応を整理する'
                key = (title, entry['code'], tuple(entry['record_indices']), entry['reason'])
                if key in seen:
                    continue
                seen.add(key)
                current = task(title, entry['record_indices'], target, 'required' if entry['code'] != 'update' or row.get('review_state') == 'action' else 'conditional', 'provisional')
                current.update(fact=entry['reason'], correction_priority='検出された問題のある経路を利用する前に対応します。',
                               confirmation_priority='変更前に、対象の導入先と適用条件を確認します。',
                               completion='表示した対象で更新・設定変更を確認します。通信問題の解消には同じ経路の検証が必要です。')
                if remedy and remedy.get('reference'):
                    current['fact'] = remedy['reference']+'。'+current['fact']
                current['steps'] = [step(personal_text(s), 'change' if re.search('更新|変更|再起動|取り除|修正|切り替|移行|有効に戻', s) else 'review') for s in (remedy or {}).get('steps', [])]
                if entry.get('next_step') and entry['next_step'] not in (remedy or {}).get('steps', []):
                    current['steps'].append(step(personal_text(entry['next_step'])))
                tasks.append(current)
        for i in indices:
            assessment = records[i].get('metadata', {}).get('registry_assessment', {})
            if assessment.get('internal'):
                current = task('Docker Desktopの内部registry設定は変更不要です', [i], target, 'unneeded', 'provisional')
                basis = ('ユーザー提供の追加確認結果（自動観測とは別）' if
                         assessment.get('basis') == 'user-confirmed-desktop-and-local-endpoint' else
                         '同じ接続先のDesktop情報とローカル接続')
                current.update(fact='Secure=falseの元観測を保持しています。'+basis+'から、内部用例外と判断しました。',
                               correction_priority='この内部設定は削除しません。別に示した外部registryの問題は対応対象です。',
                               confirmation_priority='外部registryへの実通信や他の設定・部品の判定とは別です。',
                               completion='記録にある内部registry設定だけが対象です。Docker全体の安全性やコード署名は評価していません。')
                tasks.append(current)
            if assessment.get('pending') or assessment.get('incomplete'):
                current = task('内部registryかどうかを判断する接続先情報が不足しています', [i], target)
                current.update(fact='Secure=falseは記録されていますが、Desktop内部用の例外として扱えるかは判定保留です。',
                               correction_priority='内部用か確認する前に、この設定を削除する必要はありません。',
                               confirmation_priority='追加確認済みなら、その結果をAIプロンプトへ追記してください。',
                               completion='選択中の接続先がローカルDocker Desktopかを確認し、外部registryの設定と分けられたら確認完了です。')
                current['steps'] = [step('選択中のDocker contextを表示します。', 'local_read', 'docker context show'),
                                    step('contextに保存された接続先を表示します。DOCKER_HOST・DOCKER_CONTEXTを別に指定している場合は、そちらも考慮してください。', 'local_read', "docker context inspect --format '{{json .Endpoints.docker.Host}}'"),
                                    step('選択中のEngineが返すOS名を表示します。Engineへの問い合わせで、接続先がリモートなら通信を伴います。registryへの接続検査や設定変更は行いません。', 'network', "docker info --format '{{json .OperatingSystem}}'"),
                                    step('接続先がローカルDocker Desktopだと追加確認できている場合は、その結果をプロンプトへ追記します。Desktop以外・不明の場合は、名前だけで内部用と判断しません。')]
                if assessment.get('incomplete'):
                    current['steps'].insert(0, step('Secure=falseの対象名を取得します。選択中のEngineへの問い合わせで、リモートの場合は通信を伴います。', 'network', "docker info --format '{{range $name, $config := .RegistryConfig.IndexConfigs}}{{if not $config.Secure}}{{println $name}}{{end}}{{end}}'"))
                tasks.append(current)
        if not tasks:
            scope = unit['primary_action'] in ('not_found', 'not_applicable', 'info')
            current = task('この記録から追加の修正作業は決められません' if not scope else 'この記録では操作の案内はありません', indices, target)
            current.update(fact='不足している根拠を詳細に記載しています。未確認であることだけを理由に更新や設定変更を求めません。' if not scope else '探索結果・対象範囲・環境情報の記録です。',
                           completion='必要な根拠が得られるまで判定を保留します。')
            tasks.append(current)
    for i in indices:
        row = records[i]
        if 'CRLSet' in row['name']:
            notes.append('CRLSetの保存データを照合済みです。実際の適用状態と通信の結果は別です。' if row['status'] in ('STATIC_OK', 'CHECKED') else
                         'CRLSetの保存済み記録で更新・対応対象となっています。実際の適用状態と通信は別です。' if row['status'] in ('UPDATE', 'ACTION') else
                         'CRLSetを取得・照合できませんでした。有無・適用状態は未確認です。未取得は古いことの証拠ではありません。')
    return dict(tasks=tasks, details=details, notes=notes)


def build(tool, records):
    units = [unit_work(unit, records, tool['name']) for unit in tool['units']]
    tasks, shared = [], {}
    for unit in units:
        for task_value in unit['tasks']:
            t = copy.deepcopy(task_value)
            if tool['name'] == 'Google Chrome' and not t['target'] and t['classification'] == 'unassigned':
                continue
            # Only the OS maintenance operation is common. Keep separate
            # connection evidence and identities in the canonical model.
            key = None
            if t['title'] == 'macOSの更新があれば適用する':
                bindings = {(records[i]['metadata'].get('execution_context', 'ホスト'), records[i]['metadata'].get('runtime_executable')) for i in t['record_indices']}
                if len(bindings) == 1 and next(iter(bindings))[0] in ('', 'ホスト'):
                    key = next(iter(bindings))
            if key in shared:
                shared[key]['record_indices'] = sorted(set(shared[key]['record_indices']+t['record_indices']))
                shared[key]['target'] += ' / '+t['target']
            else:
                tasks.append(t)
                if key is not None:
                    shared[key] = t
    details = []
    for u in units:
        for d in u['details']:
            if d not in details:
                details.append(copy.deepcopy(d))
    return dict(schema_version=1, tasks=tasks,
                details=details,
                notes=list(dict.fromkeys(n for u in units for n in u['notes'])))
