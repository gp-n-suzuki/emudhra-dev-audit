"""Read-only action/axis projection of canonical, saved observations.

This module neither compares versions nor collects evidence. Observation status
and the legacy review groups remain authoritative evidence, not UI categories.
"""
import copy
import json
import re
import verdicts
import remediation


GROUPS = (
    ('connection_problem', '問題の証明書を受け入れた・対応が必要'),
    ('action_required', '検出した問題への対応が必要'),
    ('configure', '設定の修正が必要'),
    ('update', '更新が必要'),
    ('investigate', '追加確認が必要'),
    ('version_complete', 'バージョン対策完了'),
    ('complete', '対応完了（導入先ごとに根拠あり）'),
    ('scoped_complete', '確認した範囲は対応不要・別の範囲は未評価'),
    ('checked', '検査した範囲で問題なし'),
    ('not_found', '見つからなかった対象'),
    ('not_applicable', '対象外'),
    ('info', '環境情報'),
)
LABELS = dict(GROUPS)
PRIORITY = {key: index for index, (key, _) in enumerate(GROUPS)}
NEEDS_ACTION = {'connection_problem', 'action_required', 'configure', 'update', 'investigate'}
VERSION_LABELS = {
    'below_fixed': '公式対策バージョン未満・更新対象',
    'update_required': '記録では更新対象・バージョンの比較情報は不足',
    'component_update_review': '部品の更新要否を確認・バージョンの比較情報は不足',
    'component_below_fixed': '同梱部品は対策バージョン未満・配布元の対応を確認',
    'fixed': '照合した本体バージョンは対応基準を満たす',
    'component_fixed': '照合した部品のみ対応基準を満たす',
    'custom_unknown': '独自配布・独自修正の取り込みは不明',
    'unknown': '取得したバージョンだけでは対応状況を判断できない',
    'missing': '判定に必要なバージョン・実行環境を取得できない',
    'observed': 'バージョンを取得（この記録では対応状況未照合）',
    'not_assessed': 'バージョンによる判定は未実施',
}
COMMUNICATION_LABELS = {
    'problem': '問題の証明書を受け入れた',
    'rejected': '検査先の証明書を拒否できた（実測）',
    'rejected_before_send': '検査先への要求を送信前に拒否した（保存ログ）',
    'inferred_rejected': '検査先の証明書を拒否できた（推定）・拒否理由は別接続から推定',
    'indeterminate': '実行失敗・結果を判定できない',
    'control_only': '通常接続のみ成功・問題の証明書の拒否は未確認',
    'synthetic_only': 'ローカル合成証明書のみ確認・外部通信は未検査',
    'synthetic_api_query': '公式APIへの合成データ照会を確認・検査用サイトは未確認',
    'not_run': '未実施',
    'not_applicable': 'この項目では対象外',
}


def _unique(entries):
    """Coalesce equal claims, retaining every source record index."""
    result, keyed = [], {}
    for entry in entries:
        key = json.dumps({k: v for k, v in entry.items() if k != 'record_indices'},
                         sort_keys=True, ensure_ascii=False)
        if key not in keyed:
            keyed[key] = copy.deepcopy(entry)
            result.append(keyed[key])
        else:
            keyed[key]['record_indices'] = sorted(set(keyed[key]['record_indices'] + entry['record_indices']))
    return result


def _entry(index, state, label, reason, scope, **extra):
    return dict(state=state, label=label, reason=reason, scope=scope,
                record_indices=[index], **extra)


def _gap(index, reason, next_step, scope):
    return dict(reason=reason, next_step=next_step, scope=scope, record_indices=[index])


def _action(index, code, reason, next_step, scope):
    return dict(code=code, label=LABELS[code], **_gap(index, reason, next_step, scope))


def _version(index, row, check=None):
    meta = row.get('metadata', {})
    value = check if check is not None else meta
    status = value.get('status', row['status'])
    current = value.get('assessed_version', value.get('version', value.get('runtime_version', '')))
    component = value.get('component') or meta.get('runtime_component') or '本体'
    python_package = None
    if check is None and component == '本体' and (meta.get('tool_id') == 'python' or meta.get('result_tool_name') == 'Python'):
        suffix = row['name'].rsplit(' / ', 1)[-1]
        python_package = ('ensurepip同梱pip（新規venv用）' if suffix.startswith('ensurepip同梱pip') else
                          'pip' if re.match(r'pip(?:\s|$)', suffix) else
                          'certifi' if re.match(r'certifi(?:\s|$)', suffix) else None)
        if python_package:
            component = python_package
    # A build record for Go's own executable is not an unrelated compiler.
    own_go = check is not None and verdicts.is_go_toolchain_check(row, check)
    embedded = (check is not None and not own_go) or bool(meta.get('runtime_component'))
    part = embedded or bool(python_package)
    reason = value.get('detail', row['detail'])
    if status == 'UPDATE':
        scoped_component = embedded or (meta.get('application') and not own_go)
        if not current or not value.get('reference_floor'):
            state = 'component_update_review' if scoped_component else 'update_required'
        else:
            state = 'component_below_fixed' if scoped_component else 'below_fixed'
    elif (meta.get('tool_id') == 'composer' and value.get('release_status') == 'fixed' and
          value.get('version_basis') == 'official-release' and value.get('reference_floor') and
          str(value.get('source', '')).startswith('https://')):
        state = 'fixed'  # Body release only; transport prerequisites remain independent.
    elif status in ('REFERENCE_OK', 'INFERRED_OK'):
        state = 'component_fixed' if part or meta.get('verified_components') else 'fixed'
    elif value.get('release_review') or meta.get('release_distribution') in ('custom', 'unknown', 'conflict'):
        state = 'custom_unknown'
    elif not current:
        state = 'missing'
    else:
        state = 'unknown'
    if meta.get('tool_id') == 'pip' and state == 'missing':
        reason = '起動先Pythonと、その環境のpipバージョンが未取得です。別のPython環境のバージョンは流用できません。'
    elif state == 'missing':
        reason = component+'のバージョンを取得できませんでした。対象：'+str(meta.get('executable') or meta.get('path') or row['name'])+'。'
    conditions = {key: copy.deepcopy(value[key]) for key in (
        'version_basis', 'release_condition', 'release_distribution', 'first_fixed_version',
        'known_fixed_versions', 'component_only', 'as_of', 'reference_date', 'release_review') if key in value}
    label = VERSION_LABELS[state]
    if state == 'component_below_fixed':
        display_component = {'electron':'同梱Electron', 'go':'同梱Go', 'certifi':'同梱certifi',
                             'node':'使用するNode.js', 'bun':'同梱Bun'}.get(component, component)
        label = display_component+'が対策バージョン未満・配布元の対応を確認'
    scope = value.get('scope') or row['scope']
    if meta.get('tool_id') == 'composer' and state == 'fixed' and value.get('release_status') == 'fixed':
        scope = 'この導入先のComposer本体バージョンのみ。使用するPHP・curl・通信設定の条件は別に評価します。'
    if python_package:
        scope += (' このPythonのensurepipが新規venvへ導入するpipのみ。既存venvのpipとは別です。'
                  if python_package.startswith('ensurepip') else ' このPython環境の'+python_package+'のみ。Python本体のバージョンではありません。')
    return _entry(index, state, label, reason, scope,
                  component=component, target='component' if part else 'application',
                  version=current, reference_floor=value.get('reference_floor'),
                  source=value.get('source', meta.get('source', '')), conditions=conditions)


def _generic_discovery(row):
    meta = row.get('metadata', {})
    return (row['status'] == 'MANUAL' and row['assessment_method'] == 'manual' and
            meta.get('application') and meta.get('coverage_state') == 'uninspected' and
            row['detail'] == 'このツールの通信は未確認。導入を確認しました。' and
            not meta.get('inspections') and not row.get('samples'))


def certificate_retry_timeouts(row):
    """A bounded log annotation, never a TLS verdict or cross-sample inference."""
    meta = row.get('metadata', {})
    if meta.get('tool_id') != 'bundler' or meta.get('probe') != 'synthetic_bundle_lock':
        return []
    return [i for i, sample in enumerate(row.get('samples', []))
            if sample.get('status') == 'UNKNOWN' and
            str(sample.get('detail', '')).startswith('TIMEOUT:') and
            re.search(r'Retrying fetcher due to error \(\d+/\d+\): Bundler::Fetcher::CertificateFailureError\b',
                      str(sample.get('detail', '')))]


RETRY_TIMEOUT_NOTE = '証明書エラーを観測した後、再試行中にタイムアウト。検査は完了していない'


def composer_denylist_samples(row):
    """Interpret exact pre-send denials without changing any saved observation."""
    meta = row.get('metadata', {})
    if (meta.get('tool_id') != 'composer' or meta.get('probe') != 'synthetic_composer_search' or
            row.get('assessment_method') != 'measured'):
        return []
    matched = []
    for i, sample in enumerate(row.get('samples', [])):
        text, url = sample.get('detail', ''), sample.get('url', '')
        if (sample.get('control') or sample.get('status') != 'UNKNOWN' or
                not isinstance(text, str) or 'TIMEOUT' in text.upper() or
                not isinstance(url, str) or not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::\d+)?/', url)):
            continue
        compact = re.sub(r'\s+', '', re.sub(r'\x1b\[[0-9;]*m', '', text))
        pattern = (r'InTlsChainDenylist\.phpline\d+:TheTLScertificatechainpresentedfor"' +
                   re.escape(url+'packages.json') +
                   r'"containsthedistrustedcertificate"[^"<>]{1,200}",thismaybeaman-in-the-middleattack\.'
                   r'Therequestwasabortedbeforeitwassent\.')
        if re.match(pattern, compact):
            matched.append(i)
    return matched


def _probe_body_version(row):
    """Recognize saved collector output, not an error containing a number.

    The curl/wget/PHP collectors store output lines, including failure text.
    These formats identify their own executable; no dependency/compiler version
    is borrowed and no fixed-version comparison is made here.
    """
    meta = row.get('metadata', {})
    patterns = {
        'git': r'^git version \d+\.\d+',
        'curl': r'^curl \d+\.\d+',
        'ruby': r'^ruby \d+\.\d+',
        'php': r'^PHP \d+\.\d+',
        'wget': r'^GNU Wget \d+\.\d+',
        'node': r'^v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?$',
        'java': r'^\d+\.\d+(?:\.\d+)*(?:[-+_][\w.-]+)?$',
    }
    raw = meta.get('version')
    value = raw[0] if isinstance(raw, list) and raw else raw
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip().splitlines()[0]
    pattern = patterns.get(meta.get('tool_id'))
    return value if pattern and re.match(pattern, value) else None


def record_axes(index, row):
    """Keep different kinds of evidence separate, including lower-level issues."""
    status, method, meta = row['status'], row['assessment_method'], row.get('metadata', {})
    scope, reason = row['scope'], row['detail']
    result = dict(record_index=index, version=[], communication=[], configuration=[],
                  gaps=[], action_reasons=[])
    if status in ('NOT_FOUND', 'NOT_APPLICABLE'):
        result['scope_state'] = 'not_found' if status == 'NOT_FOUND' else 'not_applicable'
        return result

    def gap(why, step, area=scope, fallback_axis=None):
        why, step = remediation.gap_guidance(row, why, step)
        value = _gap(index, why, step, area)
        if fallback_axis and _generic_discovery(row):
            value['fallback_axis'] = fallback_axis
        result['gaps'].append(value)

    def action(code, why, step, area=scope):
        result['action_reasons'].append(_action(index, code, why, step, area))

    def communication(state, why=reason, **extra):
        result['communication'].append(_entry(index, state, COMMUNICATION_LABELS[state], why, scope, **extra))

    checks = [check for check in meta.get('inspections', [])
              if check.get('method') == 'version' or (check.get('version') and check.get('component'))]
    result['version'] = [_version(index, row, check) for check in checks]
    if not checks and (method == 'version' or meta.get('runtime_component')):
        result['version'].append(_version(index, row))
    elif not checks and meta.get('application'):
        observed = dict(meta, version=meta.get('application_version', meta.get('version',
                              meta.get('security_tool', {}).get('version', ''))))
        result['version'].append(_version(index, row, observed))
        # Application inventory is not a component-version comparison.
        result['version'][-1].update(component='本体', target='application')
        if result['version'][-1]['state'] == 'unknown' and observed.get('version'):
            result['version'][-1].update(state='observed', label=VERSION_LABELS['observed'])
    elif not checks and method == 'inventory' and meta.get('version'):
        result['version'].append(_entry(index, 'observed', VERSION_LABELS['observed'], reason, scope,
                                       component='本体', target='application', version=meta['version'],
                                       reference_floor=None, source=meta.get('source', ''), conditions={}))
    elif not checks and method in ('measured', 'corroborated'):
        captured = _probe_body_version(row)
        if captured:
            result['version'].append(_entry(index, 'observed', VERSION_LABELS['observed'],
                'この通信記録に保存された実行ファイルの本体バージョンです。対策バージョンとの照合は行っていません。',
                'この記録の実行ファイルの本体バージョンのみ。通信結果・実効CAの対応状況とは別の情報です。',
                component='本体', target='application', version=captured,
                reference_floor=None, source='', conditions={'version_basis':'collector-metadata'},
                raw_version=copy.deepcopy(meta['version'])))

    for version in result['version']:
        state = version['state']
        if state in ('below_fixed', 'update_required'):
            action('update', version['reason'], '対象の導入先を、適用範囲が一致する配布元の対応バージョンへ更新してください。', version['scope'])
        elif state in ('component_below_fixed', 'component_update_review'):
            gap(version['reason'], '配布元の対応状況を確認し、独自修正・バックポートの有無と更新先を確認してください。', version['scope'])
        elif state in ('unknown', 'custom_unknown', 'missing'):
            if meta.get('tool_id') == 'pip' and state == 'missing':
                step = '実際の導入先を確認し、起動先Python・同じ環境のpipバージョン・実効CA設定を取得してください。'
            elif state == 'custom_unknown':
                step = '配布元情報で修正の取り込みを確認してください。独自ビルドをバージョンの数値だけで更新対象と断定しません。'
            else:
                step = row.get('action') or '同じ導入先の本体バージョン・使用部品・配布形式を取得し、適用できる公式情報と照合してください。'
            gap(version['reason'], step, version['scope'], fallback_axis='version' if state == 'missing' else None)

    for check in meta.get('inspections', []):
        check_status, check_method = check.get('status'), check.get('method')
        check_scope = check.get('scope') or scope
        check_reason = str(check.get('component', '部品'))+'：'+str(check.get('detail', '記録の詳細を確認してください。'))
        if check_status == 'ACTION':
            code = 'configure' if check_method == 'configuration' else 'connection_problem' if check_method in ('measured', 'corroborated') else 'action_required'
            action(code, check_reason, 'この部品の検出した問題と適用設定を確認し、記載された範囲で対応してください。', check_scope)
            if code == 'connection_problem':
                communication('problem', check_reason)
            elif code == 'configure':
                result['configuration'].append(_entry(index, 'problem', '部品の設定上の問題を検出', check_reason, check_scope))
        elif check not in checks and check_status in ('UPDATE', 'MANUAL', 'UNKNOWN', 'SKIP'):
            gap(check_reason, '同じ導入先のこの部品・保存データについて、配布元の対応と実際の適用状態を確認してください。', check_scope)
    for limitation in meta.get('uninspected', []):
        gap(str(limitation), row.get('action') or '記載した未検査の対象・設定を確認してください。', fallback_axis='discovery_limit')

    samples = row.get('samples', [])
    denylist_samples = composer_denylist_samples(row)
    if denylist_samples:
        communication('rejected_before_send', 'Composer自身の保存ログに、問題の証明書を検出して要求を送信前に中止した記録があります。',
                      basis='composer-denylist-log', sample_indices=denylist_samples,
                      raw_status=status, scope_note='該当する検査先の送信前拒否のみ。通常サイトの対照試験・普段の設定は別です。')
    problematic_sample = any(s.get('status') == 'ACTION' and not s.get('control') for s in samples)
    if status == 'ACTION' or problematic_sample:
        if method in ('measured', 'corroborated') or problematic_sample:
            communication('problem')
            action('connection_problem', reason, row.get('action') or 'この接続の証明書検証・CA・使用バージョンを確認し、問題の証明書を拒否するよう対応してください。')
        elif method == 'configuration':
            result['configuration'].append(_entry(index, 'problem', '設定上の問題を検出', reason, scope))
            action('configure', reason, row.get('action') or '該当する証明書検証・CA設定を修正し、同じ環境で再確認してください。')
        else:
            action('action_required', reason, row.get('action') or '検出した問題の詳細を確認し、記載された対象へ対応してください。')
    elif method == 'configuration' and status == 'CHECKED':
        result['configuration'].append(_entry(index, 'checked', '取得した設定を確認', reason, scope))
    elif status in ('STATIC_OK', 'CHECKED') and method in ('static', 'inventory'):
        result['configuration'].append(_entry(index, 'saved_data', '保存データ・配置のみ確認', reason, scope))

    evidence_text = reason + ' ' + ' '.join(str(s.get('detail', '')) for s in samples)
    cpu_failure = status == 'UNKNOWN' and 'Bad CPU type in executable' in evidence_text
    if cpu_failure:
        communication('not_run', 'CPU形式の不一致で起動できず、通信は未実施です。', failure='cpu_mismatch')
        gap('CPU形式の不一致で起動できず、通信は未実施です。', 'このMacのCPUに対応する実行ファイルと導入先を確認し、更新後に同じ経路を再診断してください。')
    elif meta.get('probe') == 'safechain_synthetic_tls':
        if meta.get('synthetic_tls_state') == 'measured' and not problematic_sample and status != 'ACTION':
            communication('synthetic_only')
        elif not result['communication']:
            communication('indeterminate')
        gap('このPC内の合成証明書テストと、eMudhra検査先・普段の外部通信は別です。',
            'ローカルproxyへの接続と、同じSafe Chainから普段の取得先への接続を分けて確認してください。')
    elif status == 'REJECTED':
        communication('rejected')
    elif status == 'INFERRED_REJECTED':
        communication('inferred_rejected')
        gap('接続失敗の原因は別接続からの推定です。', '対象クライアント自身の証明書検証エラーと、適用されたCA設定を確認してください。')
    elif status == 'CONTROL_OK':
        communication('control_only')
        gap('通常接続の成功だけでは、問題の証明書を拒否するか確認できません。', '同じクライアント・CA設定で問題の証明書を拒否する根拠を確認してください。')
    elif denylist_samples and set(denylist_samples) == {i for i,s in enumerate(samples) if not s.get('control')}:
        gap('通常サイトの対照試験は成功として確定していません。保存ログによる送信前拒否とは別の範囲です。',
            'この対照試験の未確定だけを理由に、確認済みの送信前拒否を未対応へ戻しません。')
    elif (status == 'UNKNOWN' and (method in ('measured', 'corroborated') or samples)) or (status == 'MANUAL' and samples):
        communication('indeterminate')
        gap(reason, row.get('action') or '実行失敗の原因と同じ導入先の通信・CA設定を確認し、再診断してください。')
    elif status in ('MANUAL', 'SKIP') and (method in ('manual', 'unmeasured', 'measured') or meta.get('application')):
        communication('not_run')
        gap(reason, row.get('action') or 'この導入先で使用するTLS・CA設定と、普段の接続先での拒否結果を確認してください。', fallback_axis='communication')
    elif status == 'UNKNOWN' or (status == 'MANUAL' and not result['version']):
        gap(reason, row.get('action') or '取得できなかったデータ・設定の場所と読み取り条件を確認してください。')
    if status == 'UPDATE' and not result['version']:
        # Missing rejection data, for example, is not an application-version floor.
        gap(reason, row.get('action') or '取得した拒否データ・配布元の更新状況と、実際の適用状態を確認してください。')
        if method != 'static':
            action('action_required', '記録のUPDATE判定：'+reason,
                   '更新が必要とされた対象・根拠を確認してください。この記録だけでは本体バージョンと部品バージョンを分けられません。')
    if any(s.get('status') == 'UNKNOWN' and not s.get('control') for s in samples) and status in ('REJECTED', 'ACTION'):
        communication('indeterminate', '結果を確認した接続以外に、結果を判断できない検査先があります。')
        gap('一部の検査先は結果を判断できません。', '未確認の検査先と失敗理由を確認してください。')
    retry_samples = certificate_retry_timeouts(row)
    if retry_samples:
        communication('indeterminate', RETRY_TIMEOUT_NOTE+'。ログ断片は検査完了や拒否成功の証拠ではありません。',
                      sample_indices=retry_samples, failure='certificate_error_then_retry_timeout')
    if status == 'CHECKED' and meta.get('probe') == 'synthetic_osv_query':
        communication('synthetic_api_query', reason)
        gap('公式APIへの合成依存の照会は、問題の証明書を拒否する検査とは別です。',
            '検査用サイトへの拒否結果と、利用者の実際の取得先・CA設定を確認してください。')
    return result


def _aggregate(parts):
    result = {key: _unique([entry for part in parts for entry in part[key]])
              for key in ('version', 'communication', 'configuration', 'gaps', 'action_reasons')}
    codes = {entry['code'] for entry in result['action_reasons']}
    if any(gap.get('blocks_completion', True) for gap in result['gaps']):
        codes.add('investigate')
    if codes:
        actions = sorted(codes, key=PRIORITY.get)
    else:
        scope_states = {part.get('scope_state') for part in parts}
        completed_actions = ('version_complete', 'checked', 'complete', 'scoped_complete')
        if (any(p.get('scoped_complete') or p.get('primary_action') == 'scoped_complete' for p in parts) and
                all(p.get('scoped_complete') or p.get('primary_action') in completed_actions for p in parts)):
            actions = ['scoped_complete']
        elif all(part.get('version_complete') for part in parts):
            actions = ['version_complete']
        elif (any(part.get('primary_action') in ('version_complete', 'complete') for part in parts) and
              all(part.get('primary_action') in ('version_complete', 'checked', 'complete') for part in parts)):
            actions = ['complete']
        elif any(x['state'] == 'rejected' for x in result['communication']):
            actions = ['checked']
        else:
            actions = ['not_found' if 'not_found' in scope_states else
                       'not_applicable' if 'not_applicable' in scope_states else 'info']
    result['version_complete'] = all(part.get('version_complete', False) for part in parts)
    result.update(actions=actions, primary_action=actions[0], primary_label=LABELS[actions[0]])
    return result


def scope_identities(records, aliases):
    """Use explicit captured interpreter/JDK bindings, never display grouping."""
    base = {i: verdicts.snapshot_identity(r, aliases, presentation=False) for i,r in enumerate(records)}
    python, java = {}, {}
    for row in records:
        m = row['metadata']; context = m.get('execution_context') or 'ホスト'
        binding = m.get('python_identity')
        if (m.get('tool_id') == 'python' and isinstance(binding, (list,tuple)) and len(binding)==2 and
                binding[0]=='python' and isinstance(binding[1], str) and m.get('prefix') and
                isinstance(m.get('packages'), dict)):
            python.setdefault((context,binding[1]), set()).add(str(m['prefix']))
        if m.get('tool_id') == 'java' and m.get('java_home') and m.get('executable'):
            java.setdefault((context,str(m['executable'])), set()).add(str(m['java_home']))
    result = dict(base)
    for i,row in enumerate(records):
        m = row['metadata']; context = m.get('execution_context') or 'ホスト'
        binding = m.get('python_identity')
        runtime = (binding[1] if isinstance(binding,(list,tuple)) and len(binding)==2 and binding[0]=='python'
                   and isinstance(binding[1],str) else base[i][-1] if base[i] and base[i][0]=='python' else None)
        prefixes = python.get((context,runtime), set())
        if (runtime and len(prefixes)==1 and m.get('tool_id') in ('python','pip') and
                (not m.get('prefix') or str(m['prefix']) in prefixes)):
            result[i] = ('python-environment',context,runtime,next(iter(prefixes)))
        if m.get('tool_id') == 'java' or row['name'] == 'Java / Azulブロックリスト':
            location = str(m.get('executable') or m.get('path') or '')
            homes = java.get((context,location), set())
            home = str(m.get('java_home') or (next(iter(homes)) if len(homes)==1 else ''))
            known = any(ctx==context and home in values and len(values)==1 for (ctx,_),values in java.items())
            if home and known and (not homes or homes=={home}):
                result[i] = ('java-home',context,home)
    return result


def version_completion(unit, records, aliases, axes, identities=None):
    """Complete only the matched version scope, without claiming transport success.

    Canonical assessors establish the applicable release/component rules. Here
    we require their reference, saved identity and non-conflicting conditions.
    Unknown releases/required components and known problems stay actionable.
    """
    candidates = []
    identities = identities if identities is not None else scope_identities(records, aliases)
    for version in unit['version']:
        conditions = version.get('conditions', {})
        if (version['state'] not in ('fixed', 'component_fixed') or
                not version.get('version') or not version.get('reference_floor') or
                not str(version.get('source', '')).startswith('https://') or
                conditions.get('component_only') or conditions.get('release_review') or
                conditions.get('release_distribution') in ('custom', 'unknown', 'conflict')):
            continue
        version_identities = {identities[i] for i in version['record_indices']}
        if None in version_identities or len(version_identities) != 1:
            continue
        candidates.append(version)
    unit_identities = {identities[i] for i in unit['record_indices']}
    ambiguous = None in unit_identities or len(unit_identities) != 1
    for key in ('prefix', 'java_home', 'virtual_env', 'venv', 'sys_prefix',
                'runtime_executable', 'python_executable', 'resolved_executable'):
        # Inventory of an already matched launcher does not observe its runtime.
        # Missing inventory data is not a second, contradictory runtime claim.
        values = {str(records[i]['metadata'][key]) for i in unit['record_indices']
                  if records[i]['metadata'].get(key)}
        ambiguous = ambiguous or len(values) > 1
    for key in ('prefix', 'interpreter'):
        values = {str((records[i]['metadata'].get('python_environment') or {})[key])
                  for i in unit['record_indices'] if (records[i]['metadata'].get('python_environment') or {}).get(key)}
        ambiguous = ambiguous or len(values) > 1
    blocked = any(v['state'] in ('below_fixed', 'update_required', 'component_below_fixed',
                                 'component_update_review', 'custom_unknown', 'unknown', 'missing') or
                  v.get('conditions', {}).get('component_only') for v in unit['version'])
    body_versions = set().union(*(_body_version_claims(records[i], axes[i]) for i in unit['record_indices']))
    # Strip collector prefixes/build annotations only for comparing saved claims.
    numbers = {re.search(r'\d+(?:\.\d+)+(?:[-+][\w.-]+)?', v)[0]
               if re.search(r'\d+(?:\.\d+)+(?:[-+][\w.-]+)?', v) else v for v in body_versions}
    ambiguous = ambiguous or len(numbers) > 1
    blocked = blocked or ambiguous or any(v['state'] in ('fixed', 'component_fixed') and v not in candidates
                                          for v in unit['version'])
    blocked = blocked or any(records[i]['assessment_method'] == 'static' and
                            records[i]['status'] in ('UPDATE', 'UNKNOWN', 'MANUAL', 'SKIP')
                            and not (records[i]['metadata'].get('p2_settings') and records[i]['status'] == 'MANUAL')
                            for i in unit['record_indices'])
    # Composer's fixed body release has independent transport prerequisites.
    blocked = blocked or any(records[i]['metadata'].get('tool_id') == 'composer' and
                             records[i]['metadata'].get('release_condition') for i in unit['record_indices'])
    unit['completed_versions'] = [] if ambiguous else candidates
    unit['identity_conflict'] = ambiguous
    unit['version_complete'] = bool(candidates) and not blocked
    if ambiguous and candidates:
        detail = ('本体バージョンの記録が一致しません：'+' / '.join(sorted(body_versions))+'。' if len(numbers) > 1 else
                  '同じ導入先としてまとめた記録の実体・起動先・実行環境が一致しません。')
        unit['gaps'].append(dict(reason=detail, next_step='下の原記録にある対象パスと実行環境を照合してください。使用する導入先を特定するまで、別の記録の対策済みバージョンを適用しません。',
                                scope='この導入先の記録間の照合。', record_indices=list(unit['record_indices'])))
    if unit['version_complete']:
        for gap in unit['gaps']:
            gap['blocks_completion'] = False
    return unit


def _body_version_claims(row, axis):
    """Unfiltered claims for conflict detection, separate from usable evidence."""
    values = [v['version'] for v in axis['version'] if v['target'] == 'application' and v.get('version')]
    meta = row['metadata']
    if (not values and not meta.get('application') and not meta.get('runtime_component') and
            not meta.get('inspections') and not any(v['target'] == 'component' for v in axis['version'])):
        # A MANUAL/failed record may retain a body-version claim without a
        # version-axis entry. It can veto reconciliation, never qualify it.
        values.append(meta.get('version'))
    if _generic_discovery(row):
        # Inventory display chooses one of these fields. A second, contradictory
        # saved value must not disappear merely because of that display choice.
        values += [meta.get('application_version'), meta.get('version'),
                   (meta.get('security_tool') or {}).get('version')]
    claims = {str(value).strip() for value in values if value and str(value).strip()}
    if meta.get('tool_id') == 'java':
        short, full = meta.get('version'), meta.get('runtime_version')
        if isinstance(short,str) and isinstance(full,str) and full.startswith(short+'+') and short in claims:
            claims.discard(short)
            claims.add(full)
    return claims


def _reconcile_discovery(records, indices, axes, aliases, identities=None):
    """Narrow generic fallbacks using saved identity and scope, never group IDs.

    Raw observations and record-level projections stay available. Only the
    installation's aggregate presentation omits superseded fallback claims.
    """
    parts = {i: copy.deepcopy(axes[i]) for i in indices}
    resolutions = []
    identities = identities if identities is not None else scope_identities(records, aliases)
    environment_keys = ('prefix', 'java_home', 'virtual_env', 'venv', 'sys_prefix')
    runtime_keys = ('runtime_executable', 'python_executable', 'resolved_executable')
    for i in indices:
        row, part = records[i], parts[i]
        if not _generic_discovery(row) or not identities[i]:
            continue
        meta = row['metadata']
        related = [j for j in indices if identities[j] == identities[i] and
                      all(not meta.get(k) or not records[j]['metadata'].get(k) or
                          meta[k] == records[j]['metadata'][k] for k in environment_keys) and
                      all(not (meta.get('python_environment') or {}).get(k) or
                          not (records[j]['metadata'].get('python_environment') or {}).get(k) or
                          (meta.get('python_environment') or {})[k] ==
                          (records[j]['metadata'].get('python_environment') or {})[k]
                          for k in ('prefix', 'interpreter'))]
        candidates = [j for j in related if j != i and not records[j]['metadata'].get('application')]
        # A generic launcher cannot choose between recorded Ruby/runtime
        # bindings or conflicting versions, even if the UI grouped them.
        if any(len({str(records[j]['metadata'][k]) for j in related
                    if records[j]['metadata'].get(k)}) > 1 for k in runtime_keys+environment_keys):
            continue
        observed_versions = set().union(*(_body_version_claims(records[j], axes[j]) for j in related))
        if len(observed_versions) > 1:
            part['gaps'].append(_gap(i, '同じ導入先で取得した本体バージョンの値が一致しないため、汎用表示を抑制していません。',
                '原記録の取得値・実行環境・記録時点の違いを確認してください。', row['scope']))
            continue
        versions = [(j, v) for j in candidates for v in axes[j]['version']
                    if v['target'] == 'application' and v['component'] == '本体' and v.get('version') and
                    (records[j]['status'] not in ('UNKNOWN', 'MANUAL', 'SKIP') or
                     records[j]['assessment_method'] == 'version' or
                     v.get('conditions', {}).get('version_basis') == 'collector-metadata')]
        version_sources = sorted({j for j, _ in versions})
        communication_sources = [j for j in candidates
            if records[j]['assessment_method'] in ('measured', 'corroborated') and records[j].get('samples') and
            records[j].get('scope') and any(v['state'] in ('problem', 'rejected', 'inferred_rejected', 'indeterminate', 'control_only')
                                          for v in axes[j]['communication']) and
            not any(v.get('failure') == 'cpu_mismatch' for v in axes[j]['communication'])]
        covered = set()
        if version_sources:
            part['version'] = [v for v in part['version'] if not (v['state'] == 'missing' and v['target'] == 'application')]
            covered.add('version')
        if communication_sources:
            part['communication'] = [v for v in part['communication'] if v['state'] != 'not_run']
            covered.add('communication')
        if not covered:
            continue
        part['gaps'] = [g for g in part['gaps'] if g.get('fallback_axis') not in covered]
        for gap in part['gaps']:
            if gap.get('fallback_axis') != 'discovery_limit':
                continue
            if gap['reason'] in ('TLS構成と修正バージョンの照合に必要な情報を取得できません（通信の有無も未確認）',
                                 'TLS構成と修正版の照合に必要な情報を取得できません（通信の有無も未確認）'):
                version_note = ('本体バージョンの取得結果は個別記録を参照してください。' if version_sources else
                    '本体バージョンの取得値はありますが、この集約のバージョン情報を確定する証拠には採用していません。' if observed_versions else
                    '本体バージョンを確定する取得情報が不足しています。')
                gap['reason'] = version_note + \
                    '個別検査の範囲以外のTLS構成・修正適用条件は未確認です。'
                gap['next_step'] = '個別記録のバージョン・検査範囲と、利用する設定に適用できる配布元情報を確認してください。'
            elif communication_sources and gap['reason'] == 'アプリの実効CA・独自検証設定・実通信は未検査':
                gap['reason'] = '個別検査に記載した設定・接続先以外の実効CA・独自検証設定・普段の通信は未確認です。'
                gap['next_step'] = '診断用設定やランタイム既定動作の結果と、普段の設定・アプリ固有のCAを分けて確認してください。'
        if communication_sources and not any('実効CA' in g['reason'] for g in part['gaps']):
            part['gaps'].append(_gap(i, '個別検査の範囲以外の実効CA・独自検証設定・普段の通信は未確認です。',
                '個別検査の対象範囲と、普段使用する設定・接続先を確認してください。', row['scope']))
        for axis, sources in (('version', version_sources), ('communication', communication_sources)):
            if axis in covered:
                resolutions.append(dict(axis=axis, record_index=i, source_record_indices=sources,
                    scope='同じ導入先・実行環境の個別記録に記載した範囲のみ。原記録は保持。'))
    return list(parts.values()), resolutions


def scoped_completion(unit, records):
    """Separate proven scopes from unknown ones without upgrading raw records."""
    indices = unit['record_indices']
    unit['confirmed_communications'] = []
    for fact in unit['communication']:
        if fact['state'] not in ('rejected', 'rejected_before_send'):
            continue
        for i in fact['record_indices']:
            row = records[i]
            samples = row.get('samples', [])
            targets = [s for s in samples if not s.get('control')]
            direct = (fact['state'] == 'rejected' and bool(targets) and
                      all(s['status'] == 'REJECTED' for s in targets) and
                      any(s.get('control') and s['status'] == 'CONTROL_OK' for s in samples))
            logged = (fact['state'] == 'rejected_before_send' and bool(targets) and
                      len(composer_denylist_samples(row)) == len(targets))
            if direct or logged:
                unit['confirmed_communications'].append(dict(fact, record_indices=[i]))
    if unit.get('identity_conflict'):
        return
    confirmed = unit['confirmed_communications']
    generic = {i for i in indices if _generic_discovery(records[i])}
    if confirmed:
        for gap in unit['gaps']:
            if set(gap['record_indices']) <= generic:
                gap['blocks_completion'] = False
                gap['next_step'] = '確認済みの検査経路への追加作業は不要です。別の設定・経路はこの確認の対象外です。'
    # Limited completion is only available for bound runtime/package evidence
    # or a known client's positive saved evidence. Unknown required components,
    # genuine version conflicts and any actual problem retain their own action.
    if (unit['action_reasons'] or any(v['state'] in ('below_fixed', 'update_required',
            'component_below_fixed', 'component_update_review', 'custom_unknown') or
            (v['target'] == 'component' and v['state'] in ('missing', 'unknown'))
            for v in unit['version'])):
        return
    ids = {records[i]['metadata'].get('tool_id') for i in indices}
    node = any(v['component'] == 'node' and all(
        records[i]['metadata'].get('runtime_basis') == 'entrypoint' and
        records[i]['metadata'].get('runtime_executable') for i in v['record_indices'])
        for v in unit['completed_versions'])
    python = ('python' in ids and bool(confirmed) and
              any(v['component'] == 'pip' for v in unit['completed_versions']))
    java = ('java' in ids and bool(confirmed) and any(
        records[i]['name'] == 'Java / Azulブロックリスト' and records[i]['status'] == 'STATIC_OK' for i in indices))
    composer = 'composer' in ids and any(f['state'] == 'rejected_before_send' for f in confirmed)
    if not (node or python or java or composer):
        return
    # Do not complete a second failed or unbound measurement because one passed.
    if any(c['state'] in ('problem', 'indeterminate', 'inferred_rejected', 'control_only') or c.get('failure')
           for c in unit['communication']):
        return
    if any(records[i]['assessment_method'] == 'static' and records[i]['status'] in ('UPDATE','UNKNOWN','MANUAL')
           and not records[i]['metadata'].get('p2_settings') for i in indices):
        return
    unit['scoped_complete'] = True
    unit['version_complete'] = False
    for gap in unit['gaps']:
        gap['blocks_completion'] = False
        gap['next_step'] = 'この未評価の範囲だけを理由に、確認済みの部品・検査経路の再更新や再確認は求めません。別の経路を使う場合は、その経路の結果と区別します。'


def build(records, grouped_tools, context):
    """Export stable record references and unique primary vs overlapping counts."""
    axes = [record_axes(index, row) for index, row in enumerate(records)]
    aliases = verdicts.snapshot_targets(records)
    identities = scope_identities(records, aliases)
    tools = []
    for group in grouped_tools:
        units = []
        for group_unit in group['units']:
            indices = [index for index, _ in group_unit['rows']]
            parts, resolutions = _reconcile_discovery(records, indices, axes, aliases, identities)
            unit = _aggregate(parts)
            active = bool(unit['action_reasons'] or unit['gaps']) or any(records[i]['status'] not in ('NOT_FOUND', 'NOT_APPLICABLE', 'INFO')
                         and not (records[i]['status'] == 'CHECKED' and records[i]['assessment_method'] == 'inventory')
                         for i in indices)
            if not unit['communication']:
                state = 'not_run' if active else 'not_applicable'
                unit['communication'] = [_entry(indices[0], state, COMMUNICATION_LABELS[state],
                    'この導入先について通信検証の保存済み証拠がありません。' if active else '探索結果・環境情報の項目です。',
                    '同じ導入先の通信のみ。別環境の結果を流用しません。')]
                if active:
                    unit['gaps'].append(_gap(indices[0], '通信検証は未実施です。',
                        'この導入先の実効CA・検証設定と、利用する経路の拒否結果を確認してください。',
                        'バージョンの照合結果とは独立した確認です。'))
            if not unit['version']:
                unit['version'] = [_entry(indices[0], 'not_assessed', VERSION_LABELS['not_assessed'],
                    '本体・部品の対策バージョン比較は、この項目では行っていません。', '保存済み記録の範囲。',
                    component='本体', target='application', version='', reference_floor=None, source='', conditions={})]
            unit['record_indices'] = indices
            version_completion(unit, records, aliases, axes, identities)
            scoped_completion(unit, records)
            # Recompute after adding transport and the independent version result.
            unit = dict(unit, **{k: v for k, v in _aggregate([unit]).items()
                                if k in ('actions', 'primary_action', 'primary_label')})
            if not active:
                states = {axes[i].get('scope_state') for i in indices}
                key = 'not_found' if 'not_found' in states else 'not_applicable' if 'not_applicable' in states else 'info'
                unit.update(actions=[key], primary_action=key, primary_label=LABELS[key], scope_state=key)
            unit.update(record_indices=indices, installation=group_unit['installation'], fallback_resolutions=resolutions)
            units.append(unit)
        tool = _aggregate(units)
        tool.update(name=group['name'], units=units, record_indices=[i for i, _ in group['rows']])
        tools.append(tool)
    tools.sort(key=lambda tool: (PRIORITY[tool['primary_action']], tool['name'].casefold()))
    primary_counts = {key: sum(t['primary_action'] == key for t in tools) for key, _ in GROUPS}
    action_counts = {key: sum(key in t['actions'] for t in tools) for key, _ in GROUPS}
    counting_note = ('主分類は1ツール1件。行動別フィルターは重複を含みます。'
        '追加確認が必要：行動別フィルター{}ツール（重複を含む）＝主分類{}ツール＋他の主分類に併存{}ツール。'
        '分類の変化は安全性の向上を意味しません。').format(action_counts['investigate'], primary_counts['investigate'],
                                                action_counts['investigate']-primary_counts['investigate'])
    return dict(schema_version=1, observation_status_unchanged=True,
                counting_note=counting_note, primary_action_counts=primary_counts, action_counts=action_counts,
                tool_total=len(tools), records=axes, tools=tools,
                context_record_indices=[i for i, _ in context])
