"""Turn collected observations into scoped, independently actionable verdicts."""
from collections import Counter
from pathlib import Path
import os
import re
import json
import official_versions
import version_inference
import language_checks
import research_rules
import release_evidence

METHOD_LABELS = {'measured':'実測（通信）', 'static':'自動照合（保存データ）',
                 'corroborated':'実測＋推定（別接続で再検証）',
                 'version':'推定（バージョン）', 'configuration':'自動確認（設定）',
                 'inventory':'自動確認（探索）', 'manual':'追加確認', 'unmeasured':'未実測'}
SCOPES = {
    'corroborated':'接続失敗は実測、原因は同じ版・CA設定の別接続から推定。',
    'measured':'検査したクライアントと接続先に限ります。',
    'static':'取得した保存済みCA・失効情報の照合。',
    'version':'基準日時点の参考修正版と導入版の比較。',
    'configuration':'取得できた設定の確認。',
    'inventory':'今回探索した配置と検出した環境の確認。',
    'manual':'記載した未確認の対象について、追加確認が必要です。',
    'unmeasured':'通信を実施していないため、その環境の接続結果は未確認です。',
}
PRIORITY = {'action':0,'review':1,'complete':2,'unverified':3,'scope':4,'info':5}


def review_state(status, required=False, metadata=None, method=None):
    if status == 'ACTION': return 'action'
    if status == 'MANUAL' and (metadata or {}).get('release_review'): return 'review'
    if status == 'UPDATE':
        # An embedded component's publisher may have backported a fix, and
        # missing static rejection data alone does not prove effective TLS.
        if (metadata or {}).get('application') or (metadata or {}).get('runtime_component') or method == 'static': return 'review'
        return 'action'
    if status in ('UNKNOWN','MANUAL','SKIP'): return 'unverified'
    if status in ('REJECTED','INFERRED_REJECTED','STATIC_OK','INFERRED_OK','CHECKED'): return 'complete'
    if status in ('NOT_FOUND','NOT_APPLICABLE'): return 'scope'
    return 'info'


def finish(row, method=None, required=False, scope=None):
    value = {key:val for key,val in row.items() if key != 'evidence'}
    if method is None:
        if row.get('assessment_method'): method = row['assessment_method']
        elif row.get('samples'): method = 'measured'
        elif 'reference_floor' in row.get('metadata',{}): method = 'version'
        elif row['name'] == 'Java / Azulブロックリスト': method = 'static'
        elif row['status'] == 'SKIP': method = 'unmeasured'
        elif row['status'] == 'MANUAL': method = 'manual'
        elif row['status'] == 'ACTION': method = 'configuration'
        else: method = 'inventory'
    if value['status'] == 'REFERENCE_OK' and method == 'static' and re.search(r'CA(?:\s*(?:file|bundle)|ファイル)', value['name'], re.I):
        value['status'] = 'UNKNOWN'
    if value['status'] == 'REFERENCE_OK':
        value['status'] = {'static':'STATIC_OK','version':'INFERRED_OK'}.get(method,'CHECKED')
    value['assessment_method'] = method
    value['required'] = required or bool(row.get('required'))
    value['review_state'] = review_state(value['status'],value['required'],value.get('metadata'),method)
    if value['name'] == '検査範囲 / ホストのみの検査' and value['status'] == 'SKIP':
        value['review_state'] = 'scope'
    value['requires_attention'] = value['review_state'] in ('action','review')
    value['scope'] = scope or value.get('scope') or SCOPES[method]
    if not value['requires_attention']:
        if value['review_state'] != 'unverified':
            value['action'] = ''
    elif not value.get('action'):
        value['action'] = '記載した根拠・対象を確認し、同じ条件で再診断してください。'
    return value


def observation(parent, item, prefix):
    name = prefix+' / '+item['check']
    if item.get('path') and item['kind'] == 'version': name += ' ['+item['path']+']'
    metadata = {key:value for key,value in item.items() if key not in ('check','kind','status','detail')}
    status = item['status']
    action = ''
    if item['kind']=='version' and status=='UPDATE':
        action = '記載した配布元の対応状況とバックポートの有無を確認してください。'
    if item['kind']=='configuration' and status=='ACTION':
        action = '対象registryのSecure=false設定が意図したものか確認し、必要に応じてTLS・CA設定を修正してください。'
    if 'CRLSet' in item['check'] and status=='UNKNOWN':
        action = 'このブラウザで失効情報の更新・適用状態と、配布元の対応情報を確認し、再診断してください。'
    return finish(dict(name=name,status=status,detail=item['detail'],action=action,
                       metadata=metadata,samples=[],origin=parent['name']),item['kind'])


def additional(name, detail, action, origin, metadata=None):
    return finish(dict(name=name,status='MANUAL',detail=detail,action=action,metadata=metadata or {},samples=[],origin=origin),'manual')


def installation_identity(tool_id, path):
    if not tool_id or not path: return None
    try:
        value = Path(path).expanduser().absolute()
        # Different virtual environments can point at the same Python binary.
        if tool_id == 'python' and (value.parent.parent/'pyvenv.cfg').is_file():
            return tool_id, os.path.normcase(str(value.parent.parent)), os.path.normcase(str(value.resolve()))
        return tool_id, os.path.normcase(str(value.resolve()))
    except (OSError, ValueError, RuntimeError):
        return None


def snapshot_targets(records):
    """Resolve only recorded aliases, never today's filesystem for an old report."""
    aliases = {}
    for row in records:
        meta = row.get('metadata', {})
        tool, path = meta.get('tool_id'), meta.get('path')
        if (not meta.get('application') or not tool or not path or
                meta.get('execution_context') not in (None, '', 'ホスト')):
            continue
        for alias in [path] + list(meta.get('discovered_paths') or []):
            aliases.setdefault((tool, str(alias)), set()).add(str(path))
    return aliases


def snapshot_identity(row, aliases, *, presentation=True):
    meta = row.get('metadata', {})
    if presentation and meta.get('result_identity'):
        return tuple(meta['result_identity'])
    tool = meta.get('tool_id')
    if not tool:
        return None
    if meta.get('application') and meta.get('path'):
        context = meta.get('execution_context')
        return ((tool, context, str(meta['path'])) if context and context != 'ホスト'
                else (tool, str(meta['path'])))
    executable = meta.get('executable')
    if not executable:
        return None
    context = meta.get('execution_context')
    if context and context != 'ホスト':
        return (tool, context, str(executable))
    targets = aliases.get((tool, str(executable)), set())
    if len(targets) > 1:
        return None
    path = next(iter(targets)) if targets else str(executable)
    return (tool, path)


def is_go_toolchain_check(row, check):
    """A saved build inspection of Go itself, not another app's linked Go."""
    meta = row.get('metadata', {})
    return bool(meta.get('tool_id') == 'go' and meta.get('path') and
                check.get('component') == 'go' and check.get('method') == 'version' and
                check.get('path') == meta['path'])


def version_observation(row, aliases):
    """Reassess captured version metadata without starting a program or reading disk."""
    meta = row.get('metadata', {})
    codex = meta.get('tool_id') == 'codex' and row['name'].endswith(' / バージョン')
    claude = meta.get('tool_id') == 'claude-code' and row['name'].endswith(' / バージョン')
    python = ('packages' in meta and meta.get('prefix') and meta.get('executable') and
              (meta.get('tool_id') == 'python' or re.match(r'^(?:ホスト|コンテナ [^/]+) / Python ', row['name'])))
    if not codex and not python and not claude:
        return row
    if row.get('status') in ('ACTION', 'REJECTED', 'INFERRED_REJECTED'):
        return row
    version = meta.get('version') or ''
    if not version:
        return row
    identity_row = row if codex or meta.get('tool_id') else dict(row, metadata=dict(meta, tool_id='python'))
    identity = snapshot_identity(identity_row, aliases, presentation=False)
    path = identity[-1] if identity else ''
    distribution = (official_versions.codex_distribution(path) if codex else
                    official_versions.python_distribution(path) if python and
                    meta.get('execution_context') in (None, '', 'ホスト') else 'unknown')
    result = official_versions.assess('codex' if codex else 'python' if python else 'claude-code', version, distribution)
    value = dict(row)
    value['metadata'] = dict(meta, distribution=distribution, as_of=result['as_of'],
                             source=result['source'], reference_floor=result['floor'])
    if python:
        value['metadata'].update(tool_id='python', tool_name='Python')
    value.update(status=result['status'], detail=version+' / '+result['detail'],
                 assessment_method='version')
    value['scope'] = result['scope'] or '配布形式・版または公式対策の適用範囲を特定できません。'
    if result['status'] not in ('ACTION', 'UPDATE'):
        value.pop('remediation', None)
    return value


def recorded_identities(records):
    """Index identities captured in the report, without resolving live links."""
    paths, python_prefixes = set(), {}
    for row in records:
        meta = row.get('metadata', {})
        tool = meta.get('tool_id')
        found_context = re.match(r'^(コンテナ [^/]+) / ', row['name'])
        context = meta.get('execution_context') or (found_context.group(1) if found_context else 'ホスト')
        if tool and meta.get('executable'):
            paths.add((tool, context, str(meta['executable'])))
        if meta.get('application') and tool:
            for path in [meta.get('path')] + list(meta.get('discovered_paths') or []):
                if path: paths.add((tool, context, str(path)))
        if 'packages' in meta and meta.get('prefix') and meta.get('executable'):
            python_prefixes.setdefault((context, str(meta['prefix'])), set()).add(str(meta['executable']))
    return paths, python_prefixes


def recover_legacy_identity(row, paths, python_prefixes):
    """Bind old version rows only when another record proves the exact path."""
    meta = row.get('metadata', {})
    name = row['name']
    value = row
    additions = {}
    if meta.get('executable') and meta.get('tool_id') and not meta.get('execution_context'):
        context = re.match(r'^(コンテナ [^/]+) / ', name)
        if context: additions['execution_context'] = context.group(1)
    java = re.match(r'^(ホスト|コンテナ [^/]+) / Java: (.+)$', name)
    if not meta.get('tool_id') and java and ('java', java[1], java[2]) in paths:
        additions.update(tool_id='java', tool_name='Java', executable=java[2], execution_context=java[1])
    if not meta.get('tool_id') and 'reference_floor' in meta:
        match = re.match(r'^(ホスト|コンテナ [^/]+) / Node\.js (.+)$', name)
        tool, label = 'node', 'Node.js'
        if not match:
            match = re.match(r'^(ホスト|コンテナ [^/]+) / Goバージョン \[(.+)\]$', name)
            tool, label = 'go', 'Go'
        if match and (tool, match.group(1), match.group(2)) in paths:
            additions.update(tool_id=tool, tool_name=label, executable=match.group(2),
                             execution_context=match.group(1))
            if tool == 'go': additions['source'] = official_versions.COMPONENT_SOURCES['go']
        if not match:
            python = re.match(r'^(ホスト|コンテナ [^/]+) / Python [^ ]+ \[(.+)\] / (?:pip|certifi|ensurepip)', name)
            targets = python_prefixes.get((python.group(1), python.group(2)), set()) if python else set()
            if python and len(targets) == 1:
                additions.update(tool_id='python', tool_name='Python', executable=next(iter(targets)),
                                 prefix=python.group(2), execution_context=python.group(1))
    if additions:
        value = dict(row, metadata=dict(meta, **additions))
    return value


def reevaluate_reference(row):
    """Update captured version verdicts when upstream rules have changed."""
    meta = row.get('metadata', {})
    version = meta.get('version')
    if (meta.get('application') or 'reference_floor' not in meta or not isinstance(version, str) or not version
            or row.get('assessment_method') not in (None, 'version')
            or row.get('status') in ('ACTION', 'REJECTED', 'INFERRED_REJECTED')):
        return row
    name, source = row['name'].lower(), meta.get('source', '')
    python_source = not source or source in (official_versions.PYTHON_SOURCE,
        version_inference.SOURCES['pip'],official_versions.COMPONENT_SOURCES['certifi'])
    kind = ('pip' if python_source and re.search(r'(?:^| / )pip(?: |$)|ensurepip', name) else
            'certifi' if python_source and re.search(r'(?:^| / )certifi(?: |$)', name) else
            'uv' if name.startswith('uvバージョン') or name.startswith('uv / バージョン') else None)
    source_map = {'pip':version_inference.SOURCES['pip'], 'certifi':official_versions.COMPONENT_SOURCES['certifi'],
                  'uv':'https://github.com/astral-sh/uv/releases/tag/0.13.5'}
    if kind:
        status, detail, floor = official_versions.reference(kind, version)
        new_meta = dict(meta, reference_floor=floor, source=source_map[kind], as_of=official_versions.AS_OF)
    else:
        kind = next((candidate for candidate in ('bun', 'deno', 'dart', 'flutter')
                     if source == language_checks.REFERENCES[candidate][1] and
                     (candidate in name or (candidate == 'flutter' and 'flutter' in name and 'dart' not in name))), None)
        if not kind:
            return row
        comparison = version+'-preview' if meta.get('preview') and re.fullmatch(r'\d+\.\d+\.\d+', version) else version
        status, detail, data = language_checks.version_result(kind, comparison)
        data['version'] = version
        new_meta = dict(meta, **data)
    value = dict(row, status=status, detail=version+' / '+detail, metadata=new_meta, assessment_method='version')
    if status not in ('ACTION', 'UPDATE'):
        value.pop('remediation', None)
    return value


def bind_environments(records):
    """Join captured environment identities; never resolve a saved report on disk."""
    aliases = snapshot_targets(records)
    python_keys, java_keys, rustup = {}, {}, {}
    for row in records:
        meta = row.get('metadata', {})
        context = meta.get('execution_context') or 'ホスト'
        if 'packages' in meta and meta.get('prefix') and meta.get('executable'):
            env = ('python', context, meta['prefix'])
            keys = [('path', meta['executable'])]
            captured = snapshot_identity(row, aliases, presentation=False)
            if captured: keys.append(('path', captured[-1]))
            if meta.get('python_identity'): keys.append(tuple(meta['python_identity']))
            for key in keys: python_keys.setdefault((context, key), set()).add(env)
        if meta.get('java_home'):
            env = ('java', context, meta['java_home'])
            if meta.get('executable'):
                key = snapshot_identity(dict(row, metadata=dict(meta, tool_id='java')), aliases, presentation=False)
                if key: java_keys.setdefault(key, set()).add(env)
        if meta.get('tool_id') == 'rustup' and meta.get('executable') and meta.get('version'):
            match = re.match(r'^(?:rustup )?(\d+\.\d+\.\d+)(?: |$)', meta['version'])
            if match:
                rustup.setdefault((context, match[1]), set()).add(meta['executable'])
    # A recorded Python installation can also bind its pip launchers when the
    # interpreter itself could not start. That identity supplies no success.
    for row in records:
        meta = row.get('metadata', {})
        if meta.get('tool_id') != 'python' or not meta.get('python_identity'):
            continue
        context = meta.get('execution_context') or 'ホスト'
        captured = snapshot_identity(row, aliases, presentation=False)
        keys = [tuple(meta['python_identity'])]
        if captured: keys.append(('path', captured[-1]))
        if meta.get('executable'): keys.append(('path', meta['executable']))
        candidates = set().union(*(python_keys.get((context, key), set()) for key in keys))
        env = next(iter(candidates)) if len(candidates) == 1 else (
            ('python', context, *meta['python_identity'][1:]) if not candidates else None)
        if env:
            for key in keys: python_keys.setdefault((context, key), set()).add(env)
    result = []
    for row in records:
        meta = dict(row.get('metadata', {}))
        # Recompute presentation identities, retaining only the captured facts.
        meta.pop('result_identity', None)
        meta.pop('result_tool_name', None)
        context = meta.get('execution_context') or 'ホスト'
        if meta.get('tool_id') == 'python' and meta.get('prefix'):
            meta.update(result_identity=['python', context, meta['prefix']], result_tool_name='Python')
        elif meta.get('tool_id') in ('python', 'pip'):
            keys = [('path', meta.get('executable') or meta.get('path'))]
            captured = snapshot_identity(row, aliases, presentation=False)
            if captured: keys.append(('path', captured[-1]))
            if meta.get('python_identity'): keys.append(tuple(meta['python_identity']))
            candidates = set().union(*(python_keys.get((context, key), set()) for key in keys))
            if len(candidates) == 1:
                meta.update(result_identity=list(next(iter(candidates))), result_tool_name='Python')
        if meta.get('java_home'):
            meta.update(tool_id='java', tool_name='Java', result_identity=['java', context, meta['java_home']])
        elif meta.get('tool_id') == 'java':
            key = snapshot_identity(dict(row, metadata=meta), aliases, presentation=False)
            candidates = java_keys.get(key, set())
            if len(candidates) == 1:
                meta.update(result_identity=list(next(iter(candidates))), result_tool_name='Java')
        if row['name'] == 'Rust / rustup' and not meta.get('executable'):
            candidates = rustup.get((context, meta.get('version')), set())
            if len(candidates) == 1:
                meta.update(tool_id='rustup', tool_name='rustup', executable=next(iter(candidates)))
        result.append(dict(row, metadata=meta))
    return result


def embedded_version_observation(row):
    """Show verified bundled versions, without turning CA absence into success."""
    meta = row.get('metadata', {})
    if not meta.get('application') or row['status'] not in ('MANUAL', 'INFERRED_OK'):
        return row
    checks = meta.get('inspections', [])
    versions = [c for c in checks if c.get('method') == 'version']
    if (not versions or any(c.get('status') in ('ACTION', 'UPDATE') for c in checks) or
            any(c.get('component_only') or c.get('status') != 'INFERRED_OK' or not c.get('reference_floor') or
                not c.get('source', '').startswith('https://') or
                Path(c.get('path', '')).name in ('bom.json', 'sbom.cdx.json', 'Cargo.lock')
                for c in versions)):
        return row
    components = sorted({c['component'] for c in versions})
    value = dict(row, status='INFERRED_OK', assessment_method='version',
                 scope='検出した同梱部品の版を公式の対策版と照合。実通信・独自CA設定は未検査。',
                 metadata=dict(meta, verified_components=components))
    value.pop('remediation', None)
    return value


def consolidate_records(records):
    """Collapse identical non-network findings only within a proven installation."""
    records = bind_environments(records)
    aliases = snapshot_targets(records)
    output, seen = [], {}
    for row in records:
        identity = snapshot_identity(row, aliases)
        if not identity or row.get('samples'):
            output.append(row)
            continue
        meta = {k:v for k,v in row['metadata'].items() if k not in ('collection_origins',)}
        key = json.dumps([identity, row['name'], row['status'], row['detail'],
                          row['assessment_method'], meta], sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen[key] = row
            output.append(row)
        else:
            kept = seen[key]
            origins = set(kept['metadata'].get('collection_origins', []))
            origins.update(row['metadata'].get('collection_origins', []))
            origins.update(v for v in (kept.get('origin'), row.get('origin')) if v)
            if origins: kept['metadata']['collection_origins'] = sorted(origins)
    return output


def prepare(records):
    """Promote evidence once; measured samples and uncertainty remain intact."""
    records = release_evidence.expand(records)
    records = research_rules.expand_java(records)
    records = version_inference.expand(records, snapshot_targets(records))
    output=[]
    snapshot_aliases = snapshot_targets(records)
    paths, python_prefixes = recorded_identities(records)
    measured_prefixes={str(r['metadata']['prefix']) for r in records if r.get('metadata',{}).get('prefix')}
    rust_paths={item.get('path') for r in records for item in r.get('evidence',[]) if item.get('kind')=='version'}
    rust_scanned={path for r in records if r['name'].startswith('Rust') for item in r.get('evidence',[]) for path in item.get('files',[])}
    dotnet_checked=any(r['name'].startswith('.NET HttpClient') for r in records)
    browser_measured={r.get('metadata',{}).get('browser') for r in records
                      if r.get('metadata',{}).get('source_type')=='native-ui' and r.get('samples')}
    for parent in records:
        parent = recover_legacy_identity(parent, paths, python_prefixes)
        parent = version_observation(parent, snapshot_aliases)
        parent = version_inference.published_assessment(parent)
        parent = version_inference.assess(parent)
        parent = reevaluate_reference(parent)
        parent = release_evidence.reassess_components(parent)
        parent = embedded_version_observation(parent)
        parent = research_rules.assess(parent)
        meta = parent.get('metadata', {})
        if 'review_state' in parent and 'assessment_method' in parent:
            output.append(finish(parent, parent['assessment_method'])); continue
        items=parent.get('evidence',[])
        name=parent['name']
        if not items:
            output.append(finish(parent)); continue
        if name.startswith('Rust'):
            for item in items:
                value=observation(parent,item,'Rust')
                if item['check']=='Cargo.lock探索' and 'files' in item:
                    value['name']='Rust / プロジェクト依存関係の探索'
                    if not item['files']: value['status']='NOT_FOUND'
                    for path in item['files']:
                        if path not in rust_paths:
                            output.append(additional('Rust / 未照合の依存関係',
                                'このCargo.lockには自動照合できたTLSライブラリがありません。',
                                'TLS通信を行うプロジェクトなら依存関係を確認してください: '+path,name,{'path':path}))
                output.append(finish(value,item['kind']))
        elif name=='Docker Engine / Desktop / BuildKit / registry':
            output.extend(observation(parent,item,'Docker') for item in items)
        elif name=='ブラウザ / 実際のプロファイル':
            checked=browser_measured | {item['check'].split(' / ')[0] for item in items if 'CRLSet' in item['check']}
            browser_aliases={'Google Chrome':'Chrome','Microsoft Edge':'Edge','Safari':'Safari','Firefox':'Firefox'}
            for item in items:
                value=observation(parent,item,'ブラウザ')
                if 'CRLSet' in item['check'] and item['check'].split(' / ')[0] in browser_measured and item['status']=='UNKNOWN':
                    value.update(status='INFO',detail=value['detail']+' この保存データだけでは結論を出さず、別項目の実際のプロファイルでの実測を参照してください。')
                    value=finish(value,'static')
                output.append(value)
                browser=browser_aliases.get(item['check'])
                if item['kind']=='inventory' and browser and browser not in checked:
                    output.append(additional('ブラウザ / '+browser+' の信頼確認',
                        '導入版は取得済みですが、このブラウザの失効情報・実通信の根拠は未取得です。',
                        '利用する場合は、このブラウザの配布元が公開する対応情報を確認してください。',name))
        elif name.startswith('.NET HttpClient'):
            inventory=next((i for i in items if i['check']=='.NET配置探索'),None)
            if parent['status']=='SKIP' and not parent['samples'] and inventory and 'executables' in inventory and 'project_markers' in inventory:
                absent=not inventory['executables'] and not inventory['project_markers']
                value=observation(parent,inventory,'.NET')
                if absent:
                    value.update(name='.NET / 探索範囲内の実行環境',status='NOT_FOUND')
                    output.append(finish(value,'inventory'))
                else:
                    output.append(value)
                    pending=dict(parent,detail='実行環境または.NETプロジェクトを検出しましたが、HttpClientの実通信は未実施です。',
                                 action='検出された.NET環境に対応したプローブを用意するか、対象アプリでTLS検査を実行してください。')
                    output.append(finish(pending,'unmeasured',required=True))
            else:
                output.append(finish(parent))
                output.extend(observation(parent,item,'.NET') for item in items)
        elif name=='対象範囲の確認':
            for item in items:
                value=observation(parent,item,'検査範囲')
                if item['check']=='指定プロジェクト探索':
                    if item.get('truncated'):
                        value.update(status='UNKNOWN',action='探索上限または読取制限があります。未確認のディレクトリを--projectで個別指定してください。')
                    for path in item.get('files',[]):
                        p=Path(path)
                        if p.name=='pyvenv.cfg' and str(p.parent) not in measured_prefixes:
                            output.append(additional('検査範囲 / 未検査のPython仮想環境',
                                '仮想環境を検出しましたが、この実行では検査対象として確認できません。',
                                '--pythonで次の仮想環境内のPythonを指定してください: '+str(p.parent),name,{'path':path}))
                        elif (p.name=='Cargo.lock' and path not in rust_scanned) or (p.name.endswith(('.csproj','.runtimeconfig.json')) and not dotnet_checked):
                            output.append(additional('検査範囲 / 未照合のプロジェクト',
                                '環境識別ファイルを検出しましたが、対応する照合結果がありません。',
                                '--projectと必要な--onlyを指定して確認してください: '+str(p.parent),name,{'path':path}))
                output.append(finish(value,item['kind']))
        else:
            output.append(finish(parent))
            output.extend(observation(parent,item,name) for item in items)
    return sorted(consolidate_records([finish(research_rules.assess(r)) for r in output]),key=lambda r:PRIORITY[r['review_state']])


def summarize(records):
    return {'total':len(records), 'status_counts':dict(Counter(r['status'] for r in records)),
            'method_counts':dict(Counter(r['assessment_method'] for r in records)),
            'application_counts':{key:sum(r.get('metadata',{}).get('application') is True and
                                         r['metadata'].get('coverage_state')==key for r in records)
                                  for key in ('static_checked','partial','uninspected')},
            'review_counts':{key:sum(r['review_state']==key for r in records) for key in PRIORITY}}
