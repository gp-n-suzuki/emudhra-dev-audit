"""Version evidence tied to a captured installation or its actual Node entry point."""
import json
import os
from pathlib import Path
import re

import app_inventory
import evidence
import language_checks
import official_versions

NODE_SOURCE = 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases'
UV_SOURCE = 'https://github.com/astral-sh/uv/releases/tag/0.13.5'
SOURCES = dict(official_versions.COMPONENT_SOURCES, node=NODE_SOURCE, uv=UV_SOURCE,
               pip='https://pip.pypa.io/en/stable/news/#v26-2-2')
NODE_PACKAGES = {
    'npm': ('npm',), 'pnpm': ('pnpm',), 'yarn': ('yarn', '@yarnpkg/cli-dist'),
    'corepack': ('corepack',), 'gemini-cli': ('@google/gemini-cli',),
    'firebase': ('firebase-tools',), 'vercel': ('vercel',), 'netlify': ('netlify-cli',),
    'wrangler': ('wrangler',), 'claude-code': ('@anthropic-ai/claude-code',),
}
LABELS = {'npm':'npm', 'pnpm':'pnpm', 'yarn':'Yarn', 'corepack':'Corepack',
          'gemini-cli':'Gemini CLI', 'firebase':'Firebase CLI', 'vercel':'Vercel CLI',
          'netlify':'Netlify CLI', 'wrangler':'Wrangler', 'claude-code':'Claude Code'}
VERSION = r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?'
NODE_SCOPE = 'この導入が使用するNode.jsの標準の証明書データを版照合。アプリ独自のCA・通信設定は別に確認します。'


def published_assessment(row):
    meta = row.get('metadata', {})
    application = meta.get('application')
    if row.get('samples') or row.get('assessment_method') not in (None,'inventory','version','manual'):
        return row
    if row['status'] not in ('INFO','MANUAL','UNKNOWN','UPDATE','REFERENCE_OK','INFERRED_OK'):
        return row
    if application:
        if (not meta.get('path') or row['status'] == 'UPDATE' or
                any(c.get('status') in ('ACTION','UPDATE') for c in meta.get('inspections', []))):
            return row
        result = official_versions.published(meta.get('tool_id'),meta.get('application_version'),meta.get('bundle_identifier'))
    else:
        if not meta.get('executable') or not row['name'].endswith(' / バージョン'):
            return row
        result = official_versions.published(meta.get('tool_id'),meta.get('version'))
    if not result: return row
    fields = {k:v for k,v in result.items() if k not in ('status','detail','scope')}
    value = dict(row,status=result['status'], detail=result['detail'],scope=result['scope'],
                 assessment_method='version',metadata=dict(meta,**fields))
    value.pop('remediation',None)
    return value


def assess(row):
    """Do not overwrite a measured result or a configuration finding with a version."""
    meta = row.get('metadata', {})
    runtime = meta.get('runtime_component') == 'node'
    if (meta.get('application') or row.get('samples') or
            row.get('assessment_method') not in (None, 'inventory', 'version') or
            row['status'] not in ('INFO', 'MANUAL', 'UNKNOWN', 'UPDATE', 'REFERENCE_OK', 'INFERRED_OK')):
        return row
    if not meta.get('executable'):
        return row
    kind = 'node' if runtime else meta.get('tool_id')
    if not runtime and not row['name'].endswith(' / バージョン'):
        return row
    version = meta.get('runtime_version') if runtime else meta.get('version')
    if not isinstance(version, str) or not version:
        return row
    if kind in ('bun', 'deno', 'dart', 'flutter'):
        status, detail, fields = language_checks.version_result(kind, version)
        scope = language_checks.SDK_SCOPE if kind in ('dart', 'flutter') else kind+'の標準TLS実装の版照合。独自CA・設定は別に確認します。'
    elif kind in ('uv', 'node', 'go', 'pip', 'certifi'):
        status, detail, floor = official_versions.reference(kind, version)
        fields = dict(reference_floor=floor, source=SOURCES[kind], as_of=official_versions.AS_OF)
        scope = (NODE_SCOPE if runtime else
                 'uvの標準の証明書データと漏えいした鍵の拒否を照合。0.13.4はCA更新、0.13.5は鍵の拒否も含みます。管理下Python・既存venvは別に更新します。' if kind == 'uv' else
                 'pipの同梱certifiの版照合。pip 24.2以上のsystem roots併用・PIP_CERT/REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE・実通信は別に確認します。' if kind=='pip' else
                 kind+'の標準TLS・証明書データの版照合。独自CA・別の通信部品は別に確認します。')
    else:
        return row
    value = dict(row, status=status, detail=version+' / '+detail, assessment_method='version',
                 scope=scope, metadata=dict(meta, **fields))
    if status not in ('ACTION', 'UPDATE'):
        value.pop('remediation', None)
    return value


def context(meta):
    return meta.get('execution_context') or 'ホスト'


def runtime_row(parent, version, basis, executable=None):
    meta = parent['metadata']
    fields = {key:meta[key] for key in ('tool_id', 'tool_name', 'executable', 'execution_context') if key in meta}
    fields.update(runtime_component='node', runtime_version=version, runtime_basis=basis)
    if executable:
        fields['runtime_executable'] = executable
    if basis == 'version-output':
        fields['reported_version'] = meta['version']
    return dict(name=meta.get('tool_name', meta['tool_id'])+' / 使用するNode.js',
                status='INFO', detail='使用するNode.js: '+version, action='', samples=[],
                assessment_method='version', metadata=fields)


def expand(records, aliases):
    """Derive component rows from this snapshot only; never resolve today's links."""
    def node_key(meta, path):
        ctx = context(meta)
        targets = aliases.get(('node', path), set()) if ctx == 'ホスト' else set()
        return (ctx, next(iter(targets)) if targets else path) if len(targets) <= 1 else None
    versions = {}
    for row in records:
        meta = row.get('metadata', {})
        if (meta.get('tool_id') == 'node' and meta.get('executable') and
                row.get('assessment_method') in (None, 'version', 'inventory') and not row.get('samples') and
                re.fullmatch('v?'+VERSION, str(meta.get('version', '')))):
            key = node_key(meta, meta['executable'])
            if key: versions.setdefault(key, set()).add(meta['version'].lstrip('v'))
    def identity(meta):
        return (context(meta), meta.get('tool_id'), meta.get('executable'), 'node')
    candidates = {}
    existing = {identity(r.get('metadata', {})) for r in records if r.get('metadata', {}).get('runtime_component')}
    for row in records:
        meta = row.get('metadata', {})
        if not meta.get('executable') or not meta.get('tool_id') or identity(meta) in existing:
            continue
        child = None
        if (meta['tool_id'] == 'heroku' and row['name'].endswith(' / バージョン') and
                row.get('assessment_method') in (None, 'inventory', 'version') and
                row['status'] in ('INFO', 'MANUAL', 'UNKNOWN') and not row.get('samples')):
            match = re.fullmatch(r'heroku/\S+ [A-Za-z0-9_-]+ node-v('+VERSION+')', str(meta.get('version','')))
            if match: child = runtime_row(row, match[1], 'version-output')
        elif (meta['tool_id'] in ('pnpm', 'yarn') and meta.get('probe') == 'synthetic_node_registry' and
              meta.get('runtime_executable')):
            values = versions.get(node_key(meta, meta['runtime_executable']), set())
            if len(values) == 1:
                child = runtime_row(row, next(iter(values)), 'recorded-adapter', meta['runtime_executable'])
        if child:
            candidates.setdefault(identity(meta), []).append(child)
    additions = [rows[0] for rows in candidates.values()
                 if len({r['metadata']['runtime_version'] for r in rows}) == 1]
    return list(records)+additions


def node_entrypoint(path, tool, find, node_aliases=None):
    """Recognize direct package bin scripts, not wrappers, engines ranges or nearby Node."""
    if tool not in NODE_PACKAGES:
        return None
    try:
        path = Path(path)
        if not evidence.public_path(path) or '/shims/' in path.as_posix().lower(): return None
        script = path.resolve()
        if (not evidence.public_path(script) or not script.is_file() or
                '/shims/' in script.as_posix().lower()): return None
        with script.open('rb') as stream:
            header = stream.readline(512).decode('utf-8', 'replace').strip()
        match = re.fullmatch(r'#!\s*(/[^\s]+)(?:\s+(node))?\s*', header)
        if not match: return None
        command, argument = match.groups()
        if command == '/usr/bin/env' and argument == 'node':
            node = find('node')
        elif argument is None and Path(command).name == 'node':
            node = command
        else:
            return None
        targets = (node_aliases or {}).get(node, set())
        if len(targets)>1: return None
        if targets: node = next(iter(targets))
        if not node or not evidence.public_path(node) or not Path(node).is_file(): return None
        normalized = str(node).replace('\\', '/').lower()
        resolved = Path(node).resolve().as_posix().lower()
        if any(mark in value for mark in ('/shims/', '/.volta/bin/') for value in (normalized, resolved)): return None
        with Path(node).open('rb') as stream:
            if not stream.read(16).startswith(app_inventory.NATIVE_MAGIC): return None
        for parent in list(script.parents)[:5]:
            raw = evidence.read_public_file(parent/'package.json', 65536)
            if raw is None: continue
            data = json.loads(raw)
            is_corepack = tool in ('pnpm','yarn') and data.get('name')=='corepack'
            if data.get('name') not in NODE_PACKAGES[tool] and not is_corepack: continue
            bins = data.get('bin', {})
            if is_corepack:
                bins = {tool:bins[tool]} if isinstance(bins,dict) and tool in bins else {}
            bins = [bins] if isinstance(bins, str) else list(bins.values()) if isinstance(bins, dict) else []
            for entry in bins:
                if not isinstance(entry, str) or not evidence.public_path(parent/entry): continue
                target = (parent/entry).resolve()
                if target == script and parent in target.parents:
                    return str(node), str(script)
    except (OSError, ValueError, TypeError, RuntimeError, AttributeError):
        pass
    return None


def collect(audit):
    """Read approved CLI entry points and query only the identified native Node version."""
    seen, cache = set(), {}
    node_aliases = {}
    for row in audit.records:
        m=row.get('metadata',{})
        if (m.get('tool_id')=='node' and m.get('executable') and m.get('resolved_executable') and
                m.get('execution_context') in (None,'ホスト')):
            node_aliases.setdefault(m['executable'],set()).add(m['resolved_executable'])
    for tool, paths in audit.discovered.items():
        if tool not in NODE_PACKAGES: continue
        # Reading the exact entry point and invoking native Node --version never
        # starts the package CLI, Safe Chain, its proxy or install hooks.
        for path in paths:
            binding = node_entrypoint(path, tool, audit.host.find, node_aliases)
            if not binding: continue
            node, script = binding
            if (tool, script) in seen: continue
            seen.add((tool, script))
            if node not in cache:
                env = {'NODE_OPTIONS':'', 'NODE_PATH':'', 'HOME':str(audit.work), 'USERPROFILE':str(audit.work)}
                rc, out, err = audit.host.call([node, '--version'], timeout=12, env=env)
                text = out.strip()
                cache[node] = text.lstrip('v') if rc == 0 and re.fullmatch('v?'+VERSION, text) else ''
            version = cache[node]
            meta = dict(tool_id=tool, tool_name=LABELS[tool], executable=path,
                        runtime_component='node', runtime_version=version, runtime_executable=node,
                        runtime_basis='entrypoint', entrypoint=script, execution_context='ホスト')
            if tool in audit.package_protected:
                meta['package_transport_unmeasured'] = True
            audit.add(LABELS[tool]+' / 使用するNode.js', 'INFO' if version else 'UNKNOWN',
                      '使用するNode.js: '+version if version else 'この起動経路のNode.jsの版を取得できません。', meta)
            if os.environ.get('NODE_TLS_REJECT_UNAUTHORIZED') == '0':
                audit.add(LABELS[tool]+' / TLS設定', 'ACTION', 'NODE_TLS_REJECT_UNAUTHORIZED=0 が設定されています。',
                          dict(tool_id=tool, tool_name=LABELS[tool], executable=path, execution_context='ホスト'))
