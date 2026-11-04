"""Product release evidence bound to one recorded installation.

Reassessment reads captured facts only. It never resolves paths, launches a
product, or substitutes a host runtime for that product's TLS implementation.
"""
from functools import lru_cache
import json
from pathlib import Path
import re


@lru_cache(maxsize=1)
def policy():
    return json.loads((Path(__file__).parent/'references/official-research.json').read_text(encoding='utf-8'))['targets']['safe-chain']['release_policy']


def stable_version(raw):
    if not isinstance(raw, str):
        return None
    match = re.fullmatch(r'v?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))', raw.strip())
    return match[1] if match else None


def identity(meta):
    return (meta.get('execution_context') or 'ホスト', meta.get('path') or meta.get('executable'))


def safechain_provenance(meta, version, records):
    security = meta.get('security_tool', {})
    if str(security.get('runtime', '')).startswith('node') or security.get('version_source') == 'package.json':
        return 'external-runtime', {'basis': 'recorded-node-launcher'}
    if security.get('distribution') in ('custom', 'npm', 'external-runtime'):
        return security['distribution'], {'basis': 'recorded-distribution'}
    digest = security.get('binary_sha256')
    asset = policy()['binary_hashes'].get(digest) if isinstance(digest, str) else None
    if asset:
        if asset['version'] != version:
            return 'conflict', {'basis': 'binary-hash-version-conflict'}
        return 'official-bundled', dict(asset, basis='official-release-sha256', sha256=digest)
    if digest is not None:
        return 'unknown', {'basis': 'recorded-hash-not-in-reviewed-assets'}
    # The historical probe only reached "measured" for the pinned official
    # 1.5.26 macOS arm64 binary, after verifying both original and copy hashes.
    # Use that recorded execution contract, not the TLS cases as eMudhra proof.
    if version == '1.5.26' and security.get('version_source') == '本体内のパッケージ情報':
        for record in records:
            probe = record.get('metadata', {})
            if (probe.get('tool_id') == 'safe-chain' and identity(probe) == identity(meta)
                    and record.get('assessment_method') == 'measured'
                    and probe.get('probe') == 'safechain_synthetic_tls'
                    and probe.get('synthetic_tls_state') == 'measured'
                    and probe.get('synthetic_tls_cases') == {'trusted': 'accepted', 'untrusted': 'rejected', 'mismatch': 'rejected'}):
                return 'official-bundled', dict(basis='recorded-pinned-probe-contract',
                    collector_contract='safechain_synthetic_tls / official 1.5.26 macos-arm64',
                    source_record=record['name'], limitation='過去の限定プローブの実行条件による配布推定。今回ハッシュを再取得した結果ではありません。')
    return 'unknown', {'basis': 'distribution-unverified'}


def expand(records):
    # Rebuild derived version rows to make saved-report reassessment idempotent.
    original = [r for r in records if not r.get('metadata', {}).get('product_release_evidence')]
    grouped = {}
    for record in original:
        meta = record.get('metadata', {})
        if meta.get('tool_id') != 'safe-chain' or not identity(meta)[1]:
            continue
        if meta.get('security_tool') or record['name'].endswith(' / バージョン'):
            grouped.setdefault(identity(meta), []).append(record)
    added = []
    rule = policy()
    for key, candidates in grouped.items():
        parent = candidates[0]
        meta = parent['metadata']
        raw_values = []
        for row in candidates:
            fields = row['metadata']
            raw_values.extend(v for v in (fields.get('security_tool', {}).get('version'),
                fields.get('application_version'), fields.get('version')) if v not in (None, ''))
        normalized = {stable_version(v) for v in raw_values}
        version = next(iter(normalized)) if len(normalized) == 1 and None not in normalized else None
        evidence = [safechain_provenance(r['metadata'], version, original) for r in candidates]
        distributions = {kind for kind, _ in evidence if kind != 'unknown'}
        if len(distributions) > 1:
            distribution, provenance = 'conflict', {'basis': 'recorded-distribution-conflict'}
        elif any(p.get('basis') == 'recorded-hash-not-in-reviewed-assets' for _,p in evidence):
            distribution, provenance = 'unknown', {'basis': 'recorded-hash-not-in-reviewed-assets'}
        else:
            distribution, provenance = next((e for e in evidence if e[0] != 'unknown'), evidence[0])
        status, detail = 'MANUAL', '取得した版または配布形式に対応する公式対策の適用を確認できません。'
        if distribution == 'official-bundled' and version in rule['known_affected_versions']:
            status, detail = 'UPDATE', '公式バイナリ1.5.26は、同梱Nodeの対策を含む確認済み対策版1.5.27未満です。更新してください。'
        elif distribution == 'official-bundled' and version in rule['known_fixed_versions']:
            status, detail = 'REFERENCE_OK', '公式バイナリ1.5.27は同梱Node.js 24.22.1の対策を含む確認済みの対策版です。'
        elif distribution in ('external-runtime', 'npm'):
            detail = 'npm・外部Node構成はSafe Chain本体版だけで判定できません。同じ起動経路のNodeとCA設定が必要です。'
        elif version and distribution == 'official-bundled':
            detail = 'この公式版は確認済み対策版・直接の対象前版の範囲外です。未知の過去版や後続版へ基準を流用しません。'
        if len(normalized) > 1:
            detail = '同じ導入の取得済み版情報が一致しないため判定できません。'
        fields = dict(tool_id='safe-chain', tool_name='Safe Chain', executable=key[1],
            execution_context=key[0], product_release_evidence=True,
            evidence_origin='derived-from-recorded-evidence', new_observation=False,
            version=raw_values[0] if raw_values and isinstance(raw_values[0], str) else '', recorded_versions=raw_values,
            assessed_version=version or '', version_basis='official-release',
            release_distribution=distribution, release_provenance=provenance,
            source=rule['source'], as_of=rule['checked_at'], first_fixed_version=None,
            known_fixed_versions=rule['known_fixed_versions'],
            release_review=bool(version and distribution in ('unknown', 'custom', 'conflict')),
            reference_floor='1.5.27' if status in ('UPDATE', 'REFERENCE_OK') else None)
        added.append(dict(name='Safe Chain / 公式配布版の照合', status=status, detail=detail,
            action='公式1.5.27リリースのSafe Chain配布物と適用範囲を確認してください。',
            metadata=fields, samples=[], assessment_method='version',
            scope='同じ導入実体の公式バイナリと同梱Nodeの版照合。普段の通信・独自CA・npm版・Endpoint/Noonは別の確認です。'))
    return original + added


def reassess_components(row):
    """Recompare captured components inside this recorded application boundary."""
    import app_inventory
    import official_versions
    import language_checks
    import research_rules

    meta = row.get('metadata', {})
    if (not meta.get('application') or not meta.get('path') or row.get('samples')
            or row.get('assessment_method') not in (None, 'inventory', 'manual', 'version')
            or row['status'] not in ('MANUAL', 'UNKNOWN', 'INFO', 'INFERRED_OK', 'UPDATE')):
        return row
    root = str(meta['path']).replace('\\', '/').rstrip('/')
    checks, changed = [], False
    for check in meta.get('inspections', []):
        path = str(check.get('path', '')).replace('\\', '/')
        bound = path == root or path.startswith(root+'/')
        component, version = check.get('component'), check.get('version')
        eligible = (bound and '..' not in path.split('/') and check.get('method') == 'version'
                    and isinstance(version, str) and check.get('status') in ('MANUAL','UNKNOWN','UPDATE','INFERRED_OK')
                    and path.rsplit('/',1)[-1] not in ('bom.json','sbom.cdx.json','Cargo.lock'))
        result = None
        if eligible and component in ('electron','go','node','nss','certifi','rustls-webpki','webpki-roots','webpki-root-certs'):
            result = app_inventory.version_check(official_versions.reference, component, version, path)
        elif eligible and component == 'bun':
            status, detail, fields = language_checks.version_result('bun', version)
            result = dict(fields, status=status, detail=detail, method='version', component=component, path=path)
        elif eligible and str(component).startswith('Java ') and check.get('vendor'):
            assessed = research_rules.java(dict(version=version, runtime_version=check.get('runtime_version',version), vendor=check['vendor']))
            result = dict(assessed, status='INFERRED_OK' if assessed['status']=='REFERENCE_OK' else assessed['status'])
        valid_nss = component == 'nss' and re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version or '')
        if (eligible and component in ('go','node','nss','certifi','rustls-webpki','webpki-roots','webpki-root-certs','bun')
                and stable_version(version) is None and not valid_nss):
            result = dict(status='MANUAL', reference_floor=None,
                          detail='部品の版に独自表記・曖昧さがあるため、公式の版として比較できません。')
        if not eligible and check.get('method') == 'version' and check.get('status') in ('UPDATE','INFERRED_OK'):
            result = dict(status='MANUAL', reference_floor=None,
                          detail='同じ導入実体の部品版として確認できないため、保存済みの版判定を引き継ぎません。')
        if result:
            captured = check.get('captured_assessment') or {k:check.get(k) for k in ('status','reference_floor','source')}
            result = dict(check, **result, captured_assessment=captured, reassessed_at='2026-11-02')
            checks.append(result); changed = True
        else:
            checks.append(check)
    if not changed:
        return row
    value = dict(row, metadata=dict(meta, inspections=checks))
    value['metadata']['release_review'] = any(c.get('release_review') for c in checks)
    versions = [c for c in checks if c.get('method') == 'version']
    if versions:
        # Parent prose, links and guidance must describe the new comparison too.
        # Keep previous per-component verdicts only in captured_assessment.
        value.update(detail='取得済みの同梱部品を再照合。'+' / '.join(dict.fromkeys(
            str(c['component'])+' '+str(c.get('version',''))+': '+c.get('detail','') for c in versions)),
            action='', scope='同じ導入実体で取得した部品の版照合。実通信・独自CA設定は未検査。'+' / '.join(dict.fromkeys(c['scope'] for c in versions if c.get('scope'))))
        for field in ('reference_floor','source'):
            values = {c.get(field) for c in versions if c.get(field)}
            if len(values) == 1: value['metadata'][field] = next(iter(values))
            else: value['metadata'].pop(field,None)
    if any(c.get('status') == 'UPDATE' for c in checks):
        value.update(status='UPDATE', assessment_method='version')
    elif row['status'] in ('UPDATE','INFERRED_OK'):
        value.update(status='MANUAL', assessment_method='version')
    value.pop('remediation', None)
    return value
