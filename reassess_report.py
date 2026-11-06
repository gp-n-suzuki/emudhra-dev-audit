"""Reassess a saved report into a NEW directory, without probing or networking."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import audit
import docker_registry
import verdicts


def digest(data):
    return hashlib.sha256(data).hexdigest()


def record_digest(row):
    return digest(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8'))


def attach_confirmation(records, raw, confirmation):
    """Bind a user's separate statement to one exact saved record, without edits."""
    value = json.loads(confirmation)
    if not docker_registry.confirmation_facts(value):
        raise ValueError('追加確認結果の形式が不正です。自動観測とは別のユーザー確認として指定してください。')
    if value['source_sha256'] != digest(raw):
        raise ValueError('追加確認結果の元レポートSHA256が一致しません。別の診断には適用できません。')
    targets = [i for i, row in enumerate(records) if record_digest(row) == value['record_sha256']]
    if len(targets) != 1:
        raise ValueError('追加確認結果の対象記録を一意に特定できません。')
    index = targets[0]
    row = records[index]
    if (row.get('name') != 'Docker / registryのTLS設定' or row.get('samples') or
            row.get('assessment_method') not in (None, 'configuration') or
            'registry_user_confirmation' in row.get('metadata', {})):
        raise ValueError('追加確認結果を適用できるregistry設定の原記録ではありません。')
    return [dict(r, metadata=dict(r.get('metadata', {}), registry_user_confirmation=value)) if i == index else r
            for i, r in enumerate(records)]


def communication_evidence(records):
    evidence = []
    for row in records:
        meta = row.get('metadata', {})
        captured = {k:v for k,v in meta.items() if k.startswith(('synthetic_tls_', 'connection_'))}
        if row.get('samples') or captured:
            evidence.append(json.dumps([row['name'],row.get('samples',[]),captured],
                                       ensure_ascii=False,sort_keys=True))
    return Counter(evidence)


def reassess(source, destination, docker_confirmation=None):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError('出力先は新しいディレクトリを指定してください。既存ファイルは上書きしません。')
    raw = source.read_bytes()
    original = json.loads(raw)
    input_records = original['records']
    confirmation = None
    if docker_confirmation is not None:
        with Path(docker_confirmation).open('rb') as stream:
            confirmation = stream.read(65537)
        if len(confirmation) > 65536:
            raise ValueError('追加確認結果は64 KiB以下のJSONにしてください。')
        input_records = attach_confirmation(input_records, raw, confirmation)
    records = verdicts.prepare(input_records)
    if communication_evidence(records) != communication_evidence(original['records']):
        raise ValueError('通信証拠が変わったため出力を停止しました。')
    origin = dict(path=str(source),sha256=digest(raw),tool_version=original.get('tool_version'),
                  generated_at=original.get('generated_at','不明'),new_network_requests=False,
                  new_scan_performed=False)
    if confirmation is not None:
        origin['user_confirmation'] = dict(source='user-provided', file='user-confirmation.json',
                                           sha256=digest(confirmation), automatic_observation=False)
    destination.mkdir(parents=True,exist_ok=False)
    audit.write_reports(SimpleNamespace(records=records,source_observation=origin),destination)
    if confirmation is not None:
        (destination/'user-confirmation.json').write_bytes(confirmation)
    saved = json.loads((destination/'report.json').read_text(encoding='utf-8'))
    manifest = dict(source=origin,original_unchanged=digest(source.read_bytes())==digest(raw),
                    communication_evidence_unchanged=communication_evidence(saved['records'])==communication_evidence(original['records']),
                    original_records=len(original['records']),reassessed_records=len(saved['records']),
                    new_network_requests=0,new_scan_performed=False,new_observations=0,
                    user_confirmations=sum(bool(r.get('metadata',{}).get('registry_user_confirmation')) for r in records),
                    derived_product_assessments=[r['name'] for r in saved['records']
                        if r.get('metadata',{}).get('product_release_evidence')],
                    outputs={name:digest((destination/name).read_bytes()) for name in ('report.json','report.html','summary.txt')})
    if confirmation is not None:
        manifest['outputs']['user-confirmation.json'] = digest(confirmation)
    (destination/'reassessment.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if not manifest['original_unchanged'] or not manifest['communication_evidence_unchanged']:
        raise ValueError('出力後の不変確認に失敗しました。reassessment.jsonを確認してください。')
    return manifest


def main():
    # Match the diagnostic CLI when Windows redirects streams using a legacy encoding.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source',type=Path)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--docker-confirmation',type=Path,
                        help='元レポート・記録のSHA256に結び付けたユーザー提供の追加確認JSON（自動観測と区別して保存）')
    args=parser.parse_args()
    try:
        result=reassess(args.source,args.out,args.docker_confirmation)
    except (ValueError,OSError,KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__': main()
