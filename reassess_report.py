"""Reassess a saved report into a NEW directory, without probing or networking."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import audit
import verdicts


def digest(data):
    return hashlib.sha256(data).hexdigest()


def communication_evidence(records):
    evidence = []
    for row in records:
        meta = row.get('metadata', {})
        captured = {k:v for k,v in meta.items() if k.startswith(('synthetic_tls_', 'connection_'))}
        if row.get('samples') or captured:
            evidence.append(json.dumps([row['name'],row.get('samples',[]),captured],
                                       ensure_ascii=False,sort_keys=True))
    return Counter(evidence)


def reassess(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError('出力先は新しいディレクトリを指定してください。既存ファイルは上書きしません。')
    raw = source.read_bytes()
    original = json.loads(raw)
    records = verdicts.prepare(original['records'])
    if communication_evidence(records) != communication_evidence(original['records']):
        raise ValueError('通信証拠が変わったため出力を停止しました。')
    origin = dict(path=str(source),sha256=digest(raw),tool_version=original.get('tool_version'),
                  generated_at=original.get('generated_at','不明'),new_network_requests=False,
                  new_scan_performed=False)
    destination.mkdir(parents=True,exist_ok=False)
    audit.write_reports(SimpleNamespace(records=records,source_observation=origin),destination)
    saved = json.loads((destination/'report.json').read_text(encoding='utf-8'))
    manifest = dict(source=origin,original_unchanged=digest(source.read_bytes())==digest(raw),
                    communication_evidence_unchanged=communication_evidence(saved['records'])==communication_evidence(original['records']),
                    original_records=len(original['records']),reassessed_records=len(saved['records']),
                    new_network_requests=0,new_scan_performed=False,new_observations=0,
                    derived_product_assessments=[r['name'] for r in saved['records']
                        if r.get('metadata',{}).get('product_release_evidence')],
                    outputs={name:digest((destination/name).read_bytes()) for name in ('report.json','report.html','summary.txt')})
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
    args=parser.parse_args()
    try:
        result=reassess(args.source,args.out)
    except (ValueError,OSError,KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__': main()
