"""Import explicitly supplied native UI observations; never drive a browser or fetch URLs."""
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
import evidence

ALIASES={'Chrome':'Google Chrome','Edge':'Microsoft Edge','Safari':'Safari','Firefox':'Firefox'}
TRUST_CODES={'Chrome':{'NET::ERR_CERT_REVOKED','NET::ERR_CERT_AUTHORITY_INVALID'},
             'Edge':{'NET::ERR_CERT_REVOKED','NET::ERR_CERT_AUTHORITY_INVALID'},
             'Safari':{'SAFARI_CERT_BLOCKED'},
             'Firefox':{'SEC_ERROR_REVOKED_CERTIFICATE','SEC_ERROR_UNKNOWN_ISSUER'}}


def load(path, records, targets, now=None):
    """Validate provenance/coverage before using the record as a scoped measurement.

    This is a local operator-supplied observation, not a cryptographic attestation.
    Only explicit allowlisted browser error codes establish trust rejection.
    """
    raw=evidence.read_public_file(path,128*1024)
    if raw is None: raise ValueError('結果ファイルを安全に読み取れません')
    try:
        doc=json.loads(raw)
        if doc['schema_version'] != 1 or doc['source'] != 'native-ui' or doc['security_bypassed'] is not False:
            raise ValueError('通常のUI観測ではないか、警告回避の有無を確認できません')
        browser=doc['browser']
        if browser not in ALIASES: raise ValueError('未対応のブラウザです')
        if not isinstance(doc['profile'],str) or not 1 <= len(doc['profile']) <= 100:
            raise ValueError('観測したプロファイルを指定してください')
        if not re.fullmatch(r'\d+(?:\.\d+){1,3}',doc['version']): raise ValueError('版の形式が不正です')
        observed=dt.datetime.fromisoformat(doc['observed_at'].replace('Z','+00:00'))
        if observed.tzinfo is None: raise ValueError('観測時刻にはタイムゾーンが必要です')
        age=((now or dt.datetime.now(dt.timezone.utc))-observed).total_seconds()
        if not 0 <= age <= 86400: raise ValueError('観測結果は24時間以内で、未来時刻でないものが必要です')
        installed={i.get('version') for r in records for i in r.get('evidence',[])
                   if i.get('check')==ALIASES[browser] and i.get('kind')=='inventory'}
        if doc['version'] not in installed: raise ValueError('観測した版と現在の導入版が一致しません')
        expected={url for _,url,_ in targets}
        values=doc['samples']
        if len(values)!=len(expected) or {s['url'] for s in values}!=expected:
            raise ValueError('通常サイトと代表4接続先を重複なく記録してください')
        refs=json.loads((Path(__file__).resolve().parent/'references/assessment.json').read_text(encoding='utf-8'))
        pins={entry['sha256'].lower() for entry in refs['certificates'] if 'TLS' in entry.get('name','')}
        samples=[]
        for label,url,control in targets:
            s=next(s for s in values if s['url']==url)
            if not isinstance(s['observation'],str) or not 1 <= len(s['observation']) <= 1000:
                raise ValueError('画面で確認した根拠が必要です')
            result=s['result']
            chain=s.get('certificate_chain_sha256',[])
            if not isinstance(chain,list) or len(chain)>32 or any(not isinstance(pin,str) or not re.fullmatch(r'[0-9a-fA-F:]{64,95}',pin) for pin in chain):
                raise ValueError('証明書指紋の形式が不正です')
            matched=any(pin.replace(':','').lower() in pins for pin in chain)
            if result=='loaded': status='CONTROL_OK' if control else 'ACTION' if matched else 'UNKNOWN'
            elif not control and result in TRUST_CODES[browser]: status='REJECTED'
            else: status='UNKNOWN'
            samples.append(dict(target=label,url=url,control=control,status=status,
                                detail=result+': '+s['observation']))
    except (KeyError,TypeError,AttributeError,StopIteration,UnicodeError) as exc:
        raise ValueError('ブラウザ結果の必須フィールド・型が不正です') from exc
    status='UNKNOWN'
    detail='接続結果または提示された証明書経路を確認できない接続先があります。'
    if any(s['status']=='ACTION' for s in samples[1:]):
        status='ACTION'; detail='通常のブラウザで検証先が表示され、記録された証明書指紋が対象と一致しました。'
    elif samples[0]['status']=='CONTROL_OK' and all(s['status']=='REJECTED' for s in samples[1:]):
        status='REJECTED'; detail='通常サイトを表示し、検査用サイトへの接続がブロックされたことを画面で確認しました。'
    return dict(name='ブラウザ / '+browser+' / 実際のプロファイル',status=status,detail=detail,
                action='ブラウザの失効情報・独自CA・TLS検査プロキシを確認し、同じプロファイルで再検査してください。',
                assessment_method='measured',samples=samples,
                scope=doc['observed_at']+' / '+browser+' '+doc['version']+' / '+doc['profile']+'。記録した検査用サイトのみ。別プロファイル・別時点は対象外。',
                metadata=dict(browser=browser,version=doc['version'],profile=doc['profile'],
                              observed_at=doc['observed_at'],source_type='native-ui',
                              evidence_file=str(Path(path).absolute()),sha256=hashlib.sha256(raw).hexdigest()))
