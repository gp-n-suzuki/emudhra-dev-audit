"""Reviewed release facts, with conditions kept separate from measured transport.

Inputs are captured observations only. No filesystem resolution of installations,
program execution, or network access takes place while reassessing a report.
"""
from functools import lru_cache
from itertools import islice
import json
from pathlib import Path
import re

AS_OF = '2026-11-02'
SEMVER = r'(\d+\.\d+\.\d+)'
# Full output formats prevent another component's version or a custom suffix from
# being mistaken for the product release. Floors stay within reviewed series.
RULES = {
    'rustup': (r'rustup '+SEMVER+r'(?: \([0-9a-f]+ \d{4}-\d{2}-\d{2}\))?', '1.29.2', (1,29),
               'https://blog.rust-lang.org/2026/10/20/Rustup-1.29.2/'),
    'aws': (r'aws-cli/'+SEMVER+r'(?: Python/[^\s]+ [^\r\n]+)?', '2.38.4', (2,),
            'https://github.com/aws/aws-cli/pull/10786'),
    'gcloud': (r'Google Cloud SDK '+SEMVER, '590.0.1', (),
               'https://docs.cloud.google.com/sdk/docs/release-notes'),
    'buildkit': (r'build(?:ctl|kitd)(?: github.com/moby/buildkit)? v'+SEMVER+r'(?: [0-9a-f]+)?', '0.34.1', (0,34),
                 'https://github.com/moby/buildkit/releases/tag/v0.34.1'),
    'terraform': (r'Terraform v'+SEMVER, '1.16.7', (1,),
                  'https://github.com/hashicorp/terraform/releases/tag/v1.16.7'),
    'gh': (r'gh version '+SEMVER+r'(?: \(\d{4}-\d{2}-\d{2}\))?', '2.102.1', (2,),
           'https://github.com/cli/cli/releases/tag/v2.102.1'),
    'hex': (r'Hex:\s*'+SEMVER, '2.5.4', (2,5),
            'https://github.com/hexpm/hex/releases/tag/v2.5.4'),
    'composer': (r'Composer(?: version)? '+SEMVER+r'(?: \d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?)?', '2.11.0', (2,),
                 'https://github.com/composer/composer/releases/tag/2.11.0'),
    'rebar3': (r'rebar '+SEMVER+r'(?: on Erlang/OTP [0-9.]+ Erts [0-9.]+)?', '3.28.0', (3,),
               'https://github.com/erlang/rebar3/releases/tag/3.28.0'),
    'conda': (r'conda '+SEMVER, '26.9.4', (26,),
              'https://conda.org/blog/2026-10-21-emudhra-security-updates/'),
    'docker': (r'Docker version '+SEMVER+r', build [0-9a-f]+', '29.9.2', (29,),
               'https://docs.docker.com/engine/release-notes/29/'),
}
CONDITIONS = {
    'composer': '本体は対策版です。送信前の保護にはPHP 8.4以上とcurlが必要です。古いPHP・streams経路では送信後に検出するため、使用するPHPと通信方式を確認してください。',
    'rebar3': '本体は対策版です。この版はOSのCAを使うため、OSの証明書更新も確認してください。',
    'conda': '本体は対策版です。同じ環境のcertifi 2026.10.19以上とCAパッケージ（main 2026.10.20／conda-forge 2026.10.19以上）を確認してください。',
}


@lru_cache(maxsize=1)
def catalog():
    data=json.loads((Path(__file__).parent/'references/official-research.json').read_text(encoding='utf-8'))
    data['targets']['java']['variants']=data['java_variants']
    return data['targets']


def nums(text):
    return tuple(map(int, re.findall(r'\d+', text)))


def java_output(text):
    """Extract only public JVM identity fields, not echoed JAVA_TOOL_OPTIONS."""
    lines=[line for line in text.splitlines() if re.match(r'^(?:openjdk |java |Java\(TM\)|OpenJDK |Java HotSpot)',line)]
    text='\n'.join(lines)
    version=re.search(r'version "([0-9._]+)"',text)
    runtime=re.search(r'Runtime Environment[^\n]*\(build ([0-9A-Za-z.+_-]+)\)',text)
    vendor=('Amazon.com Inc.' if 'Corretto-' in text else 'Eclipse Adoptium' if 'Temurin-' in text else
            'Oracle Corporation' if 'Java(TM)' in text else '')
    return dict(version=version[1] if version else '', runtime_version=runtime[1] if runtime else '',vendor=vendor)


def hex_archives(root):
    """Read bounded Hex archive metadata; never load a Mix project or plugin."""
    import evidence
    rows=[]
    if not evidence.public_path(root): return rows
    try:
        for archive in sorted(islice(Path(root).iterdir(),128)):
            if not re.fullmatch(r'hex-\d+\.\d+\.\d+',archive.name) or not evidence.public_path(archive): continue
            app=archive/archive.name/'ebin/hex.app'
            text=evidence.read_public_file(app,65536)
            if text is not None: text=text.decode('utf-8','replace')
            if not text or not re.search(r'\{application,\s*hex,',text): continue
            match=re.search(r'\{vsn,\s*"(\d+\.\d+\.\d+)"\}',text)
            if not match: continue
            rows.append(dict(name='Hex / バージョン',status='INFO',detail='Hex: '+match[1],action='',samples=[],
                             assessment_method='inventory',metadata=dict(tool_id='hex',tool_name='Hex',
                             executable=str(app),version='Hex: '+match[1],version_source='archive-metadata')))
    except (OSError,ValueError): pass
    return rows


def release(tool, text):
    if tool == 'git':
        match = re.fullmatch(r'git version (2\.\d+\.\d+\.windows\.\d+)', text)
        if not match: return None
        version, floor = match[1], '2.56.0.windows.3'
        source = 'https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.3'
    else:
        rule = RULES.get(tool)
        if not rule: return None
        pattern, floor, family, source = rule
        match = re.fullmatch(pattern, text)
        if not match or nums(match[1])[:len(family)] != family: return None
        version = match[1]
        if tool == 'terraform':
            if nums(version)[1] > 17: return None
            if nums(version)[1] == 17:
                floor = '1.17.0'
                source = 'https://github.com/hashicorp/terraform/releases/tag/v1.17.0'
    fixed = nums(version) >= nums(floor)
    return dict(status='MANUAL' if fixed and tool in CONDITIONS else 'REFERENCE_OK' if fixed else 'UPDATE',
                version=version, reference_floor=floor, source=source, as_of=AS_OF,
                version_basis='official-release', release_status='fixed' if fixed else 'older',
                detail=CONDITIONS[tool] if fixed and tool in CONDITIONS else
                       '公式の対策版 {} {}。'.format(floor, '以上です' if fixed else '未満です'),
                scope=catalog()[tool]['basis']+'。'+catalog()[tool]['notes'])


def java(meta):
    vendor, runtime = meta.get('vendor',''), meta.get('runtime_version','')
    result = dict(status='MANUAL', reference_floor=None, version=runtime or meta.get('version',''),
                  source='https://www.oracle.com/security-alerts/alert-cve-2026-114820.html',
                  version_basis='official-release', as_of=AS_OF,
                  detail='このJDKの配布元と完全なビルド番号に対応する対策版を確認できません。',
                  scope='このJDKの標準JSSE・信頼ストアの版照合。独自truststore・TrustManagerは別の判定。')
    if vendor == 'JetBrains s.r.o.':
        result.update(source='https://blog.jetbrains.com/security/2026/10/compromised-emudhra-certificates-ides/',
                      scope='同一実体のJBR標準JSSE・信頼ストアのみ。JCEFの拒否データ配信、jetbrainsd、独自truststore・通常通信は別に確認が必要。',
                      component_only=True)
        jbr = re.fullmatch(r'(\d+(?:\.\d+)+)\+(-?\d+)-b(\d+)\.(\d+)',runtime)
        if not jbr: return result
        known = {(25,635):('25.0.4.1',79),(25,508):('25.0.4.1',41),
                 (25,329):('25.0.4.1',142),(21,1163):('21.0.11',125),(21,1038):('21.0.9',91)}
        fixed = known.get((nums(jbr[1])[0],int(jbr[3])))
        if not fixed: return result
        base, build = fixed
        floor = base+'b'+jbr[3]+'.'+str(build)
        standard = not jbr[2].startswith('-')
        at_least = nums(jbr[1]) >= nums(base) and int(jbr[4]) >= build
        result.update(reference_floor=floor, first_fixed_version=None, known_fixed_versions=[floor],
                      release_review=not (standard and at_least))
        if standard and at_least:
            result.update(status='REFERENCE_OK',detail='同じJBRビルド系列の確認済み対策版 '+floor+' 以上です。JCEF等の対策は別です。')
        else:
            result['detail']=('独自ビルドのため配布元のバックポート確認が必要です。' if not standard else
                              '同系列の確認済み対策ビルドを下回ります。初回対策版は未確定のため未対応とは断定しません。')+' 確認済み対策版: '+floor+'。JCEF等は別途確認してください。'
        return result
    match = re.fullmatch(r'(\d+(?:\.\d+)+)\+(\d+)(?:-LTS)?', runtime)
    if vendor == 'Oracle Corporation':
        java8 = re.fullmatch(r'1\.8\.0_(\d+)-b(\d+)',runtime)
        if java8:
            version, floor = (8,int(java8[1]),int(java8[2])), (8,511,33)
            display = '8u511-b33'
        elif match:
            version = nums(match[1])+(int(match[2]),)
            major = version[0]
            floors = {27:(27,0,1,0,3,1),25:(25,0,5,0,3,1),21:(21,0,13,0,3,1),
                      17:(17,0,21,0,3,1),11:(11,0,33,0,3,1)}
            if major not in floors or len(version) != 6: return result
            floor=floors[major]; display='.'.join(map(str,floor[:-1]))+'+'+str(floor[-1])
        else: return result
        result.update(status='REFERENCE_OK' if version >= floor else 'UPDATE', reference_floor=display)
    elif vendor in ('Amazon.com Inc.','Eclipse Adoptium') and match:
        major = nums(match[1])[0]
        floors = ({27:(27,0,1,11),25:(25,0,5,10),21:(21,0,13,11),17:(17,0,21,11),11:(11,0,33,10)}
                  if vendor=='Amazon.com Inc.' else {25:(25,0,5,8),21:(21,0,13,9)})
        if major not in floors: return result
        floor=floors[major]; version=nums(match[1])+(int(match[2]),)
        if len(version)!=4: return result
        # These are confirmed patched builds, not proven first fixed releases.
        result.update(status='REFERENCE_OK' if version>=floor else 'MANUAL',
                      reference_floor='.'.join(map(str,floor[:-1]))+'+'+str(floor[-1]),
                      source=('https://github.com/corretto/corretto-'+str(major)+'/releases' if vendor=='Amazon.com Inc.'
                              else 'https://github.com/adoptium/temurin/issues/317'))
    if result['reference_floor']:
        result['detail'] = ('{} の確認済み対策ビルド {} 以上です。' if result['status']=='REFERENCE_OK' else
                            '{} の対策ビルド {} 未満です。' if result['status']=='UPDATE' else
                            '{} の確認済みビルドは {} です。初回対策版は確定できず、この旧版を未対応とは断定できません。').format(vendor,result['reference_floor'])
    return result


def expand_java(records):
    """Keep runtime build evidence distinct from the connection that captured it."""
    def key(m): return m.get('execution_context','ホスト'),m.get('executable')
    existing={key(r.get('metadata',{})) for r in records if r.get('metadata',{}).get('java_version_evidence')}
    added=[]
    for row in sorted(records,key=lambda r:not bool(r.get('metadata',{}).get('java_home'))):
        m=row.get('metadata',{})
        if m.get('tool_id')!='java' or not m.get('executable') or not m.get('vendor') or not m.get('runtime_version'): continue
        if row['name'].endswith(' / バージョン') or key(m) in existing: continue
        fields={k:m[k] for k in ('tool_id','tool_name','executable','java_home','version','runtime_version','vendor','vendor_version','execution_context') if k in m}
        fields['java_version_evidence']=True
        added.append(dict(name='Java / バージョン',status='INFO',detail=m['runtime_version'],action='',samples=[],
                          assessment_method='version',metadata=fields))
        existing.add(key(m))
    return list(records)+added


def assess(row):
    meta=row.get('metadata',{}); tool=meta.get('tool_id')
    if row.get('samples') or row.get('assessment_method') not in (None,'inventory','version','manual'): return row
    if row['status'] not in ('INFO','MANUAL','UNKNOWN','UPDATE','REFERENCE_OK','INFERRED_OK'): return row
    fact=catalog().get(tool)
    value=dict(row,metadata=dict(meta))
    if fact and (meta.get('application') or row['name'].endswith(' / バージョン')):
        value['metadata']['research']=dict(fact,as_of=AS_OF)
    # Older report records may have no catalog ID for Desktop.
    desktop = ('Docker Desktop' in row['name'] or tool=='docker' and meta.get('application') and
               (str(meta.get('path','')).endswith('.app') or str(meta.get('application_version','')).startswith('4.')))
    if desktop:
        if any(c.get('status') in ('ACTION','UPDATE') for c in meta.get('inspections',[])): return value
        value.update(status='MANUAL',detail='Docker Desktopは部品ごとに対策を段階適用しています。CLI・Engine・BuildKitなどの版を個別に確認してください。')
        value['metadata'].update(release_condition='部品ごとの対策を確認', research=catalog()['docker'])
        value['metadata'].pop('reference_floor',None)
        return value
    if (tool=='firefox' and meta.get('application') and meta.get('bundle_identifier')=='org.mozilla.firefox' and
            not any(c.get('status') in ('ACTION','UPDATE') for c in meta.get('inspections',[]))):
        version=str(meta.get('application_version',''))
        if re.fullmatch(r'\d+\.\d+\.\d+',version):
            floor={158:'158.0.1',153:'153.5.1',115:'115.43.1'}.get(nums(version)[0])
            if floor and nums(version)>=nums(floor):
                value.update(status='REFERENCE_OK',assessment_method='version',
                             detail='このFirefoxは問題の証明書を拒否するデータを含む公式の対策版です。',
                             scope='Firefox Desktopの標準の証明書検証。本体更新と独立したOneCRL配信は別の根拠として扱います。')
                value['metadata'].update(version_basis='official-release',assessed_version=version,
                                         reference_floor=floor,source='https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/')
        return value
    if meta.get('application') or not meta.get('executable') or not row['name'].endswith(' / バージョン'): return value
    result=java(meta) if tool=='java' else release(tool, str(meta.get('version','')).strip())
    if result:
        fields={k:v for k,v in result.items() if k not in ('status','detail','scope','version')}
        fields['assessed_version']=result['version']
        if result['status']=='MANUAL' and result.get('release_status')=='fixed': fields['release_condition']='本体は対策版・通信環境を確認'
        value.update(status=result['status'],detail=result['detail'],scope=result['scope'],assessment_method='version',
                     metadata=dict(value['metadata'],**fields))
        if (row['status'] != result['status'] or meta.get('reference_floor') != result.get('reference_floor')):
            value.pop('remediation',None)
    return value
