"""Build regression cases from invented inputs; never read a diagnostic report.

Case numbers retain the historical regression identifiers, not observations.
Paths, TLS fingerprints, output text and installation layouts are fictional.
Public software versions are chosen to exercise the required rule boundaries.
"""
import hashlib
import json
from pathlib import Path

NAMES = {'bundler':'Bundler', 'rubygems':'RubyGems', 'go':'Go', 'node':'Node.js',
         'ruby':'Ruby', 'php':'PHP', 'curl':'curl', 'git':'Git', 'wget':'wget'}
TARGETS = ['通常サイト', 'emSign / CTあり', 'AAA経路 / CTあり', 'emSign / CTなし', 'AAA経路 / CTなし']
SYS = '/fixture/system/bin/'
MANAGED = '/fixture/managed/bin/'
PKG = '/fixture/managed/packages/'
OTHER = '/fixture/second/bin/'


def record(name, status, method, metadata, detail='合成データによる回帰ケース。', samples=None, scope=None):
    return dict(name=name, status=status, assessment_method=method, detail=detail,
                action='対象の導入先と未確認事項を確認してください。',
                scope=scope or '合成fixtureの同一導入先・実行環境に限定した検証。',
                metadata=dict(metadata, fixture_origin='synthetic-v1'), samples=samples or [])


def samples(statuses, retry=False):
    values=[]
    for i, status in enumerate(statuses):
        detail = '合成fixture: '+status
        if retry and i == 3:
            detail = ('TIMEOUT: synthetic fixture\nRetrying fetcher due to error (2/4): '
                      'Bundler::Fetcher::CertificateFailureError at https://retry.example.invalid/')
        values.append(dict(target=TARGETS[i], control=i==0, status=status, detail=detail))
    return values


def discovery(tool, path, aliases=()):
    return record('アプリ / '+NAMES[tool]+' ['+path+']', 'MANUAL', 'manual',
                  dict(tool_id=tool, tool_name=NAMES[tool], application=True, path=path,
                       discovered_paths=[path]+list(aliases), discovery_sources=['synthetic fixture'],
                       coverage_state='uninspected', inspections=[],
                       uninspected=['TLS構成と修正版の照合に必要な情報を取得できません（通信の有無も未確認）',
                                    'アプリの実効CA・独自検証設定・実通信は未検査']),
                  'このツールの通信は未確認。導入を確認しました。')


def inventory(tool, executable, version):
    return record(NAMES[tool]+' / バージョン', 'INFO', 'inventory',
                  dict(tool_id=tool, tool_name=NAMES[tool], executable=executable, version=version))


def manager(tool, executable, runtime, status, usual=False, retry=False):
    meta=dict(tool_id=tool,tool_name=NAMES[tool],executable=executable,runtime_executable=runtime,
              probe='synthetic_bundle_lock' if tool=='bundler' else 'synthetic_gem_search',
              diagnostic_observation='connection_error')
    scope='診断用設定: 同一実体と合成データのみ。普段の設定・実効CA・別接続先は未確認。'
    if usual:
        return record(NAMES[tool]+' / gem source（普段の設定）','MANUAL','manual',meta,
                      '認証情報の送信を避けるため、普段使う設定での通信は確認していません。',scope=scope)
    statuses=['CONTROL_OK']+(['ACTION','ACTION','UNKNOWN','UNKNOWN'] if status=='ACTION' else
                              ['REJECTED']*4 if status=='REJECTED' else ['REJECTED','REJECTED','UNKNOWN','REJECTED'])
    # Fictitious socket-shaped evidence tests retention without publishing any
    # captured chain or implying a real network request took place.
    meta['connection_evidence']=[dict(target=TARGETS[i],source='ruby_ssl_socket',
        origin='https://target-'+str(i)+'.example.invalid/',origin_verified=True,
        verify_code=0 if s in ('CONTROL_OK','ACTION') else 20,
        tls_verified=s in ('CONTROL_OK','ACTION'),hostname_verified=True,
        chain_spki_sha256=[hashlib.sha256(('synthetic-chain-'+str(i)).encode()).hexdigest()],
        target_chain_verified=s=='ACTION') for i,s in enumerate(statuses) if s!='UNKNOWN']
    return record(NAMES[tool]+' / gem source（診断用設定）',status,'measured',meta,
                  samples=samples(statuses,retry),scope=scope)


def display_cases():
    rows={}
    for number,tool,path,aliases in (
        (129,'bundler',PKG+'ruby-a/bin/bundle',[MANAGED+'bundle']),
        (135,'bundler',PKG+'ruby-a/bin/bundler',[MANAGED+'bundler']),
        (137,'rubygems',PKG+'ruby-a/bin/gem',[MANAGED+'gem']),
        (163,'bundler',SYS+'bundle',[]),(171,'bundler',SYS+'bundler',[]),
        (174,'rubygems',SYS+'gem',[]),(207,'bundler',OTHER+'bundle',[]),
        (208,'bundler',OTHER+'bundler',[]),(210,'rubygems',OTHER+'gem',[]),
        (120,'wget',PKG+'wget/bin/wget',[MANAGED+'wget']),
        (130,'php',PKG+'php/bin/php',[MANAGED+'php']),
        (136,'ruby',PKG+'ruby-a/bin/ruby',[MANAGED+'ruby']),
        (165,'curl',SYS+'curl',[]),(172,'ruby',SYS+'ruby',[]),(173,'git',SYS+'git',[]),
        (202,'curl',PKG+'curl/bin/curl',[]),(211,'curl',OTHER+'curl',[]),
        (92,'node','/fixture/manager/bin/manager',['/fixture/shims/node','/fixture/node/bin/node'])):
        rows[number]=discovery(tool,path,aliases)
    for number,tool,path,version in (
        (469,'rubygems',MANAGED+'gem','4.0.20'),(470,'rubygems',SYS+'gem','3.0.3'),
        (471,'bundler',MANAGED+'bundle','Bundler version 4.0.20'),
        (472,'bundler',MANAGED+'bundler','Bundler version 4.0.20'),
        (473,'bundler',SYS+'bundle','Bundler version 1.17.2'),
        (474,'bundler',SYS+'bundler','Bundler version 1.17.2')):
        rows[number]=inventory(tool,path,version)
    for number,tool,path,runtime,status,usual,retry in (
        (10,'bundler',SYS+'bundle',SYS+'ruby','ACTION',False,False),
        (65,'rubygems',MANAGED+'gem',MANAGED+'ruby','REJECTED',False,False),
        (270,'rubygems',MANAGED+'gem',MANAGED+'ruby','MANUAL',True,False),
        (274,'bundler',MANAGED+'bundle',MANAGED+'ruby','UNKNOWN',False,True),
        (275,'bundler',MANAGED+'bundle',MANAGED+'ruby','MANUAL',True,False),
        (276,'bundler',MANAGED+'bundler',MANAGED+'ruby','UNKNOWN',False,True),
        (277,'bundler',MANAGED+'bundler',MANAGED+'ruby','MANUAL',True,False),
        (278,'bundler',SYS+'bundle',SYS+'ruby','MANUAL',True,False)):
        rows[number]=manager(tool,path,runtime,status,usual,retry)
    go='/fixture/go/bin/go'
    rows[30]=record('アプリ / Go ['+go+']','UPDATE','version',
        dict(tool_id='go',tool_name='Go',application=True,path=go,discovered_paths=[go],
             coverage_state='partial',uninspected=['実通信は未検査'],reference_floor='1.26.10',
             inspections=[dict(component='go',status='UPDATE',method='version',version='1.23.0',
                               reference_floor='1.26.10',path=go,detail='参考修正版1.26.10未満。')]))
    rows[253]=record('Go TLS ['+go+']','UNKNOWN','inventory',
        dict(tool_id='go',tool_name='Go',executable=go,execution_context='ホスト'),
        '[Errno 86] Bad CPU type in executable: '+go)
    rows[47]=record('ホスト / Node.js','INFERRED_OK','version',
        dict(tool_id='node',tool_name='Node.js',executable='/fixture/shims/node',
             resolved_executable='/fixture/node/bin/node',execution_context='ホスト',
             version='v26.12.1',reference_floor='26.12.1'))
    for number,tool,path,version,status,method in (
        (48,'node','/fixture/shims/node','v26.12.1','REJECTED','measured'),
        (49,'node','/fixture/shims/node','v26.12.1','REJECTED','measured'),
        (38,'curl',SYS+'curl',['curl 8.1.0 (synthetic)'],'REJECTED','measured'),
        (39,'curl',PKG+'curl/bin/curl',['curl 8.2.0 (synthetic)'],'REJECTED','measured'),
        (40,'git',SYS+'git','git version 2.54.0 (synthetic)','REJECTED','measured'),
        (62,'ruby',MANAGED+'ruby','ruby 4.0.0 (synthetic)','REJECTED','measured'),
        (63,'php',MANAGED+'php','PHP 8.5.0 (synthetic)','INFERRED_REJECTED','corroborated'),
        (220,'curl',OTHER+'curl',['[Errno 86] Bad CPU type in executable: '+OTHER+'curl'],'UNKNOWN','measured'),
        (244,'wget',MANAGED+'wget','GNU Wget 1.25.0 (synthetic)','UNKNOWN','measured'),
        (246,'ruby',SYS+'ruby','ruby 2.6.0 (synthetic)','UNKNOWN','measured')):
        meta=dict(tool_id=tool,tool_name=NAMES[tool],executable=path,version=version)
        if tool=='node':meta.update(resolved_executable='/fixture/node/bin/node',execution_context='ホスト')
        if tool=='git':meta.update(repository='/fixture/empty-git',**{'http.sslVerify':True})
        rows[number]=record('ホスト / '+NAMES[tool]+' TLS ['+path+']',status,method,meta,
                            detail=version[0] if number==220 else '合成fixtureによる通信状態。',
                            samples=samples(['CONTROL_OK']+[status]*4))
    assert len(rows)==45
    return [dict(display_number=n,record=row) for n,row in sorted(rows.items())]


def safechain_cases():
    path='/fixture/.safe-chain/bin/safe-chain'
    meta=dict(tool_id='safe-chain',tool_name='Safe Chain',application=True,path=path,
              discovered_paths=[path],coverage_state='uninspected',inspections=[],
              security_tool=dict(version='1.5.26',version_source='本体内のパッケージ情報',runtime='不明'),
              uninspected=['普段の設定・外部通信は未確認'])
    return [record('アプリ / Safe Chain ['+path+']','MANUAL','manual',meta),
            record('Safe Chain / 証明書の接続テスト','MANUAL','measured',
                dict(tool_id='safe-chain',tool_name='Safe Chain',executable=path,probe='safechain_synthetic_tls',
                     synthetic_tls_state='measured',
                     synthetic_tls_cases=dict(trusted='accepted',untrusted='rejected',mismatch='rejected'))),
            record('Safe Chain / 固有の通信','MANUAL','manual',
                dict(tool_id='safe-chain',tool_name='Safe Chain',executable=path,p2_coverage=True),
                '普段の設定を使った通信は未検査です。')]


if __name__=='__main__':
    folder=Path(__file__).parent/'fixtures'
    for name,data in (('display-corrections-2.7.8.json',display_cases()),('safechain-2.7.6.json',safechain_cases())):
        (folder/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
