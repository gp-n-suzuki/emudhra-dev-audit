"""Concrete, target-specific instructions; never performs the suggested changes."""
import re
import verdicts


def legacy_python_pip(row):
    meta = row.get('metadata', {})
    if row['status'] != 'UPDATE' or 'pip' not in row['name'].lower():
        return False
    version = meta.get('python_version', '')
    if not version:
        match = re.search(r'(?:^| / )Python (\d+\.\d+(?:\.\d+)?) \[', row['name'])
        version = match[1] if match else ''
    match = re.match(r'^(\d+)\.(\d+)(?:\.|$)', version)
    return bool(match and tuple(map(int, match.groups())) < (3, 10))


def plan(row):
    meta = row.get('metadata', {})
    if row['status'] == 'UPDATE' and meta.get('product_release_evidence') and meta.get('tool_id') == 'safe-chain':
        return dict(title='このSafe Chainの公式バイナリを更新する', target=meta.get('executable', ''),
                    reference='取得版: {} / 確認済み対策版: 1.5.27'.format(meta.get('version', '')),
                    steps=['公式1.5.27のリリースページで、利用するOS・CPU向けのSafe Chain配布物を確認します。',
                           '同ページの適用範囲に従って更新します。固定タグREADMEに残る1.5.26の取得例は使用しません。',
                           '更新後に同じ導入実体の版を再確認します。npm・独自配布や普段の通信は別に確認します。'])
    conditional = meta.get('release_status')=='fixed' and row['status']=='MANUAL'
    if conditional:
        steps = {
            'composer':['このComposerを実行するPHPを8.4以上にし、curl拡張を有効にします。',
                        'PHP streamsや古いPHPでは証明書の検出が送信後になります。利用するPHP・curlの組合せを確認します。'],
            'rebar3':['OSの更新機能で信頼する証明書データを更新します。',
                      'Rebar3の実行先がコンテナの場合は、そのコンテナ内のCAも更新します。'],
            'conda':['このconda環境のcertifiを2026.10.19以上、ca-certificatesをmainでは2026.10.20以上、conda-forgeでは2026.10.19以上に更新します。',
                     'base環境以外も、使う環境ごとに同じCAパッケージを確認します。'],
        }.get(meta.get('tool_id'),[])
        return dict(title='本体と合わせて通信環境を確認する', target=meta.get('executable',''),reference='',steps=steps)
    if row['status'] not in ('ACTION', 'UPDATE'):
        return None
    meta = row.get('metadata', {})
    own_go = next((c for c in meta.get('inspections', [])
                   if verdicts.is_go_toolchain_check(row, c) and c.get('status') == 'UPDATE'), None)
    if row['status'] == 'UPDATE' and own_go:
        return dict(title='このGo本体を対応版へ更新する', target=meta['path'],
                    reference='Go本体: {} / 参考修正版: {}'.format(own_go.get('version', ''), own_go.get('reference_floor', '未取得')),
                    steps=['このGo本体を導入した方法で、表示された公式情報の対象系列・適用範囲に従って対応版へ更新します。',
                           '導入する実行ファイルが、このPCのOS・CPU形式に対応することを確認します。版の更新要否と起動失敗は別の問題です。',
                           '配布元の独自修正（バックポート）がある場合は対応内容を確認します。更新後に同じ導入先の版と起動を確認し、通信を再診断します。'])
    if row['status'] == 'UPDATE' and meta.get('version_basis') == 'official-release':
        extra = {'composer':['PHP 8.4以上とcurl拡張の組合せも必要です。古いPHP・streamsは送信後に問題を検出します。'],
                 'conda':['同じ環境のcertifi・ca-certificatesも、表示された公式条件に合わせて更新します。'],
                 'rebar3':['更新後はOSのCAを使うため、OSの証明書データも更新します。']}.get(meta.get('tool_id'),[])
        return dict(title='この導入を公式の対策版へ更新する', target=meta.get('executable',meta.get('path','')),
                    reference='現在: {} / 対策版: {}'.format(meta.get('version',''),meta.get('reference_floor','')),
                    steps=['このツールを導入した方法で、表示された対策版以上に更新します。']+extra+[
                           '更新後に再診断し、この導入のバージョンを確認します。'])
    if row['status'] == 'UPDATE' and meta.get('runtime_component') == 'node':
        target = meta.get('executable', '')
        steps = (['このツールの起動ファイルが指定するNode.jsを、その導入元の方法で対策版へ更新します。対象のNode.jsの場所は「検査データ」にあります。']
                 if meta.get('runtime_basis') == 'entrypoint' else
                 ['このツールを導入した方法で更新し、表示されたNode.jsも対策版へ更新されるか確認します。'])
        steps += ['最新版でも表示が続く場合は、配布元の対応版・独自修正（バックポート）を確認します。別の場所のNode.jsを更新しても、この起動経路は変わらない場合があります。',
                  '更新後に再診断し、この導入が使用するNode.jsの版を確認します。']
        return dict(title='このツールが使用するNode.jsを更新する', target=target, steps=steps,
                    reference='使用するNode.js: {} / 対策版: {}'.format(meta.get('runtime_version',''),meta.get('reference_floor','')))
    if row['status'] == 'UPDATE' and row.get('review_state') == 'review' and not row.get('metadata', {}).get('application'):
        meta = row.get('metadata', {})
        target = next((meta[key] for key in ('executable', 'java_home', 'prefix', 'path')
                       if isinstance(meta.get(key), str) and meta[key]), '')
        reference = ('現在: {} / 参考修正版: {}'.format(meta['version'], meta['reference_floor'])
                     if meta.get('version') and meta.get('reference_floor') else '')
        return dict(title='配布元の対応状況を確認する', target=target, reference=reference,
                    steps=['配布元の対応情報と、この版への独自修正（バックポート）を確認します。',
                           '対応版が提供されている場合は、導入方法に合わせて更新し、再診断します。'])
    name = row['name'].lower()
    detail = row.get('detail', '').lower()
    meta = row.get('metadata', {})
    configuration = row.get('assessment_method') == 'configuration'
    if legacy_python_pip(row):
        title = 'Python環境を更新・移行する'
        steps = ['pip 26.2.2はPython 3.10以上が必要です。このPythonには導入できません。']
        if '/Xcode.app/' in meta.get('prefix', '') or '/CommandLineTools/' in meta.get('prefix', ''):
            steps += ['Xcode・Command Line ToolsはAppleの更新と対応情報を確認します。同梱Pythonを手動で書き換えず、開発用途は別途導入した対応版のPythonへ移行します。']
        else:
            steps += ['導入元で対策済みの対応Pythonを用意し、そのPythonで開発環境を作り直して移行します。']
        steps += ['移行先でpipが26.2.2以上になっていることを確認します。既存の仮想環境も新しいPythonで作り直します。']
    elif meta.get('application'):
        title = '配布元の対応状況を確認する'
        steps = ['アプリが最新版でも、同梱ソフトウェアが対策版に達していない場合があります。配布元の更新履歴・セキュリティ情報でeMudhraへの対応を確認します。',
                 '対応版が提供されている場合は、アプリを導入した方法で更新します。自分でビルドしたアプリは、対策済みの実行環境・ライブラリでビルドし直します。',
                 '最新版でも表示が続く場合は、配布元に対応版の提供予定・独自修正（バックポート）の有無を確認します。PC側のGo・Python・Javaだけを更新しても、アプリの同梱物は置き換わりません。']
    elif row['status'] == 'UPDATE' and meta.get('tool_id') == 'codex':
        title = 'この導入のCodexを対策版へ更新する'
        steps = ['「検査データ」の場所にあるCodexを、導入した方法で公式の対応版へ更新します。',
                 '独自ビルドや配布元によるバックポートを使っている場合は、その配布元の対応情報を確認します。']
    elif row['status'] == 'UPDATE' and meta.get('tool_id') == 'python' and 'packages' in meta:
        title = 'このPython本体を対策版へ更新する'
        steps = ['「検査データ」の場所にあるPython本体を、その導入元から同じ系列の対応版へ更新します。',
                 '既存の仮想環境では、使用するPythonとpipを環境ごとに確認します。']
    elif name.startswith(('dart','flutter')):
        title = 'SDKを更新し、対象アプリをビルドし直す'
        steps = ['DartまたはFlutterの導入元で、表示されたSDKを対策版へ更新します。',
                 'Android・Windows・Linux向けに配布したアプリを更新後のSDKで再ビルドし、配布し直します。Mac上の接続テストだけで配布先の状態は確認できません。']
    elif meta.get('tool_id') == 'bundler' or re.match(r'^bundler(?:\W|$)', name):
        title = 'このBundlerとRuby・CAの対応を確認する'
        steps = ['表示されたBundlerの起動先Rubyと、そのRubyが使うCA・証明書検証設定を確認します。',
                 'OS標準のRuby・BundlerはOS提供元、それ以外は導入元の対応情報を確認し、対象の経路へ対策を適用します。',
                 '診断用設定と普段の設定は別です。利用者のCA指定・取得先も確認します。']
    elif re.match(r'^(?:bun|deno)(?:\W|$)', name):
        title = 'この実行環境を対策版へ更新する'
        steps = ['表示された実行ファイルの導入元でBun・Denoを対策版へ更新します。',
                 '実行環境を組み込んだ配布用バイナリは、更新後にビルドし直して置き換えます。']
    elif name.startswith(('perl','erlang','elixir')):
        title = 'このアプリが使うCAライブラリを更新する'
        steps = ['表示されたMozilla::CA・certifi・castoreを、その環境の依存関係管理で対策版へ更新します。',
                 'アプリが別のCAやTLSライブラリを指定している場合は、その参照先も確認します。']
    elif 'node_tls_reject_unauthorized' in detail or ('node.js' in name and configuration):
        title = 'Node.jsの証明書検証を有効に戻す'
        steps = ['ターミナル・IDEの起動設定やOSの環境変数で、NODE_TLS_REJECT_UNAUTHORIZED=0 の設定元を探します。',
                 '設定元からこの指定を取り除き、ターミナルとIDEを開き直します。']
    elif 'git_ssl_no_verify' in detail or ('git' in name and '証明書検証無効化' in name):
        title = 'Gitの証明書検証を有効に戻す'
        steps = ['ターミナル・IDEの起動設定やOSの環境変数で、GIT_SSL_NO_VERIFY の設定元を探します。',
                 '検証を無効にしている指定を取り除き、ターミナルとIDEを開き直します。']
    elif 'git' in name and ('sslverify' in name or 'sslverify=false' in detail):
        title = 'GitのsslVerify設定を修正する'
        steps = ['対象のGitで git config --show-origin --get http.sslVerify を実行し、設定元を確認します。',
                 '表示された設定元の http.sslVerify=false を true に変更します。URL別の設定がある場合は、その接続先の設定も確認します。']
    elif 'npm' in name and configuration:
        title = 'npmの証明書検証を有効に戻す'
        steps = ['npm config get userconfig と npm config get globalconfig で設定ファイルの場所を確認します。',
                 'strict-ssl=false を指定している設定ファイルまたは環境変数を修正し、strict-ssl=true に戻します。']
    elif 'docker' in name and configuration:
        title = 'Dockerのregistry設定を確認・修正する'
        names = meta.get('insecure_registries', [])
        steps = (['対象registry: '+', '.join(names)+'。'] if names else [])
        steps += ['Docker Desktopでは「Settings → Docker Engine」の insecure-registries を確認します。別のEngineを使う場合は、接続先Engineの設定を確認します。',
                  "対象をコマンドで確認する場合: docker info --format '{{range $name, $config := .RegistryConfig.IndexConfigs}}{{if not $config.Secure}}{{println $name}}{{end}}{{end}}'",
                  '自分で追加したregistryの場合は、有効なサーバー証明書とCAを設定し、insecure-registries の対象指定を外してDockerを再起動します。Docker Desktopが管理する内部用設定の場合は、手動で削除せずDockerの対応情報を確認します。']
    elif 'ensurepip' in name:
        title = 'Python本体を更新する'
        steps = ['この項目のPythonを、同じ配布元のeMudhra対応版へ更新します。ensurepip同梱pipはPython本体に含まれます。',
                 '更新後に作る仮想環境のpipを確認します。すでにある環境のpipも、その環境ごとに更新します。']
    elif name.startswith('uv'):
        title = 'uv本体を更新する'
        steps = ['uvを導入した方法で、uv本体を参考修正版以上へ更新します。',
                 'ターミナルを開き直し、uv --version で更新後の版を確認します。']
    elif 'pip' in name or 'certifi' in name or 'python' in name:
        package = 'certifi' if 'certifi' in name else 'pip' if 'pip' in name else 'CAと関連パッケージ'
        title = 'このPythonの{}を更新する'.format(package)
        steps = ['項目名・検査データでPythonの場所を確認し、そのPythonが使う{}を導入元の方法で対応版へ更新します。'.format(package),
                 'SSL_CERT_FILE・REQUESTS_CA_BUNDLE・PIP_CERTでCAファイルを指定している場合は、指定先のCAも更新します。']
    elif 'java' in name or 'jdk' in name:
        title = 'このJDKを対応版へ更新する'
        steps = ['対象のJDKと配布元を確認し、その配布元のeMudhra対応版をインストールします。',
                 'JAVA_HOMEとPATHを更新後のJDKに合わせ、ターミナルとIDEを開き直します。',
                 'javax.net.ssl.trustStoreで独自の信頼ストアを指定している場合は、そちらにも配布元の対策を反映します。']
    elif 'node' in name or 'npm' in name:
        title = 'Node.jsとnpmを対応版へ更新する'
        steps = ['Node.jsの導入に使ったインストーラー・バージョン管理ツールで、利用中の系列の対応版へ更新します。',
                 'ターミナルとIDEを開き直します。NODE_EXTRA_CA_CERTSやnpmのcafileを指定している場合は、そのCAも更新します。']
    elif 'rustup' in name:
        title = 'rustup本体を更新する'
        steps = ['rustupを導入した方法で、rustup本体を参考修正版以上へ更新します。',
                 'rustup --version で更新後の版を確認します。']
    elif any(package in name for package in ('rustls', 'webpki', 'rust')):
        title = 'RustのTLS依存を更新してビルドし直す'
        steps = ['表示されたCargo.lockのプロジェクトで、該当するTLSライブラリを対応版へ更新します。',
                 'アプリを再ビルドし、使用中のバイナリを更新します。']
    elif 'docker' in name:
        title = 'Docker本体を対応版へ更新する'
        steps = ['Docker Desktopはアプリの更新機能から、Engineは導入元のパッケージ管理で対応版へ更新します。',
                 'Dockerを再起動して更新を反映します。']
    elif any(browser in name for browser in ('ブラウザ', 'chrome', 'edge', 'firefox', 'safari')):
        title = 'ブラウザを更新して再確認する'
        steps = ['Chrome・Edge・Firefoxは「ヘルプ／バージョン情報」から更新します。SafariはmacOSのソフトウェアアップデートを実行します。',
                 'ブラウザを完全に終了して起動し直し、このツールで再診断します。']
    elif 'php' in name:
        title = 'PHPが参照するCAを更新する'
        steps = ['対象PHPの openssl.cafile・openssl.capath・curl.cainfo と、使用しているOpenSSLのCA参照先を確認します。',
                 '導入元のパッケージ管理でPHP・OpenSSL・CAを更新し、常駐するPHPプロセスを再起動します。']
    elif 'ruby' in name:
        title = 'Rubyと参照CAを更新する'
        steps = ['Rubyの導入元でRuby・OpenSSL・CAパッケージを更新します。',
                 'SSL_CERT_FILEなどで独自CAを指定している場合は、そのファイルも更新します。']
    elif 'go' in name:
        title = 'GoとGo製アプリを更新する'
        steps = ['Goの導入元で対応版のツールチェーンへ更新します。',
                 '利用中のGo製アプリを修正版に置き換えるか、更新後のGoで再ビルドします。']
    elif 'curl' in name or 'git' in name:
        title = 'このツールと参照CAを更新する'
        steps = ['対象欄の実行ファイルを確認し、導入元のOS更新・パッケージ管理でツールとCAパッケージを更新します。',
                 'CURL_CA_BUNDLE・GIT_SSL_CAINFO・http.sslCAInfoで独自CAを指定している場合は、そのCAも更新します。']
    elif '.net' in name or 'macos' in name or 'windows' in name:
        title = 'OSと実行環境を更新する'
        steps = ['OSの更新を適用します。.NETの場合は対象アプリが使用するランタイムも対応版へ更新します。',
                 'アプリを再起動して、更新後の信頼情報・ランタイムで起動します。']
    else:
        title = '検出された対象に対策を適用する'
        steps = [row.get('action') or '判断の根拠に記載された設定・配布元の対応情報を確認し、対象を更新します。']
    if row['status'] == 'UPDATE' and not any('バックポート' in step for step in steps):
        steps.append('配布元の独自修正（バックポート）が適用されている場合は、その対応内容を確認します。')
    steps.append('更新後に再診断し、同梱バージョンと判定を確認します。' if meta.get('application') else
                 '同じPC・ネットワークで再診断し、この項目の結果を確認します。')
    if row['status'] == 'ACTION' and row.get('assessment_method') in ('measured', 'corroborated'):
        steps.append('更新後も検証先へ接続できる場合は、証明書の発行者を確認します。社内プロキシの証明書なら、レポートと発行者をIT担当へ伝えて経路を確認します。')
    target = next((meta[key] for key in ('executable', 'java_home', 'prefix', 'path') if isinstance(meta.get(key), str) and meta[key]), '')
    reference = ''
    if meta.get('version') and meta.get('reference_floor'):
        pattern = '同梱バージョン: {} / 対策版: {}' if meta.get('application') else '現在: {} / 参考修正版: {}'
        reference = pattern.format(meta['version'], meta['reference_floor'])
    return dict(title=title, steps=steps, target=target, reference=reference)


def text_lines(row):
    remedy = plan(row)
    if not remedy:
        return []
    lines = ['対応手順: ' + remedy['title']]
    if remedy['target']: lines.append('対象: ' + remedy['target'])
    if remedy['reference']: lines.append(remedy['reference'])
    lines.extend('{}. {}'.format(index, step) for index, step in enumerate(remedy['steps'], 1))
    return lines
