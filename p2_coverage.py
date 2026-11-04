"""Specific limits for installed tools whose own transport is not yet sampled."""
import tool_catalog
import verdicts


NOTES = {}


def note(ids, reason, action, source):
    identifiers=ids.split()
    for identifier in identifiers:
        # A shared reason does not make one vendor's documentation a source
        # for every other tool in the group.
        NOTES[identifier] = (reason, action, source if len(identifiers) == 1 else None)


note('pipx', '管理環境の実index・認証とuv backendの取得経路は未検査です。共有pipの診断は別に表示します。',
     '使用するpipx環境のbackend・index・CA・proxy設定を確認してください。', 'https://pipx.pypa.io/stable/')
note('conda', '各channelの認証・CA設定を使う取得経路は未検査です。環境の作成や更新は行いません。',
     '使用するchannelと各実行環境のCA・proxy設定を確認してください。', 'https://docs.conda.io/projects/conda/en/latest/user-guide/configuration/settings.html')
note('bun', 'Bunの標準fetchとpackage managerのregistry設定は別で、後者の通信は未検査です。',
     'Bunのregistry・CA・proxy設定と利用中の版を確認してください。', 'https://bun.sh/docs/pm/cli/install')
note('maven gradle sbt', 'build pluginやproject設定を実行せず、各repositoryの通信を再現できません。',
     '実際に使うbuild toolとrepositoryのCA・proxy、配布元の対応を確認してください。', 'https://maven.apache.org/guides/mini/guide-proxies.html')
note('nuget dotnet', 'NuGet feedの認証・設定を使う取得処理は未検査です。.NET標準HTTPの結果とは別です。',
     '使用するNuGet feedとSDKのCA・proxy設定を確認してください。', 'https://learn.microsoft.com/nuget/reference/nuget-config-file')
note('dart flutter', 'pubのpackage source通信は、Dart標準HTTPの検査とは別で未検査です。',
     '使用するSDKのpub source・CA・proxy設定を確認してください。', 'https://dart.dev/tools/pub/environment-variables')
note('swift xcode', 'Swift Package Managerのregistry・Git・独自設定は接続先によって異なり、未検査です。',
     '使用するSwiftと取得先ごとのCA・proxy設定を確認してください。', 'https://www.swift.org/documentation/package-manager/')
note('cocoapods', 'CocoaPodsのCDN・Git sourceとRubyの設定を使う通信は未検査です。',
     'podが使うspec sourceとRuby・GitのCA・proxy設定を確認してください。', 'https://guides.cocoapods.org/using/using-cocoapods.html')
note('conan vcpkg', 'registryの認証やport・build処理を使わない実効通信は未検査です。',
     '実際のremoteとそのCA・proxy設定を確認してください。', 'https://docs.conan.io/2/reference/config_files/remotes.html')
note('psresourceget powershellget', 'このPowerShellモジュールのrepository・認証を使う取得処理は未検査です。',
     '使用するモジュールとrepositoryごとのCA・proxy設定を確認してください。', 'https://learn.microsoft.com/powershell/module/microsoft.powershell.psresourceget/')
note('cpan cpanm', 'このCPANクライアントのmirrorとHTTP実装による通信は未検査です。',
     '使用するmirror・CA・proxy設定を確認してください。', 'https://metacpan.org/pod/App::cpanminus')
note('erlang elixir hex rebar3', 'OTPのSSLとHex・Rebar3のregistry設定は別で、package取得の通信は未検査です。',
     '使用するOTPとpackage managerのCA・proxy・registry設定を確認してください。', 'https://hexdocs.pm/hex/Mix.Tasks.Hex.Config.html')
note('homebrew', 'HomebrewのAPI mirrorは失敗時に既定先へfallbackするため、認証・設定を分離した対象先だけの通信は未検査です。',
     'brewが使うcurl・Git・API/bottle先とCA・proxy設定を確認してください。', 'https://docs.brew.sh/Manpage#environment')
note('winget', 'WinGet sourceの認証と取得経路は未検査です。source更新やパッケージ導入は行いません。',
     'WinGetの使用sourceと、その通信に適用されるCA・proxy設定を確認してください。', 'https://learn.microsoft.com/windows/package-manager/winget/source')
note('chocolatey scoop', '設定済みsourceやPowerShell・Gitを使う取得経路は未検査です。',
     '使用するsourceとPowerShell・GitのCA・proxy設定を確認してください。', 'https://docs.chocolatey.org/en-us/choco/commands/source/')
note('apt dnf pacman zypper apk', 'OS package repositoryの認証・CA設定による通信は未検査です。index更新は行いません。',
     '使用するrepositoryとOS配布元のCA・proxy設定を確認してください。', 'https://manpages.debian.org/apt/apt.conf.5.en.html')
note('mise asdf', '管理対象ごとに異なるpluginの取得経路は未検査です。pluginを実行・導入しません。',
     '使用するpluginごとに取得ツールとCA・proxy設定を確認してください。', 'https://mise.jdx.dev/dev-tools/backends/')
note('pyenv nvm rbenv sdkman', '初期化スクリプトやpluginを実行せずに取得経路は確認できません。',
     '使用する管理ツールとpluginの取得先・CA・proxy設定を確認してください。', 'https://github.com/pyenv/pyenv')
note('fnm volta fvm', '本体や管理SDKの自動取得を避けるため、取得経路の通信は未検査です。',
     '利用する管理ツールとSDKの取得先・CA・proxy設定を確認してください。', 'https://volta.sh/')
note('corepack', 'Corepackのshimがpackage managerを自動取得する可能性があり、起動を見送りました。',
     'Corepackと管理対象のpnpm・Yarnの配布元情報と設定を個別に確認してください。', 'https://nodejs.org/api/corepack.html')
note('safe-chain', 'このPC内の接続テストとは別に、普段の設定・実際の取得先・脅威情報の通信は未確認です。公式verifyも外部への接続の証拠になりません。',
     '普段の取得先や脅威情報への接続を確認してください。', 'https://github.com/AikidoSec/safe-chain')
note('gh', 'gh apiは認証付きのAPI操作であり、利用者の認証情報を検査先へ送らないため未実行です。',
     'ghの利用環境と配布元のTLS対応・CA・proxy設定を確認してください。', 'https://cli.github.com/manual/gh_api')
note('codex claude-code gemini-cli kiro-cli', 'CLI固有のサービス通信と認証は未検査です。実アカウントのAPIを使用しません。',
     'このCLIの導入形式・同梱runtime・CA・proxy設定と配布元の対応を確認してください。', 'https://github.com/openai/codex')
note('gcloud', 'クラウドCLIの認証・metadata探索・実サービス操作を伴う通信は未検査です。',
     '利用するCLIのCA・proxyと認証設定、配布元の対応を確認してください。', 'https://cloud.google.com/sdk/docs/configurations')
note('firebase vercel netlify heroku supabase wrangler', 'このCLIのログイン済みAPI通信は未検査です。実アカウントやプロジェクトを操作しません。',
     'このCLIの同梱runtime・CA・proxy設定と配布元の対応を確認してください。', 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases')
note('terraform opentofu pulumi', 'provider・plugin・stateやクラウドアカウントを使う通信は未検査です。',
     '本体と各providerの配布元対応、registry・CA・proxy設定を確認してください。', 'https://developer.hashicorp.com/terraform/cli')
note('postman insomnia bruno', 'GUI workspaceや保存済み認証を使った通信は未検査です。',
     '実際に使うworkspaceとアプリのCA・proxy設定、配布元の対応を確認してください。', 'https://www.postman.com/')
note('docker buildkit podman', 'CLIとdaemonのregistry通信は別で、認証やimage取得を伴う実通信は未検査です。',
     '使用するdaemon・BuildKitのregistryごとのCA・proxy設定を確認してください。', 'https://docs.docker.com/engine/security/certificates/')
note('filezilla cyberduck winscp transmit', '保存済みサイト・認証・ファイル転送を使わない実通信は未検査です。SSH/SFTPはTLS対象外です。',
     'HTTPS/FTPSの接続先ごとにCA・proxyとアプリ配布元の対応を確認してください。', 'https://filezilla-project.org/')


def collect(audit):
    for tool, (reason, action, source) in NOTES.items():
        spec=tool_catalog.BY_ID.get(tool)
        if not spec: continue
        seen=set()
        for path in audit.discovered.get(tool, []):
            identity=verdicts.installation_identity(tool,path)
            if identity in seen: continue
            seen.add(identity)
            audit.add(spec['name']+' / 固有の通信','MANUAL',reason,
                      {'tool_id':tool,'tool_name':spec['name'],'executable':path,
                       'p2_coverage':True,'source':source},action=action,required=True)
