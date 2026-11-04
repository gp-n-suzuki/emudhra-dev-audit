# 対象別の通信確認範囲

2026-11-02時点の実装状況。各導入実体を区別し、異なるツールやランタイムの通信を代用しません。「診断用」は認証情報・実プロジェクトを使わない合成データと一時設定での通信です。普段の設定、認証、実際の取得先を確認した意味ではありません。Cargo・RubyGems・Bundlerでは対象プロセス自身の接続証拠を取得し、通常サイトと4検査先の信頼拒否を確認できれば結果に反映します。Rubyでは同じ接続の証明書公開鍵指紋が参照対象と一致する受け入れも反映します。接続先や証明書経路が不明な通信は未判定を残します。

認証付きproxy、Safe Chainの保護を迂回する可能性、オフラインや証明書検証無効の設定、shimが追加の導入を行う可能性を検出した場合は通信を見送ります。導入実体を特定できない場合、対応形式・版ではない場合、実行できないCPU形式の場合も未確認です。診断先への認証情報・利用者の依存情報・クライアント証明書を送信せず、アプリのインストール・更新や証明書ストア変更は行いません。

Safe Chain の合成検査では、隔離条件と本体の固定ハッシュが確認できた場合だけ一時コピーを起動します。補助プロセスが検査グループの識別を保持し、終了・タイムアウト・中断時に同じグループを停止してから回収します。隔離条件や終了確認が成立しなければ未判定です。

接続の観測API: [CargoのHTTP debug設定](https://doc.rust-lang.org/cargo/reference/config.html#httpdebug)、[Ruby OpenSSLのSSLSocket](https://docs.ruby-lang.org/en/master/OpenSSL/SSL/SSLSocket.html)。Rubyの指紋照合は接続先の証明書から署名でつながる経路に限定し、無関係な添付証明書を使いません。

## パッケージ管理

| 対象 | 実装した検査 | 未確認の範囲・理由 |
|---|---|---|
| Go Modules | 対象Goの `list -m` で合成モジュールのメタデータを診断用proxyへ問い合わせる。認証、直接VCS接続、checksum DB、追加ツール取得を無効化。 | 普段のGOPROXY・認証・プロジェクトは未使用。対象Goが実行できない場合は見送り。 |
| uv | 対象uvで合成要件を一時indexに照会。実パッケージのインストールはしない。 | 普段のindex・認証・設定は未使用。保護、オフラインまたは検証を緩める設定がある場合は見送り。 |
| Cargo | rustup shimではない対象cargoで一時sparse registryを検索。本体のHTTP debugログから最初の接続先・TLS検証・HTTP応答を照合。404やJSON解析エラーとTLSの結果を分離する。credential providerとツールチェーン取得を使わない。 | 普段のregistry・認証・プロジェクトは未使用。受け入れた証明書の公開鍵指紋は取得できず、その場合は未判定。proxy設定のある通信（CONNECT前の失敗も含む）・転送先エラー・未知ログ形式は確定しない。生のログ・ヘッダー・本文は保存しない。 |
| RubyGems / Bundler | 対象スクリプトとRubyで合成source／Gemfileを照会。Bundlerは旧版にも対応するBUNDLE_GEMFILEで指定。そのプロセスの元のTLSソケットを観測し、接続先・ポート・検証コード・公開鍵指紋を記録する。TLS設定・CA・検証callbackは変更しない。 | 普段のgem source・Gemfile・認証を使わず、gemの導入はしない。proxy設定があり接続先を確定できない場合、タイムアウト、観測の欠落・上限、参照指紋に一致しない受け入れは未判定。 |
| Composer | 対象ComposerとPHPを特定し、一時repositoryで合成パッケージを検索。plugin・script・認証を使用しない。 | 普段のrepository・プロジェクト・認証は未使用。対応しない起動形式は未確認。 |
| pnpm / Yarn | 対応するCLI本体とNodeを特定し、合成registryの情報を照会。pnpmはv11、YarnはclassicおよびBerryのCLI本体に対応。 | 普段のregistry・認証は未使用。Corepack経由、npmへ委譲するpnpm旧版、追加取得の恐れがある版は見送り。 |
| pipx | pip backendの管理環境と明示的に関連付けられた共有pipを特定できた場合、その環境のPythonと共有pipで診断先をGET。`.pth`の実行・認証・既存indexを使わず、探索は最大8環境。 | 実管理環境での通信検証は未実施。uv backend、実index・認証、上限外や不明な対応関係は未確認。 |
| Poetry | 特定できたPoetry専用Python内のAuthenticatorとrequestsを使い、一時設定・無認証で診断先をGET。設定名も限定的に静的確認。 | 起動先PythonのCPUが不一致の場合は通信未実施として扱います。実repository・認証・projectと対応しない版は未検査。 |
| Conda | 既知のcondarcと環境変数の設定名、検証無効の候補を静的確認。現在の`CONDA_SSL_VERIFY=false`は環境変数の指定として要対応に表示。 | 複数のcondarcの継承・channel固有設定・pluginが関係し、認証情報を分離した実通信は未検査。ファイル中の候補は優先順位不明のため要対応と断定しない。 |
| Mamba / micromamba | ネイティブ本体で設定ファイル・環境変数を無効にし、一時rootと合成channelだけを`repoquery search`。設定名を限定的に静的確認。 | 本配布版での実機通信検証は未実施。実channel・認証・CA設定は未使用。対応しないCLI形式は未確認。環境作成・package導入はしない。 |
| Bun package manager | Bunの標準HTTPとpackage managerを区別。 | registry設定による固有通信は未検査。 |
| Maven / Gradle / sbt | 各ツールの未確認理由を表示。 | build script・pluginを実行しないため、repository固有通信は未検査。JDK一般の結果を代用しない。 |
| NuGet / dotnet restore | NuGet feedと.NET標準HTTPを区別。 | feed・認証による復元処理は未検査。 |
| rustup | 対象本体の`check`で、空の一時RUSTUP_HOMEと診断用更新情報を使用。実toolchainは使わず取得・更新もしない。 | 信頼済み対照が成立しない場合は拒否成功へ昇格せず、未確認として扱います。実配布先・実設定は未使用。 |
| Dart pub / Flutter pub | Dart標準HTTPとpubを区別。 | pubのsourceと認証を使う取得は未検査。SDKの自動取得はしない。 |
| Swift Package Manager / Xcode | 導入情報と未確認理由を表示。 | registry・Git・実Package.swiftを使う通信は未検査。 |
| CocoaPods | 導入情報と未確認理由を表示。 | Ruby・Git・CDNによるspec取得は未検査。 |
| Conan / vcpkg | 導入情報と未確認理由を表示。 | 実remote・port・buildを使う通信は未検査。 |
| PSResourceGet / PowerShellGet | PowerShellの一般的なWeb通信と各モジュールを区別。 | repository・認証を使う取得は未検査。 |
| CPAN / cpanm | Perl HTTP::Tiny・LWPと各クライアントを区別。 | mirror・固有HTTP実装の通信は未検査。 |
| OTP TLS / Hex / Rebar3 | OTPのTLSと各package managerを区別。 | registryと実プロジェクトの通信は未検査。 |

## OS・環境管理

| 対象 | 実装した検査 | 未確認の範囲・理由 |
|---|---|---|
| Homebrew | curlrcを明示する設定がある場合、関連設定名と検証無効の候補を静的確認。 | 対象curlと優先順位の確定は未検査。API mirrorに既定先へのfallbackがあるため、接続先を限定した固有通信は未検査。update・bottle取得はしない。 |
| WinGet | 導入情報と未確認理由を表示。 | source認証・更新による取得は未検査。 |
| Chocolatey / Scoop | 各ツールの未確認理由を表示。 | source・PowerShell・Gitの実取得は未検査。 |
| APT / DNF / Pacman / Zypper / APK | 対象が導入されている場合に既知の設定ファイルを限定的に読み、CA・proxy・検証・include等の設定名を静的確認。APKはHTTP repositoryの候補を確認。 | ファイルの読取範囲・include・host別設定・優先順位は未確定。検証無効のファイル記述だけでは実効設定を断定しない。repository通信やindex更新は未検査。 |
| mise / asdf | 本体と管理対象を区別。 | pluginごとに異なる取得経路は未検査。pluginは起動・導入しない。 |
| pyenv / nvm / rbenv / SDKMAN! | 既知の導入候補と管理対象を検出。 | 初期化スクリプト・pluginの取得通信は未検査。 |
| fnm / Volta / FVM | 管理ツールとSDKを区別。 | 本体・SDKの自動取得を避けるため取得通信は未検査。 |
| Corepack | 導入情報と未確認理由を表示。 | managerの自動取得を避けshimは起動しない。 |

## セキュリティ・CLI・GUI

| 対象 | 実装した検査 | 未確認の範囲・理由 |
|---|---|---|
| Safe Chain | 本体版とシェル・shim連携候補を静的に確認。macOS ARM64の公式1.5.26と本体ハッシュが一致し、同梱PythonとOS隔離の事前試験が成立する場合だけ、同一バイトの一時コピーと合成localhostで上流TLSを検査する。連携候補があればpip・npm・uv・pnpm・Yarn・Poetry・pipxの直接診断は見送る。 | 合成試験では元の本体を起動せず、既存CA鍵・普段の設定を使用しない。隔離や対照が成立しない場合はコピーを起動せず理由を表示。合成TLSはeMudhra検査先の証拠ではなく、普段の設定、実registry、脅威情報、他OS・他版は未検査。公式verifyも上流TLSの証拠にならない。 |
| OSV-Scanner | 対象バイナリーのGo・本体版を静的取得。合成依存1件だけを公式APIへ照会する。 | 実プロジェクトの依存や普段の設定は未使用。代表検査先は指定できず、接続経路も未確定。 |
| Git LFS | 対象LFSとGit本体を特定できる場合、空の一時Git設定と合成LFSロックAPIで読取照会。サーバー応答本文は記録しない。 | 本配布版での実機通信検証は未実施。実remote・認証・objectsは未使用。 |
| GitHub CLI | 導入情報と未確認理由を表示。 | `gh api`は認証付きAPI操作。認証を必要とする固有通信は自動検査の対象外。 |
| Codex / Claude Code / Gemini CLI / Kiro CLI | 各導入実体・同梱runtimeを可能な範囲で確認。 | 固有サービス・実アカウントのAPI通信は未検査。 |
| AWS CLI | 対象本体から署名なしのSTS形式の照会を診断先に固定し、一時の空config・空credentials、IMDS無効、再試行上限1を使用。 | 本配布版での実機通信検証は未実施。コマンドと資格情報の隔離をfixtureで検査。普段の認証・実AWSは未使用。S3固有のリージョン再解決を避けるためS3 APIではなくSTS形式を使用。 |
| Azure CLI | 対象CLIで`az rest --skip-authorization-header`を使い、空の一時設定で診断先のみをGET。現在の`AZURE_CLI_DISABLE_CONNECTION_VERIFICATION`指定はaz restの範囲で要対応。 | 本配布版での実機通信検証は未実施。認証・実サービス・普段の設定は未使用。利用するコマンドの検証設定は別確認。 |
| gcloud | 導入実体と未確認理由を表示。 | 認証・metadata探索・実サービス操作による通信は未検査。 |
| Firebase / Vercel / Netlify / Heroku / Supabase / Wrangler | 各導入実体と未確認理由を表示。 | ログイン済みAPIや実プロジェクトの通信は未検査。 |
| kubectl | 対象本体にユーザーなしの一時kubeconfigと診断先のみを渡し、`get --raw /`を試す。 | 匿名設定で対話認証を要求する場合は資格情報を入力せず未確認と表示。実cluster・普段のkubeconfigは未使用。 |
| Helm | 対象本体に空の一時plugin・repository設定を渡し、合成chart indexを`repo add`で取得。repository設定名を限定的に静的確認。 | 本配布版での実機通信検証は未実施。実clusterやchart repositoryの認証・操作は未検査。 |
| Terraform / OpenTofu / Pulumi | 本体・pluginの未確認理由を表示。 | provider導入・state・クラウド操作を伴う通信は未検査。 |
| rclone | 対象本体のHTTP backendで合成remoteを一覧照会。空の一時設定を使用。 | 普段のremote・認証・ファイル転送は未使用。 |
| Postman / Insomnia / Bruno | 各導入実体と未確認理由を表示。 | GUI workspace・保存済み認証による通信は未検査。 |
| Docker / BuildKit / Podman | 導入情報とCLI・daemonの違いを表示。 | daemonのregistry認証・pull/buildによる通信は未検査。 |
| FileZilla / Cyberduck / WinSCP / Transmit | 導入情報とHTTPS/FTPSの未確認理由を表示。 | 実サイト設定・認証・ファイル転送は未検査。SSH/SFTPはTLS対象外。 |

Safe Chainの限定プローブは、公式1.5.26のmacOS ARM64配布物とSHA-256が一致する本体だけを対象にします。同版ソースではパッケージ版の`bin`にある実行ファイルの位置を優先し、CA処理の読み込み時に鍵と証明書を読取・必要に応じて生成する。そのため一時HOMEへの変更だけでは既存の鍵を保護できない。自動診断では通常環境で合成データを使った隔離前後の対照を確認し、限定ポート以外の接続、保護領域の読取、一時作業領域外への書込等を拒否できない場合は本体コピーを起動しない。成立した場合はコピーを再ハッシュして実行し、自作npm代役と合成CAを使うlocalhost上流の信頼済み・未信頼CA・名前不一致を確認する。これはeMudhra対象証明書や公開検査先の結果ではなく、利用者の普段の設定も再現しない。隔離を使えない実行環境では未確認として残る。この条件を満たしても、通常環境全体の安全性を保証するものではありません。

根拠: [Go Modules](https://go.dev/ref/mod)、[uv CLI](https://docs.astral.sh/uv/reference/cli/)、[Cargo search](https://doc.rust-lang.org/cargo/commands/cargo-search.html)、[pipxの仕組み](https://pipx.pypa.io/stable/explanation/how-pipx-works.html)、[Poetry Authenticator](https://github.com/python-poetry/poetry/blob/main/src/poetry/utils/authenticator.py)、[Conda設定の探索順](https://github.com/conda/conda/blob/main/docs/source/user-guide/configuration/use-condarc.rst)、[CondaのHTTPセッション](https://github.com/conda/conda/blob/main/conda/gateways/connection/session.py)、[Mamba設定](https://mamba.readthedocs.io/en/latest/user_guide/configuration.html)、[rustup更新確認の実装](https://github.com/rust-lang/rustup/blob/master/src/cli/rustup_mode.rs)、[Git LFS locks](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-locks.adoc)、[Helm repo add](https://helm.sh/docs/helm/helm_repo_add/)、[Azure CLI az rest](https://learn.microsoft.com/en-us/cli/azure/reference-index#az-rest)、[kubectl get](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/)、[AWS CLI STS](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html)、[Homebrew環境設定](https://docs.brew.sh/Manpage#environment)、[APT設定](https://manpages.debian.org/apt/apt.conf.5.en.html)、[Safe Chain 1.5.26の配布物](https://github.com/AikidoSec/safe-chain/releases/expanded_assets/1.5.26)、[同版の導入先判定](https://github.com/AikidoSec/safe-chain/blob/1.5.26/packages/safe-chain/src/installLocation.js)、[同版の基準ディレクトリ](https://github.com/AikidoSec/safe-chain/blob/1.5.26/packages/safe-chain/src/config/safeChainDir.js)、[同版のCA処理](https://github.com/AikidoSec/safe-chain/blob/1.5.26/packages/safe-chain/src/registryProxy/certUtils.js)、[OSV-Scanner](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)。
