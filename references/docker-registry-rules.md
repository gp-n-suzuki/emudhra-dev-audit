# Docker registry設定の判定

参照日：2026-11-06。対象は取得済みのregistry設定であり、外部registryへのTLS通信やDockerアプリのコード署名ではありません。

## 公式資料で確認したこと

- Docker DesktopはLinux VM内のEngineとホストの間でbackendによるネットワーク中継を使います。macOSとWindowsのbackendは `com.docker.backend` です。
  https://docs.docker.com/desktop/features/networking/
- 一般のinsecure registryは、HTTP接続またはデーモンが信頼するCAを持たないTLS接続を許す設定です。
  https://docs.docker.com/reference/cli/dockerd/#insecure-registries
- Docker contextは接続先の設定を持ち、CLIのフラグ・環境変数でも接続先が変わります。ローカルにDesktopが存在することだけでは、問い合わせたEngineがDesktopか判断できません。
  https://docs.docker.com/engine/manage-resources/contexts/
  https://github.com/docker/cli/blob/master/cli/command/cli.go

## このツールで行う限定した判断

公式の構成説明だけで `hubproxy.docker.internal:5555` を全環境で安全と断定することはできません。この名前に一致し、同じ問い合わせ先のOS名が `Docker Desktop`、サーバー名が `docker-desktop`、接続先との対応が確認できたローカルUnixソケットまたはnamed pipeである場合に限り、内部接続用例外と判断します。これは取得情報からの判断で、外部通信の検証結果ではありません。

名前だけの一致、Desktopアプリの検出だけ、リモート接続、接続先情報の欠落・矛盾では内部例外にせず、追加確認とします。Desktop以外のOSを返す同じEngineの設定なら、同名でも一般の設定修正対象です。外部のSecure=false、名前を伏せたSecure=false、ループバック以外のinsecure CIDRは要対応を維持します。

収集処理は `docker context inspect` のメタデータと、接続先を固定した `docker info` のOS名・サーバー名・registry設定を記録します。DOCKER_HOST単独指定はその接続先を扱い、DOCKER_HOSTとDOCKER_CONTEXTの両方がある場合はCLIの選択を変えず、対応関係を確定しません。設定値の取得に失敗した場合も完了扱いにはしません。認証情報やregistry設定全体を保存せず、対象名・Secure値・CIDRと判定に必要な接続情報に限定します。

元の件数・対象名・Secure値を残し、旧判定・説明・案内は `metadata.registry_original_result` に保存します。新しい分類と根拠は `metadata.registry_assessment` です。別レコードの通信・バージョン・設定問題は変更しません。旧レポートに接続先情報がなければ、現在のホスト情報を流用せず判定保留にします。

## 保存済み結果への追加確認

利用者が接続先と実効設定を確認済みの場合は、再判定CLIの `--docker-confirmation <JSON>` で別の根拠として渡せます。自動観測の `docker_connection` やCIDRを補作せず、`metadata.registry_user_confirmation` に保存し、説明・作業一覧・全体と個別のAIプロンプトに「ユーザー提供」と表示します。外部TLSが未実測という理由だけで、この内部設定の修正作業を求めません。

JSONの形式は以下です。ハッシュは例示値であり、実際の元ファイルと対象記録から計算します。`record_sha256` は `reassess_report.record_digest(row)` による、キー順を揃えたJSONのSHA256です。

```json
{
  "schema_version": 1,
  "source": "user-provided",
  "provided_at": "2026-11-06",
  "source_sha256": "元レポートのSHA256（64桁）",
  "record_sha256": "対象registry記録のSHA256（64桁）",
  "facts": {
    "local_docker_desktop": true,
    "context": "desktop-linux",
    "endpoint_type": "unix",
    "insecure_registries": ["hubproxy.docker.internal:5555"],
    "insecure_registry_cidrs": ["127.0.0.0/8", "::1/128"],
    "user_added_insecure_registries": false,
    "user_added_registry_mirrors": false,
    "docker_hub_secure": true
  }
}
```

元ファイルのハッシュと対象記録を照合してから、新しい出力先へだけ適用します。確認JSONは出力先の `user-confirmation.json` にそのまま保存し、再判定manifestにハッシュを残します。別の診断への流用、対象の曖昧な一致、確認済みデータの再上書きは受け付けません。保存済みの外部registry、非DesktopのEngine、リモート接続などと矛盾する確認結果で問題を消しません。ユーザー確認の根拠は `user-confirmed-desktop-and-local-endpoint`、自動観測の根拠は `same-daemon-desktop-and-local-endpoint` と区別します。

この機能は提供された確認結果を使うものであり、記載内容を再実測したり署名検証したりしません。確認日時が異なる場合も、新たな観測と誤認せず、それぞれの記録日時と根拠を確認します。

回帰テスト：`tests/test_docker_registry.py`。内部だけ、内部と外部の混在、非Desktopで同名、Desktop判別不能、類似名・別ポート、環境変数の上書き、他の問題の保持を合成データで確認します。
