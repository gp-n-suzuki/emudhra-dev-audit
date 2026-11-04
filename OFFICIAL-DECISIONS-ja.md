# 公式配布版と取得済み情報の判定範囲（基準日2026-11-02）

- 固定データの対象は124基準行です。公式版27、公開依存1、部品依存87、本体閾値未確定9。`references/official-research.json`の各`review`に確認日、確認済み版と初回対策版の区別、配布・OS条件、必要な証拠、未確定事項を保持します。87部品依存行は公式文書の取得結果も記録し、取得制限を「未修正」の証明にはしません。全製品・全過去版の固定タグを確認できたという意味ではありません。各review.verification_scopeで、出典本文を確認した範囲と取得制限、未再取得の出典を区別しています。
- [Safe Chain 1.5.27](https://github.com/AikidoSec/safe-chain/releases/tag/1.5.27)は公式バイナリの同梱Node.js 24.22.1への更新を明示。[固定tagのビルド定義](https://github.com/AikidoSec/safe-chain/blob/1.5.27/.github/workflows/create-artifact.yml)と配布ハッシュで範囲を限定します。直接の前版1.5.26は更新対象、1.5.27は確認済み対策版。初回対策版の全履歴、未知の過去版・後続版、custom/npm/外部Node、別製品Endpoint/Noonへ無条件適用しません。固定tag READMEの取得例は1.5.26のため、案内にはreleaseページを使います。
- Safe Chainの過去の保存記録にハッシュがない場合、同じパス・実行環境の本体版1.5.26と、公式ハッシュを検証してから実行する限定プローブの完了記録がそろった場合だけ配布推定に使用します。新たにハッシュを取得した観測とは区別します。現在の収集は同じ静的readから版とSHA-256を保持します。
- Safe Chainの公式版照合は独立した派生レコードです。`product_release_evidence=true`、`evidence_origin=derived-from-recorded-evidence`、`new_observation=false`、空の`samples`を持ちます。普段の通信未検査、実測異常、検証無効設定を保持し、原観測の追加には数えません。
- Deno/rustupのinventory版を通常の比較へ接続し、保存済み同梱部品を現基準で再照合。同一実体との結び付けがない部品、SBOM、別runtime、曖昧な版、矛盾する配布証拠は成功の根拠にしません。コンパイラ版を既存生成物のTLSへ流用しません。
- [Go GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)は1.26.10より前のGo 1安定版も対象と明記。同じバイナリのbuildinfoを照合します。別のGoコンパイラーは利用しません。CPU不一致による起動失敗は独立して残します。
- [certifi advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2)の対策版は2026.10.18。2026.10.19の推奨更新と混同しません。[pip 26.2.2](https://pip.pypa.io/en/stable/news/#v26-2-2)は同梱certifi 2026.10.19ですが、system roots併用・CA override・通信成功は別です。
- [JetBrains公式対策](https://blog.jetbrains.com/security/2026/10/compromised-emudhra-certificates-ides/)のJBR 25.0.4.1b635.79/508.41/329.142、21.0.11b1163.125、21.0.9b1038.91をbuild family別に比較。確認済み対策版であって初回版の断定ではありません。Android Studioなどの独自buildは修正取り込みの確認が必要です。JCEF配信、jetbrainsd、独自truststoreは別です。IDEの2025.2更新はJBRのみという制限も記録しました。
- Poetry/pipは自己venvの公開パッケージName/Versionを絶対launcherから静的に収集し、参考版との比較を表示します。project envや実際のimport証拠と区別します。HomebrewのCA版は同じbrew実体に結び付く構造化情報が必要であり、実体IDのない旧記録を別導入へ流用しません。
- ツール単位の主分類と個別レコードの判定は集計単位が異なります。部品の更新対象が判明しても、同じツールに未確認の通信があれば追加確認を併記します。
- [Claude Codeの現行npm導入](https://code.claude.com/docs/en/setup#install-with-npm)もnative binaryです。Nodeはインストール時の条件であり、CLI実行のTLS根拠にはしません。Azureのcertifi更新PRは11月2日確認時には未リリース。Kiro CLI、Git GUI、ファイル転送4製品を含む本体閾値未確定9対象は、同じ実体の部品と実効CAが必要です。
- 保存済みJSONの再判定には`reassess_report.py 元report.json --out 新しい出力先`を使用できます。導入先の再探索・コマンド実行・ネットワーク検査は行わず、元ファイル不変と通信証拠の一致を確認します。新しい出力先のみを受け付け、観測日時と再判定日時を区別して表示します。

基準データの全対象・出典・適用条件は `references/official-research.json` と `references/assessment.json` に保持しています。参照データは固定スナップショットで、自動更新されません。個別環境の観測値・集計は配布文書に含めません。
