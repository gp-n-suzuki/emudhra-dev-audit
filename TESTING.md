# 保守・連携担当者向け — テストと結果データ

## 回帰テスト

ソースフォルダーでPythonのユニットテストとJavaScriptのDOM fixtureテストを実行します。JavaScriptのテストには `node --test` を利用できるNode.jsが必要です。

```bash
python3 -B -m unittest discover -s tests
node --test tests/test_quickstart.cjs tests/test_report_ui.cjs
```

fixtureは合成データです。`tests/make_synthetic_fixtures.py` から48レコードを生成します。版の数値は公開基準の境界例、同一実体・別導入・別名・venv・CPU不一致・未知配布等は架空の構成です。維持する境界は [tests/fixtures/README.md](tests/fixtures/README.md) を参照してください。実環境の診断結果を回帰fixtureとしてそのまま追加しないでください。

配布内容は `packaging/verify_release.py`、対象OS上のhelp・合成再判定・模擬起動は `packaging/offline_smoke.py` などで検査します。手順は [BUILDING-ja.md](BUILDING-ja.md)、実施範囲は [VALIDATION-ja.md](VALIDATION-ja.md) を参照してください。

`tests/integration_*.py` は別のTLS統合試験です。隔離環境で、対象クライアント・CA・接続先・書き込み先を確認してから実行してください。単体テストの成功やHTML構造検査は、全ツール・全OSの実通信や実ブラウザの表示確認を意味しません。

## 新規検査からレポート生成までの合成検証

`tests/test_report_flow.py` はソース版と6対象の配布用アプリ資材を対象に、通常CLI・オフラインCLI・デスクトップ起動からレポートを生成します。収集部分だけを合成入力に置き換え、判定・HTML/JSON/TXT生成には本体の処理を使います。導入先と更新件数、優先表示、編集可能なAIプロンプト、最新CSS/JavaScriptの組み込み、2回分の結果保持を確認します。

検証結果を残す場合は、既存のPythonを使い、未使用の出力先を指定します。

```bash
python3 -B packaging/report_flow_smoke.py --app . --out .artifacts/report-flow-check
```

配布資材の確認では `--app` を展開先の `app` フォルダーへ変更します。この検証は対象コマンド・通信・ブラウザ起動を行わず、同梱Pythonやネイティブ起動ファイルも実行しません。対象OS上の同梱ランタイムの動作確認とは別です。

## JSON連携と終了コード

診断JSONの `schema_version` は3、表示モデル `presentation.schema_version` は1です。原記録の `records[].status`・`review_state`・観測データと、表示用の行動分類は別の情報です。

`presentation.primary_action_counts` は重複しない主分類、`presentation.action_counts` は重複を含む行動別件数、`presentation.tool_total` は対象外を含む表示ツール数です。`summary` にも同じ新件数と `presentation_tool_total` があります。旧集計の `summary.tool_total`・`tool_review_counts` を新表示の件数に足さないでください。詳細は [ACTION-PRESENTATION-ja.md](ACTION-PRESENTATION-ja.md) のJSON欄にあります。

CLIの終了コードは、表示に合わせて、具体的対応があれば1、必要条件や対応状況に追加確認があれば2、それらがなければ0です。引数解析エラーも2なので、終了コードだけで診断が完了したとは扱えません。`desktop_entry.py` は結果画面を開ければ0、起動・保存・表示の失敗は3を返します。

`reassess_report.py` は保存済みJSONを新しい基準で再判定します。導入先の再探索、対象コマンドの実行、ネットワーク検査は行いません。元ファイルを変更せず、新しい出力先だけを受け付けます。観測日時は `source_observation.generated_at`、再生成日時はトップレベルの `generated_at` です。再判定を新しい通信観測として扱わないでください。

Dockerの接続先・実効設定を利用者が追加確認した場合は `--docker-confirmation <JSON>` を指定できます。元レポートと対象記録のSHA256を照合し、自動観測と区別して保存・表示します。形式と適用条件は [Docker registry設定の判定](references/docker-registry-rules.md) に記載しています。入力・通信証拠の不変、別レポートへの誤適用の拒否、追加確認の出所表示は `tests/test_saved_reassessment.py` と `tests/test_docker_registry.py` で検証します。

バージョン対策完了時も通信状態と未確認事項は保持します。`version_complete` は照合対象の更新完了、`complete` は導入先ごとにバージョン照合と通信検証の根拠が混在する完了です。`gaps[].blocks_completion=false` の未確認事項だけではCLIを2に戻しません。実体・バージョン・起動先・環境の矛盾と、必要部品・配布条件不明は完了を妨げます。回帰テストは `tests/test_action_completion.py` にあります。

## Guided report and AI prompts

`tests/test_scoped_completion.py` は確認済み部品・通信経路と未評価範囲の分離を検証します。情報欠落と実際の矛盾、明示的なPython/JDKの結び付け、別環境の不適用、Composerの行折り返しを含む送信前拒否ログと誤認防止、他の通信・設定・バージョン問題の保持を扱います。保存済み原記録を変えず、観測の解釈は表示モデルに追加します。

`tests/test_docker_registry.py` はDesktop内部registryと一般のinsecure registryを分け、接続先情報の欠落、別Engine、混在、CIDR、他の問題の保持を確認します。判定条件と出典は [Docker registry設定の判定](references/docker-registry-rules.md) を参照してください。新規のデーモン問い合わせや外部通信は実行せず、保存済み結果の再判定は元入力を保持した新しい出力先へ行います。

`tests/test_guided_report.py` covers installation-scoped CA completion, conflicting evidence, system Ruby maintenance, embedded components, retained unknowns, private-field exclusion, and the editable report structure. `tests/test_report_ui.cjs` covers selection, filters, evidence links, printing/restoration, and copying edited prompts with a manual fallback. These are offline synthetic checks; they do not execute suggested remediation commands or new TLS probes.
