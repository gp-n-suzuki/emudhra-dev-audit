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

## JSON連携と終了コード

診断JSONの `schema_version` は3、表示モデル `presentation.schema_version` は1です。原記録の `records[].status`・`review_state`・観測データと、表示用の行動分類は別の情報です。

`presentation.primary_action_counts` は重複しない主分類、`presentation.action_counts` は重複を含む行動別件数、`presentation.tool_total` は対象外を含む表示ツール数です。`summary` にも同じ新件数と `presentation_tool_total` があります。旧集計の `summary.tool_total`・`tool_review_counts` を新表示の件数に足さないでください。詳細は [ACTION-PRESENTATION-ja.md](ACTION-PRESENTATION-ja.md) のJSON欄にあります。

CLIの終了コードは、表示に合わせて、具体的対応があれば1、追加確認・未検査があれば2、それらがなければ0です。引数解析エラーも2なので、終了コードだけで診断が完了したとは扱えません。`desktop_entry.py` は結果画面を開ければ0、起動・保存・表示の失敗は3を返します。

`reassess_report.py` は保存済みJSONを新しい基準で再判定します。導入先の再探索、対象コマンドの実行、ネットワーク検査は行いません。元ファイルを変更せず、新しい出力先だけを受け付けます。観測日時は `source_observation.generated_at`、再生成日時はトップレベルの `generated_at` です。再判定を新しい通信観測として扱わないでください。
