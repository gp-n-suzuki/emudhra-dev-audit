# 保守担当者向け — 配布・公開時の確認

この文書は配布を担当する方の確認事項です。利用者向けの手順は [README.md](README.md)、成果物の作成は [BUILDING-ja.md](BUILDING-ja.md) を参照してください。

## 公開する内容を限定する

公開リポジトリとReleaseの添付物は、誰でも閲覧・取得できる前提で確認します。配布対象のファイルとGit履歴は別々に確認してください。

- 個人の診断レポート、ローカルパス、実環境由来の検証記録やそのバックアップを含めないでください。
- `.artifacts/`、ランタイムキャッシュ、作業ディレクトリ、`releases/` 全体を一括公開しないでください。
- 他のプロジェクトからコピーした場合、元プロジェクトのGit履歴をそのまま公開しないでください。現在のファイルを修正しても、過去のコミットに含まれた情報は消えません。
- 公開先、権限、既存のタグやReleaseを確認し、既存成果物を上書きしないでください。

ソース候補は `packaging/build_source.py` が許可リストから作成します。Git履歴、診断結果、ランタイムキャッシュは含みません。生成される `source-manifest.json` で内容を照合し、候補自体にも不要な情報がないか確認してください。候補の生成はGitHubへの登録や公開を行う処理ではありません。

## 配布物を確認する

表示版は **1.0**、内部版は **1.0.0**、タグ定義は **v1.0.0** です。共通定義は `distribution_version.py` です。

`packaging/build_release.py --out releases/1.0.0` は、OS・CPU別アーカイブ、`SHA256SUMS.txt`、`release-manifest.json` を生成します。全6対象を用意した場合、アーカイブ名は次の形式です。

- `emudhra-dev-audit-1.0.0-windows-x64.zip`
- `emudhra-dev-audit-1.0.0-windows-arm64.zip`
- `emudhra-dev-audit-1.0.0-macos-x64.tar.gz`
- `emudhra-dev-audit-1.0.0-macos-arm64.tar.gz`
- `emudhra-dev-audit-1.0.0-linux-x64.tar.gz`
- `emudhra-dev-audit-1.0.0-linux-arm64.tar.gz`

`python3 -B packaging/verify_release.py releases/1.0.0` で検査し、生成された `archive-verification.json` と対象OS上の実行結果を確認します。`RELEASE-NOTES-ja.md` は説明文の元資料です。ビルダーは `RELEASE-ja.md` というファイルを生成しません。一括配布用ZIPが必要な場合は [BUILDING-ja.md](BUILDING-ja.md) の手順を使います。

## 公開前に残る確認

- **本体ライセンス**：未選択です。再利用条件を確定し、第三者ランタイムのライセンスも保持してください。
- **OS・CPU別の動作**：[VALIDATION-ja.md](VALIDATION-ja.md) の未確認範囲を確認します。アーカイブ生成やCPU形式検査は対象OS上の動作保証ではありません。
- **署名・公証と起動制限**：Gatekeeper/SmartScreenを含むダウンロード後の起動を確認します。セキュリティ設定の無効化を利用手順にしないでください。
- **ハッシュ**：ルートの `SHA256SUMS.txt` は現行ソース用です。`python3 -B verify_package.py` で確認し、ソース変更時は [BUILDING-ja.md](BUILDING-ja.md) の手順で対象を保って再生成してください。ソース候補内でも検証し、同時生成の `source-manifest.json` とも照合します。配布アーカイブと展開内容には、それぞれのビルドで生成したチェックサムを使用します。公開済みの成果物・ハッシュ・署名は、現行ソースの変更に合わせて書き換えないでください。
- **真正性**：SHA-256は取り違え・破損の検出用です。署名や公開者の本人確認の代わりにはなりません。

このソースツリーに配布済みアーカイブや公開先の設定が存在することは前提にしていません。必要な成果物を作成・検証したうえで、実際に公開する内容を選んでください。
