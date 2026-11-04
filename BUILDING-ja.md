# 保守担当者向け — ビルド手順

利用者向けの実行手順は [README.md](README.md)、テストは [TESTING.md](TESTING.md)、配布時の確認は [PUBLISHING-ja.md](PUBLISHING-ja.md) にあります。

## 必要環境と配布対象

ビルドにはPython 3.12以上が必要です。ソース版の診断に必要なPython 3.8以上とは条件が異なります。表示版は1.0.1、内部版は1.0.1です。共通定義は `distribution_version.py` にあります。

| 対象 | 配布形式 | 同梱Pythonの実行ファイル |
|---|---|---|
| Windows x64 / arm64 | zip | `app/runtime/python.exe` |
| macOS x64 / arm64 | tar.gz | `app/runtime/bin/python3` |
| Linux x64 / arm64 | tar.gz | `app/runtime/bin/python3` |

`packaging/runtimes.json` はCPython 3.13.18の6対象についてURLとSHA-256を固定しています。ビルドは既成ランタイムと共通コードの再梱包です。対象OS上での実行検証とは別です。最小OSバージョンやLinuxディストリビューションごとの動作条件は、このプロジェクトでは確定していません。

## ビルドする

以下はソースフォルダーを現在のディレクトリとして実行します。既存成果物の上書きを避けるため、未使用の出力先を選んでください。

```bash
# キャッシュが不足する場合、ネットワーク取得を行う
python3 -B packaging/fetch_runtimes.py
# 回帰テストと合成サンプルの生成
python3 -B -m unittest discover -s tests
node --test tests/test_quickstart.cjs tests/test_report_ui.cjs
python3 -B packaging/generate_sample.py
# 全6対象をビルドし、アーカイブを検査
python3 -B packaging/build_release.py --out releases/1.0.1
python3 -B packaging/verify_release.py releases/1.0.1
```

キャッシュは `.artifacts/runtime-cache/` です。ソース配布にはキャッシュやビルド済み配布物を含めません。`fetch_runtimes.py` は不足分を取得し、ハッシュを検証します。`build_release.py` 自体にネットワーク取得はなく、不足・不一致時は停止します。

`build_release.py` の `--platform windows-x64` などを繰り返せば対象を限定できます。ただし `verify_release.py` と `build_bundle.py` は6対象すべてがそろった成果物を前提とします。ビルダーは既存の出力先への書き込みを禁止していないため、必ず出力先を確認してください。

配布直下は起動ファイル・`app`・`docs` の3項目です。診断コード、固定基準、サンプル、Python、利用者向け説明、第三者ライセンスを許可リストから梱包します。作業フォルダーや `releases/` 全体を圧縮して配布しないでください。テスト・Git履歴・個人診断・検証ログは含めません。Linuxランタイムは、大文字小文字を区別しないファイルシステムで内容を損なわないよう、アーカイブから直接再梱包します。

全6対象のビルド・検査後に、必要なら一括配布用ZIPも作れます。

```bash
python3 -B packaging/build_bundle.py --directory releases/1.0.1
```

出力は `releases/emudhra-dev-audit-1.0.1-all-platforms.zip` とその `.zip.sha256` です。入力先の `release-manifest.json` と、`verify_release.py` が生成する `archive-verification.json` が必要です。

## 対象OSで起動を検証する

配布物を日本語・空白入りパスへ展開し、対象OS/CPUの同梱Pythonで実行します。以下のプレースホルダーは実際のパスへ置き換えます。

```bash
# macOS / Linux
"<展開先>/app/runtime/bin/python3" -E -s -B "<ソース>/packaging/offline_smoke.py" "<展開先>"
```

```powershell
# Windows PowerShell
& '<展開先>\app\runtime\python.exe' -E -s -B '<ソース>\packaging\windows_smoke.py' '<展開先>'
```

検査内容はファイルハッシュ、help、合成記録からのJSON/HTML/TXT生成、版とschema、模擬起動、異なる作業ディレクトリ、PATHにPythonがない条件、複数回の結果保持です。実ホストの診断や通信は行わず、ブラウザ起動は記録用の代替処理を使います。

実際のGUI、OSの信頼ストア、ダウンロード後のGatekeeper/SmartScreen、署名・公証は別に確認してください。実施OS・CPUと、native・変換・コンテナ・Wineの区別を [VALIDATION-ja.md](VALIDATION-ja.md) に記録します。

## 既存コンテナでの任意検証

Dockerの利用が許可され、必要イメージが既に存在する環境で使います。スクリプトは `--pull=never`、ネットワークなし、読み取り専用root、非root、capabilityなしで起動し、ホスト資材を読み取り専用でマウントします。

```bash
bash packaging/run_virtual_checks.sh linux-x64 /absolute/path/releases/1.0.1 debian:bookworm-slim
# arm64イメージ名は利用可能なものへ置き換える
bash packaging/run_virtual_checks.sh linux-arm64 /absolute/path/releases/1.0.1 '<既存arm64イメージ>'
bash packaging/run_virtual_checks.sh windows-x64 /absolute/path/releases/1.0.1
bash packaging/run_virtual_checks.sh windows-arm64 /absolute/path/releases/1.0.1
```

Windowsの後二つは既存の `emudhra-wine-test:amd64` / `:arm64` を使う互換試験で、Windows実機検証ではありません。環境が不足する場合は停止します。

## ソース候補・ハッシュ・版更新

```bash
python3 -B packaging/build_source.py --out releases/1.0.1-public-source
```

`packaging/source-files.txt` の明示リストだけをコピーし、Git履歴を含まない候補と `source-manifest.json` を作ります。出力先は未使用である必要があります。

ルートの `SHA256SUMS.txt` は、現行ソースの整合性確認用です。対象は `packaging/source-files.txt` のうちチェックサム自身を除く167ファイルで、パス順にSHA-256を記録します。Git履歴、診断結果、ランタイムキャッシュ、配布アーカイブは対象に含めません。署名や過去の公開物のハッシュではありません。

ソース候補の生成前に、次のコマンドで確認します。

```bash
python3 -B verify_package.py
```

ソースを変更したときは、意図した変更だけであることを確認してから再生成します。ルート専用の生成スクリプトはありません。以下はmacOS / Linuxで、ソースフォルダーを現在のディレクトリとして実行する例です。既存一覧と許可リストの一致を確認し、対象・順序・書式を維持して再計算します。一覧が一致しない場合は停止するため、対象の追加・削除を暗黙に承認する処理にはなりません。

```bash
python3 -B - <<'PYTHON'
import hashlib
from pathlib import Path

root = Path.cwd().resolve()
manifest = root / 'SHA256SUMS.txt'
paths = [line.split('  ', 1)[1]
         for line in manifest.read_text(encoding='utf-8').splitlines()]
allowed = (root / 'packaging/source-files.txt').read_text(encoding='utf-8').splitlines()
expected = sorted(name for name in allowed if name != 'SHA256SUMS.txt')
if len(allowed) != len(set(allowed)) or paths != expected:
    raise SystemExit('対象一覧が一致しません。変更内容を確認してください。')
lines = []
for name in paths:
    path = root / name
    if (Path(name).is_absolute() or '..' in Path(name).parts
            or root not in path.resolve().parents
            or path.is_symlink() or not path.is_file()):
        raise SystemExit('対象ファイルを確認してください: ' + name)
    lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + name)
manifest.write_bytes(('\n'.join(lines) + '\n').encode('utf-8'))
PYTHON
python3 -B verify_package.py
```

`build_source.py` はルートのチェックサムもコピーしますが、更新はしません。ルートを検証してから候補を作成し、候補内でも `python3 -B verify_package.py` を実行してください。候補と同時生成される `source-manifest.json` は、チェックサム自身も含む168ファイルのサイズ・ハッシュを記録します。

`build_release.py` は展開内容用の `docs/SHA256SUMS.txt` と、アーカイブ用の `SHA256SUMS.txt` を新たに生成します。ルートの既存チェックサムを手で転用しないでください。

版変更時は `distribution_version.py` を更新し、`python3 -B packaging/sync_version.py` で表記を同期します。既存リリースの履歴や判定基準日、schemaは版名だけを理由に変更しません。ランタイム変更時は固定ハッシュ・出典・ライセンスを見直してください。
