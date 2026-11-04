"""Group verified end-user packages by OS in one distributable ZIP."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import zipfile

from build_release import ROOT, VERSION, DISPLAY_VERSION, stream_hash
from fetch_runtimes import sha256
from verify_release import verify


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=ROOT/'releases'/VERSION)
    args=parser.parse_args()
    directory=args.directory
    manifest=json.loads((directory/'release-manifest.json').read_text())
    assert manifest['version']==VERSION
    packages=manifest['packages']
    assert {p['platform'] for p in packages}=={'windows-x64','windows-arm64','macos-x64','macos-arm64','linux-x64','linux-arm64'}
    files={};rows=[]
    for package in packages:
        verify(directory/package['file'],package)
        family=package['platform'].split('-')[0]
        folder={'windows':'Windows','macos':'macOS','linux':'Linux'}[family]
        relative=folder+'/'+package['file']
        files[relative]=(directory/package['file']).read_bytes()
        label=package['platform'].replace('macos-arm64','Mac / Apple Silicon').replace('macos-x64','Mac / Intel')
        rows.append('<tr><td>'+html.escape(label)+'</td><td><a href="'+relative+'">'+html.escape(package['file'])+'</a></td></tr>')
    guide='''<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>はじめに — eMudhra 開発環境診断</title><style>body{font:17px/1.8 system-ui,sans-serif;max-width:900px;margin:50px auto;padding:0 24px;color:#23334d;background:#f5f7fb}h1{line-height:1.4}section{background:white;border:1px solid #dce3ee;border-radius:16px;padding:24px;margin:20px 0}table{width:100%;font-size:14px;border-collapse:collapse}td{padding:12px;border-bottom:1px solid #ddd;overflow-wrap:anywhere}a{color:#1458b5}</style>
<h1>PCに合う版を展開して<br>「診断を開始」をダブルクリック</h1>
<p>eMudhra 開発環境診断 VERSION。通常は数分で完了し、結果画面が自動で開きます。</p>
<section><h2>1. PCに合うファイルを選ぶ</h2><p>Windows・macOS・Linuxのフォルダーに、CPU別の配布ファイルが入っています。受け取る人のOS・CPUが分かる場合は、そのファイル1つだけを渡せます。</p><table>ROWS</table>
<p>Macは「このMacについて」、Windowsは「設定 → システム → バージョン情報」でCPUを確認できます。</p></section>
<section><h2>2. フォルダー全体を展開する</h2><p>圧縮ファイルを展開し、中の「診断を開始」をダブルクリックしてください。コマンドの入力やPythonの事前インストールは不要です。Linuxではファイル管理アプリの「実行」または「端末で実行」を選ぶ場合があります。</p></section>
<section><h2>3. 結果と対応手順を見る</h2><p>ブラウザに自動で開いた結果を確認します。結果は「結果」に日時ごとに残ります。開かなかった場合は、その中のreport.htmlをダブルクリックしてください。</p></section>
<p><a href="配布情報/VALIDATION-ja.md">検証範囲</a> · <a href="配布情報/P2-COVERAGE-ja.md">対象別の確認範囲</a> · <a href="配布情報/OFFICIAL-DECISIONS-ja.md">公式対策と判定範囲</a> · <a href="配布情報/SHA256SUMS.txt">配布ファイルのハッシュ</a></p></html>'''.replace('VERSION',DISPLAY_VERSION).replace('ROWS',''.join(rows))
    files['はじめに.html']=guide.encode('utf-8')
    for name in ('release-manifest.json','archive-verification.json'):
        files['配布情報/'+name]=(directory/name).read_bytes()
    files['配布情報/VALIDATION-ja.md']=(ROOT/'VALIDATION-ja.md').read_bytes()
    files['配布情報/P2-COVERAGE-ja.md']=(ROOT/'P2-COVERAGE-ja.md').read_bytes()
    files['配布情報/OFFICIAL-DECISIONS-ja.md']=(ROOT/'OFFICIAL-DECISIONS-ja.md').read_bytes()
    files['配布情報/SHA256SUMS.txt']=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n'
                                          for name,data in sorted(files.items()) if name.endswith(('.zip','.tar.gz'))).encode()
    files['配布情報/BUNDLE-SHA256SUMS.txt']=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n'
                                                 for name,data in sorted(files.items())).encode()
    base='emudhra-dev-audit-'+VERSION+'-all-platforms'
    destination=directory.parent/(base+'.zip')
    with zipfile.ZipFile(destination,'w') as archive:
        for name,data in files.items():
            info=zipfile.ZipInfo(base+'/'+name,date_time=(2026,11,2,0,0,0))
            info.compress_type=zipfile.ZIP_STORED if name.endswith(('.zip','.tar.gz')) else zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16
            archive.writestr(info,data)
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None
        for name,data in files.items():
            with archive.open(base+'/'+name) as stream: assert stream_hash(stream)==hashlib.sha256(data).hexdigest()
    digest=sha256(destination)
    destination.with_suffix('.zip.sha256').write_text(digest+'  '+destination.name+'\n')
    print(json.dumps(dict(file=str(destination),bytes=destination.stat().st_size,sha256=digest,
                         platforms=6,crc='verified',hashes='verified'),indent=2))


if __name__=='__main__': main()
