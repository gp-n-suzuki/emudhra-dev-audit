"""Rebuild the fictional report with the same renderer as real diagnostics."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import audit


def row(name, status, method, detail, action='', metadata=None, samples=None):
    return dict(name=name, status=status, assessment_method=method, detail=detail,
                action=action, metadata=metadata or {}, samples=samples or [])


def samples(status):
    return [dict(target=name, status='CONTROL_OK' if control else status,
                 detail='接続できた' if control else 'この行は表示確認用の架空の観測です。')
            for name, url, control in audit.TARGETS]


def main():
    records = [
        row('検査対象', 'INFO', 'inventory', 'このPCにインストールされている開発環境'),
        row('Java JSSE', 'ACTION', 'measured', '代表検証先へHTTPS接続が成立した例。',
            'このJDKの配布元の対策、独自truststore、プロキシによる証明書の差し替えを確認してください。', metadata={'java_home':'/example/java/jdk'}, samples=samples('ACTION')),
        row('Java / Azulブロックリスト', 'UPDATE', 'static', 'このJDKの証明書データに更新が必要な例。'),
        row('Python / pip バージョン', 'UPDATE', 'version', '参考修正版未満という版比較の例。',
            '対象のPython環境で、配布元の修正版・バックポートを確認してください。',
            metadata={'tool_id':'python','tool_name':'Python','executable':'/example/old/python3','version':'26.2.1','reference_floor':'26.2.2'}),
        row('Python / 証明書検証の設定', 'ACTION', 'configuration', '証明書検証を無効にする設定を検出した架空例。',
            metadata={'tool_id':'python','tool_name':'Python','executable':'/example/old/python3'}),
        row('Python / pip バージョン', 'INFERRED_OK', 'version', '別の導入先のpipは対応版という架空例。',
            metadata={'tool_id':'python','tool_name':'Python','executable':'/example/new/python3','version':'26.2.2','reference_floor':'26.2.2'}),
        row('Python / ensurepip同梱pip（新規venv用）', 'INFERRED_OK', 'version', '新規venv用のpipを別に照合した架空例。',
            metadata={'tool_id':'python','tool_name':'Python','executable':'/example/new/python3','version':'26.2.2','reference_floor':'26.2.2'}),
        row('Python / 普段の通信', 'MANUAL', 'manual', '別の導入先の版は良好でも、普段の通信は未検査です。',
            metadata={'tool_id':'python','tool_name':'Python','executable':'/example/new/python3'}),
        row('OSV-Scanner / 合成データの照会', 'CHECKED', 'measured', '公式APIへ合成依存を照会した架空例。検査用サイトへの拒否結果は未確認です。',
            metadata={'tool_id':'osv-scanner','tool_name':'OSV-Scanner','executable':'/example/osv-scanner','probe':'synthetic_osv_query'}),
        row('Node.js fetch', 'UNKNOWN', 'measured', '通信エラーで原因を特定できなかった例。',
            '通常サイトへの疎通と接続先の証明書エラーを確認し、同じ条件で再診断してください。', samples=samples('UNKNOWN')),
        row('ホスト / Node.js https', 'REJECTED', 'measured', '別の接続テストではブロックできた例。', samples=samples('REJECTED')),
        row('Safari の信頼確認', 'MANUAL', 'manual', '版の情報は取得したが、実通信は未確認の例。',
            'Safariの配布元が公開する対応情報を確認してください。'),
        row('Git TLS', 'REJECTED', 'measured', '通常サイトは疎通し、代表4経路を信頼エラーで拒否した例。', samples=samples('REJECTED')),
        row('PHP streams', 'INFERRED_REJECTED', 'corroborated', '接続失敗を実測し、同じ版・CA設定の別接続で拒否原因を推定した例。', samples=samples('INFERRED_REJECTED')),
        row('Docker Desktop', 'INFERRED_OK', 'version', '参考修正版以上と推定した例。', metadata={'version':'4.96.3','reference_floor':'4.96.2'}),
        row('Chrome CRLSet', 'STATIC_OK', 'static', '保存データで対象TLS用6鍵を照合した例。', metadata={'matched':6,'total':6}),
        row('Example CLI（架空例） / 使用するNode.js', 'UPDATE', 'version', '使用するNode.jsの版を照合した例。',
            metadata={'tool_id':'example-cli','tool_name':'Example CLI（架空例）','executable':'/example/bin/cli',
                      'runtime_component':'node','runtime_version':'22.22.2','runtime_basis':'version-output',
                      'reference_floor':'22.23.4','source':'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases'}),
        row('インストール済みツールの探索', 'CHECKED', 'inventory', '開発ツールの配置を確認した例。'),
        row('.NET', 'NOT_FOUND', 'inventory', '指定した探索範囲で実行環境を検出しなかった例。'),
        row('別OSのツール（架空例）', 'NOT_APPLICABLE', 'inventory', 'このOSでは対象外の例。'),
        row('アプリ / Example Scanner（架空例）', 'UPDATE', 'version', '組み込みGoが参考修正版未満の例。',
            metadata={'application':True,'path':'/example/bin/scanner','coverage_state':'partial',
                      'version':'1.27.2','reference_floor':'1.27.3',
                      'inspections':[{'component':'go','status':'UPDATE','method':'version','version':'1.27.2','reference_floor':'1.27.3',
                                      'path':'/example/bin/scanner','detail':'参考修正版1.27.3未満。配布元のバックポートを確認。'}],
                      'uninspected':['探索の深さの上限: /example/Scanner.app/Contents/Resources/app.asar.unpacked/node_modules/dependency/deep/path', 'アプリの実効CA・独自検証設定・実通信は未検査']}),
        row('アプリ / Example Desktop（架空例）', 'UPDATE', 'version', '同梱Electronが対策版未満の例。',
            metadata={'application':True,'path':'/example/Example Desktop.app','coverage_state':'partial',
                      'version':'44.4.3','reference_floor':'44.9.1',
                      'source':'https://github.com/electron/electron/security/advisories/GHSA-jr5w-w6x2-84p9',
                      'inspections':[{'component':'electron','status':'UPDATE','method':'version',
                                      'version':'44.4.3','reference_floor':'44.9.1','path':'/example/Example Desktop.app/Contents/electron','detail':'同梱版を照合。'},
                                     {'component':'CAファイル','status':'MANUAL','method':'static','matched':0,
                                      'detail':'ファイル内に対象証明書はありませんが、接続を拒否できるかは判断できません。'}],
                      'uninspected':['アプリの実効CA・独自検証設定・実通信は未検査']}),
        row('アプリ / Example Editor（架空例）', 'MANUAL', 'manual', '同梱情報を取得できなかった例。',
            '配布元の対策情報とアプリ自身の通信を確認してください。',
            metadata={'application':True,'path':'/example/Editor','coverage_state':'uninspected',
                      'inspections':[],'uninspected':['対応する同梱メタデータは見つかりません。','実通信は未検査']}),
    ]
    page = audit.render_report(records, '表示例・測定日時なし')
    page = page.replace('<title>診断結果', '<title>架空の表示例')
    page = page.replace('<header id="current-status"', '<p class="notice"><strong>表示サンプル</strong> <a href="START-HERE.html">開始ページへ戻る</a></p><header id="current-status"')
    page = page.replace('<a href="summary.txt" download>テキストを保存</a>', '').replace('<a href="report.json" download>検査データを保存（JSON）</a>', '')
    (ROOT/'sample-report.html').write_text(page, encoding='utf-8')


if __name__ == '__main__':
    main()
