"""Run a PC diagnosis from a desktop launcher and open the finished local report.

Exit 0 means the report opened, regardless of its findings; exit 3 keeps the
launcher visible on failure. The audit CLI retains its diagnostic exit codes.
"""
from datetime import datetime
import os
from pathlib import Path
import subprocess
import sys

import audit

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent if HERE.name == 'app' else HERE


def reserve_output():
    results = PACKAGE/'結果'
    results.mkdir(exist_ok=True)
    name = datetime.now().strftime('%Y%m%d-%H%M%S')
    index = 1
    while True:
        output = results/(name if index == 1 else '{}-{}'.format(name, index))
        try:
            output.mkdir()
            return output
        except FileExistsError:
            index += 1


def open_report(path):
    if sys.platform == 'win32':
        os.startfile(str(path))
        return True
    command = '/usr/bin/open' if sys.platform == 'darwin' else 'xdg-open'
    return subprocess.run([command, str(path)], timeout=20, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    try:
        output = reserve_output()
        status = audit.main(['--out', str(output)])
        report = output/'report.html'
        if status not in (0, 1, 2) or not report.is_file():
            raise RuntimeError('結果ファイルを作成できませんでした。')
    except (Exception, KeyboardInterrupt) as error:
        print('診断を完了できませんでした: {}'.format(error))
        print('docs/使い方.html の「起動できないとき」を確認してください。')
        return 3
    try:
        if not open_report(report):
            raise OSError('ブラウザを起動できませんでした。')
    except Exception:
        print('結果画面を開けませんでした。次のファイルをダブルクリックしてください。')
        print(report)
        return 3
    print('診断が完了しました。結果画面を開きました。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
