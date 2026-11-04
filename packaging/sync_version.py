"""Synchronize current display labels from distribution_version.py."""
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from distribution_version import VERSION, DISPLAY_VERSION, TAG


def main():
    rules={
        'README.md':[(r'(?m)^# eMudhra 開発環境診断 [\d.]+$', '# eMudhra 開発環境診断 '+DISPLAY_VERSION)],
        'README-ja.md':[(r'(?m)^# eMudhra 開発環境診断 [\d.]+(?= —|$)', '# eMudhra 開発環境診断 '+DISPLAY_VERSION)],
        'START-HERE-ja.md':[(r'(?m)^# eMudhra 開発環境診断 [\d.]+ —', '# eMudhra 開発環境診断 '+DISPLAY_VERSION+' —')],
        'ACTION-PRESENTATION-ja.md':[(r'(?m)^# [\d.]+ — 行動', '# '+DISPLAY_VERSION+' — 行動')],
        'START-HERE.html':[(r'<span>[\d.]+</span></footer>','<span>'+DISPLAY_VERSION+'</span></footer>')],
    }
    for name,replacements in rules.items():
        path=ROOT/name
        text=path.read_text(encoding='utf-8')
        for pattern,replacement in replacements:
            text,count=re.subn(pattern,replacement,text)
            if count!=1:raise ValueError('Expected one version label: '+name)
        path.write_text(text,encoding='utf-8')
    print('Display '+DISPLAY_VERSION+' / internal '+VERSION+' / tag '+TAG)
    print('Review release notes, publication instructions and validation for this release separately.')


if __name__=='__main__':main()
