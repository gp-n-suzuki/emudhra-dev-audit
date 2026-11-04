#!/bin/bash
set -eu
target=${1:?windows-x64 or windows-arm64}
id
/usr/lib/wine/wine64 --version
mkdir -p '/tmp/検証 日本語'
unzip -q /input/package.zip -d '/tmp/検証 日本語'
set -- /tmp/検証\ 日本語/emudhra-dev-audit-*"$target"
test "$#" -eq 1
base=$1
mkdir -p /tmp/wine-home
mkdir -m 700 /tmp/wine-home/xdg
export WINEPREFIX=/tmp/wine-home/prefix WINEDEBUG=-all LANG=C.UTF-8 XDG_RUNTIME_DIR=/tmp/wine-home/xdg
/usr/lib/wine/wine64 "$base/app/runtime/python.exe" -E -s -B Z:\\input\\scripts\\windows_smoke.py "Z:$base"
