#!/bin/bash
# Resolve the package from the launcher, independent of Finder's working directory.
case ${BASH_SOURCE[0]} in
  */*) base=${BASH_SOURCE[0]%/*} ;;
  *) base=. ;;
esac
base=$(CDPATH= cd -- "$base" && pwd) || exit 3
if [ -x "$base/app/runtime/bin/python3" ]; then
  "$base/app/runtime/bin/python3" -E -s -B "$base/app/desktop_entry.py"
  diagnosis_exit=$?
else
  printf '%s\n' '診断を開始できませんでした。appフォルダーを含めて、配布ファイルをすべて展開し直してください。'
  diagnosis_exit=3
fi
if [ "$diagnosis_exit" -ne 0 ] && [ -t 0 ]; then
  printf '%s' 'Enterキーで終了します。'
  read -r _
fi
exit "$diagnosis_exit"
