#!/usr/bin/env bash
# No sudo. Python is the controller only; it tests other tools independently.
set -u
case ${BASH_SOURCE[0]} in
  */*) base=${BASH_SOURCE[0]%/*} ;;
  *) base=. ;;
esac
base=$(CDPATH= cd -- "$base" && pwd) || exit 2
if [ -x "$base/runtime/bin/python3" ]; then
  exec "$base/runtime/bin/python3" -E -s -B "$base/audit.py" "$@"
fi
if [ -f "$base/RUNTIME.json" ]; then
  printf '%s\n' 'The bundled Python is missing or not executable. Extract the complete package for this OS/CPU again. See the usage guide in docs.' >&2
  exit 2
fi
for py in python3 python; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import sys;sys.exit(0 if sys.version_info >= (3,8) else 1)' >/dev/null 2>&1; then
    exec "$py" -E -s -B "$base/audit.py" "$@"
  fi
done
printf '%s\n' 'Python 3.8+ is required for the CLI controller; nothing was installed.' >&2
exit 2
