#!/bin/bash
# Only packaged help, integrity checks and synthetic saved-record fixtures.
set -eu
mkdir -p '/tmp/検証 日本語'
tar --no-same-owner -xzf /input/package.tar.gz -C '/tmp/検証 日本語'
set -- /tmp/検証\ 日本語/emudhra-dev-audit-*
test "$#" -eq 1
base=$1
"$base/app/runtime/bin/python3" -E -s -B /input/scripts/offline_smoke.py "$base"
