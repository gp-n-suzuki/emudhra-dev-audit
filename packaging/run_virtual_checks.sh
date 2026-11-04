#!/bin/bash
# Run the released archive in a disposable container, without network or host writes.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
target=${1:?Usage: bash packaging/run_virtual_checks.sh TARGET [RELEASE_DIR] [LINUX_IMAGE]}
version=$(python3 -B "$root/distribution_version.py")
release=${2:-$root/releases/$version}
case "$target" in
  linux-x64|windows-x64) arch=amd64 ;;
  linux-arm64|windows-arm64) arch=arm64 ;;
  *) echo 'Use linux-x64, linux-arm64, windows-x64 or windows-arm64.' >&2; exit 2 ;;
esac
case "$target" in
  linux-*)
    image=${3:-debian:bookworm-slim}
    archive="emudhra-dev-audit-$version-$target.tar.gz"
    input=package.tar.gz
    script=linux_smoke.sh
    ;;
  windows-*)
    image="emudhra-wine-test:$arch"
    archive="emudhra-dev-audit-$version-$target.zip"
    input=package.zip
    script=wine_smoke.sh
    ;;
esac
docker run --rm --pull=never --platform "linux/$arch" --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 2g --cpus 2 --tmpfs /tmp:rw,exec,nosuid,size=1536m \
  --mount "type=bind,src=$release/$archive,target=/input/$input,readonly" \
  --mount "type=bind,src=$root/packaging,target=/input/scripts,readonly" \
  --entrypoint /usr/bin/timeout "$image" -k 10 240 /bin/bash "/input/scripts/$script" "$target"
