#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

export GO="${GO:-go}"
export GOOS=windows
export GOFLAGS="${GOFLAGS} -mod=vendor"
echo "$GOFLAGS"

$GO build -o "${PWD}/bin/plugins.exe" "$@" ./launcher/windows

PLUGINS=$(cat plugins/windows_only.txt | dos2unix )
for d in $PLUGINS; do
	plugin="$(basename "$d").exe"
	ln -f bin/plugins.exe "bin/$plugin"
done
