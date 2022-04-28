#!/usr/bin/env bash
set -e

CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 \
    $GO build -o "${PWD}/bin/plugins.exe" "$@" "$REPO_PATH"/launcher/windows

PLUGINS=$(cat plugins/windows_only.txt)
for d in $PLUGINS; do
	plugin="$(basename "$d").exe"
	ln bin/plugins.exe "bin/$plugin"
done
