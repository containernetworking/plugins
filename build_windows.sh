#!/usr/bin/env sh
set -e
cd "$(dirname "$0")"

export GO="${GO:-go}"
export GOOS=windows
export GOFLAGS="${GOFLAGS} -mod=vendor"
echo "$GOFLAGS"

PLUGINS=$(cat plugins/windows_only.txt | dos2unix )
for d in $PLUGINS; do
	plugin="$(basename "$d").exe"
	echo "building $plugin"
	$GO build -o "${PWD}/bin/$plugin" "$@" ./"${d}"
done
