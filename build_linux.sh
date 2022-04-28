#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ "$(uname)" == "Darwin" ]; then
	export GOOS="${GOOS:-linux}"
fi

export GOFLAGS="${GOFLAGS} -mod=vendor"

mkdir -p "${PWD}/bin"

echo "Building plugins ${GOOS}"
${GO:-go} build -o bin/plugins "$@" ./launcher/linux/

PLUGINS="plugins/meta/* plugins/main/* plugins/ipam/*"
for d in $PLUGINS; do
	if [ -d "$d" ]; then
		plugin="$(basename "$d")"
		if [ "${plugin}" != "windows" ]; then
			ln -sf plugins "bin/$plugin"
		fi
	fi
done
