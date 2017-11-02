#!/usr/bin/env bash
set -e

if [ "$(uname)" == "Darwin" ]; then
	export GOOS=linux
fi

ORG_PATH="github.com/containernetworking"
export REPO_PATH="${ORG_PATH}/plugins"

if [ ! -h gopath/src/${REPO_PATH} ]; then
	mkdir -p gopath/src/${ORG_PATH}
	ln -s ../../../.. gopath/src/${REPO_PATH} || exit 255
fi

export GO15VENDOREXPERIMENT=1
export GOPATH=${PWD}/gopath

mkdir -p "${PWD}/bin"

echo "Building plugins"
PLUGINS="plugins/meta/* plugins/main/* plugins/ipam/* plugins/sample"
ppids=""
for d in $PLUGINS; do
	if [ -d "$d" ]; then
		plugin="$(basename "$d")"
		echo "  $plugin"
		go build -o ${PWD}/bin/$plugin -i -pkgdir "$GOPATH/pkg" "$@" "$REPO_PATH/$d" &
		ppids="$ppids $!"
	fi
done

for ppid in $ppids; do
	wait $ppid
done
