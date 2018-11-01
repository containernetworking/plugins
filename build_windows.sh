#!/usr/bin/env bash
set -e
cd $(dirname "$0")

ORG_PATH="github.com/containernetworking"
export REPO_PATH="${ORG_PATH}/plugins"

if [ ! -h gopath/src/${REPO_PATH} ]; then
	mkdir -p gopath/src/${ORG_PATH}
	ln -s ../../../.. gopath/src/${REPO_PATH} || exit 255
fi

export GOPATH=${PWD}/gopath
export GO="${GO:-go}"
export GOOS=windows

PLUGINS=$(cat plugins/windows_only.txt)
for d in $PLUGINS; do
  if [ -d "$d" ]; then
    plugin="$(basename "$d").exe"
    echo "  $plugin"
    $GO build -o "${PWD}/bin/$plugin" "$@" "$REPO_PATH"/$d
  fi
done
