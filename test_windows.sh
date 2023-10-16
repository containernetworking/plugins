#!/usr/bin/env sh
#
# Run CNI plugin tests.
#
set -e
cd "$(dirname "$0")"

. ./build_windows.sh

echo "Running tests"

PKGS="./pkg/hns/..."

PLUGINS=$(cat plugins/windows_only.txt | dos2unix )
for d in $PLUGINS; do
	PKGS="$PKGS ./$d/..."
done

echo "testing packages $PKGS"
go test -race -v $PKGS -ginkgo.randomizeAllSpecs -ginkgo.failOnPending -ginkgo.progress
