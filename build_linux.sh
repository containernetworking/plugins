#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

GO="${GO:-go}"
GOFLAGS="${GOFLAGS} -mod=vendor"
MAKEBB="${MAKEBB:-${GO} run github.com/u-root/gobusybox/src/cmd/makebb}"

# If BUNDLE=Y, use the Go busybox toolchain to build all the plugins into
# a single busybox-style bundle that muxes the individual plugins based
# on the invocation name.
BUNDLE=${BUNDLE:-N}

if [ "$(uname)" == "Darwin" ]; then
	export GOOS="${GOOS:-linux}"
fi

mkdir -p "${PWD}/bin"

echo "Building plugins ${GOOS}"
PLUGINS=$(ls -d  plugins/{meta,main,ipam}/* | grep -v windows)

case $BUNDLE in
	Y|YES|Yes|yes|y)
        echo "building cni-plugins bundle"
        GO=${GO} $MAKEBB -go-extra-args "${GOFLAGS} $*" -o "${PWD}/bin/cni-plugins" $PLUGINS
        for d in $PLUGINS; do
                echo "linking $(basename $d)"
                ln -f -s cni-plugins "${PWD}/bin/$(basename $d)"
        done
        ;;

	*)
        for d in $PLUGINS; do
                echo "building $(basename $d)"
                GOFLAGS="${GOFLAGS}" ${GO} build -o "${PWD}/bin/$plugin" "$@" ./"$d"
        done
        ;;
esac
