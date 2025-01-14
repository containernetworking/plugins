#!/usr/bin/env bash
#
# Run CNI plugin tests.
# 
# This needs sudo, as we'll be creating net interfaces.
#
set -e

# switch into the repo root directory
cd "$(dirname "$0")"

# Build all plugins before testing
. ./build_linux.sh

echo "Running tests"

testrun() {
    sudo -E sh -c "umask 0; PATH=${GOPATH}/bin:$(pwd)/bin:${PATH} go test -race $*"
}

ensure_sysctl() {
    local key
    local val
    local existing

    key="$1"
    val="$2"
    existing="$(sysctl -ben "$key")"

    sysctl -r 

    if [ "$val" -ne "$existing" ]; then
        echo "sudo sysctl -we '$key'='$val'"
        sudo sysctl -we "$key"="$val"
    fi
}

COVERALLS=${COVERALLS:-""}

if [ -n "${COVERALLS}" ]; then
    echo "with coverage profile generation..."
else
    echo "without coverage profile generation..."
fi

PKG=${PKG:-$(go list ./... | xargs echo)}

i=0
for t in ${PKG}; do
    if [ -n "${COVERALLS}" ]; then
        COVERFLAGS="-covermode atomic -coverprofile ${i}.coverprofile"
    fi
    echo "${t}"
    testrun "${COVERFLAGS:-""} ${t}"
    i=$((i+1))
done

# Run the pkg/ns tests as non root user
mkdir -p /tmp/cni-rootless
ensure_sysctl kernel.unprivileged_userns_clone 1 
ensure_sysctl kernel.apparmor_restrict_unprivileged_userns 0

(export XDG_RUNTIME_DIR=/tmp/cni-rootless; cd pkg/ns/; unshare -rmn go test)
