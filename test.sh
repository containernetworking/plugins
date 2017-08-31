#!/usr/bin/env bash
#
# Run CNI plugin tests.
# 
# This needs sudo, as we'll be creating net interfaces.
#
set -e

source ./build.sh

echo "Running tests"

# test everything that's not in vendor
pushd "$GOPATH/src/$REPO_PATH" >/dev/null
  TESTABLE="$(go list ./... | grep -v vendor | xargs echo)"
popd >/dev/null

# user has not provided PKG override
if [ -z "$PKG" ]; then
	TEST=$TESTABLE
	FMT=$TESTABLE

# user has provided PKG override
else
	TEST=$PKG

	# only run gofmt on packages provided by user
	FMT="$TEST"
fi

sudo -E bash -c "umask 0; PATH=${GOROOT}/bin:$(pwd)/bin:${PATH} go test ${TEST}"

echo "Checking gofmt..."
fmtRes=$(go fmt $FMT)
if [ -n "${fmtRes}" ]; then
	echo -e "go fmt checking failed:\n${fmtRes}"
	exit 255
fi

echo "Checking govet..."
vetRes=$(go vet $TEST)
if [ -n "${vetRes}" ]; then
	echo -e "govet checking failed:\n${vetRes}"
	exit 255
fi
