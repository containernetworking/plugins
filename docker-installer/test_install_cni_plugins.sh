#!/bin/sh

set -e

prepare() {
	echo
	echo
	echo "=== Testing: $1 ==="
	echo
	rm -rf test
	mkdir -p test/src
	mkdir -p test/dst
}

assert_file_missing() {
	FILE=test/dst/$1

	if [ -e $FILE ]; then
		echo "File $1 exists but must not exist."
		echo
		echo "=== Test failed. ==="
		exit 1
    fi
}

assert_file_content() {
	FILE=test/dst/$1

	if [ ! -e $FILE ]; then
		echo "Expected file $1 is missing."
		echo
		echo "=== Test failed. ==="
		exit 1
    fi

	EXPECTED_CONTENT=$2
	ACTUAL_CONTENT=$( cat $FILE )

	if [ "$EXPECTED_CONTENT" != "$ACTUAL_CONTENT" ]; then
		echo "File $1 has wrong content"
		echo "Expected: $EXPECTED_CONTENT"
		echo "Actual  : $ACTUAL_CONTENT"
		echo
		echo "=== Test failed. ==="
		exit 1
	fi
}


#############################################################

prepare "Installation if not exists yet"

echo "cni1.0" > test/src/cni1
./install_cni_plugins.sh test/src test/dst

assert_file_content cni1 "cni1.0"
assert_file_content cni1.by_cni_installer_image "7ec08d6ee0e5237cb34be4a31d9146c1"

echo
echo "Test passed."

#############################################################

prepare "Keep when up-to-date"

echo "cni1.0" > test/src/cni1
./install_cni_plugins.sh test/src test/dst
echo "cni1.0" > test/src/cni1
./install_cni_plugins.sh test/src test/dst

assert_file_content cni1 "cni1.0"
assert_file_content cni1.by_cni_installer_image "7ec08d6ee0e5237cb34be4a31d9146c1"

echo
echo "Test passed."

#############################################################

prepare "Upgrade when installed by this installer"

echo "cni1.0" > test/src/cni1
./install_cni_plugins.sh test/src test/dst

echo "cni1.1" > test/src/cni1
./install_cni_plugins.sh test/src test/dst

assert_file_content cni1 "cni1.1"
assert_file_content cni1.by_cni_installer_image "286f99e881938508552bb58ea1c2c565"

echo
echo "Test passed."

#############################################################

prepare "Installed by someone else"

echo "cni1.0" > test/src/cni1
echo "cni1.other" > test/dst/cni1
./install_cni_plugins.sh test/src test/dst

assert_file_content cni1 "cni1.other"
assert_file_missing cni1.by_cni_installer_image

echo
echo "Test passed."

#############################################################

prepare "Installed by me, altered by someone else"

echo "cni1.0" > test/src/cni1
./install_cni_plugins.sh test/src test/dst

echo "cni1.other" > test/dst/cni1
./install_cni_plugins.sh test/src test/dst

assert_file_content cni1 "cni1.other"
assert_file_content cni1.by_cni_installer_image "7ec08d6ee0e5237cb34be4a31d9146c1"

echo
echo "Test passed."

#############################################################

prepare "Force install overwrites plugin installed by someone else"

echo "cni1.other" > test/dst/cni1
echo "cni1.0" > test/src/cni1
FORCE=1 ./install_cni_plugins.sh test/src test/dst

assert_file_content cni1 "cni1.0"
assert_file_content cni1.by_cni_installer_image "7ec08d6ee0e5237cb34be4a31d9146c1"

prepare "Force install overwrites plugin installed by me, altered by someone else"

echo "cni1.0" > test/src/cni1
./install_cni_plugins.sh test/src test/dst
echo "cni1.other" > test/dst/cni1

FORCE=1 ./install_cni_plugins.sh test/src test/dst

assert_file_content cni1 "cni1.0"
assert_file_content cni1.by_cni_installer_image "7ec08d6ee0e5237cb34be4a31d9146c1"

echo
echo "Test passed."

#############################################################

echo
echo "All tests passed."
