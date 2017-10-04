#!/usr/bin/env bash
set -e

OUTDIR="${PWD}/bin/windows"
mkdir -p ${OUTDIR}

PLUGINS="plugins/main/windows/*"
for d in $PLUGINS; do
	if [ -d "$d" ]; then
		plugin="$(basename "$d")"
		echo "  $plugin.exe"
		$GO build -o "${PWD}/bin/$plugin" "$@" "$REPO_PATH"/$d
	fi
done
