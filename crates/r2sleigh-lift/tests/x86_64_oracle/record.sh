#!/bin/sh
# Records the host CPU's answers for cases.txt into recorded.txt; needs an x86-64 Linux host.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here/cases.txt" "$here/gen.py" "$here/driver.c" "$here/../oracle_common/stream.h" "$work/"
cd "$work"
python3 gen.py
cc -O1 -c cases.S -o cases.o
cc -O1 driver.c cases.o -o driver
./driver "${1:-16}" > "$here/recorded.txt"
