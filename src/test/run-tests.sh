#!/bin/sh
# Builds and runs every test the Makefile defines (its *EXECUTABLE variables), stopping at the first failure. Used by
# CI and the release workflow, so a new test runs in both once it's in the Makefile.
set -e
cd "$(dirname "$0")"

tests=$(sed -n 's/^[A-Z_]*EXECUTABLE *= *//p' Makefile)
if [ -z "$tests" ]; then
    echo "No tests found in the Makefile" >&2
    exit 1
fi

make clean all
for test in $tests; do
    echo "== $test"
    "./$test"
done
