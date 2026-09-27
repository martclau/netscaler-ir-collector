#!/bin/sh
# Disposable synthetic native packaging check; no appliance source files copied.
umask 077
# shellcheck disable=SC3045 # Native FreeBSD sh supports core limits.
ulimit -c 0
d=$(mktemp -d /var/tmp/nsir_primitives.XXXXXX) || exit 1
trap 'rm -rf "$d"' EXIT
printf 'synthetic harmless payload\n' > "$d/sample with space.txt"
printf '%s\0' "$d/sample with space.txt" > "$d/list0"
tar -cf "$d/evidence.tar" --null -T "$d/list0" 2>/dev/null || exit 1
tar -tf "$d/evidence.tar" > /dev/null || exit 1
tar -xOf "$d/evidence.tar" -- "${d#/}/sample with space.txt" > "$d/captured" || exit 1
cmp -s "$d/sample with space.txt" "$d/captured" || exit 1
h1=$(sha256 -q "$d/sample with space.txt")
h2=$(sha256 -q "$d/captured")
[ "$h1" = "$h2" ] || exit 1
printf 'native_null_tar=pass\nnative_tar_extract=pass\nnative_capture_digest=pass\n'
