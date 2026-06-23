#!/usr/bin/env bash
# Build and run every src/test_*.adb; exit non-zero if any fails to build,
# exits non-zero, or prints [FAIL].
set -u
# test_judicial allocates ~1 MiB bounded Byte_Array objects on the main task
# stack; raise the soft stack limit so it does not hit STORAGE_ERROR on hosts
# whose default ulimit -s is small (e.g. CI runners / this container = 12 MiB).
ulimit -s unlimited 2>/dev/null || ulimit -s 65536 2>/dev/null || true
cd "$(dirname "$0")"
export PATH=/root/.alire/bin:$PATH
OBJ=obj_tests; rm -rf "$OBJ"; mkdir -p "$OBJ"
fail=0
for src in src/test_*.adb; do
  [ -e "$src" ] || continue
  name=$(basename "$src" .adb)
  echo "=== build $name ==="
  if ! gnatmake -q -D "$OBJ" -aIsrc -o "$OBJ/$name" "$src" \
        >"$OBJ/$name.log" 2>&1; then
    echo "[BUILD-FAIL] $name"; sed 's/^/    /' "$OBJ/$name.log"; fail=1; continue
  fi
  echo "=== run $name ==="
  out=$("$OBJ/$name"); rc=$?
  echo "$out"
  if [ "$rc" -ne 0 ] || grep -q "\[FAIL\]" <<<"$out"; then
    echo "[FAIL] $name (rc=$rc)"; fail=1
  fi
done
echo
if [ "$fail" -eq 0 ]; then echo "ALL TEST MAINS PASSED"; else echo "TEST SUITE FAILED"; fi
exit "$fail"
