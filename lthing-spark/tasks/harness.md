# Agent task: aggregating test runner + Makefile + CI

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md` first. Toolchain: `gnatmake`/
`gprbuild` on PATH; `gnatprove` at `/root/.alire/bin`. The asm lib lives at
`lthing-spark/lib/liblthing_crypto_asm.{so,a}` (test_judicial links it for the
working `Compare_CT` — do not change that).

You create ONLY these three NEW files. Do NOT edit any `src/*.adb`, `lthing.gpr`,
or other files.

## 1. `lthing-spark/run_tests.sh` (exactly this; `chmod +x` it)
```sh
#!/usr/bin/env bash
# Build and run every src/test_*.adb; exit non-zero if any fails to build,
# exits non-zero, or prints [FAIL].
set -u
cd "$(dirname "$0")"
export PATH=/root/.alire/bin:$PATH
OBJ=obj_tests; rm -rf "$OBJ"; mkdir -p "$OBJ"
LIB="$PWD/lib"
fail=0
for src in src/test_*.adb; do
  [ -e "$src" ] || continue
  name=$(basename "$src" .adb)
  echo "=== build $name ==="
  if ! gnatmake -q -D "$OBJ" -aIsrc -o "$OBJ/$name" "$src" \
        -largs -L"$LIB" -llthing_crypto_asm -Wl,-rpath,"$LIB" \
        >"$OBJ/$name.log" 2>&1; then
    echo "[BUILD-FAIL] $name"; sed 's/^/    /' "$OBJ/$name.log"; fail=1; continue
  fi
  echo "=== run $name ==="
  out=$(LD_LIBRARY_PATH="$LIB" "$OBJ/$name"); rc=$?
  echo "$out"
  if [ "$rc" -ne 0 ] || grep -q "\[FAIL\]" <<<"$out"; then
    echo "[FAIL] $name (rc=$rc)"; fail=1
  fi
done
echo
if [ "$fail" -eq 0 ]; then echo "ALL TEST MAINS PASSED"; else echo "TEST SUITE FAILED"; fi
exit "$fail"
```

## 2. `lthing-spark/Makefile` (exactly this; use TABS for recipe lines)
```make
SHELL := /bin/bash
export PATH := /root/.alire/bin:$(PATH)

.PHONY: build test prove clean
build:
	gprbuild -P lthing.gpr || true
test:
	./run_tests.sh
prove:
	gnatprove -P lthing.gpr --level=2 --report=all -j0
clean:
	rm -rf obj obj_prove obj_tests
```

## 3. `.github/workflows/ci.yml` (repo root; exactly this)
```yaml
name: CI
on: [push, pull_request]
jobs:
  test-and-prove:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install GNAT + gprbuild
        run: sudo apt-get update && sudo apt-get install -y gnat gprbuild
      - name: Install gnatprove (Alire)
        run: |
          curl -sSL -o alr.zip https://github.com/alire-project/alire/releases/download/v2.0.2/alr-2.0.2-bin-x86_64-linux.zip
          unzip -q alr.zip -d alr_install
          ./alr_install/bin/alr -n settings --global --set toolchain.assistant false || true
          ./alr_install/bin/alr -n install gnatprove
          echo "$HOME/.alire/bin" >> "$GITHUB_PATH"
      - name: Tests
        run: make -C lthing-spark test
      - name: Prove
        run: make -C lthing-spark prove
```

## 4. Ralph loop — repeat until green LOCALLY
```sh
cd lthing-spark && chmod +x run_tests.sh && ./run_tests.sh ; echo "exit=$?"
```
In your worktree `test_hash.adb` does not exist yet (another agent adds it) —
that's fine, the loop over `src/test_*.adb` just won't see it. Done =
`run_tests.sh` builds+runs the present suites (`test_field`, `test_ntt`,
`test_judicial`, `test_keccak`), they all print `[PASS]`, and the script
exits 0. Sanity-check the failure path too (e.g. temporarily point it at a
bogus main) and confirm it exits non-zero, then revert. Do NOT edit any src.

## 5. Commit AND PUSH
```sh
git checkout -b claude/ralph-harness
git add -A && git commit -m "Add aggregating test runner, Makefile, and CI workflow"
git push -u origin claude/ralph-harness
```
Report: the branch name and a sample `run_tests.sh` run (its final lines + exit code).
