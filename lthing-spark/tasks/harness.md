# Agent task: Test harness + CI

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md` first.

## Goal
Give the project a single aggregating test runner that **exits non-zero on any
failure**, and a CI workflow that installs the toolchain and runs build + tests
+ proof. This is the process gap (no driver, no CI) from the coverage analysis.

## Files you own (all new)
- `lthing-spark/run_tests.sh`
- `lthing-spark/Makefile`
- `.github/workflows/ci.yml`  (repo root)
Do not edit any `src/*.adb` or other agents' files.

## Steps
1. `run_tests.sh`: discover every `src/test_*.adb`, build each with
   `gnatmake -q -D obj_tests -aIsrc -o obj_tests/<name> src/<name>.adb`, run it,
   capture exit code AND grep its output for `[FAIL]`. Aggregate; print a summary;
   `exit 1` if any main failed to build, exited non-zero, or printed `[FAIL]`.
   Make it robust to mains that don't exist yet.
2. `Makefile` targets:
   - `build` — `gprbuild -P lthing.gpr` (or gnatmake all mains);
   - `test`  — run `./run_tests.sh`;
   - `prove` — `PATH=/root/.alire/bin:$PATH gnatprove -P lthing.gpr --level=2 --report=all -j0`;
   - `clean`.
3. `.github/workflows/ci.yml`: on push/PR, Ubuntu runner:
   - `apt-get install -y gnat gprbuild`;
   - install Alire and `alr install gnatprove` (or document the pin), put it on PATH;
   - `make -C lthing-spark test` and `make -C lthing-spark prove`.
   Keep it straightforward; it's fine if the proof step is a separate job.

## Ralph loop (repeat until green LOCALLY)
```sh
cd lthing-spark && ./run_tests.sh ; echo "exit=$?"
```
Definition of done for YOUR local run: the asm-free suites
(`test_field`, `test_ntt`, `test_keccak`) build, run, and report `[PASS]`, and
`run_tests.sh` exits 0 when they all pass / non-zero if you force a failure.
NOTE: in your worktree `test_hash.adb` does not exist yet and `test_judicial`
may still need the asm lib — that's expected; your script must simply skip/мreport
mains it can't build without crashing, and they will pass after the merge. Do not
hand-edit src to make them build.

## Done
Commit to branch `claude/ralph-harness`; report the branch and a sample
`run_tests.sh` run.
