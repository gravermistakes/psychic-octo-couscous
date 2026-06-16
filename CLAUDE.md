# CLAUDE.md — psychic-octo-couscous

## What this repo holds
- `lthing-spark/` — an **Ada/SPARK** implementation of an **ML-DSA-65 (FIPS 204)**
  signature verifier and a **fail-closed `.jd.lthing` judicial-document**
  verification layer, plus a pure-Ada **Keccak/SHAKE** core (`lthing_keccak`)
  that replaces the project's historically-buggy x86-64 asm hash.
- `TEST_COVERAGE_ANALYSIS.md` — the standing coverage analysis (keep it accurate;
  back every claim with a command, not a reading).
- `collaborative_neon_garden.py` — unrelated; ignore for this work.

## Working branch
`claude/test-coverage-analysis-p6s11z`. Develop here; commit and push here.

## Toolchain (installed in this container)
- **GNAT 13.3.0** (apt): `gnatmake`, `gprbuild` on `PATH`.
- **gnatprove 14.1.1** (Alire) at `/root/.alire/bin` — `export PATH=/root/.alire/bin:$PATH`.
  Solvers: Z3 4.13, cvc5 1.1.2, alt-ergo 2.4.

## Build / run / prove (from `lthing-spark/`)
```sh
# build + run a test main (no external libs needed)
gnatmake -q -D /tmp/b -aIsrc -o /tmp/b/test_keccak src/test_keccak.adb && /tmp/b/test_keccak

# prove the whole project (Object_Dir=obj, gitignored)
export PATH=/root/.alire/bin:$PATH
gnatprove -P lthing.gpr --level=2 --report=all -j0

# prove a single unit
gnatprove -P lthing.gpr -u lthing_keccak.adb --level=2 --report=all
```
Baseline (commit `dbe9d37`): `gnatprove` → **131 checks, 0 unproved**; all test
mains pass.

## Non-negotiable conventions
- **Fail-closed is sacred.** Never make `Verify_Signature` (or any gate) return
  `True`/accept until it genuinely verifies. Never weaken a judicial
  postcondition. The audit (FINDING-002/006) is the whole reason this layer exists.
- **No frozen / self-derived test vectors.** A test asserts either (a) an
  *authoritative* KAT (FIPS 202 / `hashlib`, e.g. `keccak_f1600(0)`, SHA3-512,
  SHAKE256), or (b) a *relational / property* fact (determinism, `Chain_Hash ==
  SHAKE512(prev‖art)`, input-sensitivity, fail-closed-on-garbage). Never paste a
  magic digest you computed yourself and call it a gate.
- **SPARK_Mode (On)** for new crypto/control code; the proof target is AoRTE +
  flow + stated contracts. A change is **done only when** it builds, every test
  main prints all `[PASS]` and exits 0, **and** `gnatprove` reports **0 unproved**.
- Tests print `[PASS]`/`[FAIL]` and call `Set_Exit_Status(Failure)` on any fail.
- Don't commit `obj/` or `obj_prove/` (gitignored).
