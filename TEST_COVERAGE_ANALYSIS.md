# LTHING Ada/SPARK — Test Coverage Analysis

**Subject:** `lthing-spark` (ML-DSA-65 / FIPS 204 verifier + fail-closed `.jd.lthing` judicial layer)
**Date:** 2026-06-13
**Method:** Manual review of every source unit, every `test_*.adb`, `lthing.gpr`, `PROOF_REPORT.md`, and the `kat/` assets. No coverage instrumentation exists in the project, so figures below are derived by hand from which subprograms and branches are actually exercised.

---

## 1. What exists today

### Source units

| Unit | SPARK | Body present | Status |
|------|-------|--------------|--------|
| `lthing_types.ads` | On | (spec) | Types + `Verified_Record` predicate |
| `lthing_crypto_ffi.ads` | On (decls) | imports asm | Trust boundary, asm body outside SPARK |
| `lthing_hash.ads/.adb` | On | yes | SHAKE512 + `Chain_Hash` |
| `lthing_judicial.ads/.adb` | On | yes | `Parse_Unverified` / `Parse_And_Verify` |
| `lthing_mldsa_field.ads/.adb` | On | yes | `Add/Sub/Mul/Reduce/To_Centered` |
| `lthing_mldsa_ntt.ads/.adb` | **Off** | yes | NTT / INTT / pointwise / schoolbook |
| `lthing_mldsa65.ads` | On | **no body** | `Verify` (returns False — stub) |
| `lthing_mldsa_sample.ads` | Off | **no body** | ExpandA + SampleInBall (blocked) |

### Tests that exist

- **`test_field.adb`** — 11 hand-computed checks of field arithmetic.
- **`test_ntt.adb`** — 3 gates: INTT∘NTT roundtrip + 2 NTT-vs-schoolbook convolution vectors.
- **`test_judicial.adb`** — 4 fail-closed checks.

### Proof coverage (complementary to tests)

`gnatprove --level=2` discharges 14 VCs: every field op's canonical-range
postcondition, the `Verified_Record` `Trusted = (Status = Verified)`
predicate at every assignment, and the two judicial fail-closed
postconditions. **Where proof applies it is stronger than a test**, so the
gaps below are deliberately scoped to behavior the prover does *not* cover:
the `SPARK_Mode (Off)` NTT, the FFI/asm boundary, end-to-end KAT behavior, and
branches the proof leaves reachable-but-unexercised.

---

## 2. Coverage by unit (estimated)

| Unit | Subprogram coverage | Branch/edge coverage | Notes |
|------|--------------------:|---------------------:|-------|
| `lthing_mldsa_field` | 5/5 | ~medium | Boundary cases missing (see 3.1) |
| `lthing_mldsa_ntt` | 4/4 | low–medium | Only LCG-random inputs; no KAT, no edge polys |
| `lthing_judicial` | 2/2 entry pts | **low** | 3 of the status codes are unreachable/untested |
| `lthing_hash` | **0/2** | **none** | **No test at all** |
| `lthing_crypto_ffi` | 0/3 | none | No Ada-side regression for asm boundary |
| `lthing_mldsa65` | 0/1 | none | No test pins the fail-closed stub |
| KAT (`mldsa65_sigver.json`) | — | — | **Orphaned: no harness loads it** |

---

## 3. Gaps, by priority

### HIGH

**3.0 The 15-vector ML-DSA-65 sigVer KAT is never executed.**
`kat/mldsa65_sigver.json` holds the single most important test asset in the
project — 15 vectors, 3 expected-accept / 12 expected-reject — but **no Ada
test driver parses or runs it.** Nothing consumes `pk/message/context/signature/expected`.
This means:
- The end-to-end verifier behavior (the whole point of the library) is untested.
- When Parts 3–5 land there is no harness ready to gate them.
- *Recommendation:* add `test_kat.adb` (plus a minimal JSON reader, or a build
  step that flattens the vectors to a fixed-format binary the Ada side reads)
  that asserts `Verify` returns the `expected` boolean for all 15 vectors —
  **valid must accept, every tampered vector must reject.** Even today it is
  valuable as a *negative* gate: with the stub, all 15 must currently report
  reject, and the harness should flag if any accept slips through.

**3.1 `lthing_hash` has zero tests** and sits on a known-broken primitive.
`PROOF_REPORT.md` states the asm Keccak-f[1600] permutation **computes the
wrong output**, discovered only because the asm was hand-checked separately —
there is no Ada-level regression that would catch this or confirm a fix.
- No FIPS 202 SHAKE512 known-answer test at the Ada `LTHING_Hash.SHAKE512` level
  (e.g. `SHAKE512("")` → `46b9dd2b0ba88d13...`).
- `Chain_Hash`'s concatenation logic (64-byte seal prefix + artifact, the
  `Loop_Invariant`, the length bound) is untestable independent of the
  permutation today, but should get a test the moment Keccak is fixed.
- **Determinism** — same input → same digest — is the property the seal-match
  and chain-link checks *rely on*, and it is asserted nowhere.
- *Recommendation:* `test_hash.adb` with FIPS 202 SHAKE512 KATs (empty, short,
  and >72-byte multi-block inputs to exercise the sponge rate), a determinism
  check, and a `Chain_Hash` vector. This is also the regression that proves the
  Keccak fix when it happens.

**3.2 `lthing_judicial`: three status codes are unreachable or untested.**
`test_judicial` covers `Bad_Envelope`, `Signature_Invalid`, the
`Parse_Unverified` no-trust guarantee, and the invariant — good. But:
- **`Bad_Magic` is never exercised.** T2 sets `Doc(9)=0x04` (passes magic, fails
  at signature); T3 is too short (fails envelope *before* magic). No test feeds
  a long-enough doc with a *wrong* doctype byte. Add one.
- **`Chain_Broken` is unreachable code.** The gate is
  `Digest_Equal(Recomputed_Chain, Recomputed_Chain)` (`lthing_judicial.adb:703`)
  — a tautology that can never be false. The branch can't be tested because it
  can't be hit; this is a real correctness gap, not just a coverage gap. Once
  the carried chain-hash is sliced from the envelope, add a tampered-chain
  vector that drives `Chain_Broken`.
- **`Seal_Mismatch` and `Bad_Length` are never assigned anywhere.** They are in
  the `Verify_Status` enum with no producing path and no test. Either wire the
  gates that produce them or document them as reserved.
- **`Parse_Unverified` is only tested on a valid-length doc** — its own
  `Bad_Envelope` branch (too-short input) is untested.
- All judicial tests use synthetic zero-filled buffers; **no golden `.jd.lthing`
  envelope** is ever parsed.

**3.3 The constant-time comparison is functionally and behaviorally untested.**
`Compare_CT` / `Digest_Equal` (`lthing_judicial.adb:624`) is security-critical
(it gates seal/chain equality) yet:
- There is no test that it returns *equal* for equal digests and *not-equal* for
  digests differing in one byte (incl. first-byte and last-byte differences).
- Its **constant-time** property — the entire reason it exists — has no timing
  or statistical test. A non-CT regression in the asm would be invisible.
- *Recommendation:* functional equal/unequal vectors now; a timing-variance
  smoke test as a stretch goal.

### MEDIUM

**3.4 NTT (`SPARK_Mode Off`) leans on a single random-vector style.**
This is the project's **largest body of unproven code**, so tests carry the
full burden. Current gates (roundtrip + 2 convolution vectors) are a strong
*consistency* check but have blind spots:
- **No known-answer vector.** The convolution gate proves the
  forward/inverse/pointwise triple is a self-consistent negacyclic transform,
  but it does **not** pin the coefficient/zeta *ordering* to the FIPS 204 /
  Dilithium reference. ExpandA will produce Â in reference NTT order; if this
  NTT's basis ordering differs, the convolution gate still passes but interop
  with real vectors fails. Add a fixed-input → reference-output NTT vector.
- **Schoolbook_Mul is the oracle but is itself unvalidated.** A correlated bug
  in both would pass silently. Add one known product (e.g. `(1+x)·(1+x) = 1+2x+x²`,
  and a wrap case exercising the `x²⁵⁶ = −1` negation at `lthing_mldsa_ntt.adb:920`).
- **No edge-case polynomials:** all-zero, all-`(q-1)`, single-impulse (isolates
  each `Zetas(k)`), and max-coefficient inputs. The zeta-index walk
  (`K := K + 1` / `K := K - 1`, `lthing_mldsa_ntt.adb:847,878`) is the classic
  Dilithium off-by-one surface and is covered only in aggregate.

**3.5 Field arithmetic boundary cases.**
Proven, so this is belt-and-suspenders, but the highest-value missing regression
is **`To_Centered` at the exact pivot**: the doc says `[0, q/2]` stays positive,
`(q/2, q-1]` maps negative (`lthing_mldsa_field.adb:761`). Tests check `q-1→-1`
and `5→5` but not `To_Centered(Q/2)` and `To_Centered(Q/2 + 1)` — precisely
where an off-by-one would live. Also missing: `Add(Q-1, 1) → 0`, multiply-by-zero,
`Reduce(0)`, and `Reduce` near the `(q-1)²` upper bound.

**3.6 `lthing_mldsa65.Verify` stub is not pinned by a test.**
No `test_mldsa65.adb`. The fail-closed posture
(`Verify` ⇒ False, `Arithmetic_Core_Complete = False`) is asserted only in prose.
Add a guard test so a premature "returns True" change trips immediately — this
is the inverse of audit FINDING-002 and worth a hard assertion.

### LOW / PROCESS

**3.7 No test driver, no aggregation, no CI.**
Each `test_*.adb` is a separate `main` printing `[PASS]/[FAIL]`; nothing runs
them together or yields a non-zero exit code on failure. A failing test would
not fail a build.
- *Recommendation:* a `tests.gpr` + a `Makefile`/`alr`/shell `test` target that
  builds and runs all drivers and **exits non-zero on any `[FAIL]`** (the
  drivers already count `Fails` — surface it as the process exit code instead of
  only printing it). Wire into CI alongside `gnatprove`.

**3.8 No coverage measurement.**
Literal line/branch/MCDC coverage is unmeasured. `gnatcov` (or
`-fprofile-arcs -ftest-coverage`) over the test drivers would turn the
hand-estimates above into hard numbers and catch the dead `Chain_Broken`
branch automatically.

**3.9 No property/fuzz test of the headline guarantee.**
The library's central claim is "court-grade, fail-closed: never trusts an
unverified document." The strongest possible test is a property harness that
feeds thousands of random / malformed / truncated / boundary-length buffers to
`Parse_And_Verify` and asserts `Result.Trusted = False` every time (and that
`Parse_Unverified` is *always* untrusted). This is cheap, high-signal, and
absent.

**3.10 FFI boundary has no in-repo regression.**
Comments reference an "asm regression harness (tests/)" that is **not in this
archive**. From this repo's standpoint the asm primitives (Keccak, `compare_constant_time`,
`xor_mask`, `rule30`) are untested — which is exactly how the broken Keccak
permutation went unnoticed until late. The asm KATs should live in, or be
mirrored into, this repo and run by the same `test` target.

---

## 4. Recommended order of work

1. **Wire the orphaned KAT** (`test_kat.adb`) — even as a negative gate today (3.0).
2. **Add `test_hash.adb` with FIPS 202 SHAKE512 KATs + determinism** — this is
   also the regression that gates the Keccak fix the report is blocked on (3.1).
3. **Close the judicial branch gaps**: `Bad_Magic`, `Parse_Unverified` short
   input, and fix the tautological `Chain_Broken` gate so it is reachable and
   testable (3.2); add `Compare_CT` equal/unequal vectors (3.3).
4. **Strengthen NTT**: one reference KAT + Schoolbook oracle vector + edge polys (3.4).
5. **Process**: aggregating `test` target with non-zero exit on failure, then
   `gnatcov` numbers and a fail-closed property/fuzz harness (3.7–3.9).
6. Boundary field cases (3.5) and the `Verify` stub guard (3.6) — quick wins,
   fold in opportunistically.

## 5. Bottom line

The **proven core is in good shape**: field arithmetic and the judicial
fail-closed contracts are both gnatprove-discharged *and* runtime-tested, which
is genuinely strong. The exposure is concentrated in (a) everything that is
`SPARK_Mode Off` or behind the FFI — NTT and the asm primitives carry their full
risk on tests alone, and the asm Keccak is *known wrong*; (b) the judicial layer's
unreached status codes and one dead branch; and (c) the end-to-end KAT that
exists on disk but is never run. The single highest-leverage action is to stop
treating `kat/mldsa65_sigver.json` and the asm/SHAKE KATs as documentation and
turn them into executed, exit-code-enforced gates.
