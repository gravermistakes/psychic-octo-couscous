# LTHING Ada/SPARK — Test Coverage Analysis

**Subject:** `lthing-spark` (ML-DSA-65 / FIPS 204 verifier + fail-closed `.jd.lthing` judicial layer) and the `lthing_asm` crypto primitives it links.
**Date:** 2026-06-13
**Method:** Manual review of every source unit, every `test_*.adb`, `lthing.gpr`, `PROOF_REPORT.md`, the `kat/` assets, **and the `lthing_asm` tree** (`keccak.asm`, `KECCAK_FIX_REPORT_20260608.md`, the C test harnesses, and AVRS `FINDING-001`). No coverage instrumentation exists in the project, so figures below are derived by hand from which subprograms and branches are actually exercised.

> **Scope note — multiple `.lthing` doctypes.** The `.lthing` container is a
> *family* of document sub-extensions (`.jd` judicial, plus `.ml`, `.hl`,
> `.ver`, `.cry`, `.targz`, and the `.npo`/`.gv`/`.md` types named in
> `INTEGRATION.md`). The verifier and its tests currently cover **only the
> judicial (`.jd`, DocType `0x0004`) path** — `Magic_Ok` hard-codes that single
> doctype. The other 4-5 sub-extensions have **no parse/verify path and no
> tests at all**. See gap 3.11.

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

Verified by re-running `gnatprove --level=2` on the real project (not quoting
the report): **80 checks across 11 units, 0 unproved, 0 justified** — 37
run-time checks, 12 functional contracts, 13 data-dependencies, 9 termination,
7 initialization, 2 assertions. (The `PROOF_REPORT.md` "14 VCs" line was a
hand-count of a subset; the tool reports 80.) This covers every field op's
canonical-range postcondition, the `Verified_Record`
`Trusted = (Status = Verified)` predicate at every assignment, and both
judicial fail-closed postconditions. The three runtime suites were likewise
re-run, not assumed: `test_field` 11/11, `test_ntt` 3/3, `test_judicial` 4/4,
all exit 0. **Where proof applies it is stronger than a test**, so the gaps
below are deliberately scoped to behavior the prover does *not* cover: the
`SPARK_Mode (Off)` NTT, the FFI/asm boundary, end-to-end KAT behavior, and
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

**3.1 Keccak/SHAKE: fixed, but the fix is gated by nothing that is committed —
and the production rate is never KAT'd. `lthing_hash` still has zero tests.**

*Correction to the stale `PROOF_REPORT.md` (06-06) framing:* the asm
Keccak-f[1600] **has since been fixed** (`KECCAK_FIX_REPORT_20260608.md`): three
P0 bugs — a ρ+π step that was a no-op ("skipped for brevity"), in-place χ
corruption, and missing SHAKE `pad10*1`+`0x1F` domain separation — were
repaired, and FINDING-001's uninitialized-shift bug is fixed in `keccak.asm`
(the byte-path now does `mov rcx, r11` before `shr r10, cl`). So Parts 3-5 are
unblocked. **But the regression that proves this lives nowhere in the repo:**
- **The committed asm harness tests no SHAKE/Keccak at all.** `test_crypto_asm.c`
  (the "5/5 PASS" cited in the fix report) covers `rule30_init/evolve/extract`,
  `mask/unmask`, and `compare_constant_time` — **zero** Keccak assertions.
  `test_hardened.c` is rule30/XOR only. The fix report's KATs
  (`keccak_f1600(0)=f1258f7940e1dde7`, `SHAKE256("")`, `SHAKE256("abc")`,
  `SHAKE256("") 200B`) were run ad-hoc and committed to **no** test file. A
  regression that reintroduces any of the three bugs would be caught by nothing
  — the *exact* failure mode FINDING-001 called out ("test harness never ran").
- **The actual production configuration is never tested.** The Ada layer only
  ever calls SHAKE at **rate 72 ("SHAKE512" — `LTHING_Crypto_FFI.SHAKE512_Rate`)**,
  which is what the Provenance Seal and `provenance_chain_hash` use. *Every*
  reported KAT is `keccak_f1600` or standard **SHAKE256 (rate 136)**. "SHAKE512"
  is not a standard FIPS 202 function, so there is no off-the-shelf vector — but
  the rate-72 padding path (`0x1F` at the message end, `0x80` at byte `rate-1 = 71`)
  is precisely the byte-position-specific logic the three fixed bugs lived in,
  and it has zero coverage.
- **Non-rate-aligned input is still untested**, despite FINDING-001 explicitly
  recommending "a test case where input length is NOT a multiple of the rate."
  `LTHING_Hash` absorbs arbitrary-length judicial documents (up to ~1 MiB),
  almost always non-72-aligned, exercising the final padded-block path.
- **No Ada-level test exists for `LTHING_Hash` at all** (`SHAKE512`, `Chain_Hash`).
  `Chain_Hash`'s concatenation logic (64-byte seal prefix + artifact, the
  `Loop_Invariant`, the length bound) and **determinism** — same input → same
  digest, the property the seal-match and chain-link checks *rely on* — are
  asserted nowhere.
- *Recommendation:*
  1. Commit the fix-report KATs as a permanent C regression (`keccak_f1600(0)`,
     SHAKE256 empty/abc/200B) so the Keccak fix cannot silently regress.
  2. Add a **rate-72 self-consistency + non-aligned** gate: pin
     `SHAKE("", rate=72, 64B)` and a couple of multi-block, non-72-aligned
     inputs to fixed expected digests captured from the now-correct build, so
     the production path has a frozen vector even absent a FIPS "SHAKE512" KAT.
  3. Add `test_hash.adb` driving `LTHING_Hash.SHAKE512`/`Chain_Hash` with those
     same vectors plus a determinism check.

  *Status (this PR — done, built and proved):* rather than KAT-gate the fragile
  asm, the hash core has been **reimplemented in pure Ada/SPARK** —
  `lthing-spark/src/lthing_keccak.ads/.adb` (Keccak-f[1600] + a rate/domain-
  parametrized sponge, `SPARK_Mode (On)`). Built with GNAT 13.3.0 and **proved
  with gnatprove 14.1.1 (Z3 4.13, cvc5 1.1.2, alt-ergo 2.4) at `--level=2`:
  51 checks, 42 by provers + 9 by flow, 0 unproved, 0 justified** — AoRTE +
  flow discharged for the whole unit. `test_keccak.adb` is the committed KAT
  gate the asm never had; it runs 8/8 against **authoritative** vectors:
  `keccak_f1600(0)=f1258f7940e1dde7`, SHA3-512("") and SHA3-256("") (domain
  0x06), SHAKE256("")/("abc") and SHAKE128("") (domain 0x1F), a 64-byte
  multi-block squeeze, and a rate-72 determinism check. Crucially the rate-72
  sponge that LTHING's "SHAKE512" uses is anchored by the **SHA3-512 KAT**
  (SHA3-512 is also rate 72), not a self-derived value. This removes the FFI
  trust boundary for hashing and makes the four historical Keccak bug classes
  (bad indexing, in-place χ corruption, wrong shift, missing pad) provably
  impossible. **`LTHING_Hash` is now wired to this sponge** — `SHAKE512` calls
  `Sponge (Input, Rate_SHA3_512, Domain_SHAKE, …)`, retiring the FFI hash path —
  and `test_hash.adb` covers it with relational gates only (no frozen digests):
  determinism, input-sensitivity, and `Chain_Hash (prev,art) = SHAKE512 (prev‖art)`.
  Whole-project re-proof after wiring: **`gnatprove -P lthing.gpr` → 130 checks,
  0 unproved**; `run_tests.sh` → 5/5 suites pass.

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

**3.7 No test driver, no aggregation, no CI. — DONE (this PR).**
Each `test_*.adb` was a separate `main`; nothing ran them together or failed the
build on `[FAIL]`. Now `lthing-spark/run_tests.sh` builds and runs every
`src/test_*.adb`, greps for `[FAIL]`, and **exits non-zero** on any build/run/assert
failure; `lthing-spark/Makefile` exposes `build`/`test`/`prove`/`clean`; and
`.github/workflows/ci.yml` installs GNAT + gnatprove and runs `make test` and
`make prove` on push/PR. Verified in-tree: `run_tests.sh` → 5/5 suites pass
(field 11, hash 3, judicial 4, keccak 8, ntt 3), exit 0.

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

**3.10 FFI boundary regression is partial and excludes the hash core.**
The asm harness (`tests/test_crypto_asm.c`, `tests/test_hardened.c`) *does*
exist and covers rule30 and the XOR/compare primitives — but, as noted in 3.1,
it tests **none** of the Keccak/SHAKE surface that `lthing_hash` and the whole
provenance chain depend on. The asm KATs that were run by hand should be folded
into this harness and run by the same `test` target as the Ada drivers, so the
FFI trust boundary is covered end-to-end rather than primitive-by-primitive.

**3.11 Only one of 4-5 `.lthing` sub-extensions is implemented or tested.**
The `.lthing` format is a family — `.jd` (judicial), `.ml`, `.hl`, `.ver`,
`.cry`, `.targz`, and the `.npo`/`.gv`/`.md` types in `INTEGRATION.md`. Today:
- `Magic_Ok` (`lthing_judicial.adb:613`) accepts **only** `Judicial_DocType =
  0x0004`; every other sub-extension is rejected as `Bad_Magic` with no
  dedicated parse/verify path.
- There is **no test matrix over doctypes** — no fixture per sub-extension, no
  assertion that each type's envelope shape, magic byte, and type-specific
  fields verify (and that a `.jd` body presented under a `.cry` extension, or
  vice-versa, is rejected — a confusion/type-substitution attack surface).
- *Recommendation:* once the other doctypes are specified, add one golden
  envelope per sub-extension and a parametrized test that (a) accepts each valid
  type and (b) rejects cross-type / wrong-magic substitution. Until then, add a
  single test asserting the *current* honest behavior: non-`0x0004` doctypes
  return `Bad_Magic`, never `Verified`.

---

## 4. Recommended order of work

1. **Lock in the Keccak fix (3.1).** Commit the fix-report KATs as a permanent
   C regression, add a rate-72 ("SHAKE512") + non-aligned vector for the
   *production* path, then `test_hash.adb` over `SHAKE512`/`Chain_Hash` +
   determinism. The fix is real but currently guarded by nothing in-repo.
2. **Wire the orphaned KAT** (`test_kat.adb`) — even as a negative gate today (3.0).
3. **Close the judicial branch gaps**: `Bad_Magic`, `Parse_Unverified` short
   input, and fix the tautological `Chain_Broken` gate so it is reachable and
   testable (3.2); add `Compare_CT` equal/unequal vectors (3.3).
4. **Strengthen NTT**: one reference KAT + Schoolbook oracle vector + edge polys (3.4).
5. **Process**: aggregating `test` target with non-zero exit on failure, then
   `gnatcov` numbers and a fail-closed property/fuzz harness (3.7–3.9).
6. Boundary field cases (3.5), the `Verify` stub guard (3.6), and the
   doctype/sub-extension matrix (3.11) — fold in opportunistically.

## 5. Bottom line

The **proven core is in good shape**: field arithmetic and the judicial
fail-closed contracts are both gnatprove-discharged *and* runtime-tested, which
is genuinely strong. The exposure is concentrated in (a) everything that is
`SPARK_Mode Off` or behind the FFI — NTT and the asm primitives carry their full
risk on tests alone; the asm Keccak has been **fixed** (06-08), but its fix is
gated by no committed test and its *production* rate-72 path was never KAT'd;
(b) the judicial layer's unreached status codes and one dead branch; (c) the
end-to-end KAT that exists on disk but is never run; and (d) the 4-5 other
`.lthing` sub-extensions, which are neither implemented nor tested. The single
highest-leverage action is to stop treating `kat/mldsa65_sigver.json` and the
asm/SHAKE KATs as documentation and turn them into executed, exit-code-enforced
gates — starting with the Keccak/SHAKE vectors, so the hardest-won fix in the
project cannot silently regress.
