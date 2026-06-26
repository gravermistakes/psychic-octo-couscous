# LTHING Ada/SPARK — Test Coverage Analysis

**Subject:** `lthing-spark` — **ML-DSA-65 and ML-DSA-87 (FIPS 204)** signature
verifiers (Verify only; ML-DSA-65 also has KeyGen/Sign) plus a fail-closed
`.jd.lthing` judicial-document verification layer (suite 0x0001 → ML-DSA-65;
suite 0x0002 / CNSA 2.0 → ML-DSA-87), over a **pure-Ada Keccak/SHAKE core**
(`lthing_keccak`). The historical x86-64 asm hash and the `lthing_crypto_ffi`
trust boundary have been **retired** — there is no longer any FFI or assembly
in the build.
**Date:** 2026-06-26
**Method:** Every claim below was re-derived from the live tree, not read off an
older report:

```sh
cd lthing-spark
./run_tests.sh                                          # 15/15 suites, exit 0
export PATH=/root/.alire/bin:$PATH
gnatprove -P lthing.gpr --level=2 --report=all -j0      # 1087 checks, 0 unproved
```

No coverage instrumentation (`gnatcov`) is wired, so the per-unit *line/branch*
figures in §2 remain hand-estimates; the proof and pass/fail counts in §1 and §3
are tool output.

> **Scope note — multiple `.lthing` doctypes.** The `.lthing` container is a
> *family* of sub-extensions (`.jd` judicial, plus `.ml`, `.hl`, `.ver`,
> `.cry`, `.targz`, and the `.npo`/`.gv`/`.md` types named in `INTEGRATION.md`).
> The verifier and its tests cover **only the judicial (`.jd`) path**: `Magic_Ok`
> hard-codes the judicial doctype triple (`JD_DocType_B10/B11/B12`,
> `lthing_judicial.adb:40`). The other sub-extensions have **no parse/verify
> path and no tests**. See gap 4.4.

---

## 1. Ground truth (re-run for this revision)

- **Proof:** `gnatprove -P lthing.gpr --level=2` over the full project →
  **1087 checks, 0 unproved, 0 justified** (229 by flow / 858 by provers:
  Z3 4.13, cvc5 1.1.2, alt-ergo 2.4). **AoRTE + flow + every stated contract
  discharged** across both ML-DSA-65 and ML-DSA-87 implementations, the
  judicial dispatch layer, the shared NTT/field/codec/sampler stack, and the
  Keccak/SHAKE core. All `test_*.adb` mains are `SPARK_Mode (Off)` and
  correctly skipped by the prover.
- **Tests:** `./run_tests.sh` builds and runs **all 15** `src/test_*.adb` mains,
  greps for `[FAIL]`, and exits non-zero on any build/run/assert failure.
  Verified: **15/15 suites pass, exit 0.**

Every production unit is `SPARK_Mode (On)`; there is **no `SPARK_Mode (Off)`
code outside the test drivers**. Where proof applies it is stronger than a test,
so the residual gaps in §4 are scoped to what proof does *not* cover: external
known-answer interop, the unimplemented doctype family, and unmeasured literal
line/branch coverage.

---

## 2. Source units and what covers them

| Unit | SPARK | Role | Direct test gate |
|------|:-----:|------|------------------|
| `lthing_types` | On | `Byte`, bounded `Byte_Array` (0..1 MiB), `Digest` (64B), `Verify_Status`, `Verified_Record` + `Trusted = (Status = Verified)` predicate | exercised via judicial |
| `lthing_keccak` | On | Keccak-f[1600] + `Sponge(Input, Rate, Domain, Output)` | `test_keccak` (8 KATs) |
| `lthing_hash` | On | `SHAKE512` (rate 72 / domain `0x1F`) + `Chain_Hash` | `test_hash` (3 relational) |
| `lthing_judicial` | On | `Parse_Unverified` / `Parse_And_Verify` — full LTHING envelope verify | `test_judicial` (16) |
| `lthing_mldsa_field` | On | Z_q arithmetic | `test_field` (14) |
| `lthing_mldsa_ntt` | On | NTT / INTT / pointwise / schoolbook | `test_ntt` (3) |
| `lthing_mldsa_round` | On | Power2Round / Decompose / High/Low_Bits / UseHint | `test_round` |
| `lthing_mldsa_codec` | On | pk/sig encode + decode | `test_codec` (7), `test_encode` (3) |
| `lthing_mldsa_sample` | On | ExpandA / RejNTTPoly / SampleInBall / XOF | `test_sample`, `test_xof_cap` |
| `lthing_mldsa_sign` | On | KeyGen / Sign (proof-companion to Verify) | `test_sign` (8) |
| `lthing_mldsa65` | On | FIPS 204 `Verify (PK, Message, Context, Sig)`; `Arithmetic_Core_Complete = True` | `test_kat` (15), `test_verify_adv` (4) |
| `lthing_mldsa87` | On | FIPS 204 ML-DSA-87 `Verify`; k=8, l=7, τ=60, ω=75, PK=2592 B, Sig=4627 B; `Arithmetic_Core_Complete = True` | `test_kat87` (15) |
| `lthing_mldsa87_codec` | On | ML-DSA-87 pk/sig decode (z 20-bit/coeff, hints ω=75, c̃ 64 B) | `test_kat87` (end-to-end) |
| `lthing_mldsa87_sample` | On | ML-DSA-87 SampleInBall (τ=60), ExpandA (8×7 matrix) | `test_kat87` (end-to-end) |

**The 15 suites and their headline gates:**

- **`test_field`** — 14 relational checks: `Add(Q-1,1)=0`, commutativity,
  `Mul` distributes over `Add`, `Reduce((Q-1)²)=1`, and the `To_Centered` pivot
  (low half > 0, high half < 0, `Q-1 → -1`).
- **`test_keccak`** — 8 **authoritative** KATs: `keccak_f1600(0)` lane0
  `f1258f7940e1dde7`, SHA3-512("") (the rate-72 anchor for LTHING "SHAKE512"),
  SHA3-256(""), SHAKE256("")/("abc"), SHAKE128(""), a 64-byte multi-block
  squeeze, and rate-72 determinism. Values come from Python `hashlib`, never
  hand-written.
- **`test_hash`** — 3 relational gates (no frozen digests): SHAKE512
  determinism, input-sensitivity, and `Chain_Hash(prev,art) = SHAKE512(prev‖art)`.
- **`test_ntt`** — INTT∘NTT roundtrip + 2 NTT-multiply = schoolbook-mod-(x²⁵⁶+1)
  convolution vectors.
- **`test_round`** — Power2Round/Decompose recompose + range invariants across a
  spread of representative `r` values.
- **`test_codec` / `test_encode`** — pk/sig decode on a real vector incl.
  fail-closed on a corrupted hint end-pointer; encoders shown to invert the
  proven decoders (`pkDecode∘pkEncode = id`, `sigDecode∘sigEncode = id`).
- **`test_sample` / `test_xof_cap`** — SampleInBall produces exactly τ=49 ±1
  coeffs and is input-sensitive; ExpandA deterministic; XOF Round-0 buffer
  (1088 B) provably suffices across 5000 trials.
- **`test_sign`** — KeyGen determinism + a full Sign→Verify round-trip with and
  without context, plus tamper rejection (signature, message, context, wrong PK).
- **`test_kat`** — the authoritative **15-vector ML-DSA-65 sigVer KAT**
  (tcId 31..45, 3 accept / 12 reject) from `kat/mldsa65_sigver.json`, run through
  `LTHING_MLDSA65.Verify`. **15/15 against `expected`.**
- **`test_verify_adv`** — valid V31 accepts; 1-bit signature tamper, 1-bit PK
  tamper, and empty-message all fail-closed.
- **`test_judicial`** — 16 checks driving **every** `Verify_Status`: `Bad_Envelope`,
  `Bad_Magic` (incl. legacy offset-9 fake header, zero version), `Bad_Length`,
  `Seal_Mismatch`, `Chain_Broken`, `Signature_Invalid`, and a **genuine signed
  genesis envelope → `Verified`/`Trusted`**, plus the `Trusted ↔ Verified`
  invariant and the `Parse_Unverified`-never-trusted guarantee.
- **`test_kat87`** — the authoritative **15-vector ML-DSA-87 sigVer KAT**
  (tcId 61..75, from `kat/mldsa87_sigver.json`, NIST ACVP tgId=5:
  `parameterSet=ML-DSA-87, signatureInterface=external, preHash=pure`),
  run through `LTHING_MLDSA87.Verify`. **15/15 against `expected`** (3 accept /
  12 reject). Vector shape: PK=2592 B, sig=4627 B.
- **`test_judicial87`** — 6 relational gates for the CNSA 2.0 judicial path
  (suite 0x0002): wrong-sig-length → `Bad_Length`; ML-DSA-65-size PK for
  suite 0x0002 → `Bad_Length`; well-formed envelope with zero sig →
  `Signature_Invalid` (proves §9.1..§9.9 run for suite 0x0002); tampered body
  → `Seal_Mismatch`; wrong `prev_chain` → `Chain_Broken`; `Trusted ↔ Verified`
  invariant.

---

## 3. Coverage by unit (line/branch estimate — not instrumented)

| Unit | Subprogram coverage | Branch/edge | Notes |
|------|--------------------:|-------------|-------|
| `lthing_mldsa_field` | 5/5 | medium–high | pivot + identity boundaries pinned (§2) |
| `lthing_keccak` | full | medium | every rate/domain LTHING uses is KAT'd |
| `lthing_hash` | 2/2 | medium | relational gates; no non-72-aligned frozen vector (§4.2) |
| `lthing_judicial` | 2/2 entry, 6/6 statuses | **high** | all status codes now reachable **and** tested |
| `lthing_mldsa_ntt` | 4/4 | medium | convolution-correct; no external reference-order KAT (§4.1) |
| `lthing_mldsa_round` | full | high | recompose + range across representative inputs |
| `lthing_mldsa_codec` | encode+decode | medium–high | round-trip + fail-closed hint |
| `lthing_mldsa_sample` | full | medium | τ/±1, determinism, XOF capacity |
| `lthing_mldsa65` | 1/1 Verify | medium–high | 15-vector KAT + adversarial tamper |
| `lthing_mldsa87` | 1/1 Verify | medium–high | 15-vector KAT (tcId 61–75) |
| `lthing_mldsa87_codec` | pk+sig decode | medium–high | exercised end-to-end by test_kat87 |
| `lthing_mldsa87_sample` | full | medium | SampleInBall(τ=60), ExpandA 8×7 |

---

## 4. Remaining gaps (honest residual)

Everything the earlier revisions of this file flagged as HIGH — the orphaned
sigVer KAT, the asm-Keccak fix guarded by nothing in-repo, the tautological
`Chain_Broken` gate, the unreachable `Seal_Mismatch`/`Bad_Length`, the missing
`LTHING_Hash` test, and the `Verify` return-False stub — is **closed**. The asm
trust boundary itself is gone. What remains:

### MEDIUM

**4.1 NTT has no external reference-order KAT.** The convolution gate proves the
forward/inverse/pointwise triple is a self-consistent negacyclic transform over
`x²⁵⁶+1`, and the full verifier passing the 15-vector KAT exercises the NTT in
its real composition — so a basis-ordering bug would surface end-to-end. But
there is still no *isolated* fixed-input → FIPS-204-reference-output NTT vector;
adding one would localize any future zeta-ordering regression to the NTT unit
instead of the whole pipeline.

**4.2 `LTHING_Hash` production path has only relational gates.** `test_hash`
asserts determinism, input-sensitivity, and the `Chain_Hash = SHAKE512(prev‖art)`
relation — strong, and the underlying sponge is KAT-anchored by SHA3-512 in
`test_keccak`. Not present: a frozen multi-block, **non-72-aligned** SHAKE512
vector captured from the proven build, which would pin the exact final-padded-
block byte positions for the *judicial document* sizes (often ~MiB, rarely
72-aligned).

### LOW / PROCESS

**4.3 No literal coverage measurement.** `gnatcov` (or
`-fprofile-arcs -ftest-coverage`) over the 15 drivers would replace the §3
hand-estimates with hard line/branch/MCDC numbers. With every status code now
reachable, there is no longer a known dead branch for it to flag — but it would
keep that true.

**4.4 Only the `.jd` doctype of the `.lthing` family is implemented or tested.**
`Magic_Ok` accepts only the judicial doctype triple; every other sub-extension
(`.ml`, `.hl`, `.ver`, `.cry`, `.targz`, `.npo`/`.gv`/`.md`) is rejected as
`Bad_Magic` with no dedicated path. There is no per-doctype fixture matrix and
no cross-type substitution test (e.g. a `.jd` body presented under a `.cry`
extension). The current honest behavior — non-judicial doctypes return
`Bad_Magic`, never `Verified` — **is** asserted (`test_judicial`); the gap is the
unimplemented doctypes, not a missing test for today's behavior.

**4.5 No large-scale fail-closed fuzz harness.** `test_judicial` /
`test_verify_adv` cover hand-picked malformed/tampered/truncated/empty inputs and
all fail closed. A property harness feeding thousands of random/boundary-length
buffers to `Parse_And_Verify` asserting `Trusted = False` every time would raise
confidence in the headline guarantee further; it is cheap and still absent.

---

## 5. Bottom line

**Both ML-DSA-65 and ML-DSA-87 verifiers are implemented, proved, and KAT-true.**
The FIPS 204 Alg. 3/8 verifier stack (sampling, rounding, codec, NTT, `Verify`)
exists for both parameter sets, all `SPARK_Mode (On)`. Each has an authoritative
15-vector NIST ACVP sigVer KAT passing **15/15** (3 accept / 12 reject):
ML-DSA-65 (tcId 31..45) and ML-DSA-87 (tcId 61..75). The judicial layer
dispatches suite 0x0001 → ML-DSA-65 and suite 0x0002 / CNSA 2.0 → ML-DSA-87;
both dispatch paths are exercised and all `Verify_Status` values are reachable
and tested, including a genuine signed envelope reaching `Verified`/`Trusted`.
Hashing is proved pure-SPARK Keccak/SHAKE — the asm/FFI is retired.

Authoritative, re-run for this revision:
`gnatprove -P lthing.gpr --level=2` = **1087 checks, 0 unproved, 0 justified**
(229 flow / 858 provers); `./run_tests.sh` = **15/15 suites green**, exit 0.

Residual work is breadth, not core correctness: an isolated NTT reference KAT
(4.1), a frozen non-aligned SHAKE512 vector (4.2), `gnatcov` numbers (4.3), the
unimplemented `.lthing` doctype family (4.4), and a fail-closed fuzz harness
(4.5). The crypto core and the judicial gate — the project's reason for being —
are done for both ML-DSA-65 and ML-DSA-87, proved, and KAT-validated.
