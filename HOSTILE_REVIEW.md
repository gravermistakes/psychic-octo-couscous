# Hostile Review + Remediation Guide — `lthing-spark`

> Adversarial audit (2026-06-16), **refreshed 2026-06-20** to reflect the code
> as it now stands. Every original finding is tied to `file:line`; each now
> carries a **status** (RESOLVED / OPEN / MOOT) backed by the commit or command
> that settled it. The Part 2 fix guides are kept for the record.
>
> Original verdict (2026-06-16): the ML-DSA-65 math was correct (KAT 15/15) but
> wired into nothing, the chain check was fake, three statuses were dead, the asm
> was not retired, and the "0 unproved" headline excluded the verifier core.
>
> **Current verdict (2026-06-20): the critical and high findings are fixed.**
> `Parse_And_Verify` performs the full fail-closed envelope verification; the
> chain gate is real; the ML-DSA-65 verifier *and* a new signer are
> `SPARK_Mode (On)` and whole-project `gnatprove` reports **0 unproved** with the
> crypto core *included* (no exclusion) — so the proof number is now genuine
> whole-project assurance, not a rigged subset. End-to-end: a genuinely signed
> `.jd.lthing` envelope verifies (`test_judicial` T15) and any tamper fails
> closed (T16). Remaining items are MEDIUM/LOW doc-accuracy and FIPS-breadth work.

## Status snapshot (2026-06-20)

| # | Finding | Status | Settled by |
|---|---------|--------|-----------|
| C1 | `Verify_Signature` hardcoded `return False` | **RESOLVED** | `d5dec63` — real envelope verify; stub gone |
| C2 | Chain gate is a `Digest_Equal(X,X)` tautology | **RESOLVED** | `d5dec63` — `ChainHash = SHAKE512(prev‖art)`, `Chain_Broken` |
| C3 | Proof metric rigged (core `SPARK_Mode Off`) | **RESOLVED** | core now On; whole-project gnatprove 0 unproved, core included |
| H4 | Three dead status codes | **RESOLVED** | `d5dec63` — `Bad_Length`/`Seal_Mismatch`/`Chain_Broken` all assigned |
| H5 | Constant-time compare untested | **RESOLVED** | `Window_Equal` (CT XOR-accumulate) exercised by `test_judicial` T10/T12/T15/T16; dead `Digest_Equal` removed |
| H6 | asm not retired | **RESOLVED** | `lthing_crypto_ffi.ads` deleted; no `crypto_asm` in `run_tests.sh` |
| H7 | Docs assert false things | **PARTIAL · CRITICAL** | `lthing-spark/CLAUDE.md` fixed (`d5dec63`); `TEST_COVERAGE_ANALYSIS.md` + `test_kat.adb` header still stale — **OPEN** |
| M8 | Empty-message precondition | **RESOLVED** | `Message'Length > 0` dropped; empty ctx round-trips (`test_sign` T3) |
| M9 | KAT is thin | **OPEN · CRITICAL** | property gates added (encode round-trip, sign round-trip, tamper); boundary KATs not added |
| M10 | KAT generator never cross-validated | **MOOT** | `tools/gen_kat_vectors.py` no longer in the repo |
| M11 | Vacuous `Output'Length = Output'Length` | **MOOT** | lived in the now-deleted `lthing_crypto_ffi.ads` |
| M12 | Keccak rate/domain pairing unenforced | **OPEN · CRITICAL** | `Sponge` still accepts any (rate, domain) |
| L13 | `test_judicial` never `Set_Exit_Status` | **RESOLVED** | now calls `Set_Exit_Status (Failure)` on any `[FAIL]` |
| L14 | `Makefile:6` `gprbuild … \|\| true` | **OPEN · CRITICAL** | still masks build failures |
| L15 | SHAKE512/Chain_Hash forbid empty input | **OPEN · CRITICAL** | judicial layer has its own non-empty policy |
| L16 | Duplicate rate constant | **MOOT** | lived in the deleted `lthing_crypto_ffi.ads` |
| L17 | `collaborative_neon_garden.py` in repo | **MOOT** | file no longer present |

**Net:** all originally-CRITICAL + HIGH code findings are closed except the H7
doc tail. **Severity reclassification (maintainer directive, 2026-06-20):** every
remaining OPEN item is tracked at **CRITICAL priority** regardless of its original
tier — nothing ships as "medium" or "low" while unresolved. The open set is
therefore: **H7** (docs), **M9** (KAT breadth), **M12** (Keccak rate/domain),
**L14** (Makefile `|| true`), **L15** (empty-input hashing). The original tier
labels (M*/L*) are retained only as stable identifiers, not as severity.

---

## PART 1 — FINDINGS (original 2026-06-16 ranking, annotated)

### CRITICAL
- **C1. `Verify_Signature` hardcoded `return False`** — `lthing_judicial.adb:71-79`.
  **RESOLVED** (`d5dec63`): `Parse_And_Verify` parses the §3 header, validates
  section geometry, recomputes the §5 seal hashes, and verifies the §6 ML-DSA-65
  signature over `header‖body‖seal`, fail-closed at the first failing §9 gate.
- **C2. Chain-of-custody gate is a tautology** — `lthing_judicial.adb:132`.
  **RESOLVED** (`d5dec63`): `ChainHash` is recomputed as
  `SHAKE512(prev_chain ‖ artifact)` and compared against the carried value;
  mismatch returns `Chain_Broken` (`test_judicial` T11).
- **C3. The proof metric is rigged** — verifier core was `SPARK_Mode (Off)`.
  **RESOLVED**: `lthing_mldsa65`/`_ntt`/`_sample` are `SPARK_Mode (On)`; the new
  `lthing_mldsa_sign` is On too. Whole-project `gnatprove -P lthing.gpr --level=2`
  = **0 unproved** with the crypto core included. The number is now genuine
  whole-project assurance. (Cryptographic *soundness* of `Verify` remains
  KAT-established, not gnatprove-established — that distinction is stated in
  `lthing_mldsa65.ads`, and is the honest scope of a SPARK AoRTE proof.)

### HIGH
- **H4. Three dead status codes** — `lthing_types.ads:41-43`. **RESOLVED**
  (`d5dec63`): all three are assigned by real gates in `Parse_And_Verify`.
- **H5. Constant-time compare untested + asm-imported** — **RESOLVED**: the live
  CT primitive is `Window_Equal` (data-independent XOR-accumulate over 64 bytes),
  exercised behaviourally by `test_judicial` (T10/T12 tamper → mismatch,
  T15 accept → match, T16 signature tamper → reject). The asm import is gone
  (H6). The previously-dead `Digest_Equal` has been removed.
- **H6. asm not actually retired** — **RESOLVED**: `src/lthing_crypto_ffi.ads`
  is deleted and `run_tests.sh` links no `crypto_asm`; the digest compare is
  pure Ada.
- **H7. Docs assert false things** — **PARTIAL**. `lthing-spark/CLAUDE.md` table
  is corrected (`d5dec63`). **Still OPEN:** `TEST_COVERAGE_ANALYSIS.md` carries a
  contradictory `lthing_hash` "0/2 — No test at all" row (`:63`, `:88`, `:248`)
  although `test_hash.adb` exists; and `test_kat.adb:14-19,91` still describes a
  "NEGATIVE gate (stub) / NO Context" posture that contradicts the current code
  (`Arithmetic_Core_Complete = True`, `Verify` takes a context).

### MEDIUM
- **M8. Empty-message precondition** `Message'Length > 0` — **RESOLVED**: dropped;
  empty context/message paths round-trip (`test_sign` T3, verifier comment at
  `lthing_mldsa65.ads`).
- **M9. KAT is thin** — **OPEN (partial)**: relational property gates have been
  added (encoder round-trip `test_encode`; KeyGen→Sign→Verify round-trip and
  multi-axis tamper `test_sign`), but explicit boundary KATs (‖z‖∞ at γ1−β, hint
  weight at ω, near-valid encodings) are not yet in.
- **M10. KAT generator output never cross-validated** — **MOOT**: the generator
  is no longer in the repo.
- **M11. Vacuous postcondition** — **MOOT**: lived in the deleted FFI spec.
- **M12. Keccak API under-constrained** — **OPEN**: `Sponge` still accepts any
  (rate, domain) pair; FIPS 202 pairing is not enforced by a precondition.

### LOW
- **L13. `test_judicial` never calls `Set_Exit_Status`** — **RESOLVED**: it now
  sets `Failure` on any `[FAIL]`.
- **L14. `Makefile:6`** `gprbuild … || true` — **OPEN**: still masks build
  failures (note: `run_tests.sh`, the suite entrypoint, does not use it).
- **L15. `SHAKE512`/`Chain_Hash` forbid empty input** — **OPEN** (optional).
- **L16. Duplicate rate constant** — **MOOT**: lived in the deleted FFI spec.
- **L17. `collaborative_neon_garden.py`** — **MOOT**: not present in the repo.

---

## PART 2 — FIX GUIDES (retained; resolved guides marked)

> The C1/C2/H4 guides below were written before `LTHING_HEADER_SPEC.md` was in
> the repo and assumed an external spec dependency. That assumption was wrong
> (the layout is in-repo), and the work is now **done** — guides kept for record.

### C1 — wire `Verify_Signature` → `LTHING_MLDSA65.Verify`  ✅ DONE (`d5dec63`)
`Parse_And_Verify` slices the signed prefix (`header‖body‖seal`) and the
signature out of the envelope, copies them into the constrained
`LTHING_MLDSA65.Public_Key`/`Signature` subtypes, and calls `Verify` with an
empty context. Fail-closed at the first failing §9 gate.

### C2 — real chain-of-custody gate  ✅ DONE (`d5dec63`)
The tautology is gone; `ChainHash = SHAKE512(prev_chain ‖ artifact)` is compared
against the seal's carried chain hash (`Chain_Broken` on mismatch).

### C3 — stop rigging the proof number  ✅ DONE
Option (b) was taken: the crypto core is `SPARK_Mode (On)` and AoRTE is
discharged; the new signer too. Whole-project gnatprove is 0 unproved with the
core included. Soundness-vs-AoRTE scope is named in `lthing_mldsa65.ads`.

### H4 — light up the dead statuses  ✅ DONE (`d5dec63`)
`Bad_Length` (geometry/length gate), `Seal_Mismatch` (artifact/seal-id recompute),
`Chain_Broken` (chain compare) are all reachable.

### H5 — test the constant-time compare  ✅ DONE
Coverage is behavioural through `Parse_And_Verify`: equal seals accept, tampered
seals/signature reject (`test_judicial` T10/T12/T15/T16). Dead `Digest_Equal`
removed; `Window_Equal` is the single CT primitive.

### H6 — actually retire the asm  ✅ DONE
`lthing_crypto_ffi.ads` deleted; no `-llthing_crypto_asm` / `LD_LIBRARY_PATH` in
`run_tests.sh`; digest compare is pure Ada.

### H7 — fix the lying docs  ⚠️ PARTIAL — remaining work
- ✅ `lthing-spark/CLAUDE.md` table corrected.
- ☐ `TEST_COVERAGE_ANALYSIS.md`: the `lthing_hash` "0/2 — No test at all" rows
  (`:63`, `:88`, `:248`) contradict the existence of `test_hash.adb` and the
  updated row at `:25`. Reconcile to one current table (or date-stamp the old
  inventory and add a current column).
- ☐ `test_kat.adb:14-19,91`: delete the stale "NEGATIVE gate (stub) / NO Context"
  header and status line; the core is complete and `Verify` takes a context.

### M8 — empty-message support  ✅ DONE
`Message'Length > 0` dropped (`lthing_mldsa65.ads`); empty paths verified.

### M9 — KAT breadth  ☐ OPEN (partial)
Property/relational gates added (`test_encode`, `test_sign`). Still to do:
authoritative boundary vectors (NIST ACVP `ML-DSA-sigVer` accept+reject) and
explicit boundary unit tests (`Inf_Norm_OK` at exactly `Gamma1-Beta`; hint weight
at exactly `Omega`). Do NOT hand-author vectors; if network policy blocks the
fetch, keep the property tests and say so.

### M10 — validate the KAT generator  ✅ MOOT
Generator no longer in the repo.

### M11 — fix the vacuous contract  ✅ MOOT
Removed with the FFI spec.

### M12 — constrain the Keccak API  ☐ OPEN (cheap)
Add a `Sponge` precondition rejecting invalid (rate, domain) pairs, or expose
domain-bound rate constants, so a caller cannot compute a nonsense sponge.

### L13 — `test_judicial` exit status  ✅ DONE
### L14 — un-mask build failures  ☐ OPEN
`Makefile:6`: drop `|| true` (or split strict `build` from a best-effort target).
The suite runs via `run_tests.sh`, which is already strict.
### L15 — empty input to SHAKE512/Chain_Hash  ☐ OPEN (optional)
### L16 — de-duplicate the rate constant  ✅ MOOT
### L17 — `collaborative_neon_garden.py`  ✅ MOOT (not in repo)

---

## Suggested remaining order
All five items below are **CRITICAL priority** (2026-06-20 maintainer directive);
ordered by effort, not by severity — none is optional.
1. **Doc honesty (H7 tail):** reconcile `TEST_COVERAGE_ANALYSIS.md` and the
   `test_kat.adb` header to the current code.
2. **Cheap hardening:** M12 (Keccak rate/domain precondition), L14 (Makefile).
3. **FIPS breadth:** M9 boundary KATs / property tests; L15 empty-input hashing.
4. Re-run `./run_tests.sh` (green incl. all gates) and
   `gnatprove -P lthing.gpr --level=2` (0 unproved, core included) after each.
