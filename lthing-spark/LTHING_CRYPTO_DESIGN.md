# LTHING Cryptographic Subsystem — Design Specification

**System:** LTHING Envelope Crypto Layer
**Codebase:** `gravermistakes/psychic-octo-couscous` (`lthing-spark/`)
**Version:** Working Draft — 1750099200
**License:** ESL-ANCSA-MRA-IndiModSHA v1.3
**Standards:** FIPS 204 (ML-DSA, August 13 2024 final), FIPS 202 (Keccak/SHA-3)

---

## §1 — Architecture

### §1.1 — Language Stack

Pure Ada/SPARK. One language, one build system, one proof tool.
No C, no Fortran, no COBOL. No vendored crypto — the ML-DSA-65
implementation is built from proved field arithmetic, KAT-gated NTT,
and SPARK Keccak. External libraries are acceptable for non-crypto
purposes only.

**Remaining FFI (one call):** `lthing_judicial.adb` imports
`LTHING_Crypto_FFI` and calls `Compare_CT` (asm `compare_constant_time`)
for `Digest_Equal`. The hash path (SHAKE_Absorb/SHAKE_Squeeze) is fully
retired — nothing calls it. Only the CT comparison remains live.

**Cleanup TODO:**
- Replace `Compare_CT` with pure Ada XOR accumulation (§2.6)
- Delete `lthing_crypto_ffi.ads` after replacement
- Delete `lib/liblthing_crypto_asm.so` and `.a` after replacement
- Delete `tools/gen_kat_vectors.py` (stale Python)
- Fix stale comment in `lthing_mldsa_sample.ads`: says "calls C-FFI
  Keccak" but actually calls pure SPARK `LTHING_Keccak`

### §1.2 — Proof Posture

**Requirement: SPARK_Mode is always On.** Every Ada unit in lthing-spark
MUST have `SPARK_Mode => On`. No exceptions. Units currently Off are
flagged ILLEGAL and must be rewritten before any other work proceeds.

| Unit                  | SPARK  | Checks | Status                                    |
|-----------------------|--------|--------|-------------------------------------------|
| lthing_keccak         | **On** | 51     | Conformant                                |
| lthing_mldsa_field    | **On** | (incl) | Conformant                                |
| lthing_mldsa_codec    | **On** | (incl) | Conformant                                |
| lthing_mldsa_round    | **On** | (incl) | Conformant                                |
| lthing_hash           | **On** | (incl) | Conformant                                |
| lthing_judicial       | **On** | (incl) | Conformant (but calls FFI Compare_CT)     |
| lthing_types          | **On** | (incl) | Conformant                                |
| lthing_crypto_ffi     | **On** | —      | SPARK spec wrapping asm (to be deleted)   |
| lthing_mldsa_ntt      | Off    | —      | **ILLEGAL** — in-place butterfly          |
| lthing_mldsa_sample   | Off    | —      | **ILLEGAL** — dynamic grow-on-exhaust (stale comment says "C-FFI Keccak" but actually uses pure SPARK Keccak) |
| lthing_mldsa65 (body) | Off    | —      | **ILLEGAL** — composes Off units          |
| **Whole project**     |        | **306**| 0 unproved (conformant units)             |

Bringing the three non-conformant units to SPARK_Mode On is P0 — it
blocks signing (§2.4.1) because the signing path reuses these units.

### §1.3 — Build System

All GPL toolchain. Single `gprbuild` project + `make` wrapper.

| Tool       | Version | Purpose                              |
|------------|---------|--------------------------------------|
| GNAT       | 13.3.0  | Ada compiler (apt)                   |
| gprbuild   | —       | Project build (apt)                  |
| gnatprove  | 14.1.1  | SPARK proof (Alire, Z3/cvc5/alt-ergo)|
| make       | —       | Build/test/prove/clean targets       |

---

## §2 — Cryptographic Primitives

### §2.1 — Keccak-f[1600] (FIPS 202)

`lthing_keccak.adb`, pure Ada/SPARK. 51 checks, 0 unproved.
KAT anchor: `keccak_f1600(0) = f1258f7940e1dde7...` (FIPS 202).

Replaces the x86-64 asm that shipped four distinct correctness bugs.
The SPARK proof rules out all four bug classes by construction.

### §2.2 — Sponge

```ada
procedure Sponge
  (Input  : Byte_Array;
   Rate   : Positive;
   Domain : Byte;
   Output : out Byte_Array);
```

| Function         | Rate | Domain | Output | Standard       |
|------------------|------|--------|--------|----------------|
| SHA3-512         | 72   | 0x06   | 64 B   | FIPS 202       |
| SHA3-256         | 136  | 0x06   | 32 B   | FIPS 202       |
| SHAKE256         | 136  | 0x1F   | var    | FIPS 202       |
| SHAKE128         | 168  | 0x1F   | var    | FIPS 202       |
| LTHING "SHAKE512"| 72   | 0x1F   | 64 B   | **Non-standard** |

### §2.3 — LTHING "SHAKE512"

Anja's construction. SHA3-512's rate (72 B / capacity 1128 bits) with
SHAKE's domain separator (0x1F), producing 64 bytes. 256-bit collision
resistance with XOF flexibility.

Not a FIPS function. FIPS does not define "SHAKE512." The rate-72 sponge
path is anchored by the SHA3-512 KAT (same rate, different domain byte).
The construction is safe (Keccak's security bound depends on capacity, not
the domain byte), but has no off-the-shelf test vector.

Used for: envelope seal, chain hash. NOT used inside ML-DSA (which uses
standard SHAKE256 at rate 136).

### §2.4 — ML-DSA-65 (FIPS 204)

Parameters (FIPS 204 final, August 13 2024):

| Parameter | Value      |
|-----------|------------|
| n         | 256        |
| q         | 8,380,417  |
| (k, ℓ)   | (6, 5)     |
| η         | 4          |
| γ₁        | 2¹⁹       |
| γ₂        | 261,888    |
| τ         | 49         |
| β         | 196        |
| ω         | 55         |
| d         | 13         |
| pk        | 1,952 B    |
| sk        | 4,032 B    |
| sig       | 3,309 B (fixed) |
| c̃        | 48 B       |

#### §2.4.1 — Verify (Alg. 3 → Alg. 8) — COMPLETE

15/15 ACVP-derived sigVer KAT (3 accept, 12 reject).

```
Inputs: pk (1952 B), message, context (0..255 B), sig (3309 B)

 1. M' = 0x00 ‖ len(ctx) ‖ ctx ‖ msg
 2. pkDecode(pk) → (ρ, t₁)                   [SPARK proved]
 3. sigDecode(sig) → (c̃, z, h) or REJECT     [SPARK proved]
 4. Â ← ExpandA(ρ)                            [SHAKE128]
 5. tr ← SHAKE256(pk, 64)
 6. μ  ← SHAKE256(tr ‖ M', 64)
 7. c  ← SampleInBall(c̃)                     [SHAKE256, τ=49]
 8. ĉ  ← NTT(c)
 9. ∀r∈0..k-1:
      w_r = INTT( Σ_s Â[r,s]·ẑ_s − ĉ·NTT(t₁[r]·2^d) )
      w₁[r] = UseHint(h[r], w_r)
10. c̃₂ ← SHAKE256(μ ‖ W1Encode(w₁), 48)
11. ACCEPT iff: ‖z‖∞ < γ₁−β AND popcount(h) ≤ ω AND c̃₂ = c̃
```

Public inputs only — no timing oracle possible on verification.

#### §2.4.2 — KeyGen (Alg. 1 → Alg. 2) — TO BE IMPLEMENTED

```
Input: ξ (32 B random seed)

 1. (ρ, ρ', K) ← SHAKE256(ξ ‖ k ‖ ℓ, 128)   [32+64+32 bytes]
 2. Â ← ExpandA(ρ)                             [reuses existing]
 3. ∀i∈0..ℓ-1: s₁[i] ← RejBoundedPoly(ρ', i) [NEW, Alg. 7]
 4. ∀i∈0..k-1: s₂[i] ← RejBoundedPoly(ρ', ℓ+i)
 5. ŝ₁ ← NTT(s₁)                              [reuses existing]
 6. t ← INTT(Â · ŝ₁) + s₂
 7. (t₁, t₀) ← Power2Round(t)                  [reuses existing]
 8. pk ← pkEncode(ρ, t₁)                        [NEW, Alg. 22]
 9. tr ← SHAKE256(pk, 64)
10. sk ← skEncode(ρ, K, tr, s₁, s₂, t₀)        [NEW, Alg. 24]
11. Output: (pk, sk)
```

Secret-touching: steps 3–4 (RejBoundedPoly absorbs secret seed), steps
5–6 (NTT of secret s₁), step 10 (encoding secrets). All must be
constant-time.

#### §2.4.3 — Sign (Alg. 1 → Alg. 7) — TO BE IMPLEMENTED (PRIMARY OBJECTIVE)

```
Inputs: sk (4032 B), message, context (0..255 B), rnd (32 B from CSPRNG)

 1. M' = 0x00 ‖ len(ctx) ‖ ctx ‖ msg
 2. skDecode(sk) → (ρ, K, tr, s₁, s₂, t₀)      [NEW, inverse of skEncode]
 3. ŝ₁ ← NTT(s₁), ŝ₂ ← NTT(s₂), t̂₀ ← NTT(t₀)
 4. Â ← ExpandA(ρ)                               [reuses existing]
 5. μ  ← SHAKE256(tr ‖ M', 64)
 6. ρ' ← SHAKE256(K ‖ rnd ‖ μ, 64)              [hedged randomness]
 7. κ ← 0                                        [nonce counter]

 REJECTION LOOP:
 8.  ∀i∈0..ℓ-1: y[i] ← ExpandMask(ρ', κ+i)     [NEW, Alg. 6]
 9.  κ ← κ + ℓ
10.  ŷ ← NTT(y)
11.  w ← INTT(Â · ŷ)
12.  w₁ ← HighBits(w)                            [reuses existing]
13.  c̃ ← SHAKE256(μ ‖ W1Encode(w₁), 48)
14.  c  ← SampleInBall(c̃)                        [reuses existing]
15.  ĉ  ← NTT(c)
16.  z  ← y + INTT(ĉ · ŝ₁)
17.  IF ‖z‖∞ ≥ γ₁−β → GOTO 8                    [REJECT: norm too large]
18.  r₀ ← LowBits(w − INTT(ĉ · ŝ₂))            [reuses existing]
19.  IF ‖r₀‖∞ ≥ γ₂−β → GOTO 8                   [REJECT: residual too large]
20.  h ← MakeHint(−INTT(ĉ · t̂₀), w − INTT(ĉ · ŝ₂) + INTT(ĉ · t̂₀))
                                                   [NEW, Alg. 39]
21.  IF popcount(h) > ω → GOTO 8                  [REJECT: hint too heavy]
22.  σ ← sigEncode(c̃, z mod± q, h)               [NEW, Alg. 26]
23.  ZEROIZE: s₁, s₂, t₀, y, K                   [CT: §2.7]
24.  Output: σ (3309 B)

Average iterations: ~4.25 for ML-DSA-65.
```

**Constant-time requirements for signing:**

1. **Secret sampling** (steps 3–4): RejBoundedPoly must process full SHAKE
   output blocks with conditional assignment, no early exit on rejection.

2. **Masking vector y** (step 8): ExpandMask uses secret randomness. Same
   CT absorption pattern.

3. **z = y + cs₁** (step 16): touches secret s₁. The norm check (step 17)
   determines abort/retry. The check itself can be CT, but the iteration
   COUNT leaks timing. Mitigation: hedged randomness (FIPS 204 rnd from
   CSPRNG, step 6) makes iteration count non-reproducible from the same
   message+key.

4. **Hint computation** (step 20): MakeHint operates on secret-derived ct₀.
   Must use CT comparisons.

5. **Key zeroization** (step 23): see §2.7.

#### §2.4.4 — Primitives Inventory

**Existing (reusable for KeyGen + Sign):**

| Primitive | Unit | SPARK | Reuse |
|-----------|------|-------|-------|
| ExpandA | lthing_mldsa_sample | **Off** | KeyGen + Sign |
| SampleInBall | lthing_mldsa_sample | **Off** | Sign |
| NTT/INTT/Pointwise | lthing_mldsa_ntt | **Off** | KeyGen + Sign |
| Field Z_q | lthing_mldsa_field | On | KeyGen + Sign |
| Power2Round | lthing_mldsa_round | On | KeyGen |
| Decompose/High/Low | lthing_mldsa_round | On | Sign |
| UseHint | lthing_mldsa_round | On | Verify (done) |
| Inf_Norm_OK | lthing_mldsa_round | On | Sign |
| pkDecode/sigDecode | lthing_mldsa_codec | On | Verify (done) |
| SHAKE256/128 | lthing_keccak | On | All |

**New (must implement):**

| Primitive | FIPS 204 | CT required | Notes |
|-----------|----------|-------------|-------|
| RejBoundedPoly | Alg. 7 | Yes | Sample s₁, s₂ ∈ [-η, η] |
| ExpandMask | Alg. 6 | Yes | Sample y ∈ [-γ₁+1, γ₁] |
| MakeHint | Alg. 39 | Yes | Compute hint h |
| pkEncode | Alg. 22 | No | Inverse of pkDecode |
| skEncode | Alg. 24 | Yes | Encodes secrets |
| skDecode | — | Yes | Inverse of skEncode |
| sigEncode | Alg. 26 | No | Inverse of sigDecode |
| HintBitPack | Alg. 20 | No | Pack hint |
| BitPack | Alg. 17 | No | General packing |
| KeyGen | Alg. 1+2 | Yes | ξ → (pk, sk) |
| Sign | Alg. 1+7 | Yes | (sk, msg, ctx) → σ |

### §2.5 — NTT

256-point negacyclic NTT for Z_q[x]/(x²⁵⁶+1). ζ = 1753. Zeta table
computed at elaboration via bit-reversal, not transcribed.

**SPARK_Mode: Off (ILLEGAL).** Must be rewritten for SPARK_Mode On.
The in-place butterfly mutation pattern is the obstacle — needs
restructuring to use functional-style array returns or separate
input/output arrays. Convolution gate validates internal consistency;
FIPS 204 ordering validated downstream by sigVer KAT.

### §2.6 — Constant-Time Digest Comparison

**Current:** `Digest_Equal` in `lthing_judicial.adb` calls `Compare_CT`
from `LTHING_Crypto_FFI`, which links to x86-64 asm
`compare_constant_time`. This is the last live FFI call. No timing test
exists for it.

**Target replacement:** Pure Ada XOR accumulation, SPARK-provable:

```ada
function Digest_Equal (A, B : Digest) return Boolean
  with SPARK_Mode => On
is
   Diff : Byte := 0;
begin
   for I in Digest_Index loop
      Diff := Diff or (A (I) xor B (I));
   end loop;
   return Diff = 0;
end Digest_Equal;
```

64 iterations always. No branches on secret data. SPARK proves AoRTE.
Eliminates the last FFI dependency.

### §2.7 — Key Zeroization

Secret key material must be zeroed after use. GNAT at -O2 may elide
dead stores. Strategy: `pragma Volatile` on the zeroization target,
verify in disassembly that the store is not eliminated.

```ada
procedure Zeroize (SK : in out Secret_Key) is
   pragma Volatile (SK);
begin
   SK := (others => 0);
end Zeroize;
```

### §2.8 — CSPRNG

Signing requires 32 bytes of randomness for the `rnd` parameter (FIPS 204
hedged signing). Source: `/dev/urandom` via `Ada.Streams.Stream_IO`. No
FFI, no `Interfaces.C`, no syscall wrapper — pure Ada standard library.

```ada
procedure Read_Random (Output : out Byte_Array) is
   File : Ada.Streams.Stream_IO.File_Type;
begin
   Open (File, In_File, "/dev/urandom");
   Read (Stream (File), Output);
   Close (File);
end Read_Random;
```

---

## §3 — Envelope Integration

### §3.1 — Current State

The existing `lthing_judicial.adb` hardcodes the §2 prefix correctly.
This matches the header spec. The §2 prefix is implemented and tested.

### §3.2 — Envelope Structure (redesigned)

Five sections, all lengths in the 40-byte header:

```
Header (40 B)  →  Body  →  Provenance Seal  →  Signature  →  AEAD Tag
```

Key changes from previous iteration:
- Header shrinks from variable to **40 bytes fixed**
- Provenance seal is a section carrying signer identity, chain
  position, document relationship, artifact hash, chain hash, seal ID
- Signer identity in the seal (answers critique #5)
- AEAD tag is a section (0 if unused, structurally present)
- Signature covers header + body + seal (three sections)

### §3.3 — Chain Hash: Design Change

**Current:** `Chain_Hash(Previous_Seal, Artifact, Output)` =
`SHAKE512(Previous_Seal ‖ Artifact)` where Artifact = full document.

**New:** `chain = SHAKE512(prev_chain ‖ artifact_hash)` where
artifact_hash = SHAKE512(body) and prev_chain = previous ChainHash.

Migration: change concatenation inputs. Mechanism unchanged.

### §3.4 — Verify Wiring Plan

```
Phase V1: Header parsing (SPARK_Mode On)
  V1.1  §3 field types (Suite_Id, Timestamp, section lengths)
  V1.2  New package: LTHING_Envelope (parse 40-byte header)
  V1.3  Validate suite, version, lengths
  V1.4  Compute section offsets from lengths
  V1.5  Tests: malformed suite, bad lengths, overflow, version 0x00

Phase V2: Provenance seal parsing (SPARK_Mode On)
  V2.1  Parse seal: AncestorCount, ArtifactHash, ChainHash,
        Relation, SignerIdLen, SignerId, SealId
  V2.2  Verify ArtifactHash: recompute SHAKE512(body), compare
  V2.3  Verify ChainHash if prev_chain available
  V2.4  Verify SealId: recompute from seal fields, compare
  V2.5  Verify Relation/AncestorCount consistency
  V2.6  Tests: tampered body, tampered seal, wrong prev_chain

Phase V3: Signature wiring
  V3.1  Replace stub → LTHING_MLDSA65.Verify
  V3.2  Signed message = bytes[0..40+BL+SL-1]
  V3.3  Tests: golden .jd.lthing, tampered header → invalid

Phase V4: Status code completion
  V4.1  Fix tautological chain gate
  V4.2  Wire all status codes including new: Bad_SealId,
        Bad_Relation, Bad_AncestorCount
  V4.3  Tests: every Verify_Status code reachable
```

### §3.5 — Sign + Write Plan (PRIMARY DELIVERABLE)

```
Phase C0: Cleanup (unblocks pure Ada/SPARK)
  C0.1  Replace Compare_CT with Ada Digest_Equal (§2.6)
  C0.2  Delete lthing_crypto_ffi.ads
  C0.3  Delete lib/liblthing_crypto_asm.so and .a
  C0.4  Delete tools/gen_kat_vectors.py
  C0.5  Fix stale comment in lthing_mldsa_sample.ads
  C0.6  Remove lib/ from Makefile link flags
  C0.7  Tests: Digest_Equal + test_judicial passes

Phase S0: SPARK conformance (ILLEGAL — BLOCKS EVERYTHING)
  S0.1  lthing_mldsa_ntt → On (rewrite butterfly)
  S0.2  lthing_mldsa_sample → On (fix grow-on-exhaust)
  S0.3  lthing_mldsa65 → On (follows S0.1 + S0.2)

Phase S1: New primitives (SPARK_Mode On)
  S1.1  RejBoundedPoly (Alg. 7) — CT, proved
  S1.2  ExpandMask (Alg. 6) — CT, proved
  S1.3  MakeHint (Alg. 39) — CT, proved
  S1.4  pkEncode (Alg. 22) — roundtrip vs pkDecode
  S1.5  skEncode/skDecode (Alg. 24) — CT, proved
  S1.6  sigEncode (Alg. 26) — roundtrip vs sigDecode
  S1.7  HintBitPack/BitPack (Alg. 20/17) — proved
  S1.8  Tests: ACVP keyGen KAT

Phase S2: KeyGen (SPARK_Mode On)
  S2.1  Implement Alg. 1 + 2
  S2.2  CSPRNG: /dev/urandom via Ada.Streams.Stream_IO
  S2.3  Key zeroization: pragma Volatile
  S2.4  Tests: ACVP keyGen vectors

Phase S3: Sign (SPARK_Mode On)
  S3.1  Implement Alg. 1 + 7 with rejection loop
  S3.2  CT validation: no secret-dependent branches
  S3.3  Tests: ACVP sigGen + roundtrip Sign→Verify

Phase S4: Envelope writer
  S4.1  New package: LTHING_Envelope_Writer
  S4.2  Build_Provenance_Seal: all 7 fields
  S4.3  Serialize_Header: 40 bytes with computed lengths
  S4.4  Sign_Envelope: ML-DSA-65 over header ‖ body ‖ seal
  S4.5  Write: header ‖ body ‖ seal ‖ sig → .xx.lthing
  S4.6  Tests: write then verify = Verified

Phase S5: End-to-end
  S5.1  .jd.lthing from PDF, verify
  S5.2  Chain 3 documents, verify chain
  S5.3  Amendment (Relation=0x02), revocation (0x03)
  S5.4  Tamper at every section boundary → reject
  S5.5  Multiple doctypes: .gv, .fe, .fn
```

### §3.6 — Key Management

```
{name}.mldsa65.pub   — 1952 bytes, raw public key
{name}.mldsa65.key   — 4032 bytes, raw secret key
```

`.key` MUST be 0600. Writer refuses if group/world-readable.
Atomic writes (tmp + fsync + rename).

### §3.7 — Unverified → Verified Type Barrier

Implemented via `Verified_Record` + SPARK dynamic predicate.
New status codes needed: `Bad_SealId`, `Bad_Relation`,
`Bad_AncestorCount`.

## §4 — Test Strategy

### §4.1 — Existing Test Suites (9/9 green)

| Suite          | Count | What it covers                       |
|----------------|-------|--------------------------------------|
| test_keccak    | 8     | keccak_f1600, SHA3-512/256, SHAKE*   |
| test_hash      | 3     | SHAKE512 determinism, sensitivity    |
| test_field     | 11    | Z_q arithmetic                       |
| test_ntt       | 3     | NTT/INTT roundtrip, convolution     |
| test_codec     | (incl)| Bundled with KAT suite               |
| test_round     | (incl)| Decompose/UseHint/W1Encode           |
| test_sample    | (incl)| ExpandA/SampleInBall                 |
| test_kat       | 15    | ML-DSA-65 sigVer KAT                 |
| test_judicial  | 4     | Fail-closed verification             |

### §4.2 — Test Vector Sources

**sigVer (have):** 15 vectors in `kat/mldsa65_sigver.json`, ACVP-derived.
**keyGen (need):** NIST provides these at
`github.com/usnistgov/ACVP-Server/gen-val/json-files/ML-DSA-keyGen-FIPS204/`
**sigGen (need):** NIST provides these at
`github.com/usnistgov/ACVP-Server/gen-val/json-files/ML-DSA-sigGen-FIPS204/`

All three sets are pre-generated JSON (prompt.json + expectedResults.json
per test group). NIST's ACVP-Server is the golden reference — their C#
implementations generate the vectors used for FIPS 140-3 validation.

KAT vector ingestion: download JSON, convert to Ada specs as needed.

**Convention:** No self-derived frozen vectors. Every test asserts either
an authoritative KAT or a relational/property fact.

### §4.3 — Known Gaps

| Gap | Priority | Status |
|-----|----------|--------|
| No golden .jd.lthing envelope | P0 | Blocked on envelope writer |
| Chain_Broken unreachable | P0 | §3.3 Phase V4 fixes |
| Seal_Mismatch/Bad_Length unwired | P0 | §3.3 Phase V4 fixes |
| compare_constant_time via FFI | P0 | Replace with Ada XOR (§2.6), delete FFI |
| Stale lthing_crypto_ffi.ads | P0 | Delete after CT replacement |
| Stale lib/liblthing_crypto_asm | P0 | Delete after CT replacement |
| Stale tools/gen_kat_vectors.py | P1 | Delete (Python) |
| Stale comment in sample.ads | P1 | Says "C-FFI Keccak", uses SPARK Keccak |
| NTT SPARK_Mode Off | P0 | **ILLEGAL** — §3.4 Phase S0 |
| Sample SPARK_Mode Off | P0 | **ILLEGAL** — §3.4 Phase S0 |
| MLDSA65 body SPARK_Mode Off | P0 | **ILLEGAL** — §3.4 Phase S0 |
| No keyGen KAT vectors | P1 | Download from NIST ACVP-Server |
| No sigGen KAT vectors | P1 | Download from NIST ACVP-Server |
| NTT reference ordering KAT | P2 | Convolution gate ≠ FIPS order |
| Schoolbook_Mul unvalidated | P2 | Oracle itself unchecked |
| Field boundary cases | P2 | To_Centered at Q/2 pivot |
| No gnatcov coverage | P3 | Hand-estimated only |
| No fuzz harness | P3 | Random/malformed → rejected |

### §4.4 — New Tests (signing + writing)

```
Phase S1 tests:
  - RejBoundedPoly: coefficients ∈ [-η, η] for 1000 random seeds
  - ExpandMask: coefficients ∈ [-γ₁+1, γ₁]
  - MakeHint: roundtrip with UseHint
  - pkEncode(pkDecode(pk)) == pk for all KAT public keys
  - sigEncode(sigDecode(sig)) == sig for all KAT signatures

Phase S2 tests:
  - ACVP keyGen vectors: seed → (pk, sk) match
  - Generated pk verifies known signatures (cross-check)

Phase S3 tests:
  - ACVP sigGen vectors: (sk, msg) → sig match
  - Sign(sk, msg) then Verify(pk, msg, sig) = accept
  - Sign different messages with same key → different signatures

Phase S4 tests:
  - Write .jd.lthing, read back, verify = Verified
  - Header field values match on roundtrip
  - Timestamp is within 1 second of signing time

Phase S5 tests:
  - Chain of 3: verify all three, break link 2 → link 3 fails
  - Flip bit at every field boundary → specific rejection code
  - All 20 doctypes: write and verify one each
```

---

## §5 — Suite Registry

### §5.1 — Baseline 0x0001 (all doctypes)

| Field      | Value                           |
|------------|---------------------------------|
| Hash       | LTHING SHAKE512 (rate 72, 0x1F) |
| Signature  | ML-DSA-65 (FIPS 204)            |
| Seal width | 64 bytes                        |
| Sig size   | 3,309 bytes (fixed)             |
| AEAD       | None (plaintext body)           |

### §5.2 — Future (per-doctype, not yet specified)

| DocType | Suite   | Crypto | Regulatory driver |
|---------|---------|--------|-------------------|
| MI      | 0x0002+ | ML-DSA-87 (Level 5) | CNSA 2.0 (by 2030) |
| MD      | 0x0002+ | FIPS 140-3 validated | HIPAA §164.312 |
| GV      | 0x0002+ | FIPS 140-3 Level 1+ | FedRAMP |
| JD      | 0x0002+ | Full PQC combiner (76KB) | Evidentiary |
| All     | 0x00xx  | SHAKE512 ‖ BLAKE3 (128B seal) | Diversity |

Suite 0x0000: reserved, fail-closed, MUST reject.

---

## §6 — Compliance

### §6.1 — Conformant

| Standard | Claim | Evidence |
|----------|-------|---------|
| FIPS 204 | ML-DSA-65 Verify correct | 15/15 ACVP-derived KAT |
| FIPS 202 | Keccak-f[1600] correct | Authoritative KAT |
| FIPS 202 | SHAKE256/128 correct | FIPS 202 vectors |
| — | AoRTE (no runtime errors) | gnatprove 306/306 |
| — | Fail-closed verification | SPARK postcondition proof |

### §6.2 — Non-Conformant

| Standard | Gap | Path |
|----------|-----|------|
| FIPS 140-3 | No validated module | CMVP submission (long) |
| FIPS 204 | No KeyGen/Sign yet | Primary target (§3.4) |
| FIPS 204 | sigGen KAT pending | Requires Sign impl |
| CNSA 2.0 | ML-DSA-65 ≠ ML-DSA-87 | MI suite 0x0002+ |
| — | LTHING SHAKE512 non-standard | Documented, KAT-anchored |
| — | No signing timing validation | dudect after Sign impl |
| — | 3 units SPARK_Mode Off (ILLEGAL) | P0, §3.4 Phase S0 |
| — | FFI still live (Compare_CT) | P0, §3.4 Phase C0 |
| — | Stale files in repo | P0/P1, §3.4 Phase C0 |

### §6.3 — LTHING SHAKE512 Non-Standard Construction

Rate 72 (SHA3-512's rate), domain 0x1F (SHAKE's suffix), 64 bytes output.
Safe by Keccak's capacity-based security bound. Not a named FIPS function.
No off-the-shelf test vector. Anchored by SHA3-512 KAT at same rate.

---

## §7 — Open Design Decisions

| Decision | Options | Recommendation |
|----------|---------|----------------|
| FIPS 204 context string | Empty / doctype / preamble | Empty |
| Signing CT: loop timing | Pad / accept / hedge | Hedge + accept |
| Key zeroization | pragma Volatile / disasm | pragma Volatile + verify |
| FIPS 140-3 validation | Self / lab | Defer (MD/GV only) |
| Performance target | ops/sec | TBD after Sign works |

---

## §8 — File Manifest

```
lthing-spark/
├── src/
│   ├── lthing_types.ads              (58 LOC)
│   ├── lthing_keccak.ads/.adb        (232 LOC)
│   ├── lthing_hash.ads/.adb          (85 LOC)
│   ├── lthing_judicial.ads/.adb      (261 LOC)
│   ├── lthing_crypto_ffi.ads         (70 LOC, STALE — last live call: Compare_CT)
│   ├── lthing_mldsa_field.ads/.adb   (105 LOC)
│   ├── lthing_mldsa_ntt.ads/.adb     (195 LOC)
│   ├── lthing_mldsa_codec.ads/.adb   (334 LOC)
│   ├── lthing_mldsa_round.ads/.adb   (272 LOC)
│   ├── lthing_mldsa_sample.ads/.adb  (218 LOC)
│   ├── lthing_mldsa65.ads/.adb       (357 LOC)
│   ├── mldsa_kat_vectors.ads         (13,277 LOC, generated)
│   ├── test_*.adb                    9 test suites
├── kat/
│   └── mldsa65_sigver.json           15 vectors
├── lib/
│   ├── liblthing_crypto_asm.so       STALE — only Compare_CT used
│   └── liblthing_crypto_asm.a        STALE — only Compare_CT used
├── tools/
│   └── gen_kat_vectors.py            STALE — Python, to be deleted
├── tasks/                            Agent task guides
├── Makefile
├── run_tests.sh
├── CLAUDE.md
└── .gitignore
```

~3,600 LOC implementation + 13,300 LOC generated KAT.
306 SPARK checks, 0 unproved. 9/9 suites green.

---

*Working draft. Reflects codebase at commit `bb1d13c` (main).
Header spec designed but not yet in code. Phases V1–V4 (verify wiring)
and S0–S5 (signing + writing) connect the two.*
