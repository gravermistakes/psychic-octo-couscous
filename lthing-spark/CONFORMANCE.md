# FIPS 204 (ML-DSA-65 and ML-DSA-87) — Conformance & KAT Provenance

This note records, with a reproducible command behind every claim, (1) where the
ML-DSA-65 and ML-DSA-87 sigVer test vectors come from, (2) how each verifier
maps to FIPS 204 final, and (3) the impact of the NIST FIPS 204 errata on the
**verification path**. It complements `FIPS204_PROTOCOLS.md` (the
algorithm-by-algorithm map); this file adds the *recent-developments* layer
(errata + authoritative vector re-sourcing) requested in the test-coverage
hardening.

Companion files: `FIPS204_PROTOCOLS.md` (Alg 3/8/21/29/30/35–43 line-by-line),
`src/lthing_mldsa65.adb`, `src/lthing_mldsa87.adb` (Verify),
`src/mldsa_kat_vectors.ads` (generated), `src/mldsa87_kat_vectors.ads`
(generated), `kat/mldsa65_sigver.json`, `kat/mldsa87_sigver.json` (fixtures),
`src/test_kat.adb`, `src/test_kat87.adb` (gates).

---

## 1. Normative sources

| Artifact | Reference |
|----------|-----------|
| Standard | **FIPS 204** (Module-Lattice-Based Digital Signature Standard), final, **Aug 2024**. DOI `10.6028/NIST.FIPS.204`; PDF `nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf`; landing `csrc.nist.gov/pubs/fips/204/final`. |
| Errata | **"Potential Updates (Errata)"** spreadsheet, `csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx` — cell-stated **"Last updated 2/27/2026"** (planning note dated 2/23/2026). NIST: "minor issues … corrected in a future update/revision … DO NOT introduce new technical requirements." |
| µ FAQ | "FIPS 204 — Computing mu", `csrc.nist.gov/.../faq/fips204-sec6-03192025.pdf`. Confirms µ = H(BytesToBits(tr) ∥ M′, 64). |
| Vectors | **NIST ACVP-Server** reference vectors, `usnistgov/ACVP-Server`, path `gen-val/json-files/ML-DSA-sigVer-FIPS204/{prompt,expectedResults}.json`. `algorithm=ML-DSA mode=sigVer revision=FIPS204 vsId=42 isSample=false`. |

---

## 2. KAT vector provenance — verified byte-identical to NIST ACVP

The fixture `kat/mldsa65_sigver.json` (15 vectors, tcId 31..45) is the NIST ACVP
**ML-DSA-65 / external / pure** group. In the upstream `prompt.json` this is
**`tgId = 3`** (`parameterSet=ML-DSA-65, signatureInterface=external,
preHash=pure`). Every `pk` / `message` / `context` / `signature` byte and every
`expected` outcome is identical to the authoritative source — no value is
hand-invented or self-derived (per the repo's "no frozen / self-derived vectors"
rule).

Reproduce (no Python; `jq` + `diff` only):

```sh
cd /tmp
curl -sL -o prompt.json   https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json
curl -sL -o expected.json https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json

# fields: byte-for-byte identical (empty diff)
diff <(jq -S '.testGroups[]|select(.tgId==3)|.tests[]|{tcId,pk,message,context,signature}' prompt.json) \
     <(jq -S '.tests[]|{tcId,pk,message,context,signature}' <repo>/lthing-spark/kat/mldsa65_sigver.json)

# expected outcomes: identical (3 accept / 12 reject)
join -t$'\t' \
  <(jq -r '.testGroups[]|select(.tgId==3)|.tests[]|"\(.tcId)\t\(.testPassed)"' expected.json | sort) \
  <(jq -r '.tests[]|"\(.tcId)\t\(.expected)"' <repo>/lthing-spark/kat/mldsa65_sigver.json | sort)
```

Content-addressed anchors (so re-sourcing is checkable even if upstream moves):

| File | SHA-256 / etag |
|------|----------------|
| `kat/mldsa65_sigver.json` (local fixture) | `113ab3c3db604defc459d97b9f0249542df68bdd2e3330aa4c78410e8b8080e6` |
| ACVP `prompt.json` (raw.githubusercontent etag) | `e8ce4cf778849ea9f10557f808ecc02788593e8a09ea5f7bd286ef2c1861ff4b` |
| ACVP `expectedResults.json` (raw.githubusercontent etag) | `793aac857c2c8e30408401bd658f56775ce87e58fe20d4a5db2e2042458fdcaa` |

Vector shape: `pk = 1952 B`, `sig = 3309 B`, variable `message`/`context`
(`|ctx| ≤ 255`); outcomes **3 accept (tcId 31, 35, 37) / 12 reject**.

KAT gate is a **FULL** gate (`Result` must equal `Expected`, accepts *and*
rejects), so it proves discrimination, not replay:

```sh
gnatmake -q -D /tmp/b -aIsrc -o /tmp/b/test_kat src/test_kat.adb && /tmp/b/test_kat
# → 15× [PASS], "ALL PASS ( 15 vectors)", exit 0
```

---

## 3. Errata impact on the verification path (FIPS 204, 2/27/2026)

Each errata row was read and mapped to our verifier. **No row requires a code
change**; two touch the verification path semantically and we are already aligned
with the *corrected* text, and one historical prose error (c̃ ordering) is one our
code never reproduced.

| Errata item (location) | Nature | Verification-path impact | Status in this repo |
|---|---|---|---|
| **Sec 7.4 — Alg 40 `UseHint` upper bound** | Tightens `0 ≤ r1 ≤ (q-1)/2γ2` to `… − 1`; notes w1Encode relies on the *real* (tighter) bound | **Yes — UseHint output range** | **Already corrected.** `Use_Hint` returns `Bins = 0 .. M_Bins-1 = 0..15` (`lthing_mldsa_round.ads:51,108`); `W1_Encode` Pre requires `≤ M_Bins-1` (`:116`); verifier `Loop_Invariant`s carry `≤ M_Bins-1` (`lthing_mldsa65.adb:185,217`). We use the errata bound `0..15`, not the published `0..16`. ✓ |
| **Sec 5.3 — Alg 3 step 2** | `return ⊥` → `return "false"` for `|ctx| > 255` | **Yes — Alg 3 external** | **Semantically aligned.** Over-long context never reaches accept: enforced by `Pre => Context'Length <= 255` (`lthing_mldsa65.ads:95`); the judicial layer maps a non-accept to `Signature_Invalid` (fail-closed). ⊥ and "false" are the same outcome here. ✓ |
| **Sec 3.3 — c̃ definition** | Prose mis-states c̃ = `w1 ∥ µ`; should be `µ ∥ w1` (as Alg 7/8) | Would corrupt c̃′ if followed | **Never reproduced.** `Verify` computes `c̃′ = H(µ ∥ w1bytes, 48)` — `Mu_W1(0..63)=µ`, then `w1bytes` (`lthing_mldsa65.adb:236-248`). Correct `µ ∥ w1` order. ✓ |
| **Sec 6.2/6.3 — "M" → "M′"** | Prose: µ is over **M′** (= 0x00∥len(ctx)∥ctx∥M), not M | Clarifies µ input | **Already correct.** `M_Prime = 0x00 ∥ byte(\|ctx\|) ∥ ctx ∥ msg` then `µ = H(tr ∥ M′)` (`lthing_mldsa65.adb:99-107,128-147`). ✓ |
| **Sec 6 — Alg 8 line 7** | Outer parens on `H(...)` are unnecessary | Cosmetic | No effect; µ computed correctly. ✓ |
| **Sec 2.5/7.5 — NTT explanatory text** | Typo in the `ζ_j` definition (w evaluated twice); algorithm itself unchanged | None (prose around Alg 41/42) | Our NTT/NTT⁻¹ is validated by the negacyclic-convolution ground-truth gate (`test_ntt.adb`), independent of the prose. ✓ |
| **App. A — Montgomery reduction prose** | Range/representative wording errors in the *reference* note | None | We do not transcribe App. A; `lthing_mldsa_field` reduction is proved in SPARK (postconditions on Add/Sub/Mul/Reduce). ✓ |
| Sec 2/3/5/7 — NULL→⊥, bolding, broken links, "PowerTwoRound", "Sign"→"Sign_internal" | Editorial / typographical | None | n/a ✓ |

µ-FAQ cross-check: the FAQ's `µ = H(BytesToBits(tr) ∥ M′, 64)` is exactly our
`Sponge(tr ∥ M′, Rate_SHAKE256, Domain_SHAKE, 64)`. The FAQ concerns an optional
*external-µ* interface (computing µ in a separate module); our verifier computes µ
internally, which remains fully conformant. No change.

**Conclusion:** the 2/27/2026 errata is editorial plus two substantive
clarifications (UseHint bound; Alg 3 ⊥→false). The LTHING verifier already matches
the corrected text on both, and never reproduced the c̃-ordering prose error.
**No code correction required.**

---

## 4. Verification of this note

```sh
export PATH=/root/.alire/bin:$PATH
cd lthing-spark
# (1) vectors are authoritative — re-run the diff/join in §2 (empty diff, all OK)
# (2) FULL KAT gate green
gnatmake -q -D /tmp/b -aIsrc -o /tmp/b/test_kat src/test_kat.adb && /tmp/b/test_kat
# (3) errata UseHint bound is enforced, not assumed
gnatprove -P lthing.gpr -u lthing_mldsa_round.adb --level=2 --report=all   # Use_Hint Post 0..15 proved
```

---

## 5. ML-DSA-87 (FIPS 204 Level 5 / CNSA 2.0) — KAT Provenance & Parameter Map

### 5.1 Normative source

ML-DSA-87 is defined in the same **FIPS 204** standard (§ 1 above) under
**Table 1, row ML-DSA-87**. Key parameters:

| Parameter | Value |
|-----------|-------|
| k (rows of A) | 8 |
| l (columns of A) | 7 |
| η (private-key bound) | 2 |
| τ (commitment weight) | 60 |
| β = τ·η | 120 |
| γ₁ | 2¹⁹ |
| γ₂ = (q−1)/32 | 261888 |
| ω (max hint weight) | 75 |
| λ (security bits) | 256 |
| c̃ size | 64 B |
| Public key | 2592 B |
| Signature | 4627 B |

ML-DSA-87 targets NIST security Level 5 and satisfies the
**CNSA 2.0 / NSS** mandate. The judicial layer exposes it as suite `0x0002`.

### 5.2 KAT vector provenance — NIST ACVP

The fixture `kat/mldsa87_sigver.json` (15 vectors, tcId 61..75) is the NIST ACVP
**ML-DSA-87 / external / pure** group. In the upstream `prompt.json` this is
**`tgId = 5`** (`parameterSet=ML-DSA-87, signatureInterface=external,
preHash=pure`). Every `pk` / `message` / `context` / `signature` byte and every
`expected` outcome is identical to the authoritative ACVP source — no value is
hand-invented or self-derived (per the repo's "no frozen / self-derived vectors"
rule).

Same ACVP files as §2 (ML-DSA-65); only the tgId changes:

```sh
# fields: byte-for-byte identical (empty diff)
diff <(jq -S '.testGroups[]|select(.tgId==5)|.tests[]|{tcId,pk,message,context,signature}' prompt.json) \
     <(jq -S '.tests[]|{tcId,pk,message,context,signature}' <repo>/lthing-spark/kat/mldsa87_sigver.json)

# expected outcomes: identical (3 accept / 12 reject)
join -t$'\t' \
  <(jq -r '.testGroups[]|select(.tgId==5)|.tests[]|"\(.tcId)\t\(.testPassed)"' expected.json | sort) \
  <(jq -r '.tests[]|"\(.tcId)\t\(.expected)"' <repo>/lthing-spark/kat/mldsa87_sigver.json | sort)
```

Vector shape: `pk = 2592 B`, `sig = 4627 B`, outcomes **3 accept / 12 reject**.

KAT gate:

```sh
gnatmake -q -D /tmp/b -aIsrc -o /tmp/b/test_kat87 src/test_kat87.adb && /tmp/b/test_kat87
# → 15× [PASS], "ALL PASS ( 15 vectors)", exit 0
```

### 5.3 Algorithm mapping to FIPS 204

The ML-DSA-87 verifier (`lthing_mldsa87.adb`) follows the identical Alg. 3
(external Verify) and Alg. 8 (VerifyInternal) structure as the ML-DSA-65
verifier, with all parameters substituted per Table 1. Specific differences
from ML-DSA-65:

| Step | ML-DSA-65 | ML-DSA-87 |
|------|-----------|-----------|
| c̃ hash output | 48 B | 64 B |
| SampleInBall loop | i ∈ 207..255 (τ=49) | i ∈ 196..255 (τ=60) |
| ExpandA matrix | 6×5 (k×l) | 8×7 |
| z norm bound | γ₁−β = 2¹⁹−196 | γ₁−β = 2¹⁹−120 |
| Hint weight check | ≤ 55 (ω) | ≤ 75 (ω) |
| r0 norm bound | γ₂−β | γ₂−β (same formula) |

Errata analysis from §3 applies identically — all errata items concern
algorithm-level logic, not parameter-set-specific values.

### 5.4 Judicial CNSA 2.0 dispatch

Suite `0x0002` in the LTHING envelope header (§3.1) selects ML-DSA-87. The
judicial layer (`lthing_judicial.adb`) dispatches before any crypto runs:

- PK length must be exactly 2592 B; any other size → `Bad_Length`.
- Signature length field must encode 4627; mismatch → `Bad_Length`.
- Seal and chain hashes are verified identically to suite 0x0001.
- `LTHING_MLDSA87.Verify` is called; failure → `Signature_Invalid`.

Gate: `test_judicial87.adb` (6 relational checks, all `[PASS]`).
