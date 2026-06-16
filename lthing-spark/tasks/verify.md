# Agent task T10 — ML-DSA.Verify assembly (WAVE 2; needs T1+T2+T3 merged)

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md`. Implement strictly per
**FIPS 204 Alg. 3 (external) + Alg. 8 (internal)**; cite algorithm numbers.
`export PATH=/root/.alire/bin:$PATH`.

Depends on (must be merged into your base first): `LTHING_MLDSA_Sample`
(Expand_A, Sample_In_Ball), `LTHING_MLDSA_Round` (Use_Hint, W1_Encode,
Inf_Norm_OK), `LTHING_MLDSA_Codec` (Pk_Decode, Sig_Decode), plus
`LTHING_MLDSA_NTT`, `LTHING_Keccak`.

Files: `src/lthing_mldsa65.adb` (new body); coordinated tweaks to `src/test_kat.adb`
and `src/test_mldsa65.adb`. You MAY add a `Context` parameter to `Verify` in
`lthing_mldsa65.ads`.

Params: q=8380417, n=256, d=13, 2^d=8192, k=6, l=5, γ1=2^19, β=196, ω=55, c̃=48 B.

## Exact math

**External wrapper (Alg. 3), pure/no-prehash:**
`M' := Byte(0) & Byte(Context'Length) & Context & Message`   (Context'Length ≤ 255).

**Signed→canonical Fq:** any −1/centered coeff `c` becomes `(if c < 0 then c + Q else c)`
before calling `NTT`/`Pointwise` (which operate on `Fq`).

**Verify_internal (Alg. 8):**
1. `(Rho, T1) := Pk_Decode(PK)`.
2. `(C_Tilde, Z, H, Ok) := Sig_Decode(Sig)`;  if not `Ok` → return False.
3. `A_hat := Expand_A(Rho)`  (already NTT-domain).
4. `tr := Sponge(PK, 136, Domain_SHAKE, <64 B>)`  (SHAKE256).
   `mu := Sponge(tr & M', 136, Domain_SHAKE, <64 B>)`.
5. `c := Sample_In_Ball(C_Tilde)`; map to Fq; `c_hat := NTT(c)`.
6. For each `r in 0..5`:
   `acc := 0_poly`;
   for `s in 0..4`: `acc := acc + Pointwise(A_hat(r,s), NTT(Z(s)))`  (coeff-wise add mod q);
   `t1d := T1(r)` scaled: each coeff `* 8192 mod Q`;  `t1d_hat := NTT(t1d)`;
   `w_hat(r) := acc - Pointwise(c_hat, t1d_hat)`  (coeff-wise sub mod q);
   `w(r) := Inv_NTT(w_hat(r))`.
7. `w1(r) := ` coeff-wise `Use_Hint(H(r)(i), w(r)(i))`.
8. `w1bytes := W1_Encode(w1(0)) & … & W1_Encode(w1(5))`  (6 * 128 = 768 B).
   `c_tilde2 := Sponge(mu & w1bytes, 136, Domain_SHAKE, <48 B>)`.
9. Return  `Inf_Norm_OK(Z, γ1 - β)`  AND  `c_tilde2 = C_Tilde`  AND
   `(Σ over r,i of H(r)(i)) ≤ ω`.

(Use `LTHING_MLDSA_NTT.Poly`; build small add/sub over `Fq` via
`LTHING_MLDSA_Field.Add`/`Sub`. `NTT`/`Inv_NTT` are in place — copy first.)

## Steps
1. Implement `Verify` (with `Context` param) per the math. `SPARK_Mode` may be
   Off (it composes the Off NTT/sample layers); if On, target AoRTE only.
2. Set `Arithmetic_Core_Complete := True` in `lthing_mldsa65.ads` ONLY after the
   KAT passes (next step).
3. Update `test_kat.adb` to pass `Context` and assert against `Expected`.
   Update `test_mldsa65.adb` guard to the new reality.
4. Build+run the KAT — the bar:
   `gnatmake -q -D /tmp/k -aIsrc -o /tmp/k/test_kat src/test_kat.adb && /tmp/k/test_kat`
   MUST show **15/15** against `expected` (accepts tcId 31/32/33, rejects 34..45).
5. Whole-project proof: `gnatprove -P lthing.gpr --level=2 --report=all -j0` → 0 unproved.

## Honesty
If a KAT vector won't pass, that's a real bug to find (mirrors how the Keccak
KAT caught the asm). Do NOT flip `Arithmetic_Core_Complete` or fudge the test to
go green. If stuck, push your branch and report exactly which vector fails and
your diagnosis.

## Done
`git checkout -b claude/ralph-verify`, commit, `git push -u origin claude/ralph-verify`.
Report branch + the 15-vector KAT result + gnatprove Total line.
