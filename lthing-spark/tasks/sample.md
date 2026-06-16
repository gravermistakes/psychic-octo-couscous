# Agent task T1 — ML-DSA sampling: ExpandA + SampleInBall

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md`. Implement strictly per
**FIPS 204**; cite algorithm numbers in comments. Edit ONLY your two files.
`export PATH=/root/.alire/bin:$PATH`.

Params: q=8380417, n=256, τ=49, k=6, l=5. Reuse `LTHING_Keccak.Sponge`,
`LTHING_MLDSA_NTT` (`Poly` = array(0..255) of `Fq`), `LTHING_MLDSA_Field`.

Files: `src/lthing_mldsa_sample.adb` (new body — spec already exists), `src/test_sample.adb` (new).
SPARK_Mode (Off) (calls the NTT layer). No gnatprove for this unit.

## XOF helper (one-shot Sponge, grow on exhaustion)
`Sponge` re-derives a consistent prefix, so squeezing N then 2N agrees on the
first N bytes. Write:
```
function XOF (Seed : Byte_Array; Rate : Positive; Need : Positive) return Byte_Array
--  Output (0 .. Need-1) := Sponge(Seed, Rate, Domain_SHAKE, <Need bytes>)
```
For rejection loops, request a generous `Need` (e.g. 1088) and, if you run out
before filling the poly, recompute `XOF` with `Need*2`.

## Exact math

**Sign bits.** From the first 8 squeezed bytes `s(0..7)`:
`h(b) = (Integer(s(b/8)) / 2**(b mod 8)) mod 2`, for `b in 0..63`.

**Sample_In_Ball (Alg. 29).** Stream `= XOF(C_Tilde, 136, …)` (SHAKE256).
```
C := (others => 0);
pos := 8;                       -- bytes 0..7 already consumed as sign bits
for i in 207 .. 255 loop        -- 256-τ .. 255
   loop  j := stream(pos); pos := pos+1;  exit when j <= i;  end loop;
   C(i) := C(Integer(j));
   C(Integer(j)) := (if h(i - 207) = 0 then 1 else -1);   -- (-1)^h ; i+τ-256 = i-207 ∈ 0..48
end loop;
```
Result: exactly τ=49 nonzero coeffs, each ±1.

**RejNTTPoly (Alg. 30).** From 3 stream bytes `b0,b1,b2`:
`d := Integer(b0) + 256*Integer(b1) + 65536*(Integer(b2) mod 128)`  (23 bits, 0..2^23-1).
Accept `d` as the next coeff iff `d < Q`; else skip. Fill all 256 coeffs.
Output is ALREADY NTT-domain — do not call `NTT` on it.

**Expand_A (Alg. 32).** For `r in 0..5`, `s in 0..4`:
seed `:= Rho(Rho'First .. Rho'First+31) & Byte(s) & Byte(r)`;
`A(r,s) := RejNTTPoly(XOF(seed, 168, …))`   (SHAKE128, rate 168).

## Steps
1. Write `XOF` helper.
2. `Sample_In_Ball` per the math.
3. `Count_Nonzero` = count of coeffs ≠ 0.
4. `Expand_A` per the math.
5. `test_sample.adb` (relational self-gates, NO frozen digests):
   - pick 2 fixed `C_Tilde` (e.g. all-0x01, all-0xAB): assert `Count_Nonzero = 49`
     and every nonzero coeff’s `To_Centered` is `+1` or `-1`;
   - pick a fixed `Rho`: assert `Expand_A` is deterministic (run twice, equal) and
     every coeff of every `A(r,s)` is `in 0 .. Q-1`.
   - `[PASS]/[FAIL]`; `Ada.Command_Line.Set_Exit_Status(Failure)` on any fail.
6. Build+run:
   `gnatmake -q -D /tmp/s -aIsrc -o /tmp/s/test_sample src/test_sample.adb && /tmp/s/test_sample`

## Done
`git checkout -b claude/ralph-sample`, commit, `git push -u origin claude/ralph-sample`.
Report branch + test_sample output. (Full correctness is confirmed later by the
15-vector KAT once Verify lands — your self-gates are the local proxy.)
