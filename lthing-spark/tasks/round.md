# Agent task T2 — ML-DSA rounding / hint layer

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md`. Implement strictly per
**FIPS 204**; cite algorithm numbers. Edit ONLY your files.
`export PATH=/root/.alire/bin:$PATH`. Reuse `LTHING_MLDSA_Field` (`Fq`, `Q`, `To_Centered`).

Files: `src/lthing_mldsa_round.ads/.adb` (new), `src/test_round.adb` (new).
**SPARK_Mode (On)** — give every routine range/AoRTE postconditions.

Constants: q=8380417, d=13, 2^d=8192, γ2=(q-1)/32=261888, 2γ2=523776,
m=(q-1)/(2γ2)=16, γ1=2^19=524288, β=196, ω=55.

## Exact math (all arithmetic on Integer_32/Integer_64, results reduced to Fq)

**Centered remainder `mod±`.** For even `a`:
```
function Mod_Pm (r : Integer_64; a : Integer_64) return Integer_64 is
   m : Integer_64 := r mod a;        -- 0 .. a-1
begin
   if m > a/2 then return m - a; else return m; end if;   -- result in (-a/2 , a/2]
end;
```

**Power2Round (Alg. 35)** → `(r1, r0)`:
`r := r mod Q;  r0 := Mod_Pm(r, 8192);  r1 := (r - r0) / 8192`   (r1 ∈ 0..1023).

**Decompose (Alg. 36)** → `(r1, r0)`:
```
rp := r mod Q;
r0 := Mod_Pm(rp, 523776);
if rp - r0 = Q - 1 then  r1 := 0;  r0 := r0 - 1;
else                     r1 := (rp - r0) / 523776;          -- r1 ∈ 0..15
end if;
```

**HighBits (Alg. 37)** = `Decompose(r).r1`.   **LowBits (Alg. 38)** = `Decompose(r).r0`.

**Use_Hint (Alg. 40)** (`h` is 0 or 1) → Fq in 0..15:
```
(r1, r0) := Decompose(r);
if h = 1 and r0 > 0  then return (r1 + 1) mod 16;
elsif h = 1          then return (r1 - 1 + 16) mod 16;     -- r0 <= 0
else                      return r1;
end if;
```

**W1_Encode** (w1 coeffs ∈ 0..15, 4 bits each, 2 per byte, little nibble first):
`out(t) := w1(2*t) + 16 * w1(2*t+1)`, `t in 0..127` → 128 bytes per poly.

**Inf_Norm_OK (p, bound)**: for every coeff, `abs(To_Centered(coeff)) < bound`.

## Steps
1. `lthing_mldsa_round.ads`: declare `Power2Round`, `Decompose` (return a small
   record or two out-params), `High_Bits`, `Low_Bits`, `Use_Hint`,
   `W1_Encode` (poly→`Byte_Array(0..127)`), `Inf_Norm_OK`. SPARK contracts:
   results of High_Bits/Use_Hint in `0..15`, Low_Bits in `-(γ2) .. γ2`, etc.
2. `.adb`: implement per the math. Keep everything in `Integer_64` before
   reducing; prove AoRTE (no overflow: |products| < 2^46).
3. `test_round.adb` (relational, no frozen consts):
   - recompose: for a spread of `r`, `Decompose` gives `(r1,r0)` with
     `(r1*523776 + r0) mod Q = r mod Q` (except the special top case);
   - hint round-trip: for `r` and a small `z`, with
     `hh := (if High_Bits(r) /= High_Bits((r+z) mod Q) then 1 else 0)`,
     assert `Use_Hint(hh, r) = High_Bits((r + z) mod Q)`;
   - boundaries: `r = Q-1`, `r = γ2`, `r = γ2+1`, `r = 0`.
   - `[PASS]/[FAIL]`; `Set_Exit_Status` on fail.
4. Build+run, then prove:
   ```
   gnatmake -q -D /tmp/r -aIsrc -o /tmp/r/test_round src/test_round.adb && /tmp/r/test_round
   gnatprove -P lthing.gpr -u lthing_mldsa_round.adb --level=2 --report=all
   ```
   Done = test all `[PASS]` exit 0 AND gnatprove `Total` shows 0 Unproved.

## Done
`git checkout -b claude/ralph-round`, commit, `git push -u origin claude/ralph-round`.
Report branch + test output + gnatprove Total line.
