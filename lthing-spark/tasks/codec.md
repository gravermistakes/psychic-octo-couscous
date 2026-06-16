# Agent task T3 — ML-DSA pk/sig decode (codec)

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md`. Implement strictly per
**FIPS 204**; cite algorithm numbers. Edit ONLY your files.
`export PATH=/root/.alire/bin:$PATH`. Use constants from `lthing_mldsa65.ads`
and `Fq`/`Poly` from the field/ntt units.

Files: `src/lthing_mldsa_codec.ads/.adb` (new), `src/test_codec.adb` (new).
**SPARK_Mode (On)** — AoRTE + index/range postconditions.

Params: q=8380417, n=256, k=6, l=5, γ1=2^19=524288, ω=55, PK=1952, Sig=3309, c̃=48.

## Exact byte math

**Bit reader.** For a byte slice `v`, bit `n` is
`bit(n) = (Integer(v(v'First + n/8)) / 2**(n mod 8)) mod 2`.

**SimpleBitUnpack(v, bitlen) (Alg. 19)** → 256 coeffs:
`coeff(i) = Σ_{j=0..bitlen-1} bit(i*bitlen + j) * 2**j`,  `i in 0..255`.

**BitUnpack(v, a, b) (Alg. 18)** with `bitlen = number of bits in (a+b)`:
`raw := SimpleBitUnpack(v, bitlen)`; `coeff(i) = b - raw(i)`  (range `-a .. b`).

**Pk_Decode (Alg. 23).** `Rho := pk(0..31)`. For `i in 0..5`:
`T1(i) := SimpleBitUnpack(pk(32 + 320*i .. 32 + 320*i + 319), 10)` → coeffs 0..1023.
(320 = 256*10/8.)

**Sig_Decode (Alg. 27).** `C_Tilde := sig(0..47)`.
- For `i in 0..4`: `Z(i) := BitUnpack(sig(48 + 640*i .. 48 + 640*i + 639), γ1-1, γ1)`,
  `bitlen = 20`, coeffs in `-(γ1-1) .. γ1` (640 = 256*20/8; l*640 = 3200).
  Store Z coeffs as canonical Fq: `(if c < 0 then c + Q else c)`.
- `H := HintBitUnpack(sig(3248 .. 3308))` (ω+k = 61 bytes), **Alg. 21**:
  ```
  H := (others => (others => 0));  Index := 0;  Ok := True;
  for i in 0..5 loop
     last := Integer(sig(3248 + 55 + i));            -- end pointer for poly i
     if last < Index or last > ω then Ok := False; exit; end if;
     for jj in Index .. last-1 loop
        pos := Integer(sig(3248 + jj));
        if jj > Index and then pos <= prev then Ok := False; exit; end if;  -- strictly increasing
        H(i)(pos) := 1;  prev := pos;
     end loop;
     Index := last;
  end loop;
  -- trailing padding bytes sig(3248+Index .. 3248+54) must all be 0 else Ok := False
  ```

## Steps
1. `.ads`: declare `Pk_Decode (PK : Public_Key; Rho : out …; T1 : out T1_Vec)`,
   `Sig_Decode (Sig : Signature; C_Tilde : out …; Z : out Z_Vec; H : out H_Vec;
   Ok : out Boolean)`, and the bit-unpack helpers. Pick simple array types
   (e.g. `type T1_Vec is array (0..5) of Poly`).
2. `.adb`: implement per the math; add postconditions (T1 coeffs `in 0..1023`,
   Z coeffs canonical `in 0..Q-1`, hint poly entries `in 0..1`).
3. `test_codec.adb`: paste ONE accept-vector pk+sig (tcId 31) hex as `Byte_Array`
   (or read the array T7 generates if present); assert `Rho` length, T1 ranges,
   Z canonical ranges, `Ok = True`; then corrupt the hint region (set a non-zero
   trailing pad byte) and assert `Ok = False`. `[PASS]/[FAIL]`; `Set_Exit_Status`.
4. Build+run, then prove:
   ```
   gnatmake -q -D /tmp/c -aIsrc -o /tmp/c/test_codec src/test_codec.adb && /tmp/c/test_codec
   gnatprove -P lthing.gpr -u lthing_mldsa_codec.adb --level=2 --report=all
   ```
   Done = test `[PASS]` exit 0 AND gnatprove 0 Unproved.

## Done
`git checkout -b claude/ralph-codec`, commit, `git push -u origin claude/ralph-codec`.
Report branch + test output + gnatprove Total line.
