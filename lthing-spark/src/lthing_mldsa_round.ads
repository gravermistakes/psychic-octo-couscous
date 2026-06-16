------------------------------------------------------------------------------
--  LTHING.MLDSA.Round — ML-DSA-65 rounding / hint layer (FIPS 204)
--
--  Implements the rounding and hint algorithms of FIPS 204:
--    * Mod_Pm       — centered remainder mod a (even a), result in (-a/2, a/2]
--    * Power2Round  — Alg. 35  r -> (r1, r0), r0 = r mod+- 2^d
--    * Decompose    — Alg. 36  r -> (r1, r0) about 2*gamma2
--    * High_Bits    — Alg. 37  = Decompose(r).r1
--    * Low_Bits     — Alg. 38  = Decompose(r).r0
--    * Use_Hint     — Alg. 40  recover high bits given a 1-bit hint
--    * W1_Encode    —          pack w1 coeffs (0..15) 2-per-byte, low nibble 1st
--    * Inf_Norm_OK  —          all centered coeffs strictly below a bound
--
--  Constants (FIPS 204, ML-DSA-65):
--    q = 8380417, d = 13, 2^d = 8192,
--    gamma2 = (q-1)/32 = 261888, 2*gamma2 = 523776, m = (q-1)/(2*gamma2) = 16,
--    gamma1 = 2^19 = 524288, beta = 196, omega = 55.
--
--  SPARK posture: SPARK_Mode (On). Every routine carries range / AoRTE
--  postconditions; all internal arithmetic is performed in Integer_64 before
--  reduction (|products| < 2^46), so the prover guarantees no overflow.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;          use Interfaces;
with LTHING_Types;        use LTHING_Types;
with LTHING_MLDSA_Field;  use LTHING_MLDSA_Field;

package LTHING_MLDSA_Round is

   --  ML-DSA parameters (FIPS 204, ML-DSA-65).
   D_Bits     : constant := 13;
   Two_Pow_D  : constant := 8_192;          --  2^d
   Gamma2     : constant := 261_888;        --  (q-1)/32
   Two_Gamma2 : constant := 523_776;        --  2*gamma2
   M_Bins     : constant := 16;             --  (q-1)/(2*gamma2)
   Gamma1     : constant := 524_288;        --  2^19
   Beta       : constant := 196;
   Omega      : constant := 55;

   --  256-coefficient polynomial over Z_q (matches the NTT layer's Poly).
   type Poly is array (0 .. 255) of Fq;

   --  W1 encoding: one byte per two coefficients => 128 bytes per poly.
   subtype W1_Bytes is Byte_Array (0 .. 127);

   --  High-bit / hint outputs live in 0 .. m-1 = 0 .. 15.
   subtype Bins is Integer_32 range 0 .. M_Bins - 1;

   --  Low-bit (centered) output for Decompose, in (-gamma2, gamma2].
   subtype Low_Range is Integer_32 range -Gamma2 .. Gamma2;

   --  Power2Round low part: r0 = r mod+- 2^d in (-2^(d-1), 2^(d-1)].
   subtype P2R_Low is Integer_32 range -(Two_Pow_D / 2) .. (Two_Pow_D / 2);

   --  Power2Round high part: r1 in 0 .. (q-1)/2^d = 0 .. 1023.
   subtype P2R_High is Integer_32 range 0 .. 1_023;

   ---------------------------------------------------------------------------
   --  Mod_Pm — centered remainder mod a, for even a > 0.
   --  Result in (-a/2, a/2].  (FIPS 204 mod+- notation.)
   ---------------------------------------------------------------------------
   function Mod_Pm (R : Integer_64; A : Integer_64) return Integer_64
     with Global => null,
          Pre    => A > 0 and then A <= Two_Gamma2 and then A mod 2 = 0,
          Post   => Mod_Pm'Result > -(A / 2)
                    and then Mod_Pm'Result <= A / 2
                    and then (Mod_Pm'Result mod A) = (R mod A);

   ---------------------------------------------------------------------------
   --  Power2Round (Alg. 35).  r mod q -> (r1, r0) with r = r1*2^d + r0,
   --  r0 the centered residue mod 2^d.
   ---------------------------------------------------------------------------
   procedure Power2Round (R : Fq; R1 : out P2R_High; R0 : out P2R_Low)
     with Global => null,
          Post   => Integer_64 (R1) * Two_Pow_D + Integer_64 (R0) = Integer_64 (R);

   ---------------------------------------------------------------------------
   --  Decompose (Alg. 36).  r mod q -> (r1, r0) about 2*gamma2.
   --  Recomposition: (r1*2*gamma2 + r0) mod q = r mod q.
   ---------------------------------------------------------------------------
   procedure Decompose (R : Fq; R1 : out Bins; R0 : out Low_Range)
     with Global => null,
          Post   => (Integer_64 (R1) * Two_Gamma2 + Integer_64 (R0)) mod Q
                    = Integer_64 (R) mod Q;

   ---------------------------------------------------------------------------
   --  High_Bits (Alg. 37) = Decompose(r).r1.
   ---------------------------------------------------------------------------
   function High_Bits (R : Fq) return Bins
     with Global => null;

   ---------------------------------------------------------------------------
   --  Low_Bits (Alg. 38) = Decompose(r).r0.
   ---------------------------------------------------------------------------
   function Low_Bits (R : Fq) return Low_Range
     with Global => null;

   ---------------------------------------------------------------------------
   --  Use_Hint (Alg. 40).  h in {0,1}; recover the high bits, result 0..15.
   ---------------------------------------------------------------------------
   function Use_Hint (H : Integer_32; R : Fq) return Bins
     with Global => null,
          Pre    => H = 0 or else H = 1;

   ---------------------------------------------------------------------------
   --  W1_Encode — pack a polynomial of w1 coeffs (each 0..15) into 128 bytes,
   --  two coeffs per byte, low nibble first: out(t)=w1(2t)+16*w1(2t+1).
   ---------------------------------------------------------------------------
   function W1_Encode (W1 : Poly) return W1_Bytes
     with Global => null,
          Pre    => (for all I in W1'Range => W1 (I) <= M_Bins - 1);

   ---------------------------------------------------------------------------
   --  Inf_Norm_OK — True iff every centered coeff has abs value < Bound.
   ---------------------------------------------------------------------------
   function Inf_Norm_OK (P : Poly; Bound : Integer_32) return Boolean
     with Global => null,
          Pre    => Bound >= 0,
          Post   => Inf_Norm_OK'Result =
                      (for all I in P'Range =>
                         abs (To_Centered (P (I))) < Bound);

end LTHING_MLDSA_Round;
