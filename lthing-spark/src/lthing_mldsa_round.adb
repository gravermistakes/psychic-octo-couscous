------------------------------------------------------------------------------
--  LTHING.MLDSA.Round (body) — ML-DSA-65 rounding / hint layer (FIPS 204)
--
--  All arithmetic is carried in Integer_64; the operand magnitudes are all
--  well under 2^46 so AoRTE holds. Each routine reduces back into Fq / the
--  declared subtype ranges proven in the spec.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA_Round is

   ---------------------------------------------------------------------------
   --  Mod_Pm
   ---------------------------------------------------------------------------
   function Mod_Pm (R : Integer_64; A : Integer_64) return Integer_64 is
      M : constant Integer_64 := R mod A;   --  0 .. A-1 (A > 0)
   begin
      if M > A / 2 then
         --  M - A in (-A/2, 0); and (M - A) mod A = M mod A = R mod A.
         return M - A;
      else
         --  M in [0, A/2]; M mod A = M = R mod A.
         return M;
      end if;
   end Mod_Pm;

   ---------------------------------------------------------------------------
   --  Power2Round (Alg. 35)
   ---------------------------------------------------------------------------
   procedure Power2Round (R : Fq; R1 : out P2R_High; R0 : out P2R_Low) is
      Rr  : constant Integer_64 := Integer_64 (R);          --  already 0..q-1
      Low : constant Integer_64 := Mod_Pm (Rr, Two_Pow_D);  --  (-4096, 4096]
      Hi  : constant Integer_64 := (Rr - Low) / Two_Pow_D;
   begin
      --  Rr - Low is an exact multiple of 2^d (since Low = Rr mod+- 2^d),
      --  in 0 .. q-1+4096, so Hi in 0 .. 1023.
      pragma Assert (Rr - Low >= 0);
      pragma Assert ((Rr - Low) mod Two_Pow_D = 0);
      pragma Assert (Hi * Two_Pow_D = Rr - Low);
      R0 := Integer_32 (Low);
      R1 := Integer_32 (Hi);
   end Power2Round;

   ---------------------------------------------------------------------------
   --  Decompose (Alg. 36)
   ---------------------------------------------------------------------------
   procedure Decompose (R : Fq; R1 : out Bins; R0 : out Low_Range) is
      Rp  : constant Integer_64 := Integer_64 (R) mod Q;    --  0 .. q-1
      Lo  : Integer_64 := Mod_Pm (Rp, Two_Gamma2);          --  (-gamma2, gamma2]
      Hi  : Integer_64;
   begin
      if Rp - Lo = Q - 1 then
         --  Top special case: fold to r1 = 0, r0 reduced by one.
         Hi := 0;
         Lo := Lo - 1;
         --  (0*2g2 + (Lo-1)) mod q = (Rp - (q-1) - 1) mod q = Rp mod q.
         pragma Assert (Lo = Mod_Pm (Rp, Two_Gamma2) - 1);
         pragma Assert ((Hi * Two_Gamma2 + Lo) mod Q = Rp mod Q);
      else
         --  Rp - Lo is an exact multiple of 2*gamma2 in 0 .. q-1, so the
         --  quotient lands in 0 .. m-1 = 0 .. 15.
         pragma Assert ((Rp - Lo) mod Two_Gamma2 = 0);
         Hi := (Rp - Lo) / Two_Gamma2;
         pragma Assert (Hi * Two_Gamma2 + Lo = Rp);
         pragma Assert ((Hi * Two_Gamma2 + Lo) mod Q = Rp mod Q);
      end if;
      R1 := Integer_32 (Hi);
      R0 := Integer_32 (Lo);
   end Decompose;

   ---------------------------------------------------------------------------
   --  High_Bits (Alg. 37)
   ---------------------------------------------------------------------------
   function High_Bits (R : Fq) return Bins is
      R1 : Bins;
      R0 : Low_Range;
   begin
      Decompose (R, R1, R0);
      return R1;
   end High_Bits;

   ---------------------------------------------------------------------------
   --  Low_Bits (Alg. 38)
   ---------------------------------------------------------------------------
   function Low_Bits (R : Fq) return Low_Range is
      R1 : Bins;
      R0 : Low_Range;
   begin
      Decompose (R, R1, R0);
      return R0;
   end Low_Bits;

   ---------------------------------------------------------------------------
   --  Use_Hint (Alg. 40)
   ---------------------------------------------------------------------------
   function Use_Hint (H : Integer_32; R : Fq) return Bins is
      R1 : Bins;
      R0 : Low_Range;
   begin
      Decompose (R, R1, R0);
      if H = 1 and then R0 > 0 then
         return Integer_32 ((Integer_64 (R1) + 1) mod M_Bins);
      elsif H = 1 then
         return Integer_32 ((Integer_64 (R1) - 1 + M_Bins) mod M_Bins);
      else
         return R1;
      end if;
   end Use_Hint;

   ---------------------------------------------------------------------------
   --  W1_Encode
   ---------------------------------------------------------------------------
   function W1_Encode (W1 : Poly) return W1_Bytes is
      Out_B : W1_Bytes := (others => 0);
   begin
      for T in 0 .. 127 loop
         --  W1 (2T), W1 (2T+1) each in 0..15, so the byte is in 0..255.
         Out_B (T) :=
           Byte (Integer_32 (W1 (2 * T)) + 16 * Integer_32 (W1 (2 * T + 1)));
         pragma Loop_Invariant
           (for all K in 0 .. T => Out_B (K) <= 255);
      end loop;
      return Out_B;
   end W1_Encode;

   ---------------------------------------------------------------------------
   --  Inf_Norm_OK
   ---------------------------------------------------------------------------
   function Inf_Norm_OK (P : Poly; Bound : Integer_32) return Boolean is
   begin
      for I in P'Range loop
         if abs (To_Centered (P (I))) >= Bound then
            return False;
         end if;
         pragma Loop_Invariant
           (for all K in P'First .. I =>
              abs (To_Centered (P (K))) < Bound);
      end loop;
      return True;
   end Inf_Norm_OK;

end LTHING_MLDSA_Round;
