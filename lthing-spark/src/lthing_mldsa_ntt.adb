------------------------------------------------------------------------------
--  LTHING.MLDSA.NTT (body)
--  Cooley-Tukey forward, Gentleman-Sande inverse, computed zeta table.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA_NTT is

   type Zeta_Table is array (0 .. 255) of Fq;

   --  8-bit bit-reversal.
   function BRV (X : Natural) return Natural
     with Global => null,
          Pre  => X <= 255,
          Post => BRV'Result <= 255
   is
      R : Natural := 0;
      V : Natural := X;
   begin
      for I in 0 .. 7 loop
         pragma Loop_Invariant (R <= 2 ** I - 1);
         pragma Loop_Invariant (V <= 255);
         R := R * 2 + (V mod 2);
         V := V / 2;
      end loop;
      return R;
   end BRV;

   --  Compute zetas[i] = zeta^brv(i) mod q, i in 0..255, by square-and-multiply.
   --  Used once to initialize the constant table below at elaboration; since the
   --  table is a constant, the transforms that read it need no Global aspect.
   function Compute_Zetas return Zeta_Table
     with Global => null
   is
      T   : Zeta_Table;
      Acc : Fq;
      E   : Natural;
   begin
      for I in 0 .. 255 loop
         Acc := 1;
         E   := BRV (I);                  --  E in 0 .. 255
         declare
            Base : Fq      := Zeta_Root;
            Exp  : Natural := E;
         begin
            while Exp > 0 loop
               pragma Loop_Variant (Decreases => Exp);
               if Exp mod 2 = 1 then
                  Acc := Mul (Acc, Base);
               end if;
               Base := Mul (Base, Base);
               Exp  := Exp / 2;
            end loop;
         end;
         T (I) := Acc;
      end loop;
      return T;
   end Compute_Zetas;

   --  Precomputed at elaboration; immutable thereafter.
   Zetas : constant Zeta_Table := Compute_Zetas;

   ---------------------------------------------------------------------------
   --  Forward NTT (Cooley-Tukey), matching the Dilithium reference layout.
   --
   --  AoRTE proof sketch. The middle loop maintains
   --      2 * Len * K = 256 - 2 * Len + Start          (rel)
   --  with Start a multiple of 2*Len and 2*Len dividing 256. From (rel) and
   --  Start < 256, after K := K + 1 we get 2*Len*K = 256 + Start < 512, hence
   --  K <= 255, so Zetas (K) is in range; and Start + 2*Len <= 256, so the
   --  butterfly indices J and J+Len stay within 0 .. 255.
   ---------------------------------------------------------------------------
   procedure NTT (A : in out Poly) is
      Len  : Natural := 128;
      K    : Natural := 0;
      Zeta : Fq;
      T    : Fq;
   begin
      while Len >= 1 loop
         pragma Loop_Invariant (Len in 1 .. 128);
         pragma Loop_Invariant (256 mod (2 * Len) = 0);
         pragma Loop_Invariant (2 * Len * (K + 1) = 256);
         pragma Loop_Variant (Decreases => Len);
         declare
            Start : Natural := 0;
         begin
            while Start < 256 loop
               pragma Loop_Invariant (Start mod (2 * Len) = 0);
               pragma Loop_Invariant (Start <= 256);
               pragma Loop_Invariant (2 * Len * K = 256 - 2 * Len + Start);
               pragma Loop_Variant (Increases => Start);

               K := K + 1;
               --  From (rel): 2*Len*K = 256 + Start < 512  =>  K <= 255.
               pragma Assert (2 * Len * K = 256 + Start);
               pragma Assert (K <= 255);
               --  2*Len | 256, 2*Len | Start, Start < 256  =>  Start+2*Len<=256.
               pragma Assert (Start + 2 * Len <= 256);

               Zeta := Zetas (K);
               for J in Start .. Start + Len - 1 loop
                  pragma Loop_Invariant (J >= Start and then J <= Start + Len - 1);
                  T := Mul (Zeta, A (J + Len));
                  A (J + Len) := Sub (A (J), T);
                  A (J)       := Add (A (J), T);
               end loop;
               Start := Start + 2 * Len;
            end loop;
         end;
         Len := Len / 2;
      end loop;
   end NTT;

   ---------------------------------------------------------------------------
   --  Inverse NTT (Gentleman-Sande) + final scaling by n^{-1}.
   --
   --  AoRTE proof sketch. The middle loop maintains
   --      2 * K * Len = 512 - Start                     (rel')
   --  with Start a multiple of 2*Len and 2*Len dividing 256. From (rel') and
   --  Start < 256 we get 2*K*Len > 256, so K >= 1 (K-1 stays >= 0); after
   --  K := K - 1, 2*K*Len = 512 - Start - 2*Len, and since the first access has
   --  K-1 <= 255, Zetas (K) is in range. Butterfly indices as in NTT.
   ---------------------------------------------------------------------------
   procedure Inv_NTT (A : in out Poly) is
      Len   : Natural := 1;
      K     : Natural := 256;
      Zeta  : Fq;
      T     : Fq;
      --  n^{-1} mod q for n=256: 256^{-1} mod 8380417 = 8347681
      N_Inv : constant Fq := 8_347_681;
   begin
      while Len <= 128 loop
         pragma Loop_Invariant (Len in 1 .. 128);
         pragma Loop_Invariant (256 mod (2 * Len) = 0);
         pragma Loop_Invariant (K * Len = 256);
         pragma Loop_Variant (Increases => Len);
         declare
            Start : Natural := 0;
         begin
            while Start < 256 loop
               pragma Loop_Invariant (Start mod (2 * Len) = 0);
               pragma Loop_Invariant (Start <= 256);
               pragma Loop_Invariant (2 * K * Len = 512 - Start);
               pragma Loop_Variant (Increases => Start);

               --  2*K*Len = 512 - Start > 256 (Start<256), Len<=128 => K >= 1.
               pragma Assert (2 * K * Len > 256);
               pragma Assert (K >= 1);
               pragma Assert (Start + 2 * Len <= 256);

               K := K - 1;
               --  2*(K+1)*Len = 512 - Start, K+1 <= 256 => K <= 255.
               pragma Assert (K <= 255);

               Zeta := Sub (0, Zetas (K));    --  GS uses -zeta
               for J in Start .. Start + Len - 1 loop
                  pragma Loop_Invariant (J >= Start and then J <= Start + Len - 1);
                  T := A (J);
                  A (J)       := Add (T, A (J + Len));
                  A (J + Len) := Sub (T, A (J + Len));
                  A (J + Len) := Mul (Zeta, A (J + Len));
               end loop;
               Start := Start + 2 * Len;
            end loop;
         end;
         Len := Len * 2;
      end loop;
      for I in A'Range loop
         A (I) := Mul (A (I), N_Inv);
      end loop;
   end Inv_NTT;

   function Pointwise (A, B : Poly) return Poly is
      R : Poly;
   begin
      for I in A'Range loop
         R (I) := Mul (A (I), B (I));
      end loop;
      return R;
   end Pointwise;

   ---------------------------------------------------------------------------
   --  Negacyclic schoolbook multiply mod (x^256 + 1): the ground-truth gate.
   ---------------------------------------------------------------------------
   function Schoolbook_Mul (A, B : Poly) return Poly is
      R   : Poly := (others => 0);
      Idx : Natural;
   begin
      for I in 0 .. 255 loop
         for J in 0 .. 255 loop
            Idx := I + J;
            if Idx < 256 then
               R (Idx) := Add (R (Idx), Mul (A (I), B (J)));
            else
               --  x^256 = -1 : wrap with negation
               R (Idx - 256) := Sub (R (Idx - 256), Mul (A (I), B (J)));
            end if;
         end loop;
      end loop;
      return R;
   end Schoolbook_Mul;

end LTHING_MLDSA_NTT;
