------------------------------------------------------------------------------
--  LTHING.MLDSA.NTT (body)
--  Cooley-Tukey forward, Gentleman-Sande inverse, computed zeta table.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA_NTT is

   --  8-bit bit-reversal.
   function BRV (X : Natural) return Natural
     with Pre  => X <= 255,
          Post => BRV'Result <= 255
   is
      R : Natural := 0;
      V : Natural := X;
   begin
      for I in 0 .. 7 loop
         --  After I iterations R holds I bits (< 2**I) and V is X shifted
         --  right by I bits (so V <= 255 throughout).
         pragma Loop_Invariant (R < 2 ** I);
         pragma Loop_Invariant (V <= 255);
         R := R * 2 + (V mod 2);
         V := V / 2;
      end loop;
      return R;
   end BRV;

   --  Index type into the 256-entry zeta table.
   subtype Zeta_Index is Natural range 0 .. 255;

   type Zeta_Table is array (Zeta_Index) of Fq;

   --  Compute zetas[i] = zeta^brv(i) mod q, i in 0..255, at elaboration time.
   --  Global => null makes Zetas a constant WITHOUT variable input (not SPARK
   --  state), so callers like Verify need not list it in their Global aspect.
   function Compute_Zetas return Zeta_Table
     with Global => null
   is
      Result : Zeta_Table;
      Acc    : Fq;
      E      : Natural;
   begin
      for I in Zeta_Index loop
         --  zeta^brv(i) by square-and-multiply
         Acc := 1;
         E   := BRV (I);
         declare
            Base : Fq := Zeta_Root;
            Exp  : Natural := E;
         begin
            while Exp > 0 loop
               pragma Loop_Invariant (Exp <= E);
               pragma Loop_Variant (Decreases => Exp);
               if Exp mod 2 = 1 then
                  Acc := Mul (Acc, Base);
               end if;
               Base := Mul (Base, Base);
               Exp  := Exp / 2;
            end loop;
         end;
         Result (I) := Acc;
      end loop;
      return Result;
   end Compute_Zetas;

   --  Elaboration-time constant: no mutable global state, no lazy init.
   Zetas : constant Zeta_Table := Compute_Zetas;

   --  Layer stride: power of two in 1 .. 128.
   subtype Layer_Len is Natural range 1 .. 128;

   ---------------------------------------------------------------------------
   --  Forward NTT (Cooley-Tukey), matching the Dilithium reference layout.
   --
   --  K is incremented once per butterfly group. Over the whole transform the
   --  group counts per layer sum to 1+2+...+128 = 255, so K stays in 0 .. 255
   --  and Zetas (K) is always in range. The invariants below pin the exact
   --  value of K from (Len, Start) so the prover can discharge the bounds.
   ---------------------------------------------------------------------------
   procedure NTT (A : in out Poly) is
      Len  : Layer_Len := 128;
      GPL  : Natural   := 1;   --  groups per layer = 128 / Len (linear witness)
      K    : Natural   := 0;
      Zeta : Fq;
      T    : Fq;
   begin
      while Len >= 1 loop
         pragma Loop_Invariant (Len in Layer_Len);
         --  Len * GPL = 128 is the linear divisibility witness: it makes
         --  2*Len*GPL = 256 and lets the prover see Start strides tile 0..255.
         pragma Loop_Invariant (Len * GPL = 128);
         --  Number of groups already fully processed in earlier layers.
         pragma Loop_Invariant (K = GPL - 1);
         pragma Loop_Variant (Decreases => Len);
         declare
            Start : Natural := 0;
            G     : Natural := 0;   --  group index within layer = Start/(2*Len)
         begin
            while Start < 256 loop
               pragma Loop_Invariant (G <= GPL);
               pragma Loop_Invariant (Start = G * (2 * Len));
               pragma Loop_Invariant (K = GPL - 1 + G);
               pragma Loop_Invariant (K <= 254);
               pragma Loop_Variant (Increases => Start);
               --  G < GPL here (Start < 256 = GPL*2*Len), so Start+2*Len <= 256.
               pragma Assert (G < GPL);
               pragma Assert (Start + 2 * Len <= 256);
               K := K + 1;
               Zeta := Zetas (K);
               for J in Start .. Start + Len - 1 loop
                  pragma Loop_Invariant (J in Start .. Start + Len - 1);
                  pragma Loop_Invariant (J + Len <= 255);
                  T := Mul (Zeta, A (J + Len));
                  A (J + Len) := Sub (A (J), T);
                  A (J)       := Add (A (J), T);
               end loop;
               Start := Start + 2 * Len;
               G     := G + 1;
            end loop;
            --  After the sweep G = GPL, so K advanced by GPL groups.
            pragma Assert (K = 2 * GPL - 1);
         end;
         exit when Len = 1;
         Len := Len / 2;
         GPL := GPL * 2;
      end loop;
   end NTT;

   ---------------------------------------------------------------------------
   --  Inverse NTT (Gentleman-Sande) + final scaling by n^{-1}.
   --
   --  K starts at 256 and is decremented once per butterfly group; mirror of
   --  the forward direction, so K stays in 1 .. 255 and Zetas (K) is in range.
   ---------------------------------------------------------------------------
   procedure Inv_NTT (A : in out Poly) is
      Len   : Layer_Len := 1;
      GPL   : Natural   := 128;   --  groups per layer = 128 / Len (linear witness)
      K     : Natural   := 256;
      Zeta  : Fq;
      T     : Fq;
      --  n^{-1} mod q for n=256: 256^{-1} mod 8380417 = 8347681
      N_Inv : constant Fq := 8_347_681;
   begin
      while Len <= 128 loop
         pragma Loop_Invariant (Len in Layer_Len);
         --  Len * GPL = 128: linear divisibility witness (see NTT).
         pragma Loop_Invariant (Len * GPL = 128);
         --  Groups not yet processed for this and remaining layers.
         pragma Loop_Invariant (K = 2 * GPL);
         pragma Loop_Variant (Increases => Len);
         declare
            Start : Natural := 0;
            G     : Natural := 0;   --  group index within layer = Start/(2*Len)
         begin
            while Start < 256 loop
               pragma Loop_Invariant (G <= GPL);
               pragma Loop_Invariant (Start = G * (2 * Len));
               pragma Loop_Invariant (K = 2 * GPL - G);
               pragma Loop_Invariant (K >= 1);
               pragma Loop_Variant (Increases => Start);
               --  G < GPL here (Start < 256 = GPL*2*Len), so Start+2*Len <= 256.
               pragma Assert (G < GPL);
               pragma Assert (Start + 2 * Len <= 256);
               K := K - 1;
               --  GS uses -zeta; (q - zetas(k)) is the negation
               Zeta := Sub (0, Zetas (K));
               for J in Start .. Start + Len - 1 loop
                  pragma Loop_Invariant (J in Start .. Start + Len - 1);
                  pragma Loop_Invariant (J + Len <= 255);
                  T := A (J);
                  A (J)       := Add (T, A (J + Len));
                  A (J + Len) := Sub (T, A (J + Len));
                  A (J + Len) := Mul (Zeta, A (J + Len));
               end loop;
               Start := Start + 2 * Len;
               G     := G + 1;
            end loop;
            --  After the sweep G = GPL, so K dropped by GPL groups.
            pragma Assert (K = GPL);
         end;
         exit when Len = 128;
         Len := Len * 2;
         GPL := GPL / 2;
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
      R : Poly := (others => 0);
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
