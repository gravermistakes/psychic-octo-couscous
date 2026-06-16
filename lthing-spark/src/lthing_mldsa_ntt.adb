------------------------------------------------------------------------------
--  LTHING.MLDSA.NTT (body)
--  Cooley-Tukey forward, Gentleman-Sande inverse, computed zeta table.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA_NTT is

   --  8-bit bit-reversal.
   function BRV (X : Natural) return Natural is
      R : Natural := 0;
      V : Natural := X;
   begin
      for I in 0 .. 7 loop
         R := R * 2 + (V mod 2);
         V := V / 2;
      end loop;
      return R;
   end BRV;

   --  Precompute zetas[i] = zeta^brv(i) mod q, i in 0..255.
   Zetas : array (0 .. 255) of Fq;

   procedure Init_Zetas is
      Acc : Fq;
      E   : Natural;
   begin
      for I in 0 .. 255 loop
         --  zeta^brv(i) by square-and-multiply
         Acc := 1;
         E   := BRV (I);
         declare
            Base : Fq := Zeta_Root;
            Exp  : Natural := E;
         begin
            while Exp > 0 loop
               if Exp mod 2 = 1 then
                  Acc := Mul (Acc, Base);
               end if;
               Base := Mul (Base, Base);
               Exp  := Exp / 2;
            end loop;
         end;
         Zetas (I) := Acc;
      end loop;
   end Init_Zetas;

   Initialized : Boolean := False;

   procedure Ensure_Init is
   begin
      if not Initialized then
         Init_Zetas;
         Initialized := True;
      end if;
   end Ensure_Init;

   ---------------------------------------------------------------------------
   --  Forward NTT (Cooley-Tukey), matching the Dilithium reference layout.
   ---------------------------------------------------------------------------
   procedure NTT (A : in out Poly) is
      Len  : Natural := 128;
      K    : Natural := 0;
      Zeta : Fq;
      T    : Fq;
   begin
      Ensure_Init;
      while Len >= 1 loop
         declare
            Start : Natural := 0;
         begin
            while Start < 256 loop
               K := K + 1;
               Zeta := Zetas (K);
               for J in Start .. Start + Len - 1 loop
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
   ---------------------------------------------------------------------------
   procedure Inv_NTT (A : in out Poly) is
      Len   : Natural := 1;
      K     : Natural := 256;
      Zeta  : Fq;
      T     : Fq;
      --  n^{-1} mod q for n=256: 256^{-1} mod 8380417 = 8347681
      N_Inv : constant Fq := 8_347_681;
   begin
      Ensure_Init;
      while Len <= 128 loop
         declare
            Start : Natural := 0;
         begin
            while Start < 256 loop
               K := K - 1;
               --  GS uses -zeta; (q - zetas(k)) is the negation
               Zeta := Sub (0, Zetas (K));
               for J in Start .. Start + Len - 1 loop
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
