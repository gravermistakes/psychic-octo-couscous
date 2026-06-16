------------------------------------------------------------------------------
--  LTHING.MLDSA.Field (body) — provable Z_q arithmetic
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA_Field is

   function Add (A, B : Fq) return Fq is
      S : constant Integer_64 := Integer_64 (A) + Integer_64 (B);
   begin
      --  A,B in [0,q-1] so S in [0, 2q-2]; one conditional subtract suffices,
      --  but mod keeps the proof direct and is constant-work for fixed q.
      return Fq (S mod Q);
   end Add;

   function Sub (A, B : Fq) return Fq is
      S : constant Integer_64 := Integer_64 (A) - Integer_64 (B) + Integer_64 (Q);
   begin
      --  Add q before mod so the intermediate is nonneg in [1, 2q-1].
      return Fq (S mod Q);
   end Sub;

   function Mul (A, B : Fq) return Fq is
      P : constant Integer_64 := Integer_64 (A) * Integer_64 (B);
   begin
      --  P in [0, (q-1)^2] < 2**46, fits Integer_64.
      return Fq (P mod Q);
   end Mul;

   function Reduce (X : Wide) return Fq is
   begin
      return Fq (X mod Q);
   end Reduce;

   function To_Centered (A : Fq) return Integer_32 is
   begin
      if A > Q / 2 then
         return A - Q;          --  maps (q/2, q-1] to (-q/2, -1]
      else
         return A;              --  [0, q/2] stays
      end if;
   end To_Centered;

end LTHING_MLDSA_Field;
