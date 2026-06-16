------------------------------------------------------------------------------
--  test_round — relational gate for the ML-DSA rounding / hint layer.
--
--  No frozen constants. Every assertion is a property:
--    * Decompose recomposes: (r1*2g2 + r0) mod q = r mod q (incl. top case)
--    * Power2Round recomposes exactly: r1*2^d + r0 = r
--    * Hint round-trip: Use_Hint(hh, r) = High_Bits((r+z) mod q) where hh is
--      derived from whether the high bits changed
--    * range invariants of High_Bits / Low_Bits / Use_Hint
--    * boundaries: r = q-1, gamma2, gamma2+1, 0
--    * W1_Encode nibble packing is invertible
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

with LTHING_MLDSA_Round; use LTHING_MLDSA_Round;
with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;
with LTHING_Types;       use LTHING_Types;
with Interfaces;         use Interfaces;
with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Command_Line;

procedure Test_Round is

   Fails : Natural := 0;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then
         Put_Line ("[PASS] " & Name);
      else
         Put_Line ("[FAIL] " & Name);
         Fails := Fails + 1;
      end if;
   end Chk;

   procedure Chk_Eq (Name : String; Got, Want : Integer_64) is
   begin
      if Got = Want then
         Put_Line ("[PASS] " & Name);
      else
         Put_Line ("[FAIL] " & Name
                   & " got=" & Got'Image & " want=" & Want'Image);
         Fails := Fails + 1;
      end if;
   end Chk_Eq;

   --  A spread of representative residues covering the whole range.
   Samples : constant array (Positive range <>) of Fq :=
     (0, 1, 2, 100, 8_191, 8_192, 8_193,
      Gamma2 - 1, Gamma2, Gamma2 + 1,
      Two_Gamma2 - 1, Two_Gamma2, Two_Gamma2 + 1,
      Gamma1, 1_000_000, 4_000_000, Q / 2, Q - 2, Q - 1);

begin
   ----------------------------------------------------------------------
   --  Power2Round: exact recomposition r1*2^d + r0 = r, ranges hold.
   ----------------------------------------------------------------------
   for S of Samples loop
      declare
         R1 : P2R_High;
         R0 : P2R_Low;
      begin
         Power2Round (S, R1, R0);
         Chk_Eq ("Power2Round recompose r=" & S'Image,
                 Integer_64 (R1) * Two_Pow_D + Integer_64 (R0),
                 Integer_64 (S));
      end;
   end loop;

   ----------------------------------------------------------------------
   --  Decompose: recomposition mod q, and range of r1/r0.
   ----------------------------------------------------------------------
   for S of Samples loop
      declare
         R1 : Bins;
         R0 : Low_Range;
      begin
         Decompose (S, R1, R0);
         Chk_Eq ("Decompose recompose mod q r=" & S'Image,
                 (Integer_64 (R1) * Two_Gamma2 + Integer_64 (R0)) mod Q,
                 Integer_64 (S) mod Q);
         Chk ("Decompose r1 in 0..15 r=" & S'Image,
              R1 in 0 .. 15);
         Chk ("Decompose r0 in (-g2,g2] r=" & S'Image,
              R0 > -Gamma2 and then R0 <= Gamma2);
         --  High_Bits / Low_Bits agree with Decompose components.
         Chk ("High_Bits = Decompose.r1 r=" & S'Image,
              High_Bits (S) = R1);
         Chk ("Low_Bits = Decompose.r0 r=" & S'Image,
              Low_Bits (S) = R0);
      end;
   end loop;

   ----------------------------------------------------------------------
   --  Top special case must produce r1 = 0 exactly at r = q-1.
   ----------------------------------------------------------------------
   Chk ("Decompose top case High_Bits(q-1) = 0",
        High_Bits (Q - 1) = 0);

   ----------------------------------------------------------------------
   --  Hint round-trip: for r and a small offset z, the hint recovers the
   --  high bits of (r+z) mod q.  Property, not a frozen value.
   ----------------------------------------------------------------------
   declare
      Offsets : constant array (Positive range <>) of Integer_32 :=
        (-Gamma2, -1000, -1, 1, 2, 100, 1000, Gamma2);
   begin
      for S of Samples loop
         for Z of Offsets loop
            declare
               --  (r + z) mod q, reduced into Fq via field Sub/Add.
               Rz_64 : constant Integer_64 :=
                 ((Integer_64 (S) + Integer_64 (Z)) mod Q + Q) mod Q;
               Rz    : constant Fq := Fq (Rz_64);
               H_R   : constant Bins := High_Bits (S);
               H_Rz  : constant Bins := High_Bits (Rz);
               HH    : constant Integer_32 := (if H_R /= H_Rz then 1 else 0);
            begin
               Chk ("Hint round-trip r=" & S'Image & " z=" & Z'Image,
                    Use_Hint (HH, S) = H_Rz);
               Chk ("Use_Hint in 0..15 r=" & S'Image & " z=" & Z'Image,
                    Use_Hint (HH, S) in 0 .. 15);
            end;
         end loop;
      end loop;
   end;

   ----------------------------------------------------------------------
   --  Explicit boundaries called out in the task.
   ----------------------------------------------------------------------
   declare
      procedure Boundary (Name : String; R : Fq) is
         R1 : Bins;
         R0 : Low_Range;
      begin
         Decompose (R, R1, R0);
         Chk_Eq ("Boundary recompose " & Name,
                 (Integer_64 (R1) * Two_Gamma2 + Integer_64 (R0)) mod Q,
                 Integer_64 (R) mod Q);
         --  With zero hint, Use_Hint is the identity on high bits.
         Chk ("Boundary Use_Hint(0)=High_Bits " & Name,
              Use_Hint (0, R) = High_Bits (R));
      end Boundary;
   begin
      Boundary ("q-1", Q - 1);
      Boundary ("gamma2", Gamma2);
      Boundary ("gamma2+1", Gamma2 + 1);
      Boundary ("0", 0);
   end;

   ----------------------------------------------------------------------
   --  W1_Encode: nibble packing is invertible (low nibble = w1(2t)).
   ----------------------------------------------------------------------
   declare
      W : Poly;
      B : W1_Bytes;
   begin
      for I in W'Range loop
         W (I) := Fq (Integer_32 (I) mod 16);   --  each coeff in 0..15
      end loop;
      B := W1_Encode (W);
      declare
         All_OK : Boolean := True;
      begin
         for T in 0 .. 127 loop
            if Integer_32 (B (T) mod 16) /= Integer_32 (W (2 * T))
              or else Integer_32 (B (T) / 16) /= Integer_32 (W (2 * T + 1))
            then
               All_OK := False;
            end if;
         end loop;
         Chk ("W1_Encode nibble packing invertible", All_OK);
      end;
   end;

   ----------------------------------------------------------------------
   --  Inf_Norm_OK: relational — passes below bound, fails on a spike.
   ----------------------------------------------------------------------
   declare
      P : Poly := (others => 5);   --  centered |5| < small bounds
   begin
      Chk ("Inf_Norm_OK true for small coeffs", Inf_Norm_OK (P, 6));
      Chk ("Inf_Norm_OK false at bound", not Inf_Norm_OK (P, 5));
      P (42) := Q - 1;             --  centered = -1, abs 1
      Chk ("Inf_Norm_OK handles centered negatives", Inf_Norm_OK (P, 6));
      P (42) := 200;               --  centered 200, abs 200
      Chk ("Inf_Norm_OK false on spike", not Inf_Norm_OK (P, 100));
   end;

   New_Line;
   if Fails = 0 then
      Put_Line ("ROUND GATE PASSED: rounding/hint layer correct (tested)");
   else
      Put_Line ("ROUND FAILURES:" & Fails'Image);
      Ada.Text_IO.Put_Line ("");
   end if;

   if Fails /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Round;
