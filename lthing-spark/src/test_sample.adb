------------------------------------------------------------------------------
--  test_sample — relational self-gates for ML-DSA sampling (FIPS 204)
--
--  No frozen / hand-written vectors. Gates are RELATIONAL / property facts:
--    * Sample_In_Ball produces exactly tau=49 nonzero coeffs, each centered
--      to +1 or -1 (Alg. 29 invariant), for two distinct c_tilde inputs.
--    * Expand_A is deterministic (run twice -> equal) and every coefficient
--      of every A(r,s) lies in 0 .. q-1 (Alg. 30/32 range invariant).
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

with LTHING_MLDSA_Sample; use LTHING_MLDSA_Sample;
with LTHING_MLDSA_NTT;    use LTHING_MLDSA_NTT;
with LTHING_MLDSA_Field;  use LTHING_MLDSA_Field;
with LTHING_Types;        use LTHING_Types;
with Interfaces;          use Interfaces;
with Ada.Text_IO;         use Ada.Text_IO;
with Ada.Command_Line;    use Ada.Command_Line;

procedure Test_Sample is

   Q_Const : constant := 8_380_417;
   Fails   : Natural := 0;

   procedure Check (Cond : Boolean; Msg : String) is
   begin
      if Cond then
         Put_Line ("[PASS] " & Msg);
      else
         Put_Line ("[FAIL] " & Msg);
         Fails := Fails + 1;
      end if;
   end Check;

   ---------------------------------------------------------------------------
   --  Sample_In_Ball gate for one c_tilde fill value.
   ---------------------------------------------------------------------------
   procedure Gate_Ball (Fill : Byte; Label : String) is
      C_Tilde : Byte_Array (0 .. 47) := (others => Fill);   --  48 bytes
      C       : Poly;
      Cnt     : Natural;
      Pm_Ok   : Boolean := True;
   begin
      Sample_In_Ball (C_Tilde, C);
      Cnt := Count_Nonzero (C);
      Check (Cnt = 49,
             "SampleInBall(" & Label & "): Count_Nonzero = 49 (got"
             & Cnt'Image & ")");

      --  every nonzero coeff centers to +1 or -1
      for I in C'Range loop
         if C (I) /= 0 then
            declare
               Ctr : constant Integer_32 := To_Centered (C (I));
            begin
               if Ctr /= 1 and then Ctr /= -1 then
                  Pm_Ok := False;
               end if;
            end;
         end if;
      end loop;
      Check (Pm_Ok,
             "SampleInBall(" & Label & "): every nonzero coeff centers to +-1");
   end Gate_Ball;

   ---------------------------------------------------------------------------
   --  Equality of two matrices (for determinism gate).
   ---------------------------------------------------------------------------
   function Eq (A, B : Matrix) return Boolean is
   begin
      for R in A'Range (1) loop
         for S in A'Range (2) loop
            for I in 0 .. 255 loop
               if A (R, S) (I) /= B (R, S) (I) then
                  return False;
               end if;
            end loop;
         end loop;
      end loop;
      return True;
   end Eq;

   Rho  : Byte_Array (0 .. 31);
   A1   : Matrix;
   A2   : Matrix;
   Rng  : Boolean := True;

begin
   Put_Line ("== ML-DSA sampling self-gates (FIPS 204, relational) ==");

   --  GATE 1+2: Sample_In_Ball for two distinct c_tilde fills.
   Gate_Ball (16#01#, "0x01");
   Gate_Ball (16#AB#, "0xAB");

   --  fixed rho (deterministic, distinct bytes so each (r,s) seed differs)
   for I in Rho'Range loop
      Rho (I) := Byte ((I * 7 + 3) mod 256);
   end loop;

   --  GATE 3: Expand_A determinism (run twice -> equal).
   Expand_A (Rho, A1);
   Expand_A (Rho, A2);
   Check (Eq (A1, A2), "Expand_A is deterministic (two runs equal)");

   --  GATE 4: every coeff of every A(r,s) is in 0 .. q-1.
   for R in A1'Range (1) loop
      for S in A1'Range (2) loop
         for I in 0 .. 255 loop
            if not (Integer (A1 (R, S) (I)) in 0 .. Q_Const - 1) then
               Rng := False;
            end if;
         end loop;
      end loop;
   end loop;
   Check (Rng, "Expand_A: every coeff in 0 .. q-1");

   New_Line;
   if Fails = 0 then
      Put_Line ("ALL GATES PASSED: ML-DSA sampling self-gates green");
   else
      Put_Line ("FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Sample;
