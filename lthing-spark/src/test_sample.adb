--  test_sample — SampleInBall (tau=49, coeffs +-1) + ExpandA determinism +
--  input-sensitivity (adversarial). c_tilde / rho sourced from KAT vector V31.
with LTHING_MLDSA_Sample; use LTHING_MLDSA_Sample;
with LTHING_MLDSA_NTT;    use LTHING_MLDSA_NTT;     --  Poly
with LTHING_MLDSA_Field;  use LTHING_MLDSA_Field;   --  Fq, To_Centered
with MLDSA_KAT_Vectors;
with LTHING_Types;        use LTHING_Types;
with Interfaces;          use Interfaces;
with Ada.Text_IO;         use Ada.Text_IO;
with Ada.Command_Line;
procedure Test_Sample is
   package M renames MLDSA_KAT_Vectors;
   V     : M.Vector renames M.V31;
   Ct    : Byte_Array (0 .. 47);
   C     : Poly;
   Fails : Natural := 0;
   PM1   : Boolean := True;
   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;
   function Nonzero (P : Poly) return Natural is
      N : Natural := 0;
   begin
      for I in P'Range loop if P (I) /= 0 then N := N + 1; end if; end loop;
      return N;
   end Nonzero;
begin
   for I in 0 .. 47 loop Ct (I) := V.Sig (I); end loop;   --  c_tilde = sig[0..47]
   Sample_In_Ball (Ct, C);
   Chk ("SampleInBall: exactly tau=49 nonzero coeffs", Nonzero (C) = 49);
   for I in C'Range loop
      if C (I) /= 0 and then abs (To_Centered (C (I))) /= 1 then PM1 := False; end if;
   end loop;
   Chk ("SampleInBall: every nonzero coeff centers to +-1", PM1);

   --  Adversarial input-sensitivity: a flipped c_tilde byte changes the challenge.
   declare
      Ct2  : Byte_Array (0 .. 47) := Ct;
      C2   : Poly;
      Diff : Boolean := False;
   begin
      Ct2 (0) := Ct2 (0) xor 1;
      Sample_In_Ball (Ct2, C2);
      for I in C'Range loop if C (I) /= C2 (I) then Diff := True; end if; end loop;
      Chk ("SampleInBall input-sensitive (flipped c_tilde changes output)", Diff);
   end;

   --  ExpandA determinism.
   declare
      Rho : Byte_Array (0 .. 31);
      A1, A2 : Matrix;
      Det : Boolean := True;
   begin
      for I in 0 .. 31 loop Rho (I) := V.PK (I); end loop;
      Expand_A (Rho, A1);
      Expand_A (Rho, A2);
      for R in 0 .. 5 loop
         for S in 0 .. 4 loop
            for J in 0 .. 255 loop
               if A1 (R, S) (J) /= A2 (R, S) (J) then Det := False; end if;
            end loop;
         end loop;
      end loop;
      Chk ("ExpandA deterministic (two runs equal)", Det);
   end;

   New_Line;
   if Fails = 0 then Put_Line ("SAMPLE GATE PASSED: SampleInBall tau=49/+-1 + ExpandA determinism");
   else Put_Line ("SAMPLE FAILURES:" & Fails'Image);
        Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Sample;
