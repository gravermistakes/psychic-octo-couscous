--  test_codec — pk/sig decode on an AUTHORITATIVE vector (V31) + fail-closed hint.
--  Genuine: decodes a real ML-DSA-65 key/signature and checks ranges, then a
--  one-byte hint corruption must drive Sig_Decode to Ok=False (Alg 21 ⊥).
with LTHING_MLDSA_Codec; use LTHING_MLDSA_Codec;
with LTHING_MLDSA65;      use LTHING_MLDSA65;
with MLDSA_KAT_Vectors;
with LTHING_Types;        use LTHING_Types;
with Interfaces;          use Interfaces;
with Ada.Text_IO;         use Ada.Text_IO;
with Ada.Command_Line;
procedure Test_Codec is
   package M renames MLDSA_KAT_Vectors;
   V : M.Vector renames M.V31;
   Rho     : Rho_Array;
   T1      : T1_Vec;
   C_Tilde : C_Tilde_Array;
   Z       : Z_Vec;
   H       : H_Vec;
   Ok      : Boolean;
   Fails   : Natural := 0;
   T1_OK   : Boolean := True;
   Z_OK    : Boolean := True;
   HW      : Natural := 0;
   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;
begin
   Pk_Decode (V.PK, Rho, T1);
   Chk ("Rho(0) = pk(0)", Rho (0) = V.PK (0));
   for I in T1_Vec'Range loop
      for J in 0 .. 255 loop
         if T1 (I) (J) < 0 or else T1 (I) (J) > 1023 then T1_OK := False; end if;
      end loop;
   end loop;
   Chk ("T1 coeffs in 0..1023 (real key decode)", T1_OK);

   Sig_Decode (V.Sig, C_Tilde, Z, H, Ok);
   Chk ("Sig_Decode Ok=True on valid vector", Ok);
   Chk ("C_Tilde(0) = sig(0)", C_Tilde (0) = V.Sig (0));
   for I in Z_Vec'Range loop
      for J in 0 .. 255 loop
         if Z (I) (J) < 0 or else Z (I) (J) > Q - 1 then Z_OK := False; end if;
      end loop;
   end loop;
   Chk ("Z coeffs canonical 0..Q-1", Z_OK);
   for I in H_Vec'Range loop
      for J in 0 .. 255 loop
         if H (I) (J) = 1 then HW := HW + 1; end if;
      end loop;
   end loop;
   Chk ("hint weight <= omega", HW <= Omega);

   --  Adversarial: corrupt a hint end-pointer (> omega) -> fail-closed (Alg 21).
   declare
      Bad      : Signature := V.Sig;
      Hint_Off : constant := Sig_Bytes - (Omega + K_Dim);   --  3248
   begin
      Bad (Hint_Off + Omega) := 200;     --  y[omega+0] = 200 > omega(55) -> ⊥
      Sig_Decode (Bad, C_Tilde, Z, H, Ok);
      Chk ("corrupted hint end-pointer -> Ok=False (fail-closed)", not Ok);
   end;

   New_Line;
   if Fails = 0 then Put_Line ("CODEC GATE PASSED: pk/sig decode + fail-closed hint");
   else Put_Line ("CODEC FAILURES:" & Fails'Image);
        Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Codec;
