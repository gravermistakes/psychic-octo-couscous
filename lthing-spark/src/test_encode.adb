--  test_encode — round-trip property gate for the ML-DSA-65 encoders.
--
--  The encoders (Pk_Encode/Sig_Encode/Simple_Bit_Pack) are validated against
--  the already-KAT-anchored decoders by the relational identity
--      decode(encode(x)) = x
--  over pseudo-random in-range inputs. This is a property fact (per CLAUDE.md),
--  not a self-derived magic vector: it ties the new packers to the proven
--  unpackers without asserting any digest we computed ourselves.
pragma SPARK_Mode (Off);

with LTHING_Types;       use LTHING_Types;
with LTHING_MLDSA65;     use LTHING_MLDSA65;
with LTHING_MLDSA_Codec; use LTHING_MLDSA_Codec;
with Interfaces;         use Interfaces;
with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Command_Line;   use Ada.Command_Line;

procedure Test_Encode is

   Fails : Natural := 0;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;

   --  Deterministic LCG (numerical-recipes constants); no external entropy.
   State : Unsigned_64 := 16#2545F4914F6CDD1D#;
   function Next return Unsigned_64 is
   begin
      State := State * 6364136223846793005 + 1442695040888963407;
      return State;
   end Next;
   function Rand_Mod (M : Positive) return Natural is
     (Natural (Shift_Right (Next, 33) mod Unsigned_64 (M)));

begin
   ---------------------------------------------------------------------------
   --  T1: pkEncode round-trip — rho (32 B) + t1 (k polys, coeffs 0..1023).
   ---------------------------------------------------------------------------
   declare
      Rho  : Rho_Array := (others => 0);
      T1   : T1_Vec := (others => (others => 0));
      Rho2 : Rho_Array;
      T12  : T1_Vec;
      Ok   : Boolean := True;
   begin
      for I in Rho_Array'Range loop Rho (I) := Byte (Rand_Mod (256)); end loop;
      for I in T1_Vec'Range loop
         for J in T1 (I)'Range loop
            T1 (I) (J) := LTHING_MLDSA_Codec.Coeff (Rand_Mod (1024));   --  10-bit
         end loop;
      end loop;

      Pk_Decode (Pk_Encode (Rho, T1), Rho2, T12);

      for I in Rho_Array'Range loop
         if Rho2 (I) /= Rho (I) then Ok := False; end if;
      end loop;
      for I in T1_Vec'Range loop
         for J in T1 (I)'Range loop
            if T12 (I) (J) /= T1 (I) (J) then Ok := False; end if;
         end loop;
      end loop;
      Chk ("pkDecode(pkEncode(rho,t1)) = (rho,t1)", Ok);
   end;

   ---------------------------------------------------------------------------
   --  T2: sigEncode round-trip — c_tilde + z (centered band) + valid hint.
   ---------------------------------------------------------------------------
   declare
      CT   : C_Tilde_Array := (others => 0);
      Z    : Z_Vec := (others => (others => 0));
      H    : H_Vec := (others => (others => 0));
      CT2  : C_Tilde_Array;
      Z2   : Z_Vec;
      H2   : H_Vec;
      Ok2  : Boolean;
      Same : Boolean := True;
   begin
      for I in C_Tilde_Array'Range loop CT (I) := Byte (Rand_Mod (256)); end loop;

      --  z: centered c in -(gamma1-1) .. gamma1, stored canonical in 0..Q-1.
      for I in Z_Vec'Range loop
         for J in Z (I)'Range loop
            declare
               C : constant Integer := Rand_Mod (2 * Gamma1) - (Gamma1 - 1);
            begin
               Z (I) (J) := LTHING_MLDSA_Codec.Coeff (if C < 0 then C + Q else C);
            end;
         end loop;
      end loop;

      --  hint: <= Omega set bits total; strictly increasing positions per poly.
      --  9 per poly * 6 polys = 54 <= Omega (55).
      for I in H_Vec'Range loop
         for T in 0 .. 8 loop
            H (I) (5 + T * 25 + I) := 1;   --  distinct, increasing in J
         end loop;
      end loop;

      Sig_Decode (Sig_Encode (CT, Z, H), CT2, Z2, H2, Ok2);

      for I in C_Tilde_Array'Range loop
         if CT2 (I) /= CT (I) then Same := False; end if;
      end loop;
      for I in Z_Vec'Range loop
         for J in Z (I)'Range loop
            if Z2 (I) (J) /= Z (I) (J) then Same := False; end if;
         end loop;
      end loop;
      for I in H_Vec'Range loop
         for J in H (I)'Range loop
            if H2 (I) (J) /= H (I) (J) then Same := False; end if;
         end loop;
      end loop;

      Chk ("sigDecode reports Ok on encoded hint", Ok2);
      Chk ("sigDecode(sigEncode(ct,z,h)) = (ct,z,h)", Same);
   end;

   New_Line;
   if Fails = 0 then
      Put_Line ("ENCODE GATE PASSED: pk/sig encoders invert the proven decoders");
   else
      Put_Line ("RUNTIME FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Encode;
