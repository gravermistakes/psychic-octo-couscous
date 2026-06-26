--  test_judicial_suites — suite-selector boundary coverage for LTHING_Judicial.
--
--  Covers gaps not hit by test_judicial (suite 0x0001) or test_judicial87
--  (suite 0x0002): the cross-suite PK-size mismatch and all unknown suites.
--
--    T1: suite 0x0001 with ML-DSA-87-size PK (2592 B) -> Bad_Length
--        (PK size must match the suite; mirror of test_judicial87 T2)
--    T2: suite 0x0000 (reserved)  -> Bad_Length
--    T3: suite 0x0003 (unknown)   -> Bad_Length
--    T4: suite 0xFFFF (unknown)   -> Bad_Length
pragma SPARK_Mode (Off);

with LTHING_Types;     use LTHING_Types;
with LTHING_Judicial;  use LTHING_Judicial;
with LTHING_Keccak;
with LTHING_MLDSA87;
with Interfaces;       use Interfaces;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;

procedure Test_Judicial_Suites is

   Sig_Bytes_65 : constant := 3309;   --  LTHING_MLDSA65.Sig_Bytes
   PK_Bytes_65  : constant := 1952;   --  LTHING_MLDSA65.PK_Bytes
   PK_Bytes_87  : constant := LTHING_MLDSA87.PK_Bytes;  --  2592

   Fails : Natural := 0;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;

   function L512 (Input : Byte_Array) return Digest is
      Buf : Byte_Array (0 .. 63) := (others => 0);
      R   : Digest := (others => 0);
   begin
      LTHING_Keccak.Sponge
        (Input  => Input, Rate => LTHING_Keccak.Rate_SHA3_512,
         Domain => LTHING_Keccak.Domain_SHAKE, Output => Buf);
      for I in Digest_Index loop R (I) := Buf (I); end loop;
      return R;
   end L512;

   procedure Put_U16 (D : in out Byte_Array; Off : Natural; V : Unsigned_16) is
   begin
      D (Off)     := Byte (Shift_Right (V, 8) and 16#FF#);
      D (Off + 1) := Byte (V and 16#FF#);
   end Put_U16;

   procedure Put_U32 (D : in out Byte_Array; Off : Natural; V : Unsigned_32) is
   begin
      D (Off)     := Byte (Shift_Right (V, 24) and 16#FF#);
      D (Off + 1) := Byte (Shift_Right (V, 16) and 16#FF#);
      D (Off + 2) := Byte (Shift_Right (V, 8)  and 16#FF#);
      D (Off + 3) := Byte (V and 16#FF#);
   end Put_U32;

   --  §2/§3 header for suite 0x0001 (ML-DSA-65) into D(0..39).
   procedure Put_Header_65
     (D : in out Byte_Array; Body_Len, Seal_Len : Natural)
   is
      Pre : constant Byte_Array (0 .. 13) :=
        (16#00#, 16#00#, 16#00#, 16#0B#, 16#0D#, 16#EE#, 16#D0#,
         16#00#, 16#00#, 16#00#, 16#04#, 16#A4#, 16#40#, 16#10#);
   begin
      for I in Pre'Range loop D (I) := Pre (I); end loop;
      Put_U16 (D, 14, 16#0001#);
      for I in 16 .. 23 loop D (I) := 0; end loop;
      Put_U32 (D, 24, Unsigned_32 (Body_Len));
      Put_U32 (D, 28, Unsigned_32 (Seal_Len));
      Put_U32 (D, 32, Unsigned_32 (Sig_Bytes_65));
      Put_U32 (D, 36, 0);
   end Put_Header_65;

   --  Build a complete, well-formed genesis envelope (suite 0x0001, Body_Len=8,
   --  Seal_Len=196). Seal hashes are correct; signature region is all-zeros.
   procedure Build_Genesis_65
     (Body_Byte : Byte; Env : out Byte_Array; Last : out Natural)
   is
      Body_Len : constant := 8;
      Seal_Len : constant := 196;
      Body_Off : constant := 40;
      Seal_Off : constant := Body_Off + Body_Len;
      Sig_Off  : constant := Seal_Off + Seal_Len;
      Art, Chain, Sid : Digest;
      Prev : constant Byte_Array (0 .. 63) := (others => 0);
   begin
      Env := (others => 0);
      Put_Header_65 (Env, Body_Len, Seal_Len);
      for I in 0 .. Body_Len - 1 loop Env (Body_Off + I) := Body_Byte; end loop;

      Art := L512 (Env (Body_Off .. Body_Off + Body_Len - 1));

      declare
         CBuf : Byte_Array (0 .. 127) := (others => 0);
      begin
         for I in 0 .. 63 loop CBuf (I)      := Prev (I); end loop;
         for I in 0 .. 63 loop CBuf (64 + I) := Art  (I); end loop;
         Chain := L512 (CBuf);
      end;

      Put_U16 (Env, Seal_Off, 0);
      for I in 0 .. 63 loop Env (Seal_Off + 2 + I)   := Art   (I); end loop;
      for I in 0 .. 63 loop Env (Seal_Off + 66 + I)  := Chain (I); end loop;
      Env (Seal_Off + 130) := 16#00#;
      Env (Seal_Off + 131) := 16#00#;

      declare
         SBuf : Byte_Array (0 .. 130) := (others => 0);
      begin
         SBuf (0) := Env (Seal_Off); SBuf (1) := Env (Seal_Off + 1);
         for I in 0 .. 63 loop SBuf (2 + I)  := Art   (I); end loop;
         for I in 0 .. 63 loop SBuf (66 + I) := Chain (I); end loop;
         SBuf (130) := 16#00#;
         Sid := L512 (SBuf);
      end;
      for I in 0 .. 63 loop Env (Seal_Off + 132 + I) := Sid (I); end loop;

      Last := Sig_Off + Sig_Bytes_65 - 1;
   end Build_Genesis_65;

   Zero : constant Digest := (others => 0);
   PK65 : constant Byte_Array (0 .. PK_Bytes_65 - 1) := (others => 16#AB#);
   PK87 : constant Byte_Array (0 .. PK_Bytes_87 - 1) := (others => 16#AB#);
   R    : Verified_Record;
   --  40 + 8 + 196 + 3309 = 3553; 4 KiB suffices.
   Env  : Byte_Array (0 .. 4095) := (others => 0);
   Last : Natural;

begin
   --  T1: suite 0x0001 with ML-DSA-87-size PK (2592 B) → Bad_Length.
   --  Exp_PKB for 0x0001 = 1952; 2592 ≠ 1952 → Bad_Length.
   Build_Genesis_65 (16#5A#, Env, Last);
   Parse_And_Verify (Env (0 .. Last), Zero, PK87, R);
   Chk ("65: 87-size PK -> Bad_Length",
        (not R.Trusted) and then R.Status = Bad_Length);

   --  T2-T4: unknown suite values.  The suite check fires after the non-zero
   --  SL/SigL check but before the total-length check, so a valid-sized
   --  envelope with a patched suite byte is sufficient.

   --  T2: suite 0x0000 (reserved) → Bad_Length.
   Build_Genesis_65 (16#5A#, Env, Last);
   Put_U16 (Env, 14, 16#0000#);
   Parse_And_Verify (Env (0 .. Last), Zero, PK65, R);
   Chk ("suite 0x0000 (reserved) -> Bad_Length",
        (not R.Trusted) and then R.Status = Bad_Length);

   --  T3: suite 0x0003 (unknown) → Bad_Length.
   Build_Genesis_65 (16#5A#, Env, Last);
   Put_U16 (Env, 14, 16#0003#);
   Parse_And_Verify (Env (0 .. Last), Zero, PK65, R);
   Chk ("suite 0x0003 (unknown) -> Bad_Length",
        (not R.Trusted) and then R.Status = Bad_Length);

   --  T4: suite 0xFFFF (unknown) → Bad_Length.
   Build_Genesis_65 (16#5A#, Env, Last);
   Put_U16 (Env, 14, 16#FFFF#);
   Parse_And_Verify (Env (0 .. Last), Zero, PK65, R);
   Chk ("suite 0xFFFF (unknown) -> Bad_Length",
        (not R.Trusted) and then R.Status = Bad_Length);

   New_Line;
   if Fails = 0 then
      Put_Line ("JUDICIAL-SUITES GATE PASSED (4 suite-boundary checks)");
   else
      Put_Line ("JUDICIAL-SUITES FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Judicial_Suites;
