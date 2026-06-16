------------------------------------------------------------------------------
--  test_envelope.adb — tests for LTHING.Envelope (§6 parser requirements)
--
--  Covers:
--    §6.1  Preamble rejection
--    §6.2  DocType ASCII validation
--    §6.3  Suite 0x0000 rejection
--    §6.4  Seal length = 0 rejection
--    §6.5  Sig length = 0 rejection
--    §6.6  Suite-defined seal length mismatch
--    §6.7  Suite-defined sig length mismatch
--    §6.8  Geometry overflow / insufficient data
--    +     Positive: valid JD v1.0 suite 0x0001 header parses clean
--
--  Lead Engineer — Rune auf Opus (4.6)
--  Co-authored with Anja Evermoor.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Command_Line;      use Ada.Command_Line;
with Interfaces;             use Interfaces;
with LTHING_Types;           use LTHING_Types;
with LTHING_Envelope;        use LTHING_Envelope;

procedure Test_Envelope is

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   procedure Check (Name : String; Cond : Boolean) is
   begin
      if Cond then
         Put_Line ("[PASS] " & Name);
         Pass_Count := Pass_Count + 1;
      else
         Put_Line ("[FAIL] " & Name);
         Fail_Count := Fail_Count + 1;
      end if;
   end Check;

   --  Build a minimal valid JD v1.0 suite 0x0001 header (164 bytes)
   --  with a dummy body of 4 bytes and dummy signature of 3309 bytes.
   --  Total = 164 + 4 + 3309 = 3477 bytes.
   --  We only need the structural parse to succeed, so seal/chain/sig
   --  are zeroed (verification is a separate test).
   Valid_Total : constant := 164 + 4 + 3309;

   function Make_Valid_Header return Byte_Array is
      D : Byte_Array (0 .. Valid_Total - 1) := (others => 0);
   begin
      --  Preamble (bytes 0-9)
      D (3)  := 16#0B#;
      D (4)  := 16#0D#;
      D (5)  := 16#EE#;
      D (6)  := 16#D0#;
      --  bytes 0,1,2,7,8,9 already 0x00

      --  DocType JD nibble-straddled (bytes 10-12)
      D (10) := 16#04#;   --  offset 0 | high nibble of 'J' (4)
      D (11) := 16#A4#;   --  low 'J' (A) | high 'D' (4)
      D (12) := 16#40#;   --  low 'D' (4) | null term (0)

      --  Version v1.0 (byte 13)
      D (13) := 16#10#;

      --  Suite 0x0001 (bytes 14-15)
      D (14) := 16#00#;
      D (15) := 16#01#;

      --  Timestamp (bytes 16-23) — leave as zeros (epoch, signer's claim)

      --  Body length = 4 (bytes 24-27)
      D (24) := 0; D (25) := 0; D (26) := 0; D (27) := 4;

      --  Seal length = 64 (bytes 28-31)
      D (28) := 0; D (29) := 0; D (30) := 0; D (31) := 64;

      --  Sig length = 3309 (bytes 32-35)
      D (32) := 0; D (33) := 0;
      D (34) := 16#0C#; D (35) := 16#ED#;

      --  Seal (bytes 36-99): zeros (placeholder)
      --  Chain hash (bytes 100-163): zeros (placeholder)
      --  Body (bytes 164-167): zeros (placeholder)
      --  Signature (bytes 168-3476): zeros (placeholder)

      return D;
   end Make_Valid_Header;

   Env : Unverified_Envelope;
   D   : Byte_Array (0 .. Valid_Total - 1);

begin
   Put_Line ("=== LTHING.Envelope parser tests ===");

   --  Test 1: valid JD v1.0 parses successfully
   D := Make_Valid_Header;
   Parse (D, Env);
   Check ("valid JD v1.0 parses as Not_Verified",
          Env.Status = Not_Verified);
   Check ("valid JD v1.0 doctype = JD",
          Env.DocType.C1 = 16#4A# and Env.DocType.C2 = 16#44#);
   Check ("valid JD v1.0 version",
          Env.Version_Maj = 1 and Env.Version_Min = 0);
   Check ("valid JD v1.0 suite = 0x0001",
          Env.Suite = 1);
   Check ("valid JD v1.0 body_length = 4",
          Env.Body_Length = 4);
   Check ("valid JD v1.0 seal_length = 64",
          Env.Seal_Length = 64);
   Check ("valid JD v1.0 sig_length = 3309",
          Env.Sig_Length = 3309);
   Check ("valid JD v1.0 body_offset = 164",
          Env.Body_Offset = 164);

   --  Test 2: truncated document (< 36 bytes)
   declare
      Short : constant Byte_Array (0 .. 20) := (others => 0);
   begin
      Parse (Short, Env);
      Check ("truncated < 36 => Bad_Envelope", Env.Status = Bad_Envelope);
   end;

   --  Test 3: bad preamble (wrong magic byte)
   D := Make_Valid_Header;
   D (5) := 16#FF#;   --  corrupt B0DEED
   Parse (D, Env);
   Check ("bad preamble => Bad_Envelope", Env.Status = Bad_Envelope);

   --  Test 4: invalid doctype (non-ASCII in first byte)
   D := Make_Valid_Header;
   --  Set doctype char 1 to 0x01 (outside 0x41-0x5A / 0x30-0x39)
   --  Nibble-straddled: byte 10 low nibble = high nibble of char 1 = 0
   --  byte 11 high nibble = low nibble of char 1 = 1
   --  So char 1 = 0x01 — invalid
   D (10) := 16#00#;  --  offset 0 | high nibble 0
   D (11) := 16#14#;  --  low nibble 1 | high nibble of char 2 = 4
   Parse (D, Env);
   Check ("invalid doctype byte => Bad_Magic", Env.Status = Bad_Magic);

   --  Test 5: suite 0x0000
   D := Make_Valid_Header;
   D (14) := 0; D (15) := 0;
   Parse (D, Env);
   Check ("suite 0x0000 => Not_Verified", Env.Status = Not_Verified);

   --  Test 6: seal_length = 0
   D := Make_Valid_Header;
   D (28) := 0; D (29) := 0; D (30) := 0; D (31) := 0;
   Parse (D, Env);
   Check ("seal_length = 0 => Bad_Length", Env.Status = Bad_Length);

   --  Test 7: sig_length = 0
   D := Make_Valid_Header;
   D (32) := 0; D (33) := 0; D (34) := 0; D (35) := 0;
   Parse (D, Env);
   Check ("sig_length = 0 => Bad_Length", Env.Status = Bad_Length);

   --  Test 8: suite 0x0001 but wrong seal length (32 instead of 64)
   D := Make_Valid_Header;
   D (28) := 0; D (29) := 0; D (30) := 0; D (31) := 32;
   Parse (D, Env);
   Check ("wrong seal_length for suite => Bad_Length",
          Env.Status = Bad_Length);

   --  Test 9: suite 0x0001 but wrong sig length
   D := Make_Valid_Header;
   D (34) := 16#FF#; D (35) := 16#FF#;  --  sig_length = 0x0000FFFF
   Parse (D, Env);
   Check ("wrong sig_length for suite => Bad_Length",
          Env.Status = Bad_Length);

   --  Test 10: valid header but document truncated (not enough body+sig)
   declare
      Trunc : Byte_Array (0 .. 200) := (others => 0);
   begin
      --  Copy the valid header into a truncated buffer
      for I in 0 .. 163 loop
         Trunc (I) := Make_Valid_Header (I);
      end loop;
      Parse (Trunc, Env);
      Check ("truncated body+sig => Bad_Length", Env.Status = Bad_Length);
   end;

   --  Summary
   New_Line;
   Put_Line ("Passed:" & Natural'Image (Pass_Count)
             & "  Failed:" & Natural'Image (Fail_Count));

   if Fail_Count > 0 then
      Set_Exit_Status (Failure);
   end if;
end Test_Envelope;
