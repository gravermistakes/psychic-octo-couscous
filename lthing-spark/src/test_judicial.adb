with LTHING_Types;     use LTHING_Types;
with LTHING_Judicial;  use LTHING_Judicial;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;

procedure Test_Judicial is

   --  Stamp the fixed §2 LTHING JD v1.0 header prefix into Doc (0 .. 13):
   --    00 00 00 0B 0D EE D0 00 00 00  04 A4 40  10
   procedure Put_JD_Header (Doc : in out Byte_Array) is
   begin
      Doc (Doc'First + 0)  := 16#00#;
      Doc (Doc'First + 1)  := 16#00#;
      Doc (Doc'First + 2)  := 16#00#;
      Doc (Doc'First + 3)  := 16#0B#;
      Doc (Doc'First + 4)  := 16#0D#;
      Doc (Doc'First + 5)  := 16#EE#;
      Doc (Doc'First + 6)  := 16#D0#;
      Doc (Doc'First + 7)  := 16#00#;
      Doc (Doc'First + 8)  := 16#00#;
      Doc (Doc'First + 9)  := 16#00#;
      Doc (Doc'First + 10) := 16#04#;   --  JD doctype hi (= Judicial_DocType)
      Doc (Doc'First + 11) := 16#A4#;   --  'J''D' block
      Doc (Doc'First + 12) := 16#40#;   --  doctype null terminator
      Doc (Doc'First + 13) := 16#10#;   --  version v1.0
   end Put_JD_Header;

   Doc   : Byte_Array (0 .. 99) := (others => 0);
   PK    : Byte_Array (0 .. 31) := (others => 16#AB#);
   Zero  : Digest := (others => 0);
   R     : Verified_Record;
   Fails : Natural := 0;
begin
   Put_JD_Header (Doc);

   --  T1: Parse_Unverified must NEVER be trusted
   Parse_Unverified (Doc, R);
   if not R.Trusted then Put_Line ("[PASS] Parse_Unverified never trusted");
   else Put_Line ("[FAIL] Parse_Unverified returned trusted"); Fails := Fails + 1; end if;

   --  T2: full verify on a well-formed JD header with no valid ML-DSA sig must
   --  fail closed at the signature gate (C1 chain / H1 verifier deferred until
   --  format spec §3 defines the signature and chain-hash fields).
   Parse_And_Verify (Doc, Zero, PK, R);
   if not R.Trusted and then R.Status = Signature_Invalid then
      Put_Line ("[PASS] Parse_And_Verify fails closed at signature gate");
   else Put_Line ("[FAIL] verify did not fail closed: " & R.Status'Image); Fails := Fails + 1; end if;

   --  T3: too-short envelope -> Bad_Envelope, not trusted
   declare
      Tiny : Byte_Array (0 .. 9) := (others => 0);
   begin
      Parse_And_Verify (Tiny, Zero, PK, R);
      if not R.Trusted and then R.Status = Bad_Envelope then
         Put_Line ("[PASS] short envelope rejected");
      else Put_Line ("[FAIL] short envelope: " & R.Status'Image); Fails := Fails + 1; end if;
   end;

   --  T4: corrupted doctype block -> Bad_Magic (now a reachable, real gate;
   --  previously dead because Magic_Ok checked the wrong offset).
   declare
      Bad : Byte_Array (0 .. 99) := (others => 0);
   begin
      Put_JD_Header (Bad);
      Bad (Bad'First + 11) := 16#FF#;   --  break the JD doctype block
      Parse_And_Verify (Bad, Zero, PK, R);
      if not R.Trusted and then R.Status = Bad_Magic then
         Put_Line ("[PASS] corrupted doctype rejected as Bad_Magic");
      else Put_Line ("[FAIL] bad doctype: " & R.Status'Image); Fails := Fails + 1; end if;
   end;

   --  T5: corrupted fixed preamble -> Bad_Magic.
   declare
      Bad : Byte_Array (0 .. 99) := (others => 0);
   begin
      Put_JD_Header (Bad);
      Bad (Bad'First + 3) := 16#FF#;    --  break the fixed B0DEED preamble
      Parse_And_Verify (Bad, Zero, PK, R);
      if not R.Trusted and then R.Status = Bad_Magic then
         Put_Line ("[PASS] corrupted preamble rejected as Bad_Magic");
      else Put_Line ("[FAIL] bad preamble: " & R.Status'Image); Fails := Fails + 1; end if;
   end;

   --  T6: the historical fake header (doctype byte forced at offset 9) must NOT
   --  validate any more — it is part of the null preamble, so it is Bad_Magic.
   declare
      Old_Fake : Byte_Array (0 .. 99) := (others => 0);
   begin
      Old_Fake (9) := 16#04#;           --  what the buggy gate used to accept
      Parse_And_Verify (Old_Fake, Zero, PK, R);
      if not R.Trusted and then R.Status = Bad_Magic then
         Put_Line ("[PASS] legacy offset-9 fake header no longer accepted");
      else Put_Line ("[FAIL] legacy fake header: " & R.Status'Image); Fails := Fails + 1; end if;
   end;

   --  T7: invariant — trusted iff verified, can never desync
   if (R.Trusted = (R.Status = Verified)) then
      Put_Line ("[PASS] Trusted<->Verified invariant holds");
   else Put_Line ("[FAIL] invariant broken"); Fails := Fails + 1; end if;

   New_Line;
   if Fails = 0 then
      Put_Line ("ALL RUNTIME TESTS PASS (matches proven contracts)");
   else
      Put_Line ("RUNTIME FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Judicial;
