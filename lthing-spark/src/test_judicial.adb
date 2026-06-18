with LTHING_Types;    use LTHING_Types;
with LTHING_Judicial; use LTHING_Judicial;
with Ada.Text_IO;     use Ada.Text_IO;
with Ada.Command_Line;

procedure Test_Judicial is
   Doc  : Byte_Array (0 .. 99) := (others => 0);
   PK   : Byte_Array (0 .. 31) := (others => 16#AB#);
   Zero : Digest := (others => 0);
   R    : Verified_Record;
   Fails : Natural := 0;
begin
   --  Set doctype byte (offset 9) to 0x04 so Magic_Ok passes
   Doc (9) := 16#04#;

   --  T1: Parse_Unverified must NEVER be trusted
   Parse_Unverified (Doc, R);
   if not R.Trusted then Put_Line ("[PASS] Parse_Unverified never trusted");
   else Put_Line ("[FAIL] Parse_Unverified returned trusted"); Fails := Fails + 1; end if;

   --  T2: full verify on a doc with no valid ML-DSA sig must fail closed
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

   --  T4: invariant — trusted iff verified, can never desync
   if (R.Trusted = (R.Status = Verified)) then
      Put_Line ("[PASS] Trusted<->Verified invariant holds");
   else Put_Line ("[FAIL] invariant broken"); Fails := Fails + 1; end if;

   New_Line;
   if Fails = 0 then Put_Line ("ALL RUNTIME TESTS PASS (matches proven contracts)");
   else Put_Line ("RUNTIME FAILURES:" & Fails'Image);
        Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Judicial;
