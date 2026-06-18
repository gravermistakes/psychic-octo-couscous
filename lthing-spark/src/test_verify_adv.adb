--  test_verify_adv — adversarial gate on the public LTHING_MLDSA65.Verify:
--  an authoritative valid vector must ACCEPT; a single-bit tamper of the
--  signature or the public key must REJECT. Proves the verifier discriminates,
--  not just replays the KAT. Bytes come from KAT vector V31 (reference-sourced).
with LTHING_MLDSA65;
with MLDSA_KAT_Vectors;
with LTHING_Types;  use LTHING_Types;
with Interfaces;    use Interfaces;
with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
procedure Test_Verify_Adv is
   package M renames MLDSA_KAT_Vectors;
   V     : M.Vector renames M.V31;            --  an authoritative ACCEPT vector
   Msg   : Byte_Array (0 .. V.Msg_Len - 1);
   Ctx   : Byte_Array (0 .. V.Ctx_Len - 1);
   PK    : LTHING_MLDSA65.Public_Key := V.PK;
   Sg    : LTHING_MLDSA65.Signature  := V.Sig;
   Fails : Natural := 0;
   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;
begin
   for I in 1 .. V.Msg_Len loop Msg (I - 1) := V.Msg (I); end loop;
   for I in 1 .. V.Ctx_Len loop Ctx (I - 1) := V.Ctx (I); end loop;

   Chk ("valid V31 accepts",
        LTHING_MLDSA65.Verify (PK, Msg, Ctx, Sg));

   Sg (100) := Sg (100) xor 1;                --  flip one signature bit
   Chk ("1-bit signature tamper rejects",
        not LTHING_MLDSA65.Verify (PK, Msg, Ctx, Sg));

   Sg := V.Sig;                               --  restore signature
   PK (0) := PK (0) xor 1;                     --  flip one public-key bit
   Chk ("1-bit public-key tamper rejects",
        not LTHING_MLDSA65.Verify (PK, Msg, Ctx, Sg));

   New_Line;
   if Fails = 0 then Put_Line ("VERIFY-ADV GATE PASSED: accepts valid, rejects 1-bit tamper");
   else Put_Line ("VERIFY-ADV FAILURES:" & Fails'Image);
        Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Verify_Adv;
