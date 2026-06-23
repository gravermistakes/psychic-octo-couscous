--  test_sign — authoritative end-to-end gate for the ML-DSA-65 signer.
--
--  Relational property (per CLAUDE.md): a freshly key-generated, freshly signed
--  message must verify, and any tamper (signature bit, message, context) must
--  fail closed. No self-derived signature vector is asserted — correctness is
--  pinned by the existing KAT-validated Verify accepting what Sign produced.
pragma SPARK_Mode (Off);

with Interfaces;        use Interfaces;
with LTHING_Types;      use LTHING_Types;
with LTHING_MLDSA65;    use LTHING_MLDSA65;
with LTHING_MLDSA_Sign; use LTHING_MLDSA_Sign;
with Ada.Text_IO;       use Ada.Text_IO;
with Ada.Command_Line;  use Ada.Command_Line;

procedure Test_Sign is
   Fails : Natural := 0;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;

   Seed : Byte_Array (0 .. 31);
   PK   : Public_Key;
   SK   : Secret_Key;
   Sig  : Signature;
   Ok   : Boolean;

   Msg  : Byte_Array (0 .. 11) :=
     (72, 101, 108, 108, 111, 44, 32, 76, 84, 72, 33, 33);   --  "Hello, LTH!!"
   Ctx  : Byte_Array (0 .. 3) := (1, 2, 3, 4);
   Empty : constant Byte_Array (1 .. 0) := (others => 0);
begin
   for I in Seed'Range loop Seed (I) := Byte (I * 7 + 1); end loop;

   Key_Gen (Seed, PK, SK);

   --  T1: deterministic KeyGen — same seed yields same pk.
   declare
      PK2 : Public_Key; SK2 : Secret_Key;
   begin
      Key_Gen (Seed, PK2, SK2);
      Chk ("KeyGen deterministic (pk reproducible)", PK2 = PK);
   end;

   --  T2: sign then verify (with context) round-trips to True.
   Sign (SK, Msg, Ctx, Sig, Ok);
   Chk ("Sign reports success", Ok);
   Chk ("Verify accepts a genuine signature (with ctx)",
        Verify (PK, Msg, Ctx, Sig));

   --  T3: empty context round-trips.
   declare
      Sig0 : Signature; Ok0 : Boolean;
   begin
      Sign (SK, Msg, Empty, Sig0, Ok0);
      Chk ("Verify accepts genuine signature (empty ctx)",
           Ok0 and then Verify (PK, Msg, Empty, Sig0));
   end;

   --  T4: a single flipped signature byte must be rejected.
   declare
      Bad : Signature := Sig;
   begin
      Bad (100) := Bad (100) xor 1;
      Chk ("tampered signature rejected", not Verify (PK, Msg, Ctx, Bad));
   end;

   --  T5: a flipped message byte must be rejected.
   declare
      Bad_Msg : Byte_Array := Msg;
   begin
      Bad_Msg (0) := Bad_Msg (0) xor 1;
      Chk ("tampered message rejected", not Verify (PK, Bad_Msg, Ctx, Sig));
   end;

   --  T6: verifying under a different context must be rejected.
   declare
      Other_Ctx : Byte_Array (0 .. 3) := (9, 9, 9, 9);
   begin
      Chk ("wrong context rejected", not Verify (PK, Msg, Other_Ctx, Sig));
   end;

   --  T7: a different key must not verify this signature.
   declare
      Seed2 : Byte_Array (0 .. 31); PK_B : Public_Key; SK_B : Secret_Key;
   begin
      for I in Seed2'Range loop Seed2 (I) := Byte (I * 3 + 5); end loop;
      Key_Gen (Seed2, PK_B, SK_B);
      Chk ("signature rejected under a different public key",
           not Verify (PK_B, Msg, Ctx, Sig));
   end;

   New_Line;
   if Fails = 0 then
      Put_Line ("SIGN GATE PASSED: KeyGen/Sign round-trip + tamper rejection");
   else
      Put_Line ("RUNTIME FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Sign;
