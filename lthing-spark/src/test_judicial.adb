with LTHING_Types;    use LTHING_Types;
with LTHING_Hash;     use LTHING_Hash;
with LTHING_Judicial; use LTHING_Judicial;
with Ada.Text_IO;     use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;

procedure Test_Judicial is

   --  §3 layout offsets (must match lthing_judicial.adb).
   Chain_Hash_Off : constant := 14;
   Sig_Off        : constant := 78;
   Content_Off    : constant := 3387;
   Min_Doc        : constant := 3388;

   --  Stamp the fixed §2 LTHING JD v1.0 header prefix into Doc (0 .. 13).
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
      Doc (Doc'First + 10) := 16#04#;
      Doc (Doc'First + 11) := 16#A4#;
      Doc (Doc'First + 12) := 16#40#;
      Doc (Doc'First + 13) := 16#10#;
   end Put_JD_Header;

   --  A full-sized doc (Min_Doc bytes): valid header, everything else zero.
   --  Caller can overwrite specific fields before passing to Parse_And_Verify.
   procedure Make_Big_Doc (Doc : out Byte_Array) is
   begin
      for I in Doc'Range loop
         Doc (I) := 0;
      end loop;
      Put_JD_Header (Doc);
   end Make_Big_Doc;

   Doc   : Byte_Array (0 .. 99)  := (others => 0);
   PK32  : Byte_Array (0 .. 31)  := (others => 16#AB#);   --  wrong-length PK
   PK    : Byte_Array (0 .. 1951) := (others => 16#AB#);  --  valid-length PK
   Zero  : constant Digest := (others => 0);
   R     : Verified_Record;
   Fails : Natural := 0;

   procedure Pass (Tag : String) is
   begin
      Put_Line ("[PASS] " & Tag);
   end Pass;

   procedure Fail (Tag : String; Got : String) is
   begin
      Put_Line ("[FAIL] " & Tag & " (got " & Got & ")");
      Fails := Fails + 1;
   end Fail;

begin
   Put_JD_Header (Doc);

   --  T1: Parse_Unverified must NEVER be trusted.
   Parse_Unverified (Doc, R);
   if not R.Trusted then Pass ("Parse_Unverified never trusted");
   else Fail ("Parse_Unverified never trusted", R.Status'Image); end if;

   --  T2: Parse_And_Verify on a 100-byte JD header — passes gates 1+2,
   --  fails gate 3 (document too short for §3 fields) → Bad_Length.
   Parse_And_Verify (Doc, Zero, PK32, R);
   if not R.Trusted and then R.Status = Bad_Length then
      Pass ("short doc rejected at format-length gate (Bad_Length)");
   else Fail ("short doc / Bad_Length", R.Status'Image); end if;

   --  T3: too-short envelope -> Bad_Envelope, not trusted.
   declare
      Tiny : Byte_Array (0 .. 9) := (others => 0);
   begin
      Parse_And_Verify (Tiny, Zero, PK32, R);
      if not R.Trusted and then R.Status = Bad_Envelope then
         Pass ("short envelope rejected (Bad_Envelope)");
      else Fail ("short envelope / Bad_Envelope", R.Status'Image); end if;
   end;

   --  T4: corrupted doctype block -> Bad_Magic.
   declare
      Bad : Byte_Array (0 .. 99) := (others => 0);
   begin
      Put_JD_Header (Bad);
      Bad (Bad'First + 11) := 16#FF#;
      Parse_And_Verify (Bad, Zero, PK32, R);
      if not R.Trusted and then R.Status = Bad_Magic then
         Pass ("corrupted doctype rejected (Bad_Magic)");
      else Fail ("corrupted doctype / Bad_Magic", R.Status'Image); end if;
   end;

   --  T5: corrupted fixed preamble -> Bad_Magic.
   declare
      Bad : Byte_Array (0 .. 99) := (others => 0);
   begin
      Put_JD_Header (Bad);
      Bad (Bad'First + 3) := 16#FF#;
      Parse_And_Verify (Bad, Zero, PK32, R);
      if not R.Trusted and then R.Status = Bad_Magic then
         Pass ("corrupted preamble rejected (Bad_Magic)");
      else Fail ("corrupted preamble / Bad_Magic", R.Status'Image); end if;
   end;

   --  T6: the historical fake header (doctype at offset 9) must not validate.
   declare
      Old_Fake : Byte_Array (0 .. 99) := (others => 0);
   begin
      Old_Fake (9) := 16#04#;
      Parse_And_Verify (Old_Fake, Zero, PK32, R);
      if not R.Trusted and then R.Status = Bad_Magic then
         Pass ("legacy offset-9 fake header rejected (Bad_Magic)");
      else Fail ("legacy fake header / Bad_Magic", R.Status'Image); end if;
   end;

   --  T7: Trusted<->Verified invariant.
   if R.Trusted = (R.Status = Verified) then
      Pass ("Trusted<->Verified invariant holds");
   else Fail ("Trusted<->Verified invariant", ""); end if;

   --  T8: full-size doc, valid header, wrong-length PK (32 B instead of 1952 B)
   --  -> PK gate fires -> Signature_Invalid.
   declare
      Big : Byte_Array (0 .. Min_Doc - 1) := (others => 0);
   begin
      Make_Big_Doc (Big);
      Parse_And_Verify (Big, Zero, PK32, R);
      if not R.Trusted and then R.Status = Signature_Invalid then
         Pass ("wrong-length PK rejected at PK gate (Signature_Invalid)");
      else Fail ("wrong-length PK / Signature_Invalid", R.Status'Image); end if;
   end;

   --  T9: full-size doc, correct chain hash embedded at runtime, valid-length
   --  PK, zero (invalid) signature -> chain gate passes, sig gate fires ->
   --  Signature_Invalid.
   declare
      Big  : Byte_Array (0 .. Min_Doc - 1) := (others => 0);
      Hash : Digest;
   begin
      Make_Big_Doc (Big);
      --  Content = Big (Content_Off .. Min_Doc - 1) — one zero byte.
      Chain_Hash (Zero, Big (Content_Off .. Min_Doc - 1), Hash);
      for I in Digest_Index loop
         Big (Chain_Hash_Off + I) := Hash (I);
      end loop;
      --  Signature bytes Big (Sig_Off .. Sig_Off + 3308) remain all zero —
      --  that is an invalid ML-DSA-65 signature.
      Parse_And_Verify (Big, Zero, PK, R);
      if not R.Trusted and then R.Status = Signature_Invalid then
         Pass ("chain gate passes, sig gate rejects bad sig (Signature_Invalid)");
      else Fail ("chain-pass / sig-reject", R.Status'Image); end if;
   end;

   --  T10: Parse_Unverified on a too-short doc — its own Bad_Envelope branch.
   declare
      Tiny2 : Byte_Array (0 .. 5) := (others => 0);
   begin
      Parse_Unverified (Tiny2, R);
      if not R.Trusted and then R.Status = Bad_Envelope then
         Pass ("Parse_Unverified rejects short doc (Bad_Envelope)");
      else Fail ("Parse_Unverified short / Bad_Envelope", R.Status'Image); end if;
   end;

   New_Line;
   if Fails = 0 then
      Put_Line ("ALL RUNTIME TESTS PASS (matches proven contracts)");
   else
      Put_Line ("RUNTIME FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Judicial;
