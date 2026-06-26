--  test_judicial87 — ML-DSA-87 (suite 0x0002) dispatch in LTHING_Judicial.
--
--  Validates the judicial layer's CNSA 2.0 path (§3.1 suite 0x0002).
--  Six relational property gates:
--
--    T1: suite 0x0002 with wrong signature length      -> Bad_Length
--    T2: suite 0x0002 with ML-DSA-65-size (1952 B) PK -> Bad_Length
--    T3: well-formed 87 envelope (all seal gates pass) -> Signature_Invalid
--        (proves §9.1..§9.9 run correctly for suite 0x0002)
--    T4: tampered body in suite 0x0002 envelope        -> Seal_Mismatch
--    T5: suite 0x0002, wrong prev_chain                -> Chain_Broken
--    T6: Trusted<->Verified invariant                  -> always consistent
--
--  There is no genuinely-signed T7 (no ML-DSA-87 signer in this library;
--  verifier-only). The 87 verifier is validated end-to-end by test_kat87
--  (15/15 FIPS 204 NIST ACVP sigVer KAT vectors).
pragma SPARK_Mode (Off);

with LTHING_Types;    use LTHING_Types;
with LTHING_Judicial; use LTHING_Judicial;
with LTHING_Keccak;
with LTHING_MLDSA87;
with Interfaces;      use Interfaces;
with Ada.Text_IO;     use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;

procedure Test_Judicial87 is

   Hash_Bytes   : constant := 64;
   Sig_Bytes_87 : constant := LTHING_MLDSA87.Sig_Bytes;   --  4627
   PK_Bytes_87  : constant := LTHING_MLDSA87.PK_Bytes;    --  2592
   PK_Bytes_65  : constant := 1952;  --  LTHING_MLDSA65.PK_Bytes

   Fails : Natural := 0;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;

   --  LTHING SHAKE512 (rate 72, domain 0x1F, 64-byte output) — same as verifier.
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

   --  §2/§3 header for suite 0x0002 (ML-DSA-87): sig length = 4627.
   procedure Put_Header_87
     (D                  : in out Byte_Array;
      Body_Len, Seal_Len : Natural)
   is
      Pre : constant Byte_Array (0 .. 13) :=
        (16#00#, 16#00#, 16#00#, 16#0B#, 16#0D#, 16#EE#, 16#D0#,
         16#00#, 16#00#, 16#00#, 16#04#, 16#A4#, 16#40#, 16#10#);
   begin
      for I in Pre'Range loop D (I) := Pre (I); end loop;
      Put_U16 (D, 14, 16#0002#);                   --  suite (ML-DSA-87)
      for I in 16 .. 23 loop D (I) := 0; end loop; --  timestamp
      Put_U32 (D, 24, Unsigned_32 (Body_Len));
      Put_U32 (D, 28, Unsigned_32 (Seal_Len));
      Put_U32 (D, 32, Unsigned_32 (Sig_Bytes_87));
      Put_U32 (D, 36, 0);                           --  AEAD len = 0
   end Put_Header_87;

   --  Build a complete genesis envelope using suite 0x0002.
   --  Seal hashes are computed correctly; signature region is all-zeros.
   procedure Build_Genesis_87
     (Body_Byte : Byte;
      Env       : out Byte_Array;
      Last      : out Natural)
   is
      Body_Len : constant := 8;
      Seal_Len : constant := 196;        --  signer_len = 0
      Body_Off : constant := 40;
      Seal_Off : constant := Body_Off + Body_Len;
      Sig_Off  : constant := Seal_Off + Seal_Len;
      Art, Chain, Sid : Digest;
      Prev : constant Byte_Array (0 .. 63) := (others => 0);
   begin
      Env := (others => 0);
      Put_Header_87 (Env, Body_Len, Seal_Len);

      for I in 0 .. Body_Len - 1 loop Env (Body_Off + I) := Body_Byte; end loop;

      Art := L512 (Env (Body_Off .. Body_Off + Body_Len - 1));

      declare
         CBuf : Byte_Array (0 .. 127) := (others => 0);
      begin
         for I in 0 .. 63 loop CBuf (I) := Prev (I); end loop;
         for I in 0 .. 63 loop CBuf (64 + I) := Art (I); end loop;
         Chain := L512 (CBuf);
      end;

      Put_U16 (Env, Seal_Off, 0);
      for I in 0 .. 63 loop Env (Seal_Off + 2 + I)  := Art   (I); end loop;
      for I in 0 .. 63 loop Env (Seal_Off + 66 + I) := Chain (I); end loop;
      Env (Seal_Off + 130) := 16#00#;   --  Relation = GENESIS
      Env (Seal_Off + 131) := 16#00#;   --  SignerIdLen = 0

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

      Last := Sig_Off + Sig_Bytes_87 - 1;
   end Build_Genesis_87;

   Zero : constant Digest := (others => 0);
   PK87 : constant Byte_Array (0 .. PK_Bytes_87 - 1) := (others => 16#AB#);
   R    : Verified_Record;
   --  40 + 8 + 196 + 4627 = 4871; use 8 KiB to be safe.
   Env  : Byte_Array (0 .. 8191) := (others => 0);
   Last : Natural;

begin
   --  T1: suite 0x0002 but sig length field says 3309 (ML-DSA-65 size).
   --  Total in header = 40+8+196+3309+0 = 3553 ≠ wire size (4871) → Bad_Length.
   --  (SigL /= Exp_SigB also fires first.)
   Build_Genesis_87 (16#5A#, Env, Last);
   Put_U32 (Env, 32, 3309);
   Parse_And_Verify (Env (0 .. Last), Zero, PK87, R);
   Chk ("87: wrong sig length -> Bad_Length",
        (not R.Trusted) and then R.Status = Bad_Length);

   --  T2: suite 0x0002 but PK is ML-DSA-65 size (1952 B) → PK size mismatch.
   declare
      PK65 : constant Byte_Array (0 .. PK_Bytes_65 - 1) := (others => 16#CC#);
   begin
      Build_Genesis_87 (16#5A#, Env, Last);
      Parse_And_Verify (Env (0 .. Last), Zero, PK65, R);
      Chk ("87: 65-size PK -> Bad_Length",
           (not R.Trusted) and then R.Status = Bad_Length);
   end;

   --  T3: well-formed suite 0x0002 envelope, zeros in sig region.
   --  All seal gates (§9.1..§9.9) pass; verifier reaches ML-DSA-87.Verify
   --  which returns False for a zero sig → Signature_Invalid.
   Build_Genesis_87 (16#5A#, Env, Last);
   Parse_And_Verify (Env (0 .. Last), Zero, PK87, R);
   Chk ("87: well-formed envelope reaches signature gate (Signature_Invalid)",
        (not R.Trusted) and then R.Status = Signature_Invalid);

   --  T4: flip a body byte after the seal is built → ArtifactHash mismatch.
   Build_Genesis_87 (16#5A#, Env, Last);
   Env (40) := 16#5B#;
   Parse_And_Verify (Env (0 .. Last), Zero, PK87, R);
   Chk ("87: tampered body -> Seal_Mismatch",
        (not R.Trusted) and then R.Status = Seal_Mismatch);

   --  T5: well-formed envelope but wrong prev_chain → ChainHash link fails.
   Build_Genesis_87 (16#5A#, Env, Last);
   declare
      Wrong_Prev : Digest := (others => 16#11#);
   begin
      Parse_And_Verify (Env (0 .. Last), Wrong_Prev, PK87, R);
      Chk ("87: wrong prev_chain -> Chain_Broken",
           (not R.Trusted) and then R.Status = Chain_Broken);
   end;

   --  T6: trust/verified invariant is always consistent.
   Chk ("87: Trusted<->Verified invariant", R.Trusted = (R.Status = Verified));

   New_Line;
   if Fails = 0 then
      Put_Line ("ALL RUNTIME TESTS PASS (ML-DSA-87 judicial dispatch)");
   else
      Put_Line ("RUNTIME FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Judicial87;
