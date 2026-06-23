--  test_judicial — fail-closed verification of the LTHING envelope
--  (LTHING_HEADER_SPEC.md §2/§3/§5/§6/§9).
--
--  Three kinds of gate are exercised:
--    * structural / magic / length gates (T1..T8) — pure rejections;
--    * a WELL-FORMED genesis envelope (T9..T13) whose seal hashes are
--      recomputed here exactly as the verifier does (LTHING SHAKE512 via the
--      same Sponge), so every seal gate (§9.6 artifact, §9.7 chain, §9.8
--      seal-id, §9.9 relation) PASSES and the verifier reaches the signature
--      gate (with a non-signer key it fails closed there, Signature_Invalid);
--    * a GENUINELY SIGNED envelope (T15/T16): KeyGen + Sign produce a real
--      ML-DSA-65 signature over header‖body‖seal, so Parse_And_Verify returns
--      Verified/Trusted — and flipping a signature byte fails closed. This is
--      the full end-to-end relational gate: a real signed judicial document
--      verifies, tamper does not, and no Verified result is ever faked.
pragma SPARK_Mode (Off);

with LTHING_Types;      use LTHING_Types;
with LTHING_Judicial;   use LTHING_Judicial;
with LTHING_Keccak;
with LTHING_MLDSA65;    use LTHING_MLDSA65;
with LTHING_MLDSA_Sign; use LTHING_MLDSA_Sign;
with Interfaces;        use Interfaces;
with Ada.Text_IO;       use Ada.Text_IO;
with Ada.Command_Line;  use Ada.Command_Line;

procedure Test_Judicial is

   Hash_Bytes : constant := 64;
   Sig_Bytes  : constant := LTHING_MLDSA65.Sig_Bytes;   --  3309
   PK_Bytes   : constant := LTHING_MLDSA65.PK_Bytes;     --  1952

   Fails : Natural := 0;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;

   --  LTHING "SHAKE512" — the verifier's seal/chain hash (rate 72, 0x1F, 64B).
   function L512 (Input : Byte_Array) return Digest is
      Buf : Byte_Array (0 .. 63) := (others => 0);
      R   : Digest := (others => 0);
   begin
      LTHING_Keccak.Sponge
        (Input  => Input,
         Rate   => LTHING_Keccak.Rate_SHA3_512,
         Domain => LTHING_Keccak.Domain_SHAKE,
         Output => Buf);
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

   --  §2/§3 fixed JD v1.0 + suite 0x0001 header into D(0..39); sets the four
   --  section lengths.
   procedure Put_Header
     (D                      : in out Byte_Array;
      Body_Len, Seal_Len     : Natural)
   is
      Pre : constant Byte_Array (0 .. 13) :=
        (16#00#, 16#00#, 16#00#, 16#0B#, 16#0D#, 16#EE#, 16#D0#,
         16#00#, 16#00#, 16#00#, 16#04#, 16#A4#, 16#40#, 16#10#);
   begin
      for I in Pre'Range loop D (I) := Pre (I); end loop;
      Put_U16 (D, 14, 16#0001#);                 --  suite (baseline)
      for I in 16 .. 23 loop D (I) := 0; end loop;  --  timestamp
      Put_U32 (D, 24, Unsigned_32 (Body_Len));
      Put_U32 (D, 28, Unsigned_32 (Seal_Len));
      Put_U32 (D, 32, Unsigned_32 (Sig_Bytes));
      Put_U32 (D, 36, 0);                         --  AEAD len = 0
   end Put_Header;

   --  Build a complete, well-formed genesis envelope (Relation=0, Ancestor=0,
   --  empty signer id) over a small body. All seal hashes are correct; the
   --  signature region is left as zeros (no valid signer exists yet).
   --  Returns the envelope in Env (0 .. Last).
   procedure Build_Genesis
     (Body_Byte : Byte;
      Env       : out Byte_Array;
      Last      : out Natural)
   is
      Body_Len : constant := 8;
      Seal_Len : constant := 196;                 --  signer_len = 0
      Body_Off : constant := 40;
      Seal_Off : constant := Body_Off + Body_Len;
      Sig_Off  : constant := Seal_Off + Seal_Len;
      Art      : Digest;
      Chain    : Digest;
      Sid      : Digest;
      Prev     : constant Byte_Array (0 .. 63) := (others => 0);
   begin
      Env := (others => 0);
      Put_Header (Env, Body_Len, Seal_Len);

      --  body
      for I in 0 .. Body_Len - 1 loop Env (Body_Off + I) := Body_Byte; end loop;

      --  §9.6 artifact = L512(body)
      Art := L512 (Env (Body_Off .. Body_Off + Body_Len - 1));

      --  §9.7 chain = L512(prev(64 zero) ‖ artifact)
      declare
         CBuf : Byte_Array (0 .. 127) := (others => 0);
      begin
         for I in 0 .. 63 loop CBuf (I) := Prev (I); end loop;
         for I in 0 .. 63 loop CBuf (64 + I) := Art (I); end loop;
         Chain := L512 (CBuf);
      end;

      --  ancestor(2)=0, artifact, chain, relation=0, signer_len=0
      Put_U16 (Env, Seal_Off, 0);                       --  AncestorCount
      for I in 0 .. 63 loop Env (Seal_Off + 2 + I) := Art (I); end loop;
      for I in 0 .. 63 loop Env (Seal_Off + 66 + I) := Chain (I); end loop;
      Env (Seal_Off + 130) := 16#00#;                   --  Relation = GENESIS
      Env (Seal_Off + 131) := 16#00#;                   --  SignerIdLen = 0

      --  §9.8 seal_id = L512(ancestor(2) ‖ artifact ‖ chain ‖ relation)
      declare
         SBuf : Byte_Array (0 .. 130) := (others => 0);  --  2+64+64+1, signer=0
      begin
         SBuf (0) := Env (Seal_Off);
         SBuf (1) := Env (Seal_Off + 1);
         for I in 0 .. 63 loop SBuf (2 + I) := Art (I); end loop;
         for I in 0 .. 63 loop SBuf (66 + I) := Chain (I); end loop;
         SBuf (130) := 16#00#;                          --  relation
         Sid := L512 (SBuf);
      end;
      for I in 0 .. 63 loop Env (Seal_Off + 132 + I) := Sid (I); end loop;

      --  signature region: zeros (no valid signer). Sig_Off .. +3308.
      Last := Sig_Off + Sig_Bytes - 1;
   end Build_Genesis;

   Zero : constant Digest := (others => 0);
   PK   : constant Byte_Array (0 .. PK_Bytes - 1) := (others => 16#AB#);
   R    : Verified_Record;

   --  Big buffer for a full envelope: 40 + 8 + 196 + 3309 = 3553.
   Env  : Byte_Array (0 .. 4095) := (others => 0);
   Last : Natural;

begin
   ---------------------------------------------------------------------------
   --  Structural / magic / length gates
   ---------------------------------------------------------------------------

   --  T1: Parse_Unverified is never trusted.
   declare
      D : Byte_Array (0 .. 99) := (others => 0);
   begin
      Build_Genesis (16#5A#, Env, Last);
      Parse_Unverified (Env (0 .. Last), R);
      Chk ("Parse_Unverified never trusted",
           (not R.Trusted) and then R.Status /= Verified);
      pragma Unreferenced (D);
   end;

   --  T2: too-short envelope (< 40 B) -> Bad_Envelope.
   declare
      Tiny : Byte_Array (0 .. 9) := (others => 0);
   begin
      Parse_And_Verify (Tiny, Zero, PK, R);
      Chk ("short envelope -> Bad_Envelope",
           (not R.Trusted) and then R.Status = Bad_Envelope);
   end;

   --  T3: corrupted doctype block -> Bad_Magic.
   Build_Genesis (16#5A#, Env, Last);
   Env (11) := 16#FF#;
   Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
   Chk ("corrupted doctype -> Bad_Magic",
        (not R.Trusted) and then R.Status = Bad_Magic);

   --  T4: corrupted preamble -> Bad_Magic.
   Build_Genesis (16#5A#, Env, Last);
   Env (3) := 16#FF#;
   Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
   Chk ("corrupted preamble -> Bad_Magic",
        (not R.Trusted) and then R.Status = Bad_Magic);

   --  T5: legacy offset-9 fake header (byte 9 nonzero) -> Bad_Magic.
   declare
      Fake : Byte_Array (0 .. 99) := (others => 0);
   begin
      Fake (9) := 16#04#;
      Parse_And_Verify (Fake, Zero, PK, R);
      Chk ("legacy offset-9 fake header -> Bad_Magic",
           (not R.Trusted) and then R.Status = Bad_Magic);
   end;

   --  T6: zero version byte (§2.4 RESERVED) -> Bad_Magic.
   Build_Genesis (16#5A#, Env, Last);
   Env (13) := 16#00#;
   Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
   Chk ("zero version byte -> Bad_Magic",
        (not R.Trusted) and then R.Status = Bad_Magic);

   --  T7: reserved suite 0x0000 -> Bad_Length.
   Build_Genesis (16#5A#, Env, Last);
   Env (14) := 16#00#; Env (15) := 16#00#;
   Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
   Chk ("reserved suite 0x0000 -> Bad_Length",
        (not R.Trusted) and then R.Status = Bad_Length);

   --  T8: declared lengths don't sum to the wire size -> Bad_Length.
   Build_Genesis (16#5A#, Env, Last);
   Parse_And_Verify (Env (0 .. Last - 1), Zero, PK, R);  --  drop 1 byte
   Chk ("length/size mismatch -> Bad_Length",
        (not R.Trusted) and then R.Status = Bad_Length);

   ---------------------------------------------------------------------------
   --  Well-formed seal: every seal gate passes, sig gate is the arbiter
   ---------------------------------------------------------------------------

   --  T9: well-formed genesis envelope, garbage signature -> reaches and fails
   --  at the SIGNATURE gate (proves §9.1..§9.9 all accept a good seal).
   Build_Genesis (16#5A#, Env, Last);
   Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
   Chk ("well-formed seal reaches signature gate (Signature_Invalid)",
        (not R.Trusted) and then R.Status = Signature_Invalid);

   --  T10: tamper one body byte after the seal is built -> ArtifactHash no
   --  longer matches -> Seal_Mismatch (earlier than the signature gate).
   Build_Genesis (16#5A#, Env, Last);
   Env (40) := 16#5B#;                       --  flip a body byte
   Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
   Chk ("tampered body -> Seal_Mismatch",
        (not R.Trusted) and then R.Status = Seal_Mismatch);

   --  T11: genesis envelope but caller supplies a non-zero prev_chain ->
   --  ChainHash link fails -> Chain_Broken.
   Build_Genesis (16#5A#, Env, Last);
   declare
      Wrong_Prev : Digest := (others => 16#11#);
   begin
      Parse_And_Verify (Env (0 .. Last), Wrong_Prev, PK, R);
      Chk ("wrong prev_chain -> Chain_Broken",
           (not R.Trusted) and then R.Status = Chain_Broken);
   end;

   --  T12: tamper the stored SealId -> §9.8 recompute fails -> Seal_Mismatch.
   Build_Genesis (16#5A#, Env, Last);
   declare
      Seal_Off   : constant := 40 + 8;
      Sealid_Off : constant := Seal_Off + 132;   --  signer_len = 0
   begin
      Env (Sealid_Off) := Env (Sealid_Off) xor 1;
      Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
      Chk ("tampered seal_id -> Seal_Mismatch",
           (not R.Trusted) and then R.Status = Seal_Mismatch);
   end;

   --  T13: inconsistent provenance — Relation=GENESIS but AncestorCount=5.
   Build_Genesis (16#5A#, Env, Last);
   declare
      Seal_Off : constant := 40 + 8;
   begin
      Put_U16 (Env, Seal_Off, 5);   --  ancestor=5 while relation stays GENESIS
      Parse_And_Verify (Env (0 .. Last), Zero, PK, R);
      Chk ("genesis with ancestor/=0 -> Seal_Mismatch",
           (not R.Trusted) and then R.Status = Seal_Mismatch);
   end;

   ---------------------------------------------------------------------------
   --  Genuinely signed envelope: full end-to-end accept + tamper reject
   ---------------------------------------------------------------------------

   --  T15: a real ML-DSA-65 signature over header‖body‖seal -> Verified.
   declare
      Seed    : Byte_Array (0 .. 31);
      GPK     : Public_Key;
      SK      : Secret_Key;
      Sg      : Signature;
      Ok      : Boolean;
      Sig_Off : constant := 40 + 8 + 196;           --  header+body+seal = 244
      Empty   : constant Byte_Array (1 .. 0) := (others => 0);
   begin
      for I in Seed'Range loop Seed (I) := Byte (I * 5 + 3); end loop;
      Key_Gen (Seed, GPK, SK);

      Build_Genesis (16#5A#, Env, Last);
      Sign (SK, Env (0 .. Sig_Off - 1), Empty, Sg, Ok);
      for I in 0 .. Sig_Bytes - 1 loop
         Env (Sig_Off + I) := Sg (I);
      end loop;

      Parse_And_Verify (Env (0 .. Last), Zero, GPK, R);
      Chk ("genuine signed genesis envelope -> Verified/Trusted",
           Ok and then R.Trusted and then R.Status = Verified);

      --  T16: flip one signature byte -> Signature_Invalid (fail-closed).
      Env (Sig_Off + 50) := Env (Sig_Off + 50) xor 1;
      Parse_And_Verify (Env (0 .. Last), Zero, GPK, R);
      Chk ("tampered signature in signed envelope -> Signature_Invalid",
           (not R.Trusted) and then R.Status = Signature_Invalid);
   end;

   --  T14: the trust invariant can never desync.
   Chk ("Trusted<->Verified invariant holds",
        R.Trusted = (R.Status = Verified));

   New_Line;
   if Fails = 0 then
      Put_Line ("ALL RUNTIME TESTS PASS (matches proven contracts)");
   else
      Put_Line ("RUNTIME FAILURES:" & Fails'Image);
      Set_Exit_Status (Failure);
   end if;
end Test_Judicial;
