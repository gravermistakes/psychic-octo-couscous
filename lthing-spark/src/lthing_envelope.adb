------------------------------------------------------------------------------
--  LTHING.Envelope (body) — parse and verify per §3 wire format
--
--  Gate sequence (fail-closed, each returns on failure):
--    Parse:
--      1. Preamble check (§6 rule 1)
--      2. DocType ASCII validation (§6 rule 2)
--      3. Suite validation (§6 rule 3)
--      4. Seal length > 0 (§6 rule 4)
--      5. Sig length > 0 (§6 rule 5)
--      6. Suite-defined seal/sig length match (§6 rules 6-7)
--      7. Geometry overflow / data availability (§6 rule 8)
--    Verify:
--      8. Seal recomputation (§6 rule 9)
--      9. Chain hash check (§6 rule 10)
--     10. ML-DSA-65 signature (§6 rule 11)
--
--  Lead Engineer — Rune auf Opus (4.6)
--  Co-authored with Anja Evermoor.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (Off);
--  Off because we compose the SPARK_Mode (Off) ML-DSA verifier and
--  do unchecked byte slicing. The spec contracts still hold.

with LTHING_Keccak;  use LTHING_Keccak;
with LTHING_Hash;    use LTHING_Hash;
with LTHING_MLDSA65; use LTHING_MLDSA65;

package body LTHING_Envelope is

   ---------------------------------------------------------------------------
   --  Helpers
   ---------------------------------------------------------------------------

   --  Read a big-endian Unsigned_16 from Document at offset Off (relative
   --  to Document'First).
   function Read_U16 (Document : Byte_Array; Off : Natural) return Unsigned_16
   is
      Base : constant Natural := Document'First + Off;
   begin
      return Shift_Left (Unsigned_16 (Document (Base)), 8)
             or Unsigned_16 (Document (Base + 1));
   end Read_U16;

   --  Read a big-endian Unsigned_32 from Document at offset Off.
   function Read_U32 (Document : Byte_Array; Off : Natural) return Unsigned_32
   is
      Base : constant Natural := Document'First + Off;
   begin
      return Shift_Left (Unsigned_32 (Document (Base)),     24)
             or Shift_Left (Unsigned_32 (Document (Base + 1)), 16)
             or Shift_Left (Unsigned_32 (Document (Base + 2)),  8)
             or Unsigned_32 (Document (Base + 3));
   end Read_U32;

   --  Read a big-endian Unsigned_64 from Document at offset Off.
   function Read_U64 (Document : Byte_Array; Off : Natural) return Unsigned_64
   is
      Base : constant Natural := Document'First + Off;
   begin
      return Shift_Left (Unsigned_64 (Document (Base)),     56)
             or Shift_Left (Unsigned_64 (Document (Base + 1)), 48)
             or Shift_Left (Unsigned_64 (Document (Base + 2)), 40)
             or Shift_Left (Unsigned_64 (Document (Base + 3)), 32)
             or Shift_Left (Unsigned_64 (Document (Base + 4)), 24)
             or Shift_Left (Unsigned_64 (Document (Base + 5)), 16)
             or Shift_Left (Unsigned_64 (Document (Base + 6)),  8)
             or Unsigned_64 (Document (Base + 7));
   end Read_U64;

   --  Extract the nibble-straddled doctype from bytes 10-12 (§2.2).
   --  Byte 10: [offset 0 | high nibble of char 1]
   --  Byte 11: [low nibble of char 1 | high nibble of char 2]
   --  Byte 12: [low nibble of char 2 | null terminator]
   procedure Extract_DocType
     (Document : Byte_Array;
      DT       : out DocType_Code;
      Valid    : out Boolean)
   is
      Base : constant Natural := Document'First;
      B10  : constant Byte := Document (Base + 10);
      B11  : constant Byte := Document (Base + 11);
      B12  : constant Byte := Document (Base + 12);
      Hi_C1 : Byte;
      Lo_C1 : Byte;
      Hi_C2 : Byte;
      Lo_C2 : Byte;
      Null_Term : Byte;
   begin
      --  Nibble 20 = high nibble of B10 should be 0 (offset nibble from
      --  preamble, already checked). Nibble 21 = low nibble of B10.
      Hi_C1 := B10 and 16#0F#;            --  nibble 21: high nibble of char 1
      Lo_C1 := Shift_Right (B11, 4);      --  nibble 22: low nibble of char 1
      Hi_C2 := B11 and 16#0F#;            --  nibble 23: high nibble of char 2
      Lo_C2 := Shift_Right (B12, 4);      --  nibble 24: low nibble of char 2
      Null_Term := B12 and 16#0F#;        --  nibble 25: must be 0

      DT.C1 := Shift_Left (Hi_C1, 4) or Lo_C1;
      DT.C2 := Shift_Left (Hi_C2, 4) or Lo_C2;

      --  §2.3: only 0x41-0x5A (A-Z) and 0x30-0x39 (0-9) are valid.
      Valid := Null_Term = 0
               and then ((DT.C1 >= 16#41# and DT.C1 <= 16#5A#)
                         or (DT.C1 >= 16#30# and DT.C1 <= 16#39#))
               and then ((DT.C2 >= 16#41# and DT.C2 <= 16#5A#)
                         or (DT.C2 >= 16#30# and DT.C2 <= 16#39#));
   end Extract_DocType;

   --  Constant-time 64-byte comparison (no short-circuit).
   function Digest_Equal (A, B : Digest) return Boolean
   is
      Diff : Byte := 0;
   begin
      for I in Digest_Index loop
         Diff := Diff or (A (I) xor B (I));
      end loop;
      return Diff = 0;
   end Digest_Equal;

   ---------------------------------------------------------------------------
   --  Parse — structural parse, §6 rules 1-8
   ---------------------------------------------------------------------------
   procedure Parse
     (Document : Byte_Array;
      Env      : out Unverified_Envelope)
   is
      DT_Valid : Boolean;
      Suite_Val : Unsigned_16;
      BL, SL, SigL : Unsigned_32;
      Header_Size : Natural;
      Total_Needed : Natural;
   begin
      --  Initialize to rejected state
      Env := (DocType     => (C1 => 0, C2 => 0),
              Version_Maj => 0,
              Version_Min => 0,
              Suite       => 0,
              Timestamp   => 0,
              Body_Length  => 0,
              Seal_Length  => 0,
              Sig_Length   => 0,
              Body_Offset => 0,
              Seal_Offset => 0,
              Chain_Offset => 0,
              Sig_Offset  => 0,
              Status      => Bad_Envelope);

      --  Gate 1: preamble (§6 rule 1) — need at least the fixed header
      if Document'Length < Fixed_Header then
         Env.Status := Bad_Envelope;
         return;
      end if;

      for I in 0 .. Preamble_Length - 1 loop
         if Document (Document'First + I) /= Preamble (I) then
            Env.Status := Bad_Envelope;
            return;
         end if;
      end loop;

      --  Gate 2: doctype (§6 rule 2)
      Extract_DocType (Document, Env.DocType, DT_Valid);
      if not DT_Valid then
         Env.Status := Bad_Magic;
         return;
      end if;

      --  Version (byte 13)
      Env.Version_Maj := Shift_Right (Document (Document'First + 13), 4);
      Env.Version_Min := Document (Document'First + 13) and 16#0F#;

      --  Gate 3: crypto suite (§6 rule 3)
      Suite_Val := Read_U16 (Document, Off_Suite);
      if Suite_Val = Unsigned_16 (Suite_Reserved) then
         Env.Status := Not_Verified;  --  unknown/reserved suite
         return;
      end if;
      Env.Suite := Suite_Val;

      --  Timestamp (informational — signer's claim)
      Env.Timestamp := Read_U64 (Document, Off_Timestamp);

      --  Length fields
      BL   := Read_U32 (Document, Off_Body_Len);
      SL   := Read_U32 (Document, Off_Seal_Len);
      SigL := Read_U32 (Document, Off_Sig_Len);

      --  Gate 4: seal_length > 0 (§6 rule 4)
      if SL = 0 then
         Env.Status := Bad_Length;
         return;
      end if;

      --  Gate 5: sig_length > 0 (§6 rule 5)
      if SigL = 0 then
         Env.Status := Bad_Length;
         return;
      end if;

      --  Gate 6-7: suite-defined length match (§6 rules 6-7)
      if Suite_Val = Unsigned_16 (Suite_Default) then
         if SL /= Suite_0001_Seal_Length then
            Env.Status := Bad_Length;
            return;
         end if;
         if SigL /= Suite_0001_Sig_Length then
            Env.Status := Bad_Length;
            return;
         end if;
      else
         --  Unknown suite — reject (§6 rule 3 fallback)
         Env.Status := Not_Verified;
         return;
      end if;

      Env.Body_Length := BL;
      Env.Seal_Length := SL;
      Env.Sig_Length  := SigL;

      --  Compute offsets
      Env.Seal_Offset  := Fixed_Header;                            --  36
      Env.Chain_Offset := Fixed_Header + Natural (SL);             --  36 + SL
      Header_Size      := Fixed_Header + Natural (SL) + Chain_Length; --  100 + SL
      Env.Body_Offset  := Header_Size;
      Env.Sig_Offset   := Header_Size + Natural (BL);

      --  Gate 8: geometry overflow / data availability (§6 rule 8)
      --  Check for overflow before computing total.
      if Natural (BL) > Max_Document_Bytes
         or else Natural (SigL) > Max_Document_Bytes
      then
         Env.Status := Bad_Length;
         return;
      end if;

      Total_Needed := Header_Size + Natural (BL) + Natural (SigL);
      if Document'Length < Total_Needed then
         Env.Status := Bad_Length;
         return;
      end if;

      --  All structural checks passed
      Env.Status := Not_Verified;
   end Parse;

   ---------------------------------------------------------------------------
   --  Verify — cryptographic verification, §6 rules 9-11
   ---------------------------------------------------------------------------
   procedure Verify
     (Document   : Byte_Array;
      Env        : Unverified_Envelope;
      Prev_Chain : Digest;
      PK         : Byte_Array;
      Result     : out Verified_Record)
   is
      Seal_Recomputed : Digest;
      Chain_Recomputed : Digest;
      Carried_Seal  : Digest;
      Carried_Chain : Digest;
      Chain_Input   : Byte_Array (0 .. 127);  --  prev_chain(64) ‖ seal(64)
      Body_Start    : Natural;
      Body_End      : Natural;
      Sig_Start     : Natural;
      Sig_End       : Natural;
      Signed_End    : Natural;
   begin
      Result := (Status => Not_Verified, Trusted => False);

      Body_Start := Document'First + Env.Body_Offset;
      Body_End   := Body_Start + Natural (Env.Body_Length) - 1;
      Sig_Start  := Document'First + Env.Sig_Offset;
      Sig_End    := Sig_Start + Natural (Env.Sig_Length) - 1;
      Signed_End := Sig_Start - 1;  --  everything before the signature

      --  Gate 9: seal recomputation (§6 rule 9)
      --  Seal = SHAKE512(body) for suite 0x0001
      if Env.Body_Length > 0 then
         declare
            Body_Bytes : Byte_Array (0 .. Natural (Env.Body_Length) - 1);
         begin
            for I in Body_Bytes'Range loop
               Body_Bytes (I) := Document (Body_Start + I);
            end loop;
            SHAKE512 (Body_Bytes, Seal_Recomputed);
         end;
      else
         --  Empty body (tombstone): SHAKE512 of empty — but SHAKE512 has
         --  Pre => Input'Length > 0. For tombstones, the seal is SHAKE512
         --  of a single zero byte as a canonical empty-body hash.
         declare
            Empty : constant Byte_Array (0 .. 0) := (0 => 0);
         begin
            SHAKE512 (Empty, Seal_Recomputed);
         end;
      end if;

      --  Extract the carried seal from the document
      for I in Digest_Index loop
         Carried_Seal (I) := Document (Document'First + Env.Seal_Offset + I);
      end loop;

      if not Digest_Equal (Seal_Recomputed, Carried_Seal) then
         Result := (Status => Seal_Mismatch, Trusted => False);
         return;
      end if;

      --  Gate 10: chain hash check (§6 rule 10)
      --  Chain = SHAKE512(prev_chain ‖ current_seal)
      for I in Digest_Index loop
         Chain_Input (I) := Prev_Chain (I);
      end loop;
      for I in Digest_Index loop
         Chain_Input (64 + I) := Carried_Seal (I);
      end loop;
      SHAKE512 (Chain_Input, Chain_Recomputed);

      --  Extract carried chain hash
      for I in Digest_Index loop
         Carried_Chain (I) :=
           Document (Document'First + Env.Chain_Offset + I);
      end loop;

      if not Digest_Equal (Chain_Recomputed, Carried_Chain) then
         Result := (Status => Chain_Broken, Trusted => False);
         return;
      end if;

      --  Gate 11: ML-DSA-65 signature verification (§6 rule 11)
      --  Signed message = bytes[0 .. before signature], no canonicalization.
      declare
         Signed_Msg : Byte_Array (0 .. Signed_End - Document'First);
         Context    : constant Byte_Array (0 .. -1) := (others => 0);
         --  Empty context for FIPS 204 pure mode.
         Sig_Bytes  : LTHING_MLDSA65.Signature;
         PK_Bytes   : LTHING_MLDSA65.Public_Key;
      begin
         --  Copy the signed message (everything before the signature)
         for I in Signed_Msg'Range loop
            Signed_Msg (I) := Document (Document'First + I);
         end loop;

         --  Copy the signature
         for I in LTHING_MLDSA65.Signature'Range loop
            Sig_Bytes (I) := Document (Sig_Start + I);
         end loop;

         --  Copy the public key
         for I in LTHING_MLDSA65.Public_Key'Range loop
            PK_Bytes (I) := PK (PK'First + I);
         end loop;

         if not LTHING_MLDSA65.Verify
                  (PK      => PK_Bytes,
                   Message => Signed_Msg,
                   Context => Context,
                   Sig     => Sig_Bytes)
         then
            Result := (Status => Signature_Invalid, Trusted => False);
            return;
         end if;
      end;

      --  All gates passed. This is the ONLY place Trusted becomes True.
      Result := (Status => Verified, Trusted => True);
   end Verify;

end LTHING_Envelope;
