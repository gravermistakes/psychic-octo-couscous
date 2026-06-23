------------------------------------------------------------------------------
--  LTHING.Judicial (body) — fail-closed .jd.lthing verification
--
--  Design for provability and safety:
--    * Result starts as (Not_Verified, False) and Trusted is assigned in
--      exactly ONE place — the final line — only after every gate passed.
--    * Every failure path assigns a specific Status and returns immediately
--      with Trusted = False (the type predicate keeps the two consistent).
--
--  §3 in-document layout (byte offsets from Document'First):
--    [0   .. 13  ]  §2 header prefix (preamble + doctype + version, 14 B)
--    [14  .. 77  ]  carried provenance_chain_hash (64 B = Digest)
--    [78  .. 3386]  ML-DSA-65 signature (3309 B = LTHING_MLDSA65.Sig_Bytes)
--    [3387.. Last]  message / content payload (>= 1 B)
--  Minimum document length: 3388 bytes.  Documents that pass the §2 magic
--  check but are shorter than 3388 bytes are rejected as Bad_Length.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Hash;    use LTHING_Hash;
with LTHING_MLDSA65;
with Interfaces;     use Interfaces;

package body LTHING_Judicial is

   ---------------------------------------------------------------------------
   --  §2 layout constants.
   ---------------------------------------------------------------------------

   Preamble : constant Byte_Array (0 .. 9) :=
     (16#00#, 16#00#, 16#00#, 16#0B#, 16#0D#, 16#EE#, 16#D0#,
      16#00#, 16#00#, 16#00#);

   JD_DocType_B11      : constant := 16#A4#;
   JD_DocType_B12      : constant := 16#40#;
   Header_Prefix_Bytes : constant := 14;

   ---------------------------------------------------------------------------
   --  §3 layout constants.
   ---------------------------------------------------------------------------

   Chain_Hash_Offset : constant := Header_Prefix_Bytes;
   Sig_Offset        : constant := Chain_Hash_Offset + 64;
   Content_Offset    : constant := Sig_Offset + LTHING_MLDSA65.Sig_Bytes;
   Min_Sig_Doc_Bytes : constant := Content_Offset + 1;

   ---------------------------------------------------------------------------
   --  Internal helpers (all pure, all fail-closed).
   ---------------------------------------------------------------------------

   function Envelope_Ok (Document : Byte_Array) return Boolean
     with Global => null
   is
   begin
      return Document'Length >= Header_Prefix_Bytes;
   end Envelope_Ok;

   function Magic_Ok (Document : Byte_Array) return Boolean
     with Global => null
   is
   begin
      if Document'Length < Header_Prefix_Bytes then
         return False;
      end if;
      for I in Preamble'Range loop
         if Natural (Document (Document'First + I)) /= Natural (Preamble (I)) then
            return False;
         end if;
      end loop;
      return Natural (Document (Document'First + 10)) = Judicial_DocType
        and then Natural (Document (Document'First + 11)) = JD_DocType_B11
        and then Natural (Document (Document'First + 12)) = JD_DocType_B12;
   end Magic_Ok;

   --  Constant-time digest equality, pure Ada (no early exit):
   --  OR-accumulate per-byte XOR so the loop always runs all 64 bytes.
   function Digest_Equal (A, B : Digest) return Boolean
     with Global => null
   is
      Diff : Byte := 0;
   begin
      for I in Digest_Index loop
         Diff := Diff or (A (I) xor B (I));
      end loop;
      return Diff = 0;
   end Digest_Equal;

   ---------------------------------------------------------------------------
   --  Parse_Unverified — structural only, never trusted.
   ---------------------------------------------------------------------------
   procedure Parse_Unverified
     (Document : Byte_Array;
      Result   : out Verified_Record)
   is
   begin
      if not Envelope_Ok (Document) then
         Result := (Status => Bad_Envelope, Trusted => False);
      else
         Result := (Status => Not_Verified, Trusted => False);
      end if;
   end Parse_Unverified;

   ---------------------------------------------------------------------------
   --  Parse_And_Verify — full gate; Trusted set once, at the very end.
   ---------------------------------------------------------------------------
   procedure Parse_And_Verify
     (Document      : Byte_Array;
      Previous_Seal : Digest;
      Public_Key    : Byte_Array;
      Result        : out Verified_Record)
   is
      Recomputed_Chain : Digest;
      Carried_Hash     : Digest;
   begin
      Result := (Status => Not_Verified, Trusted => False);

      --  Gate 1: envelope shape — must carry at least the §2 header prefix.
      if not Envelope_Ok (Document) then
         Result := (Status => Bad_Envelope, Trusted => False);
         return;
      end if;

      --  Gate 2: magic / doctype.
      if not Magic_Ok (Document) then
         Result := (Status => Bad_Magic, Trusted => False);
         return;
      end if;

      --  Gate 3: §3 format length — must carry chain hash + sig + >= 1 B content.
      if Document'Length < Min_Sig_Doc_Bytes then
         Result := (Status => Bad_Length, Trusted => False);
         return;
      end if;

      --  Gate 4: public key must be a valid ML-DSA-65 key (1952 bytes).
      if Public_Key'Length /= LTHING_MLDSA65.PK_Bytes then
         Result := (Status => Signature_Invalid, Trusted => False);
         return;
      end if;

      --  Gate 5: chain-of-custody link.
      --  Recompute SHAKE512(Previous_Seal || content) and compare against the
      --  hash carried at [Chain_Hash_Offset .. Chain_Hash_Offset + 63].
      Chain_Hash (Previous_Seal,
                  Document (Document'First + Content_Offset .. Document'Last),
                  Recomputed_Chain);

      for I in Digest_Index loop
         Carried_Hash (I) := Document (Document'First + Chain_Hash_Offset + I);
      end loop;

      if not Digest_Equal (Recomputed_Chain, Carried_Hash) then
         Result := (Status => Chain_Broken, Trusted => False);
         return;
      end if;

      --  Gate 6: ML-DSA-65 signature verification.
      declare
         Typed_PK  : LTHING_MLDSA65.Public_Key;
         Typed_Sig : LTHING_MLDSA65.Signature;
         Empty_Ctx : constant Byte_Array (2 .. 1) := (others => 0);
      begin
         for I in LTHING_MLDSA65.Public_Key'Range loop
            Typed_PK (I) := Public_Key (Public_Key'First + I);
         end loop;

         for I in LTHING_MLDSA65.Signature'Range loop
            Typed_Sig (I) := Document (Document'First + Sig_Offset + I);
         end loop;

         if not LTHING_MLDSA65.Verify
           (PK      => Typed_PK,
            Message => Document (Document'First + Content_Offset .. Document'Last),
            Context => Empty_Ctx,
            Sig     => Typed_Sig)
         then
            Result := (Status => Signature_Invalid, Trusted => False);
            return;
         end if;
      end;

      --  All gates passed: this is the ONLY place Trusted becomes True.
      Result := (Status => Verified, Trusted => True);
   end Parse_And_Verify;

end LTHING_Judicial;
