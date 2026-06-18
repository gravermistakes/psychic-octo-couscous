------------------------------------------------------------------------------
--  LTHING.Judicial (body) — fail-closed .jd.lthing verification
--
--  Design for provability and safety:
--    * Result starts as (Not_Verified, False) and Trusted is assigned in
--      exactly ONE place — the final line — only after every gate passed.
--    * Every failure path assigns a specific Status and returns immediately
--      with Trusted = False (the type predicate keeps the two consistent).
--    * The ML-DSA-65 verifier (LTHING_MLDSA65) now exists and passes the
--      FIPS 204 KAT, but it is NOT wired here yet: Parse_And_Verify cannot
--      slice the signature/message out of the document until the .jd.lthing
--      envelope byte layout is specified. Until then Verify_Signature returns
--      False, so the pipeline fails closed. This is the safe inverse of audit
--      FINDING-002 ("signature stub returns True"): missing wiring rejects.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;   --  bitwise or/xor on Byte (Unsigned_8)

package body LTHING_Judicial is

   ---------------------------------------------------------------------------
   --  Internal helpers (all pure, all fail-closed).
   ---------------------------------------------------------------------------

   --  Fixed LTHING header (spec §2). Every envelope opens with this exact
   --  10-byte preamble (§2.1), then the 3-byte doctype block (§2.2/§2.3) and a
   --  version byte (§2.4). On the wire, the JD v1.0 prefix is:
   --    00 00 00 0B 0D EE D0 00 00 00  04 A4 40  10
   --    └────── preamble (10 B) ─────┘ └ JD──┘  └ver┘
   Preamble : constant Byte_Array (0 .. 9) :=
     (16#00#, 16#00#, 16#00#, 16#0B#, 16#0D#, 16#EE#, 16#D0#,
      16#00#, 16#00#, 16#00#);

   --  JD doctype block, bytes 10..12. Byte 10 is the doctype high byte and
   --  equals Judicial_DocType (0x04); bytes 11..12 carry 'D' + the null
   --  terminator nibble (§2.5 nibble reconciliation).
   JD_DocType_B11 : constant := 16#A4#;
   JD_DocType_B12 : constant := 16#40#;

   --  Fixed header prefix length through the version byte (§2.5). The §3
   --  post-version fields (crypto suite, content length, provenance chain
   --  hash, signature, seal) are still "TO BE SPECIFIED" in the format spec,
   --  so this floor is the most we can require today; it rises once §3 lands.
   Header_Prefix_Bytes : constant := 14;

   --  Envelope shape: must at least carry the fixed §2 header prefix.
   function Envelope_Ok (Document : Byte_Array) return Boolean
     with Global => null
   is
   begin
      return Document'Length >= Header_Prefix_Bytes;
   end Envelope_Ok;

   --  Magic / doctype check (spec §2). Validates the exact 10-byte preamble
   --  and the JD doctype block (bytes 10..12 = 04 A4 40). This is the real
   --  format gate. NOTE: the doctype high byte lives at offset 10, NOT offset
   --  9 — offset 9 is part of the fixed null preamble and is always 0x00.
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

   --  Constant-time digest equality in PURE SPARK Ada (no asm FFI). Data-
   --  independent: XOR-accumulate every byte difference, then test the
   --  accumulator once. Retained as the helper the seal (Seal_Mismatch) and
   --  chain (Chain_Broken) gates will use once the envelope spec lands.
   --  (GNAT does not guarantee a constant-time object-code lowering, but the
   --  control flow is data-independent -- the standard software mitigation.)
   function Digest_Equal (A, B : Digest) return Boolean
     with Global => null
   is
      Acc : Byte := 0;
   begin
      for I in Digest_Index loop
         Acc := Acc or (A (I) xor B (I));
      end loop;
      return Acc = 0;
   end Digest_Equal;

   --  ML-DSA-65 signature verification boundary.
   --  NOT WIRED YET: LTHING_MLDSA65.Verify exists and is KAT-correct, but
   --  slicing PK/Sig/Message/Context out of the envelope needs the .jd.lthing
   --  byte spec. Until that lands this returns False so the pipeline fails
   --  closed. Wire it to LTHING_MLDSA65.Verify once the spec is written; do
   --  NOT make it return True before then.
   function Verify_Signature
     (Document   : Byte_Array;
      Public_Key : Byte_Array) return Boolean
     with Global => null
   is
      pragma Unreferenced (Document, Public_Key);
   begin
      return False;  --  fail closed: missing verifier rejects
   end Verify_Signature;

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
         --  Structure recognized, but this entry point grants NO trust.
         Result := (Status => Not_Verified, Trusted => False);
      end if;
   end Parse_Unverified;

   ---------------------------------------------------------------------------
   --  Parse_And_Verify — full gate; Trusted set once, at the end.
   ---------------------------------------------------------------------------
   procedure Parse_And_Verify
     (Document      : Byte_Array;
      Previous_Seal : Digest;
      Public_Key    : Byte_Array;
      Result        : out Verified_Record)
   is
      pragma Unreferenced (Previous_Seal);
      --  Previous_Seal feeds the chain-of-custody gate, which is not yet
      --  implemented (it needs the envelope byte spec to locate the carried
      --  chain hash). Unused until that gate is wired.
   begin
      Result := (Status => Not_Verified, Trusted => False);

      --  Gate 1: envelope shape
      if not Envelope_Ok (Document) then
         Result := (Status => Bad_Envelope, Trusted => False);
         return;
      end if;

      --  Gate 2: magic / doctype
      if not Magic_Ok (Document) then
         Result := (Status => Bad_Magic, Trusted => False);
         return;
      end if;

      --  Length (-> Bad_Length), provenance-seal (-> Seal_Mismatch) and
      --  chain-of-custody (-> Chain_Broken) gates are NOT YET IMPLEMENTED:
      --  they need the .jd.lthing envelope byte spec to slice the carried
      --  seal/chain hash and field lengths out of the document. They are
      --  intentionally ABSENT rather than faked -- the old chain gate compared
      --  a value to itself and could never fire. The fail-closed signature
      --  gate below still rejects every document until a verifier is wired.

      --  Gate 3: ML-DSA-65 signature. Reject-by-default until wired.
      if not Verify_Signature (Document, Public_Key) then
         Result := (Status => Signature_Invalid, Trusted => False);
         return;
      end if;

      --  All gates passed: this is the ONLY place Trusted becomes True.
      Result := (Status => Verified, Trusted => True);
   end Parse_And_Verify;

end LTHING_Judicial;
