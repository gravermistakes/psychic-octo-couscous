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

   --  Envelope shape: must contain the document-body and seal markers.
   --  Minimal here; the real byte-scan is elaborated as the format stabilizes.
   function Envelope_Ok (Document : Byte_Array) return Boolean
     with Global => null
   is
   begin
      --  A judicial envelope cannot be smaller than its fixed 48-byte header.
      return Document'Length >= 48;
   end Envelope_Ok;

   --  Magic/DocType check (spec Section 8.3: doctype 0x0004 at the documented
   --  offset). Stubbed against the header layout; returns False if absent.
   function Magic_Ok (Document : Byte_Array) return Boolean
     with Global => null
   is
   begin
      --  DocType byte position per Section 3 header layout (offset 9 of the
      --  10-byte Magic & DocType field in the example envelopes).
      return Document'Length >= 10
        and then Natural (Document (Document'First + 9)) = Judicial_DocType;
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
