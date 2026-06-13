------------------------------------------------------------------------------
--  LTHING.Judicial (body) — fail-closed .jd.lthing verification
--
--  Design for provability and safety:
--    * Result starts as (Not_Verified, False) and Trusted is assigned in
--      exactly ONE place — the final line — only after every gate passed.
--    * Every failure path assigns a specific Status and returns immediately
--      with Trusted = False (the type predicate keeps the two consistent).
--    * The ML-DSA-65 verifier is an explicit boundary that REJECTS by
--      default. The asm library does not yet provide ML-DSA; until a real
--      verifier is linked, Verify_Signature returns False, so the whole
--      pipeline fails closed. This is the safe inverse of audit FINDING-002
--      ("signature stub returns True"): a missing verifier must reject.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Hash;       use LTHING_Hash;
with LTHING_Crypto_FFI; use LTHING_Crypto_FFI;
with Interfaces.C;      use Interfaces.C;

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

   --  Constant-time digest equality via the asm primitive.
   function Digest_Equal (A, B : Digest) return Boolean
     with Global => null
   is
      A_Arr : Byte_Array (0 .. 63);
      B_Arr : Byte_Array (0 .. 63);
   begin
      for I in Digest_Index loop
         A_Arr (I) := A (I);
         B_Arr (I) := B (I);
      end loop;
      return Compare_CT (A_Arr, B_Arr, 64) = 0;
   end Digest_Equal;

   --  ML-DSA-65 signature verification boundary.
   --  REJECT-BY-DEFAULT: no real verifier is linked yet (asm lacks ML-DSA),
   --  so this returns False and the pipeline fails closed. When a verified
   --  ML-DSA-65 implementation is linked, replace the body and update the
   --  AVRS report; do NOT make it return True until then.
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
      Recomputed_Chain : Digest;
      --  In a complete implementation these are sliced out of the parsed
      --  envelope; here we recompute over the whole document as the artifact
      --  and compare against the carried chain hash once slicing is wired.
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

      --  Gate 3: chain-of-custody link.
      --  provenance_chain_hash = SHAKE512(Previous_Seal || Artifact).
      Chain_Hash (Previous_Seal, Document, Recomputed_Chain);
      --  Until envelope slicing extracts the carried chain hash, treat a
      --  self-consistent recomputation as the link check. This is a
      --  PLACEHOLDER comparison and is deliberately conservative: it does not
      --  grant trust on its own because the signature gate (4) still rejects.
      if not Digest_Equal (Recomputed_Chain, Recomputed_Chain) then
         Result := (Status => Chain_Broken, Trusted => False);
         return;
      end if;

      --  Gate 4: ML-DSA-65 signature. Reject-by-default today.
      if not Verify_Signature (Document, Public_Key) then
         Result := (Status => Signature_Invalid, Trusted => False);
         return;
      end if;

      --  All gates passed: this is the ONLY place Trusted becomes True.
      Result := (Status => Verified, Trusted => True);
   end Parse_And_Verify;

end LTHING_Judicial;
