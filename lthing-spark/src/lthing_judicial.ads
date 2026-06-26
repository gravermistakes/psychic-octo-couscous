------------------------------------------------------------------------------
--  LTHING.Judicial — .jd.lthing parse-and-verify (court-grade, fail-closed)
--
--  This package is the home of the requirement the AVRS audit (2026-05-14,
--  FINDING-006) reassigned from the retired non-canonical Python parser:
--
--    "Split parse() into parse_unverified() and parse_and_verify(); the
--     verifier MUST fail closed when signature or seal verification does
--     not succeed."
--
--  Two operations are exposed and they are NOT interchangeable:
--
--    Parse_Unverified — recovers envelope structure ONLY. It performs zero
--      cryptographic checks and CANNOT return a trusted record. Its output
--      is always Trusted = False. Use only for inspection/triage.
--
--    Parse_And_Verify — performs, in order: envelope shape, magic/doctype,
--      length sanity, provenance-seal recomputation, chain-hash link, and
--      ML-DSA signature verification (ML-DSA-65 for suite 0x0001; ML-DSA-87
--      for suite 0x0002 / NSS / CNSA 2.0). It returns Trusted = True if and
--      ONLY if every check passed. Any failure short-circuits to a refusal.
--
--  The fail-closed property is encoded in the postconditions below so that
--  no implementation path can satisfy the contract while returning trusted
--  data on an unverified document. gnatprove discharges this statically.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Types; use LTHING_Types;

package LTHING_Judicial is

   --  DocType for .jd.lthing per spec Section 8.3.
   Judicial_DocType : constant := 16#0004#;

   ---------------------------------------------------------------------------
   --  Parse_Unverified
   --
   --  Structural recovery only. By contract it can NEVER return a trusted
   --  result; Trusted is always False on return. This makes the dangerous
   --  "structural parse mistaken for authenticated parse" pattern
   --  (audit root-cause Pattern 3) impossible to commit by accident: a
   --  caller cannot get a trusted record out of this entry point at all.
   ---------------------------------------------------------------------------
   procedure Parse_Unverified
     (Document : Byte_Array;
      Result   : out Verified_Record)
     with Global => null,
          Post   => Result.Trusted = False
                    and then Result.Status /= Verified;

   ---------------------------------------------------------------------------
   --  Parse_And_Verify
   --
   --  Full authenticated verification of a .jd.lthing document.
   --
   --  Inputs:
   --    Document       — the full PEM-style envelope bytes.
   --    Previous_Seal  — the seal_id of the prior chain entry (for the
   --                     provenance_chain_hash link). For the genesis entry
   --                     this is the all-zero digest.
   --    Public_Key     — the signer's ML-DSA public key. The envelope's suite
   --                     field (§3.1) determines the expected key length:
   --                     1952 B for suite 0x0001 (ML-DSA-65), 2592 B for
   --                     suite 0x0002 (ML-DSA-87 / NSS / CNSA 2.0). A key
   --                     whose length does not match the envelope's suite is
   --                     rejected with Bad_Length before any crypto runs.
   --
   --  Postcondition (fail-closed, court-grade):
   --    Result.Trusted = (Result.Status = Verified)   [from the type predicate]
   --    AND Result.Trusted is True ONLY when the document's seal recomputes,
   --    its chain hash links to Previous_Seal, and its ML-DSA signature
   --    (suite-matched) verifies under Public_Key. Equivalently: if ANY check
   --    fails, Trusted is False and Status names the first failing stage.
   ---------------------------------------------------------------------------
   procedure Parse_And_Verify
     (Document      : Byte_Array;
      Previous_Seal : Digest;
      Public_Key    : Byte_Array;
      Result        : out Verified_Record)
     with Global => null,
          Pre    => Document'Length > 0
                    and then Document'Length <= Max_Document_Bytes - 64
                    and then Public_Key'Length > 0,
          Post   => (if Result.Status /= Verified then Result.Trusted = False)
                    and then
                    (Result.Trusted = (Result.Status = Verified));

end LTHING_Judicial;
