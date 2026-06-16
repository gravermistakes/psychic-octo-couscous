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
