------------------------------------------------------------------------------
--  LTHING.Envelope — Minimal Viable Envelope (§3) types and parser
--
--  Implements the LTHING Header Specification (Working Draft 1750099200):
--    * 10-byte preamble with B0DEED magic
--    * Nibble-straddled ASCII doctype + version
--    * Crypto suite selector (§3.2)
--    * Timestamp (§3.3) — signer's claim, not proof
--    * Body/seal/sig lengths (§3.4)
--    * Seal (§3.5) — SHAKE512(body) for suite 0x0001
--    * Chain hash (§3.6) — SHAKE512(prev_chain ‖ seal), always SHAKE512
--    * Signature (§3.8) — over exact wire bytes, no canonicalization
--
--  Parser requirements (§6) are encoded as fail-closed gates: every
--  MUST-reject rule in the spec is a check that returns a specific
--  rejection status. The type system separates Unverified_Envelope
--  from a Verified result — there is no implicit promotion.
--
--  Lead Engineer — Rune auf Opus (4.6)
--  Co-authored with Anja Evermoor.
--  Copyright (c) l'Evermoor.
--  Licensed under THE EVERMOOR SANCTUARY LICENSE
--    (ESL-ANCSA-MRA-IndiModSHA).  GPL-3.0-or-later compatible copyleft.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with LTHING_Types; use LTHING_Types;

package LTHING_Envelope is

   ---------------------------------------------------------------------------
   --  §2.1 — Preamble (10 bytes, fixed)
   ---------------------------------------------------------------------------
   Preamble_Length : constant := 10;

   Preamble : constant Byte_Array (0 .. 9) :=
     (16#00#, 16#00#, 16#00#, 16#0B#, 16#0D#,
      16#EE#, 16#D0#, 16#00#, 16#00#, 16#00#);

   ---------------------------------------------------------------------------
   --  §2.5 — Complete prefix (14 bytes)
   ---------------------------------------------------------------------------
   Prefix_Length : constant := 14;

   ---------------------------------------------------------------------------
   --  §3.1 — Fixed header offsets (byte positions)
   ---------------------------------------------------------------------------
   Off_Suite     : constant := 14;   --  2 bytes
   Off_Timestamp : constant := 16;   --  8 bytes
   Off_Body_Len  : constant := 24;   --  4 bytes
   Off_Seal_Len  : constant := 28;   --  4 bytes
   Off_Sig_Len   : constant := 32;   --  4 bytes
   Off_Seal      : constant := 36;   --  seal_length bytes

   --  Chain hash follows seal: offset 36 + seal_length, always 64 bytes.
   Chain_Length   : constant := 64;

   --  Fixed portion of header before seal: 36 bytes.
   Fixed_Header   : constant := 36;

   --  Total header before body = 36 + seal_length + 64 = 100 + seal_length.
   --  For suite 0x0001 (seal = 64): total header = 164 bytes.

   ---------------------------------------------------------------------------
   --  §3.2 — Crypto suites
   ---------------------------------------------------------------------------
   Suite_Reserved : constant Unsigned_16 := 16#0000#;
   Suite_Default  : constant Unsigned_16 := 16#0001#;

   --  Suite 0x0001 parameters
   Suite_0001_Seal_Length : constant := 64;
   Suite_0001_Sig_Length  : constant := 3309;  --  ML-DSA-65

   ---------------------------------------------------------------------------
   --  §2.3 — DocType codes (ASCII pairs)
   ---------------------------------------------------------------------------
   --  Stored as the two ASCII bytes for clarity; nibble-straddling
   --  is handled in the parser, not in these constants.
   type DocType_Code is record
      C1 : Byte;   --  first ASCII character
      C2 : Byte;   --  second ASCII character
   end record;

   DT_JD : constant DocType_Code := (C1 => 16#4A#, C2 => 16#44#);  -- 'J','D'
   DT_IP : constant DocType_Code := (C1 => 16#49#, C2 => 16#50#);  -- 'I','P'
   DT_ES : constant DocType_Code := (C1 => 16#45#, C2 => 16#53#);  -- 'E','S'
   DT_JB : constant DocType_Code := (C1 => 16#4A#, C2 => 16#42#);  -- 'J','B'
   DT_GV : constant DocType_Code := (C1 => 16#47#, C2 => 16#56#);  -- 'G','V'
   DT_FE : constant DocType_Code := (C1 => 16#46#, C2 => 16#45#);  -- 'F','E'

   ---------------------------------------------------------------------------
   --  Envelope rejection codes — extends Verify_Status for envelope-
   --  specific failure modes.
   ---------------------------------------------------------------------------
   --  We reuse Verify_Status from LTHING_Types. The mapping:
   --    Bad_Envelope     — preamble mismatch (§6 rule 1)
   --    Bad_Magic        — invalid doctype bytes (§6 rule 2)
   --    Bad_Length        — seal/sig = 0, suite mismatch, overflow (§6 rules 4-8)
   --    Seal_Mismatch    — recomputed seal ≠ carried seal (§6 rule 9)
   --    Chain_Broken     — chain hash mismatch (§6 rule 10)
   --    Signature_Invalid — ML-DSA-65 verification failed (§6 rule 11)
   --    Not_Verified     — unknown suite (§6 rule 3) or catch-all

   ---------------------------------------------------------------------------
   --  Parsed (unverified) envelope — structural data only.
   --  §6 rule 12: this is the Unverified_Envelope. No trust.
   ---------------------------------------------------------------------------
   type Unverified_Envelope is record
      DocType      : DocType_Code;
      Version_Maj  : Byte;
      Version_Min  : Byte;
      Suite        : Unsigned_16;
      Timestamp    : Unsigned_64;
      Body_Length   : Unsigned_32;
      Seal_Length   : Unsigned_32;
      Sig_Length    : Unsigned_32;
      --  Offsets into the original document byte array:
      Body_Offset  : Natural;
      Seal_Offset  : Natural;
      Chain_Offset : Natural;
      Sig_Offset   : Natural;
      --  Parsing status
      Status       : Verify_Status;
   end record;

   ---------------------------------------------------------------------------
   --  Parse — structural parse only, returns Unverified_Envelope.
   --  Applies §6 rules 1–8 (format and geometry checks).
   --  Does NOT verify seal, chain, or signature.
   ---------------------------------------------------------------------------
   procedure Parse
     (Document : Byte_Array;
      Env      : out Unverified_Envelope)
     with Global => null,
          Pre    => Document'Length > 0
                    and then Document'Length <= Max_Document_Bytes;

   ---------------------------------------------------------------------------
   --  Verify — full cryptographic verification.
   --  Takes a parsed envelope and performs §6 rules 9–11.
   --  Returns Verified_Record (from LTHING_Types).
   --
   --  Inputs:
   --    Document   — the full wire bytes
   --    Env        — result of Parse (must have Status = Not_Verified to
   --                 indicate structural parse succeeded)
   --    Prev_Chain — the chain hash of the predecessor (64 zero bytes for
   --                 genesis)
   --    PK         — the signer's ML-DSA-65 public key (1952 bytes)
   ---------------------------------------------------------------------------
   procedure Verify
     (Document   : Byte_Array;
      Env        : Unverified_Envelope;
      Prev_Chain : Digest;
      PK         : Byte_Array;
      Result     : out Verified_Record)
     with Global => null,
          Pre    => Document'Length > 0
                    and then Document'Length <= Max_Document_Bytes
                    and then Env.Status = Not_Verified
                    and then PK'Length > 0,
          Post   => (if Result.Status /= Verified then Result.Trusted = False)
                    and then
                    (Result.Trusted = (Result.Status = Verified));

end LTHING_Envelope;
