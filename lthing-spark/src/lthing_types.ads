------------------------------------------------------------------------------
--  LTHING.Types — Shared types for the Ada/SPARK control layer
--
--  Copyright (c) l'Evermoor.
--  Licensed under THE EVERMOOR SANCTUARY LICENSE
--    (ESL-ANCSA-MRA-IndiModSHA).  GPL-3.0-or-later compatible copyleft.
--
--  Court-grade posture: this layer is SPARK_Mode (On). Contracts state the
--  fail-closed property the AVRS audit (2026-05-14, FINDING-006) reassigned
--  here from the retired non-canonical Python parser.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;

package LTHING_Types is

   subtype Byte is Interfaces.Unsigned_8;

   --  Bounded octet string. A hard upper bound is required for SPARK proof
   --  (no unbounded heap reasoning). 1 MiB ceiling on a judicial body is
   --  generous and bounds the DoS surface the audit flagged (FINDING-008).
   Max_Document_Bytes : constant := 1_048_576;

   subtype Index_Range is Natural range 0 .. Max_Document_Bytes;

   type Byte_Array is array (Index_Range range <>) of Byte;

   --  A SHAKE512 digest is 64 bytes.
   subtype Digest_Index is Natural range 0 .. 63;
   type Digest is array (Digest_Index) of Byte;

   --  Outcome of any verification step. There is no "partially valid" value;
   --  the audit's fail-closed requirement is encoded as: anything that is not
   --  Verified is a refusal to trust.
   type Verify_Status is
     (Verified,            --  all cryptographic checks passed
      Bad_Envelope,        --  PEM-style structure malformed
      Bad_Magic,           --  magic/doctype mismatch
      Bad_Length,          --  declared lengths inconsistent / over bound
      Seal_Mismatch,       --  provenance seal hash did not match body
      Chain_Broken,        --  provenance_chain_hash did not link
      Signature_Invalid,   --  ML-DSA-65 signature did not verify
      Not_Verified);       --  default / catch-all refusal

   --  A trust-tagged result. The Boolean is redundant with the status by
   --  design: it lets contracts assert the invariant
   --  (Trusted = (Status = Verified)) so no code path can return data marked
   --  trusted without having reached Verified.
   type Verified_Record is record
      Status  : Verify_Status := Not_Verified;
      Trusted : Boolean       := False;
   end record
     with Dynamic_Predicate =>
       (Verified_Record.Trusted = (Verified_Record.Status = Verified));

end LTHING_Types;
