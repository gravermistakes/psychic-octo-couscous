------------------------------------------------------------------------------
--  LTHING.Hash — SHAKE512 digest over the hardened Keccak asm core
--
--  Wraps absorb/squeeze into a one-shot 64-byte digest. This is the hash
--  used for the Provenance Seal and the provenance_chain_hash in the
--  .jd.lthing judicial schema.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Types; use LTHING_Types;

package LTHING_Hash is

   --  Compute SHAKE512 (64-byte output) over Input.
   --  Deterministic: same input always yields the same digest (relied on by
   --  the seal-match and chain-link checks).
   procedure SHAKE512
     (Input  : Byte_Array;
      Output : out Digest)
     with Global => null,
          Pre    => Input'Length > 0;

   --  Chain link for judicial chain-of-custody:
   --    provenance_chain_hash = SHAKE512(Previous_Seal_ID & Current_Artifact)
   --  Returns the recomputed link so the caller can compare it (constant-time)
   --  against the value carried in the document body.
   procedure Chain_Hash
     (Previous_Seal : Digest;
      Artifact      : Byte_Array;
      Output        : out Digest)
     with Global => null,
          Pre    => Artifact'Length > 0
                    and then Artifact'Length <= Max_Document_Bytes - 64;

end LTHING_Hash;
