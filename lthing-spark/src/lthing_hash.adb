------------------------------------------------------------------------------
--  LTHING.Hash (body) — SHAKE512 over the pure Ada/SPARK Keccak sponge.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Keccak; use LTHING_Keccak;

package body LTHING_Hash is

   procedure SHAKE512
     (Input  : Byte_Array;
      Output : out Digest)
   is
      Buf : Byte_Array (0 .. 63);
   begin
      --  LTHING "SHAKE512" = Keccak sponge at rate 72 with the SHAKE domain.
      Sponge (Input, Rate_SHA3_512, Domain_SHAKE, Buf);
      for I in Digest_Index loop
         Output (I) := Buf (I);
      end loop;
   end SHAKE512;

   procedure Chain_Hash
     (Previous_Seal : Digest;
      Artifact      : Byte_Array;
      Output        : out Digest)
   is
      Concat_Len : constant Natural := 64 + Artifact'Length;
      Concat     : Byte_Array (0 .. Concat_Len - 1) := (others => 0);
      J          : Natural := 0;
   begin
      for I in Digest_Index loop
         Concat (I) := Previous_Seal (I);
      end loop;
      J := 64;
      for I in Artifact'Range loop
         pragma Loop_Invariant
           (J = 64 + (I - Artifact'First) and then J < Concat_Len);
         Concat (J) := Artifact (I);
         J := J + 1;
      end loop;
      SHAKE512 (Concat, Output);
   end Chain_Hash;

end LTHING_Hash;
