------------------------------------------------------------------------------
--  LTHING.Hash (body) — SHAKE512 over the asm Keccak sponge
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;        use Interfaces;
with Interfaces.C;
with LTHING_Crypto_FFI; use LTHING_Crypto_FFI;

package body LTHING_Hash is

   procedure SHAKE512
     (Input  : Byte_Array;
      Output : out Digest)
   is
      State : Keccak_State := (others => 0);
      Buf   : Byte_Array (0 .. 63) := (others => 0);
   begin
      SHAKE_Absorb
        (State    => State,
         Data     => Input,
         Data_Len => Interfaces.C.unsigned (Input'Length),
         Rate     => SHAKE512_Rate);

      SHAKE_Squeeze
        (State      => State,
         Output     => Buf,
         Output_Len => 64,
         Rate       => SHAKE512_Rate);

      for I in Digest_Index loop
         Output (I) := Buf (I);
      end loop;
   end SHAKE512;

   procedure Chain_Hash
     (Previous_Seal : Digest;
      Artifact      : Byte_Array;
      Output        : out Digest)
   is
      --  Concatenate Previous_Seal (64 bytes) || Artifact, then SHAKE512.
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
           (J = 64 + (I - Artifact'First)
            and then J < Concat_Len);
         Concat (J) := Artifact (I);
         J := J + 1;
      end loop;

      SHAKE512 (Concat, Output);
   end Chain_Hash;

end LTHING_Hash;
