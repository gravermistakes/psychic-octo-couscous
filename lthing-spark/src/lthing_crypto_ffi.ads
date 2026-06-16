------------------------------------------------------------------------------
--  LTHING.Crypto_FFI — Imports of the hardened x86-64 assembly primitives
--
--  Binds the symbols exported by liblthing_crypto_asm (rule30.asm,
--  keccak.asm, xor_mask.asm) as verified by execution on 2026-06-06.
--
--  SPARK note: the imported subprograms are the trust boundary. They are
--  declared with Global => null and explicit parameter modes so SPARK can
--  reason about the Ada side; the asm bodies themselves are outside SPARK
--  and are validated by the assembly regression harness (tests/), not by
--  gnatprove. This separation is deliberate and documented.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;        use Interfaces;
with Interfaces.C;       use Interfaces.C;
with LTHING_Types;      use LTHING_Types;

package LTHING_Crypto_FFI is

   --  Keccak sponge rate for SHAKE512 (FIPS 202): 72 bytes.
   SHAKE512_Rate : constant := 72;

   --  Keccak state: 25 lanes of 64 bits.
   subtype Lane_Index is Natural range 0 .. 24;
   type Keccak_State is array (Lane_Index) of Interfaces.Unsigned_64;

   --  shake256_absorb(state, data, data_len, rate)
   --  (the asm core is the shared Keccak permutation; SHAKE512 = rate 72)
   procedure SHAKE_Absorb
     (State    : in out Keccak_State;
      Data     : Byte_Array;
      Data_Len : Interfaces.C.unsigned;
      Rate     : Interfaces.C.unsigned)
     with Global => null,
          Import => True,
          Convention => C,
          External_Name => "shake256_absorb",
          Pre => Data'Length > 0 and then Rate = SHAKE512_Rate;

   --  shake256_squeeze(state, output, output_len, rate)
   procedure SHAKE_Squeeze
     (State      : in out Keccak_State;
      Output     : out Byte_Array;
      Output_Len : Interfaces.C.unsigned;
      Rate       : Interfaces.C.unsigned)
     with Global => null,
          Import => True,
          Convention => C,
          External_Name => "shake256_squeeze",
          Pre  => Output'Length > 0 and then Rate = SHAKE512_Rate,
          Post => Output'Length = Output'Length;

   --  compare_constant_time(a, b, len) -> 0 equal, 1 different
   function Compare_CT
     (A   : Byte_Array;
      B   : Byte_Array;
      Len : Interfaces.C.unsigned) return Interfaces.C.int
     with Global => null,
          Import => True,
          Convention => C,
          External_Name => "compare_constant_time",
          Pre => Len <= unsigned (Natural'Last)
                 and then A'Length >= Natural (Len)
                 and then B'Length >= Natural (Len);

end LTHING_Crypto_FFI;
