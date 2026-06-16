------------------------------------------------------------------------------
--  LTHING.Crypto_FFI — Import of the hardened x86-64 constant-time compare
--
--  Binds compare_constant_time from liblthing_crypto_asm. The SHAKE
--  absorb/squeeze imports were REMOVED: the hash path is pure-Ada LTHING_Keccak
--  now, so they were dead trust surface. Only the constant-time digest compare
--  remains on the asm boundary (used by LTHING_Judicial.Digest_Equal).
--
--  SPARK note: the imported subprogram is the trust boundary; declared with
--  Global => null and explicit modes so SPARK can reason about the Ada side.
--  The asm body is validated by the assembly regression harness, not gnatprove.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces.C;  use Interfaces.C;
with LTHING_Types;  use LTHING_Types;

package LTHING_Crypto_FFI is

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
