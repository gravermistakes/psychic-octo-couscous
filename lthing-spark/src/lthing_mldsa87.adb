------------------------------------------------------------------------------
--  LTHING.MLDSA87 body — fail-closed stub
--
--  Returns False unconditionally until the ML-DSA-87 arithmetic core
--  (codec + sampler + verifier) is implemented and validated by the
--  FIPS 204 sigVer KAT (test_kat87: tcId 61..75). Arithmetic_Core_Complete
--  in the spec guards the test harness gate; flip it to True only when all
--  15 vectors pass.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA87 is

   function Verify
     (PK      : Public_Key;
      Message : Byte_Array;
      Context : Byte_Array;
      Sig     : Signature) return Boolean
   is
      pragma Unreferenced (PK, Message, Context, Sig);
   begin
      return False;
   end Verify;

end LTHING_MLDSA87;
