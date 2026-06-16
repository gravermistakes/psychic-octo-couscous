------------------------------------------------------------------------------
--  LTHING.MLDSA65 (body) — fail-closed stub until the arithmetic core lands.
--
--  Verify returns False unconditionally while Arithmetic_Core_Complete = False.
--  This is the safe inverse of audit FINDING-002 ("signature stub returns
--  True"): a missing verifier must REJECT. Agent T10 (tasks/verify.md) replaces
--  this body with the real FIPS 204 ML-DSA.Verify and flips the flag only when
--  the 15-vector sigVer KAT passes. Do NOT make this return True before then.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_MLDSA65 is

   function Verify
     (PK      : Public_Key;
      Message : Byte_Array;
      Sig     : Signature) return Boolean
   is
      pragma Unreferenced (PK, Message, Sig);
   begin
      return False;  --  fail closed: arithmetic core incomplete
   end Verify;

end LTHING_MLDSA65;
