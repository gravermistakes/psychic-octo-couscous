------------------------------------------------------------------------------
--  LTHING.MLDSA.NTT — Part 2: Number-Theoretic Transform over Z_q
--
--  256-point negacyclic NTT for ML-DSA-65 (ring Z_q[x]/(x^256+1)).
--  Primitive 512th root of unity: zeta = 1753 (FIPS 204 / Dilithium).
--
--  The zeta table is COMPUTED at elaboration from zeta=1753 via bit-reversal,
--  not transcribed from memory. This avoids the "256 magic constants in the
--  wrong order" failure mode: if the value or ordering were wrong, the
--  convolution gate (NTT(a) o NTT(b) -> INTT == schoolbook negacyclic
--  product) would fail. That gate is self-validating; no external vectors.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;          use Interfaces;
with LTHING_MLDSA_Field;  use LTHING_MLDSA_Field;

package LTHING_MLDSA_NTT is

   type Poly is array (0 .. 255) of Fq;

   Zeta_Root : constant := 1753;

   --  Forward NTT, in place. a <- NTT(a).
   procedure NTT (A : in out Poly);

   --  Inverse NTT, in place. a <- INTT(a).
   procedure Inv_NTT (A : in out Poly);

   --  Pointwise (coefficient-wise) multiplication in the NTT domain.
   function Pointwise (A, B : Poly) return Poly;

   --  Schoolbook negacyclic convolution mod (x^256 + 1), for the gate.
   function Schoolbook_Mul (A, B : Poly) return Poly;

end LTHING_MLDSA_NTT;
