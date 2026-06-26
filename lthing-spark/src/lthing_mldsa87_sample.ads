------------------------------------------------------------------------------
--  LTHING.MLDSA87.Sample — ExpandA + SampleInBall (FIPS 204), Level-5 set
--
--  Level-5 sibling of LTHING_MLDSA_Sample. Uses the pure-Ada Keccak core
--  (SHAKE128 for ExpandA, SHAKE256 for SampleInBall) via the SHAKE wrapper.
--
--  Differences from the ML-DSA-65 sampler:
--    * SampleInBall self-gate: exactly tau = 60 nonzero coeffs (vs 49), each
--      +1 or -1, derived from a 64-byte c_tilde (vs 48).
--    * Matrix A is k x l = 8 x 7 (vs 6 x 5).
--  Full correctness is confirmed downstream by the ML-DSA-87 sigVer KAT.
--
--  STATUS: SPEC ONLY. No body yet (see LTHING_MLDSA87 header).
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);   --  spec-only; declarations are in SPARK

with Interfaces;          use Interfaces;
with LTHING_MLDSA_NTT;    use LTHING_MLDSA_NTT;
with LTHING_Types;        use LTHING_Types;

package LTHING_MLDSA87_Sample is

   Tau : constant := 60;

   --  SampleInBall: derive challenge polynomial c from c_tilde (64 bytes for
   --  ML-DSA-87). Result has exactly tau nonzero coeffs in {-1,+1}.
   procedure Sample_In_Ball
     (C_Tilde : Byte_Array;
      C       : out Poly);

   --  Matrix A is k x l of polynomials in NTT domain.
   type Matrix is array (0 .. 7, 0 .. 6) of Poly;   --  k=8, l=7

   --  ExpandA: expand rho (32 bytes) into the k x l matrix A_hat (NTT domain).
   --  Rho is exactly the 32-byte ML-DSA-87 matrix seed; the precondition both
   --  documents that and bounds the seed-assembly indexing (Rho'First + I).
   --  Mirrors LTHING_MLDSA_Sample.Expand_A.
   procedure Expand_A
     (Rho : Byte_Array;
      A   : out Matrix)
     with Pre => Rho'First = 0 and then Rho'Last = 31;

   --  count nonzero coeffs (for the self-gate / debugging) <-- NOT ALLOWED
   -- function Count_Nonzero (C : Poly) return Natural;

end LTHING_MLDSA87_Sample;
