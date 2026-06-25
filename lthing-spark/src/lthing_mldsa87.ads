------------------------------------------------------------------------------
--  LTHING.MLDSA87 — ML-DSA-87 (FIPS 204) verifier spec, pure Ada/SPARK
--
--  Level-5 sibling of LTHING_MLDSA65, added so the judicial layer can target
--  NIST Security Level 5 / NSA CNSA 2.0 (which mandates ML-DSA-87 for National
--  Security Systems; the Level-3 ML-DSA-65 set is not approved for NSS).
--
--  ADDITIVE: this package does NOT replace LTHING_MLDSA65. Both parameter sets
--  coexist; the caller (or the judicial layer) selects the set. ML-DSA-65 and
--  every shared lower layer (field, NTT, round) are untouched.
--
--  Parameter set per FIPS 204 (final), Table of ML-DSA parameter sets,
--  ML-DSA-87 column. Note the differences from ML-DSA-65 that matter here:
--    (k, l) = (8, 7)          [vs (6, 5)]      -- NIST Security Level 5
--    eta = 2                  [vs 4]           -- (affects keygen/sign only,
--                                                 not the verify decode path)
--    tau = 60                 [vs 49]
--    beta = tau*eta = 120     [vs 196]
--    omega = 75               [vs 55]
--    lambda = 256, c_tilde = lambda/4 = 64 bytes   [vs 192 / 48]
--    public key  = 2592 bytes (rho:32 || t1: k*320 = 2560)   [vs 1952]
--    signature   = 4627 bytes (c_tilde:64 || z: l*640 = 4480 || h: omega+k = 83)
--                                                             [vs 3309]
--  Unchanged from ML-DSA-65 (shared lower layers rely on these):
--    n = 256, q = 8380417 = 2**23 - 2**13 + 1, d = 13,
--    gamma1 = 2**19 = 524288, gamma2 = (q-1)/32 = 261888.
--
--  STATUS (honest): SPEC ONLY. There is no body yet. Until an ML-DSA-87
--  arithmetic/decoder core exists AND passes the authoritative FIPS 204
--  ML-DSA-87 sigVer KATs, this package must not be wired into any accepting
--  path. Any future body MUST be fail-closed by construction: Verify returns
--  False unless it reaches a genuine FIPS 204 acceptance. Do NOT flip
--  Arithmetic_Core_Complete to True before the KATs pass (mirrors the
--  ML-DSA-65 discipline).
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with LTHING_Types; use LTHING_Types;

package LTHING_MLDSA87 is

   --  ----- FIPS 204 ML-DSA-87 constants (NIST Security Level 5) -----
   N      : constant := 256;
   Q      : constant := 8_380_417;
   K_Dim  : constant := 8;
   L_Dim  : constant := 7;
   Eta    : constant := 2;
   Gamma1 : constant := 2 ** 19;
   Gamma2 : constant := (Q - 1) / 32;        --  261888
   Tau    : constant := 60;
   Beta   : constant := Tau * Eta;           --  120
   Omega  : constant := 75;
   D_Bits : constant := 13;

   PK_Bytes      : constant := 2592;         --  32 + K_Dim*320
   Sig_Bytes     : constant := 4627;         --  64 + L_Dim*640 + (Omega + K_Dim)
   C_Tilde_Bytes : constant := 64;           --  lambda/4 for Level 5

   subtype Public_Key is Byte_Array (0 .. PK_Bytes - 1);
   subtype Signature  is Byte_Array (0 .. Sig_Bytes - 1);

   --  Coefficient in Z_q, kept as a 32-bit signed value during reduction.
   subtype Coeff is Interfaces.Integer_32;

   --  A degree-255 polynomial (matches the shared NTT layer's Poly shape).
   type Poly is array (0 .. N - 1) of Coeff;

   --  FIPS 204 Algorithm 3 (ML-DSA.Verify), external/pure interface.
   --  Context is the application context string (length 0 .. 255). The verifier
   --  forms M' = 0x00 || len(ctx) || ctx || Message internally (Alg. 3) before
   --  hashing into mu. Same signature shape as LTHING_MLDSA65.Verify so the two
   --  sets are drop-in selectable.
   --
   --  Postcondition note: as with ML-DSA-65, cryptographic soundness (True
   --  implies a genuine FIPS 204 acceptance) cannot be proved statically; the
   --  safety direction is the contract obligation -- while no validated core
   --  exists, any body must return False unconditionally (fail-closed).
   --  Upper bound on the application message length, mirrored from
   --  LTHING_MLDSA65. The verifier forms M' = 0x00 || len(ctx) || ctx ||
   --  Message (2 framing bytes + up to 255 context bytes) and then tr || M'
   --  (64 extra bytes), so the largest derived buffer is indexed up to
   --  65 + Context'Length + Message'Length, which must stay <= Index_Range'Last
   --  (= Max_Document_Bytes). The 512-byte headroom covers the 64+2+255
   --  overhead; real documents are far below this ceiling.
   Max_Message_Bytes : constant := Max_Document_Bytes - 512;

   function Verify
     (PK      : Public_Key;
      Message : Byte_Array;
      Context : Byte_Array;
      Sig     : Signature) return Boolean
     with Global => null,
          --  FIPS 204 permits an empty message (M = epsilon); the verifier must
          --  not false-reject it. Mirrors LTHING_MLDSA65.Verify exactly so the
          --  two parameter sets stay drop-in selectable.
          Pre    => Message'Length <= Max_Message_Bytes
                    and then Context'Length <= 255;

   --  Posture flag, mirrored from LTHING_MLDSA65. FALSE until the ML-DSA-87
   --  arithmetic core is implemented and passes the FIPS 204 ML-DSA-87 sigVer
   --  KAT. Flip ONLY when that holds.
   Arithmetic_Core_Complete : constant Boolean := False;

end LTHING_MLDSA87;
