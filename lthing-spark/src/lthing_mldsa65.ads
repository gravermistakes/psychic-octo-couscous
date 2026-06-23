------------------------------------------------------------------------------
--  LTHING.MLDSA65 — ML-DSA-65 (FIPS 204) verifier, pure Ada/SPARK
--
--  Parameter set verified against FIPS 204 final and multiple independent
--  sources on 2026-06-06:
--    n = 256, q = 8380417 = 2**23 - 2**13 + 1
--    (k, l) = (6, 5)            [NIST Security Level 3]
--    eta = 4, gamma1 = 2**19, gamma2 = (q-1)/32 = 261888
--    tau = 49, beta = tau*eta = 196, omega = 55, d = 13
--    public key  = 1952 bytes   (rho:32 || t1: k*320)
--    signature   = 3309 bytes   (c_tilde:48 || z enc || h enc)
--    c_tilde length for ML-DSA-65 = 48 bytes (384 bits, lambda/4)
--
--  SCOPE: this package implements the full FIPS 204 Algorithm 3 (ML-DSA.Verify,
--  external/pure) and Algorithm 8 (ML-DSA.Verify_internal) — pkDecode, sigDecode
--  (with ⊥ on malformed/over-weight hint), ExpandA, SampleInBall, the
--  NTT⁻¹(Â∘NTT(z) − NTT(c)∘NTT(t1·2^d)) recomputation, UseHint, w1Encode, and the
--  final ‖z‖∞ < γ1−β ∧ c̃=c̃' acceptance. The arithmetic core is COMPLETE and
--  passes the 15-vector ML-DSA-65 sigVer KAT (3 accept / 12 reject). The whole
--  unit is SPARK_Mode (On) and gnatprove-clean (0 unproved).
--  Fail-closed is preserved: any decode failure, malformed/over-weight hint,
--  norm overflow, or challenge mismatch returns False; Verify returns True only
--  on a genuine FIPS 204 acceptance. See FIPS204_PROTOCOLS.md for the conformance
--  map. Do NOT make Verify return True on any path that has not genuinely passed
--  Algorithm 8.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;
with LTHING_Types; use LTHING_Types;

package LTHING_MLDSA65 is

   --  ----- FIPS 204 ML-DSA-65 constants -----
   N      : constant := 256;
   Q      : constant := 8_380_417;
   K_Dim  : constant := 6;
   L_Dim  : constant := 5;
   Eta    : constant := 4;
   Gamma1 : constant := 2 ** 19;
   Gamma2 : constant := (Q - 1) / 32;        --  261888
   Tau    : constant := 49;
   Beta   : constant := Tau * Eta;           --  196
   Omega  : constant := 55;
   D_Bits : constant := 13;

   PK_Bytes      : constant := 1952;
   Sig_Bytes     : constant := 3309;
   C_Tilde_Bytes : constant := 48;           --  lambda/4 for Level 3

   subtype Public_Key is Byte_Array (0 .. PK_Bytes - 1);
   subtype Signature  is Byte_Array (0 .. Sig_Bytes - 1);

   --  Coefficient in Z_q, kept as a 32-bit signed value during reduction.
   subtype Coeff is Interfaces.Integer_32;

   --  A degree-255 polynomial.
   type Poly is array (0 .. N - 1) of Coeff;

   --  Verify result: deliberately just a Boolean here; the judicial layer
   --  maps False -> Signature_Invalid (fail-closed).
   --
   --  Soundness note: SPARK proves AoRTE + flow for this unit, NOT cryptographic
   --  soundness (that True implies a genuine FIPS 204 acceptance) — that property
   --  is established by the authoritative 15-vector sigVer KAT, not by gnatprove.
   --  FIPS 204 Algorithm 3 (ML-DSA.Verify), external/pure interface.
   --  Context is the application context string (length 0 .. 255). The
   --  verifier forms the external prefix  M' = 0x00 || len(ctx) || ctx ||
   --  Message  internally (Alg. 3) before hashing into mu.
   --  Upper bound on the application message length. The verifier forms the
   --  internal prefix  M' = 0x00 || len(ctx) || ctx || Message  (2 framing
   --  bytes + up to 255 context bytes) and then the hash input  tr || M'
   --  (64 extra bytes). The largest derived buffer is therefore indexed up to
   --  65 + Context'Length + Message'Length, which must stay <= Index_Range'Last
   --  (= Max_Document_Bytes). A 512-byte headroom comfortably covers the
   --  64 (tr) + 2 (framing) + 255 (ctx) overhead. Real documents (judicial
   --  bodies and the KAT vectors, all < 8200 bytes) are far under this
   --  ceiling, so the bound is non-restrictive in practice.
   Max_Message_Bytes : constant := Max_Document_Bytes - 512;

   function Verify
     (PK      : Public_Key;
      Message : Byte_Array;
      Context : Byte_Array;
      Sig     : Signature) return Boolean
     with Global => null,
          --  FIPS 204 permits an empty message (M = epsilon); the verifier must
          --  not false-reject it. The body forms M' = 0x00 || len(ctx) || ctx
          --  with an empty message tail (M_Prime range 0 .. 1; the copy loop is
          --  a null range), so Message'Length = 0 is well-defined and accepted.
          Pre    => Message'Length <= Max_Message_Bytes
                    and then Context'Length <= 255;

   --  Exposed so the judicial layer and tests can assert the current posture.
   --  Flipped to True now that the FIPS 204 arithmetic core (Alg. 8) is
   --  implemented and passes the 15-vector ML-DSA-65 sigVer KAT.
   Arithmetic_Core_Complete : constant Boolean := True;

end LTHING_MLDSA65;
