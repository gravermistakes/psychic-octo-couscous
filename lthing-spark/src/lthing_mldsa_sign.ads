------------------------------------------------------------------------------
--  LTHING.MLDSA.Sign — ML-DSA-65 (FIPS 204) key generation + signing
--
--  Completes the signing side that pairs with the existing verifier
--  (LTHING_MLDSA65.Verify, Alg.3/8). Implements:
--    * Key_Gen — FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal): from a 32-byte
--      seed produce the 1952-byte public key and an in-memory expanded secret
--      key (rho, K, tr, s1, s2, t0).
--    * Sign    — FIPS 204 Algorithm 7 (ML-DSA.Sign_internal) with the bounded
--      rejection loop, producing a 3309-byte signature that Verify accepts.
--
--  The mu / M' / c_tilde / w1Encode constructions are byte-for-byte identical
--  to the verifier (see lthing_mldsa65.adb), so signatures round-trip:
--      Verify(pk, m, ctx, Sign(KeyGen(seed).sk, m, ctx)) = True.
--  That round-trip (plus tamper -> reject) is the authoritative relational gate
--  in test_sign; no self-derived signature vector is pasted anywhere.
--
--  SPARK_Mode (On); proof target is AoRTE + flow. Sign's rejection loop is a
--  bounded for-loop (Max_Attempts); exhaustion is fail-closed (Ok=False), which
--  is cryptographically unreachable but keeps the loop total for the prover.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;       use Interfaces;
with LTHING_Types;     use LTHING_Types;
with LTHING_MLDSA65;   use LTHING_MLDSA65;
with LTHING_MLDSA_NTT;

package LTHING_MLDSA_Sign is

   --  Secret polynomials are stored as Fq vectors (NTT-layer Poly), so the
   --  0..Q-1 element invariant is carried by the type and the conversions into
   --  the field/NTT primitives are free.
   subtype SPoly is LTHING_MLDSA_NTT.Poly;          --  array (0..255) of Fq

   --  Secret-key polynomial vectors, coefficients canonical in 0..Q-1.
   type L_Vec is array (0 .. L_Dim - 1) of SPoly;   --  l = 5
   type K_Vec is array (0 .. K_Dim - 1) of SPoly;   --  k = 6

   --  Expanded secret key (the FIPS 204 sk, kept structured in memory rather
   --  than byte-encoded — the verifier only ever consumes the public key).
   type Secret_Key is record
      Rho : Byte_Array (0 .. 31);   --  matrix seed
      KK  : Byte_Array (0 .. 31);   --  signing seed K
      Tr  : Byte_Array (0 .. 63);   --  H(pk, 64)
      S1  : L_Vec;                  --  coeffs in [-eta, eta] (canonical)
      S2  : K_Vec;                  --  coeffs in [-eta, eta] (canonical)
      T0  : K_Vec;                  --  low part of t (canonical)
   end record;

   --  Algorithm 6: KeyGen_internal. Seed must be exactly 32 bytes.
   procedure Key_Gen
     (Seed : Byte_Array;
      PK   : out Public_Key;
      SK   : out Secret_Key)
     with Global => null,
          Pre    => Seed'Length = 32;

   --  Algorithm 7: Sign_internal (deterministic variant, rnd = 0). Forms the
   --  same external prefix M' = 0x00 || len(ctx) || ctx || Message as Verify.
   --  Ok is True on success; False only if the bounded rejection loop is
   --  exhausted (unreachable in practice) — fail-closed.
   procedure Sign
     (SK      : Secret_Key;
      Message : Byte_Array;
      Context : Byte_Array;
      Sig     : out Signature;
      Ok      : out Boolean)
     with Global => null,
          Pre    => Message'Length <= Max_Message_Bytes
                    and then Context'Length <= 255;

end LTHING_MLDSA_Sign;
