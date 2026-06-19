------------------------------------------------------------------------------
--  LTHING.MLDSA.Codec — ML-DSA-65 (FIPS 204) public-key / signature decoding
--
--  Implements the byte (de)serialization primitives from FIPS 204:
--    * SimpleBitUnpack   (Algorithm 19)
--    * BitUnpack         (Algorithm 18)
--    * pkDecode          (Algorithm 23)
--    * sigDecode         (Algorithm 27)
--    * HintBitUnpack     (Algorithm 21, fail-closed -> Ok=False on malformed)
--
--  ML-DSA-65 parameters (FIPS 204, NIST Security Level 3):
--    n = 256, q = 8380417, k = 6, l = 5, gamma1 = 2**19 = 524288,
--    omega = 55, public key = 1952 bytes, signature = 3309 bytes,
--    c_tilde = 48 bytes.
--
--  SPARK posture: SPARK_Mode (On). Every routine is proved free of run-time
--  errors (AoRTE) and carries range postconditions:
--    * T1 coefficients in 0 .. 1023            (10-bit SimpleBitUnpack)
--    * Z  coefficients canonical in 0 .. Q-1    (BitUnpack then field-canonical)
--    * H  hint entries in 0 .. 1
--  Decoding is total: bytes always parse into in-range values; the only
--  *validity* signal is HintBitUnpack's Ok flag, which is fail-closed.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;        use Interfaces;
with LTHING_Types;      use LTHING_Types;
with LTHING_MLDSA65;    use LTHING_MLDSA65;

package LTHING_MLDSA_Codec is

   subtype Coeff is Interfaces.Integer_32;

   --  ----- result container types -----

   --  rho seed: first 32 bytes of the public key.
   subtype Rho_Array is Byte_Array (0 .. 31);

   --  c_tilde: first 48 bytes of the signature.
   subtype C_Tilde_Array is Byte_Array (0 .. C_Tilde_Bytes - 1);

   --  t1 vector: k = 6 polynomials, each coefficient a 10-bit value (0..1023).
   type T1_Vec is array (0 .. K_Dim - 1) of Poly;

   --  z vector: l = 5 polynomials, coefficients stored canonical in 0 .. Q-1.
   type Z_Vec is array (0 .. L_Dim - 1) of Poly;

   --  hint: k = 6 polynomials of {0,1} indicator bits.
   subtype Hint_Bit is Coeff range 0 .. 1;
   type Hint_Poly is array (0 .. N - 1) of Hint_Bit;
   type H_Vec is array (0 .. K_Dim - 1) of Hint_Poly;

   --  ----- bit-unpack helpers (FIPS 204 Alg. 19 / Alg. 18) -----

   --  Single bit of a byte slice: bit n = (V(V'First + n/8) / 2**(n mod 8)) mod 2.
   function Get_Bit (V : Byte_Array; N : Natural) return Coeff
     with Global => null,
          Pre    => V'Length > 0 and then N / 8 <= V'Last - V'First,
          Post   => Get_Bit'Result in 0 .. 1;

   --  SimpleBitUnpack (Algorithm 19): unpack 256 coefficients of Bit_Len bits.
   --  Caller passes Hi = 2**Bit_Len - 1 as a concrete value (1023 for the 10-bit
   --  t1 fields, 1_048_575 for the 20-bit z fields). The contract states only
   --  the proved property -- every coefficient lies in 0 .. Hi -- using purely
   --  linear arithmetic, so no symbolic exponential appears in any proof
   --  obligation. The exact coefficient *values* are validated at run time by
   --  the FIPS 204 known-answer vector in test_codec.
   function Simple_Bit_Unpack
     (V : Byte_Array; Bit_Len : Positive; Hi : Coeff) return Poly
     with Global => null,
          Pre    => Bit_Len <= 20
                    and then V'Length = (N * Bit_Len) / 8
                    and then Hi in 1 .. 1_048_575,
          Post   => (for all I in Poly'Range =>
                       Simple_Bit_Unpack'Result (I) in 0 .. Hi);

   --  ----- pkDecode (Algorithm 23) -----
   procedure Pk_Decode
     (PK  : Public_Key;
      Rho : out Rho_Array;
      T1  : out T1_Vec)
     with Global => null,
          Post   => (for all I in T1_Vec'Range =>
                       (for all J in Poly'Range => T1 (I) (J) in 0 .. 1023));

   --  ----- encode primitives (inverses of the decoders above) -----
   --  These are the FIPS 204 packing algorithms (SimpleBitPack Alg.16,
   --  pkEncode Alg.22, sigEncode Alg.26). Each is the exact inverse of the
   --  matching decoder: the round-trip identity decode(encode(x)) = x is the
   --  relational property validated at run time (test_encode), exactly as the
   --  decoders' exact values are KAT-validated. The SPARK contracts here state
   --  only what is proved (AoRTE + output length / input-range guards); they do
   --  not assert the inverse relation (that is the runtime gate's job).

   --  SimpleBitPack (Algorithm 16): pack 256 coefficients of Bit_Len bits each,
   --  LSB-first, into (N*Bit_Len)/8 bytes. Exact inverse of Simple_Bit_Unpack.
   function Simple_Bit_Pack
     (V : Poly; Bit_Len : Positive; Hi : Coeff) return Byte_Array
     with Global => null,
          Pre    => Bit_Len <= 20
                    and then Hi in 1 .. 1_048_575
                    and then (for all I in Poly'Range => V (I) in 0 .. Hi),
          Post   => Simple_Bit_Pack'Result'First = 0
                    and then Simple_Bit_Pack'Result'Length = (N * Bit_Len) / 8;

   --  pkEncode (Algorithm 22): rho || SimpleBitPack(t1(i),10) for i in 0..k-1.
   function Pk_Encode (Rho : Rho_Array; T1 : T1_Vec) return Public_Key
     with Global => null,
          Pre    => (for all I in T1_Vec'Range =>
                       (for all J in Poly'Range => T1 (I) (J) in 0 .. 1023));

   --  sigEncode (Algorithm 26): c_tilde || BitPack(z(i)) || HintBitPack(h).
   --  Z is supplied in the same canonical 0..Q-1 form Sig_Decode emits. For a
   --  valid signature each z coeff is in the band (centered value in
   --  (-gamma1, gamma1]), and the packing is the exact inverse of Sig_Decode;
   --  the 20-bit field is taken mod 2^20 so the routine is total for any
   --  canonical input (the reduction is the identity on the valid band, so the
   --  decode/encode round-trip is unaffected). The hint H must carry at most
   --  Omega set bits in total (FIPS 204 guarantees this for a real signature);
   --  excess bits beyond Omega are dropped (encoder, not a gate).
   function Sig_Encode
     (C_Tilde : C_Tilde_Array; Z : Z_Vec; H : H_Vec) return Signature
     with Global => null,
          Pre    => (for all I in Z_Vec'Range =>
                       (for all J in Poly'Range => Z (I) (J) in 0 .. Q - 1));

   --  ----- sigDecode (Algorithm 27) + HintBitUnpack (Algorithm 21) -----
   --  Ok is fail-closed: False on any malformed hint encoding.
   procedure Sig_Decode
     (Sig     : Signature;
      C_Tilde : out C_Tilde_Array;
      Z       : out Z_Vec;
      H       : out H_Vec;
      Ok      : out Boolean)
     with Global => null,
          Post   => (for all I in Z_Vec'Range =>
                       (for all J in Poly'Range => Z (I) (J) in 0 .. Q - 1))
                    and then
                    (for all I in H_Vec'Range =>
                       (for all J in Hint_Poly'Range => H (I) (J) in 0 .. 1));

end LTHING_MLDSA_Codec;
