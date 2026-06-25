------------------------------------------------------------------------------
--  LTHING.MLDSA87.Codec — ML-DSA-87 (FIPS 204) public-key / signature decoding
--
--  Level-5 sibling of LTHING_MLDSA_Codec. Same FIPS 204 byte (de)serialization
--  primitives, sized to the ML-DSA-87 parameter set:
--    * SimpleBitUnpack   (Algorithm 19)
--    * BitUnpack         (Algorithm 18)
--    * pkDecode          (Algorithm 23)
--    * sigDecode         (Algorithm 27)
--    * HintBitUnpack     (Algorithm 21, fail-closed -> Ok=False on malformed)
--
--  ML-DSA-87 parameters (FIPS 204, NIST Security Level 5):
--    n = 256, q = 8380417, k = 8, l = 7, gamma1 = 2**19 = 524288,
--    omega = 75, public key = 2592 bytes, signature = 4627 bytes,
--    c_tilde = 64 bytes.
--
--  Only k, l, omega and c_tilde differ from ML-DSA-65; the z field bit-width
--  (20 bits, from gamma1 = 2**19) and the t1 field bit-width (10 bits) are the
--  same, so the bit-unpack helpers are byte-for-byte identical in behaviour.
--  They are re-declared here to keep the Level-5 codec self-contained (a future
--  refactor could hoist Get_Bit / Simple_Bit_Unpack into a shared unit).
--
--  SPARK posture: SPARK_Mode (On). Same proof targets as the Level-3 codec:
--    * T1 coefficients in 0 .. 1023            (10-bit SimpleBitUnpack)
--    * Z  coefficients canonical in 0 .. Q-1    (BitUnpack then field-canonical)
--    * H  hint entries in 0 .. 1
--  Decoding is total; the only *validity* signal is HintBitUnpack's fail-closed
--  Ok flag. Coefficient *values* are validated by the FIPS 204 ML-DSA-87 KAT
--  (to be added with the body).
--
--  STATUS: SPEC ONLY. No body yet (see LTHING_MLDSA87 header).
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;        use Interfaces;
with LTHING_Types;      use LTHING_Types;
with LTHING_MLDSA87;    use LTHING_MLDSA87;

package LTHING_MLDSA87_Codec is

   subtype Coeff is Interfaces.Integer_32;

   --  ----- result container types (sized to k = 8, l = 7) -----

   --  rho seed: first 32 bytes of the public key.
   subtype Rho_Array is Byte_Array (0 .. 31);

   --  c_tilde: first 64 bytes of the signature.
   subtype C_Tilde_Array is Byte_Array (0 .. C_Tilde_Bytes - 1);

   --  t1 vector: k = 8 polynomials, each coefficient a 10-bit value (0..1023).
   type T1_Vec is array (0 .. K_Dim - 1) of Poly;

   --  z vector: l = 7 polynomials, coefficients stored canonical in 0 .. Q-1.
   type Z_Vec is array (0 .. L_Dim - 1) of Poly;

   --  hint: k = 8 polynomials of {0,1} indicator bits.
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
   --  Caller passes Hi = 2**Bit_Len - 1 (1023 for the 10-bit t1 fields,
   --  1_048_575 for the 20-bit z fields). The contract states only the proved
   --  property -- every coefficient lies in 0 .. Hi -- using purely linear
   --  arithmetic; exact values are validated by the ML-DSA-87 KAT.
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

   --  ----- sigDecode (Algorithm 27) + HintBitUnpack (Algorithm 21) -----
   --  Ok is fail-closed: False on any malformed hint encoding. The hint section
   --  is omega + k = 75 + 8 = 83 bytes for ML-DSA-87.
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

end LTHING_MLDSA87_Codec;
