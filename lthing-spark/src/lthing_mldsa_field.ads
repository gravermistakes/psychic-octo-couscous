------------------------------------------------------------------------------
--  LTHING.MLDSA.Field — Part 1: Z_q field arithmetic for ML-DSA-65
--
--  Modulus q = 8380417 = 2**23 - 2**13 + 1  (FIPS 204, verified 2026-06-06).
--  All operations keep coefficients reduced into the canonical range [0, q-1]
--  or the signed-centered range (-q/2, q/2] as documented per routine.
--
--  SPARK posture: every routine carries a postcondition bounding its result
--  into the canonical range, so the prover guarantees no operation can emit an
--  out-of-field value. This is the property the rest of the verifier relies on.
--
--  Self-validating: gated by hand-computed known values (see test_field.adb),
--  no external vectors required for this part.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces; use Interfaces;

package LTHING_MLDSA_Field is

   Q : constant := 8_380_417;

   --  Canonical field element in [0, q-1].
   subtype Fq is Integer_32 range 0 .. Q - 1;

   --  A wider type for products before reduction (q ~ 2**23, q*q < 2**46).
   subtype Wide is Integer_64;

   --  Modular addition: (a + b) mod q.
   function Add (A, B : Fq) return Fq
     with Global => null,
          Post   => Integer_64 (Add'Result) = (Integer_64 (A) + Integer_64 (B)) mod Q;

   --  Modular subtraction: (a - b) mod q, result canonical.
   function Sub (A, B : Fq) return Fq
     with Global => null,
          Post   => Integer_64 (Sub'Result) = ((Integer_64 (A) - Integer_64 (B)) mod Q);

   --  Modular multiplication: (a * b) mod q.
   function Mul (A, B : Fq) return Fq
     with Global => null,
          Post   => Integer_64 (Mul'Result) = (Integer_64 (A) * Integer_64 (B)) mod Q;

   --  Barrett-style reduction of an arbitrary nonneg wide value into Fq.
   function Reduce (X : Wide) return Fq
     with Global => null,
          Pre    => X >= 0,
          Post   => Integer_64 (Reduce'Result) = X mod Q;

   --  Centered representative in (-q/2, q/2], used by norm bound checks.
   function To_Centered (A : Fq) return Integer_32
     with Global => null,
          Post   => To_Centered'Result in -(Q / 2) .. (Q / 2)
                    and then (To_Centered'Result mod Q) = Integer_32 (A);

end LTHING_MLDSA_Field;
