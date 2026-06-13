------------------------------------------------------------------------------
--  LTHING.Keccak — pure Ada/SPARK Keccak-f[1600] + sponge (FIPS 202)
--
--  Replaces the x86-64 asm hash core (keccak.asm), which shipped four distinct
--  correctness bugs over the project's history — 3-register addressing + an
--  uninitialised shift (AVRS FINDING-001), and three masking bugs fixed
--  2026-06-08 (rho+pi no-op, in-place chi corruption, missing SHAKE pad/domain)
--  — none caught by the committed asm harness, which never exercised Keccak.
--  Those are bad-index / read-half-overwritten-state / wrong-shift bugs: exactly
--  the class SPARK's Absence-of-Run-Time-Errors proof plus structured array
--  code (write-to-B, read-from-B) rules out by construction.
--
--  POSTURE
--    * SPARK_Mode (On); the proof obligation is AoRTE + flow. Discharged with
--      gnatprove 14.1.1 (Z3 4.13, cvc5 1.1.2, alt-ergo 2.4) at --level=2.
--    * Functional correctness is KAT-gated (proving a hash equals FIPS 202 is
--      infeasible). See test_keccak.adb; the rate-72 sponge path that LTHING's
--      "SHAKE512" digest uses is anchored by the authoritative SHA3-512 KAT
--      (SHA3-512 is also rate 72), not a self-derived vector.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with Interfaces;   use Interfaces;
with LTHING_Types; use LTHING_Types;

package LTHING_Keccak is

   --  Byte and the bounded Byte_Array come from LTHING_Types, so the sponge
   --  shares one octet-string type with LTHING_Hash and the judicial layer
   --  (no conversion at the call boundary). The bound on the index is what lets
   --  gnatprove bound 'Length and discharge the offset arithmetic.

   --  Keccak state: 25 lanes of 64 bits, lane index = x + 5*y.
   type State is array (0 .. 24) of Unsigned_64;

   --  FIPS 202 sponge rates (bytes). SHA3-512 and LTHING "SHAKE512" share the
   --  rate-72 sponge; they differ only in the domain byte and output length.
   Rate_SHAKE128 : constant := 168;
   Rate_SHAKE256 : constant := 136;
   Rate_SHA3_512 : constant := 72;

   --  Domain-separation suffixes (FIPS 202 sec. 6.1 / B.2).
   Domain_SHAKE : constant Byte := 16#1F#;   --  SHAKE128/256, "SHAKE512"
   Domain_SHA3  : constant Byte := 16#06#;   --  SHA3-224/256/384/512

   --  Keccak-f[1600] permutation (24 rounds), in place.
   procedure Keccak_F1600 (A : in out State)
     with Global => null;

   --  Generic sponge: absorb Input (rate-blocked, pad10*1 + Domain), then
   --  squeeze Output'Length bytes. Deterministic for a given (Input, Rate,
   --  Domain) — the property LTHING's seal/chain comparisons depend on.
   procedure Sponge
     (Input  : Byte_Array;
      Rate   : Positive;
      Domain : Byte;
      Output : out Byte_Array)
     with Global => null,
          Pre    => Rate <= 200 and then Output'Length > 0;

end LTHING_Keccak;
