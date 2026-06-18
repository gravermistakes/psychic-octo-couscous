------------------------------------------------------------------------------
--  LTHING.MLDSA.Sample (body) — ExpandA + SampleInBall (FIPS 204)
--
--  Implements:
--    * Sample_In_Ball   (FIPS 204 Algorithm 29)
--    * RejNTTPoly       (FIPS 204 Algorithm 30) -- internal
--    * Expand_A         (FIPS 204 Algorithm 32)
--    * Count_Nonzero    (self-gate helper)
--
--  XOF = one-shot Keccak Sponge (SHAKE128 rate 168 for ExpandA, SHAKE256
--  rate 136 for SampleInBall). Sponge re-derives a consistent prefix, so the
--  "grow on exhaustion" strategy (recompute with double Need) is sound.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Keccak;      use LTHING_Keccak;
with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;

package body LTHING_MLDSA_Sample is

   Q_Const : constant := 8_380_417;   --  FIPS 204 modulus q

   --  SHAKE sponge rates are bytes; FIPS 202 caps them well under 200 (the
   --  Sponge precondition).  Constraining the formal makes that precondition
   --  trivially discharged at both call sites (SHAKE128=168, SHAKE256=136).
   subtype Rate_Range is Positive range 1 .. 200;

   --  Squeezed-stream length.  Bounding the request at Max_Need keeps Need - 1
   --  a valid Byte_Array index (Max_Need = Max_Document_Bytes) and bounds the
   --  stream position arithmetic.  The rejection sampling always succeeds far
   --  below this ceiling, so it is behaviour-neutral.
   Max_Need : constant := 1_048_576;   --  = Max_Document_Bytes
   subtype Need_Range is Positive range 1 .. Max_Need;

   ---------------------------------------------------------------------------
   --  XOF helper: Output(0 .. Need-1) := Sponge(Seed, Rate, Domain_SHAKE, ..)
   --  Sponge gives a consistent prefix, so squeezing Need then 2*Need agrees
   --  on the first Need bytes.
   ---------------------------------------------------------------------------
   function XOF
     (Seed : Byte_Array;
      Rate : Rate_Range;
      Need : Need_Range) return Byte_Array
     with Post => XOF'Result'First = 0 and then XOF'Result'Last = Need - 1
   is
      Out_Buf : Byte_Array (0 .. Need - 1);
   begin
      Sponge (Input  => Seed,
              Rate   => Rate,
              Domain => Domain_SHAKE,
              Output => Out_Buf);
      return Out_Buf;
   end XOF;

   ---------------------------------------------------------------------------
   --  Count_Nonzero
   ---------------------------------------------------------------------------
   function Count_Nonzero (C : Poly) return Natural is
      N : Natural := 0;
   begin
      for I in C'Range loop
         pragma Loop_Invariant (N <= I - C'First);
         if C (I) /= 0 then
            N := N + 1;
         end if;
      end loop;
      return N;
   end Count_Nonzero;

   ---------------------------------------------------------------------------
   --  Plus_One / Minus_One as canonical Fq values.
   --   +1 -> 1 ; -1 -> q-1   (their centered reps are +1 and -1).
   ---------------------------------------------------------------------------
   Plus_One  : constant Fq := 1;
   Minus_One : constant Fq := Q_Const - 1;

   ---------------------------------------------------------------------------
   --  Sample_In_Ball  (FIPS 204 Algorithm 29)
   ---------------------------------------------------------------------------
   procedure Sample_In_Ball
     (C_Tilde : Byte_Array;
      C       : out Poly)
   is
      --  Sign bits h(0..63) from the first 8 stream bytes (Alg. 29 lines 1-5).
      H : array (0 .. 63) of Integer;

      Pos  : Natural;
      J    : Byte;

      --  One-shot squeeze.  1088 SHAKE256 bytes cover the tau=49 rejection
      --  sampling with overwhelming margin (each i needs ~1 byte on average,
      --  and Sponge gives a consistent prefix).  Reads past the end are
      --  guarded below, so a short stream can never index out of range.
      Stream : constant Byte_Array := XOF (C_Tilde, Rate_SHAKE256, 1088);
   begin
      C := (others => 0);

      --  h(b) = (s(b/8) / 2**(b mod 8)) mod 2, for b in 0..63.
      --  Stream'Last = 1087 >= 7, so Stream(B/8) is always valid.
      for B in 0 .. 63 loop
         H (B) := (Integer (Stream (B / 8)) / (2 ** (B mod 8))) mod 2;
      end loop;

      Pos := 8;                          --  bytes 0..7 consumed as sign bits

      --  for i in 256-tau .. 255  (= 207 .. 255)
      for I in 207 .. 255 loop
         --  inner rejection loop: scan the finite stream until j <= i.
         --  Bounded by Stream'Last so it provably terminates (Verify is a
         --  function -> its callees must terminate). On exhaustion J keeps its
         --  last value; C (Integer (J)) stays in range (J is a Byte, 0..255).
         J := 0;
         while Pos <= Stream'Last loop
            pragma Loop_Variant (Increases => Pos);
            J   := Stream (Pos);
            Pos := Pos + 1;
            exit when Integer (J) <= I;
         end loop;

         C (I)           := C (Integer (J));
         C (Integer (J)) :=
           (if H (I - 207) = 0 then Plus_One else Minus_One);
      end loop;
   end Sample_In_Ball;

   ---------------------------------------------------------------------------
   --  RejNTTPoly  (FIPS 204 Algorithm 30)
   --  Output is ALREADY in NTT domain — do not call NTT on it.
   ---------------------------------------------------------------------------
   procedure Rej_NTT_Poly
     (Seed : Byte_Array;
      P    : out Poly)
   is
      --  One-shot squeeze.  1088 SHAKE128 bytes yield 256 accepted coeffs with
      --  overwhelming margin (acceptance prob ~ q/2**23 ~ 0.9986 per 3-byte
      --  group).  Reads past the end are guarded, so a short stream can never
      --  index out of range; an unfilled tail is impossible in practice.
      Stream : constant Byte_Array := XOF (Seed, Rate_SHAKE128, 1088);
      Pos    : Natural := 0;
      Filled : Natural := 0;
      D      : Integer;
      B0, B1, B2 : Integer;
   begin
      P := (others => 0);

      --  Scan the finite stream in 3-byte groups; bounded by Stream'Last so it
      --  provably terminates. 1088 SHAKE128 bytes fill 256 coeffs with
      --  overwhelming margin, so it never exhausts in practice; if it did, the
      --  unfilled tail stays 0 (P initialised above) -> fail-closed.
      while Filled < 256 and then Pos + 2 <= Stream'Last loop
         pragma Loop_Invariant (Filled < 256);
         pragma Loop_Invariant (Pos <= Stream'Last + 1);
         pragma Loop_Variant (Increases => Pos);

         B0 := Integer (Stream (Pos));
         B1 := Integer (Stream (Pos + 1));
         B2 := Integer (Stream (Pos + 2));
         Pos := Pos + 3;

         --  d := b0 + 256*b1 + 65536*(b2 mod 128)   (23-bit value)
         D := B0 + 256 * B1 + 65536 * (B2 mod 128);

         if D < Q_Const then
            P (Filled) := Fq (D);
            Filled := Filled + 1;
         end if;
      end loop;
   end Rej_NTT_Poly;

   ---------------------------------------------------------------------------
   --  Expand_A  (FIPS 204 Algorithm 32)
   --  For r in 0..k-1 (0..5), s in 0..l-1 (0..4):
   --    seed := rho(0..31) & byte(s) & byte(r)
   --    A(r,s) := RejNTTPoly(SHAKE128(seed))
   ---------------------------------------------------------------------------
   procedure Expand_A
     (Rho : Byte_Array;
      A   : out Matrix)
   is
      --  Fully initialised up front so flow analysis sees every element of
      --  Seed defined before the Rej_NTT_Poly read; the loop then overwrites
      --  0 .. 31 with rho, and 32/33 with the (s, r) indices.
      Seed : Byte_Array (0 .. 33) := (others => 0);
   begin
      for R in 0 .. 5 loop
         for S in 0 .. 4 loop
            --  rho is the first 32 bytes (Rho'First = 0 by precondition)
            for I in 0 .. 31 loop
               Seed (I) := Rho (Rho'First + I);
            end loop;
            Seed (32) := Byte (S);     --  column index s
            Seed (33) := Byte (R);     --  row index r
            Rej_NTT_Poly (Seed, A (R, S));
         end loop;
      end loop;
   end Expand_A;

end LTHING_MLDSA_Sample;
