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

pragma SPARK_Mode (Off);

with LTHING_Keccak;      use LTHING_Keccak;
with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;

package body LTHING_MLDSA_Sample is

   Q_Const : constant := 8_380_417;   --  FIPS 204 modulus q

   ---------------------------------------------------------------------------
   --  XOF helper: Output(0 .. Need-1) := Sponge(Seed, Rate, Domain_SHAKE, ..)
   --  Sponge gives a consistent prefix, so squeezing Need then 2*Need agrees
   --  on the first Need bytes.
   ---------------------------------------------------------------------------
   function XOF
     (Seed : Byte_Array;
      Rate : Positive;
      Need : Positive) return Byte_Array
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

      Pos  : Integer;
      Need : Positive := 1088;          --  generous initial request
      J    : Byte;

      --  Grab the stream fresh (Sponge prefix is consistent across sizes).
      Stream : Byte_Array := XOF (C_Tilde, Rate_SHAKE256, Need);
   begin
      C := (others => 0);

      --  h(b) = (s(b/8) / 2**(b mod 8)) mod 2, for b in 0..63.
      for B in 0 .. 63 loop
         H (B) := (Integer (Stream (B / 8)) / (2 ** (B mod 8))) mod 2;
      end loop;

      Pos := 8;                          --  bytes 0..7 consumed as sign bits

      --  for i in 256-tau .. 255  (= 207 .. 255)
      for I in 207 .. 255 loop
         --  inner rejection loop: read bytes until j <= i
         loop
            if Pos > Stream'Last then
               --  exhausted: regrow the stream (consistent prefix).
               Need   := Need * 2;
               Stream := XOF (C_Tilde, Rate_SHAKE256, Need);
            end if;
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
      Need   : Positive := 1088;
      Stream : Byte_Array := XOF (Seed, Rate_SHAKE128, Need);
      Pos    : Integer := 0;
      Filled : Natural := 0;
      D      : Integer;
      B0, B1, B2 : Integer;
   begin
      P := (others => 0);

      while Filled < 256 loop
         if Pos + 2 > Stream'Last then
            --  not enough bytes for a 3-byte group: regrow.
            Need   := Need * 2;
            Stream := XOF (Seed, Rate_SHAKE128, Need);
            --  Pos stays valid because the prefix is consistent.
         end if;

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
      Seed : Byte_Array (0 .. 33);
   begin
      for R in 0 .. 5 loop
         for S in 0 .. 4 loop
            --  rho is the first 32 bytes
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
