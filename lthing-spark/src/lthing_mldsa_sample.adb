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
--  rate 136 for SampleInBall). A fixed, generously-sized buffer is squeezed
--  once; the rejection loops index it under a bounds-guarding loop condition,
--  so AoRTE holds. The buffers are sized so the FIPS 204 KAT never exhausts
--  them; a (cryptographically negligible) exhausting stream simply leaves the
--  unfilled coefficients at 0, which fails closed downstream.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Keccak;      use LTHING_Keccak;
with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;

package body LTHING_MLDSA_Sample is

   Q_Const : constant := 8_380_417;   --  FIPS 204 modulus q

   --  Fixed XOF output sizes (see header). 3-byte groups for RejNTTPoly accept
   --  with probability q/2^23 ~ 0.999, so 256 coeffs need ~770 bytes; 4096 is
   --  a >5x margin. SampleInBall needs ~70 bytes; 1088 is ample.
   Rej_Stream_Bytes  : constant := 4096;
   Ball_Stream_Bytes : constant := 1088;

   type Sign_Bits  is array (0 .. 63) of Integer range 0 .. 1;
   type Pow2_Table is array (0 .. 7) of Integer;

   Pow2 : constant Pow2_Table := (1, 2, 4, 8, 16, 32, 64, 128);

   ---------------------------------------------------------------------------
   --  XOF helper: Output(0 .. Need-1) := Sponge(Seed, Rate, Domain_SHAKE, ..)
   ---------------------------------------------------------------------------
   function XOF
     (Seed : Byte_Array;
      Rate : Positive;
      Need : Positive) return Byte_Array
     with Global => null,
          Pre    => Rate <= 200 and then Need <= Max_Document_Bytes,
          Post   => XOF'Result'First = 0 and then XOF'Result'Length = Need
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
         pragma Loop_Invariant (N <= I);
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
      H      : Sign_Bits := (others => 0);
      Pos    : Natural;
      J      : Byte;
      Stream : constant Byte_Array :=
        XOF (C_Tilde, Rate_SHAKE256, Ball_Stream_Bytes);
      --  Stream'First = 0, Stream'Last = Ball_Stream_Bytes - 1 = 1087.
   begin
      C := (others => 0);

      --  Sign bits h(b) from the first 8 stream bytes (Alg. 29 lines 1-5).
      for B in 0 .. 63 loop
         H (B) := (Integer (Stream (B / 8)) / Pow2 (B mod 8)) mod 2;
      end loop;

      Pos := 8;                          --  bytes 0..7 consumed as sign bits

      --  for i in 256-tau .. 255  (= 207 .. 255)
      for I in 207 .. 255 loop
         --  inner rejection loop: advance until a byte j <= i (Alg. 29).
         --  Bounded by the fixed stream; the guard makes Stream (Pos) safe.
         while Pos <= Stream'Last and then Integer (Stream (Pos)) > I loop
            pragma Loop_Invariant (Pos <= Stream'Last);
            pragma Loop_Variant (Increases => Pos);
            Pos := Pos + 1;
         end loop;

         if Pos <= Stream'Last then
            J   := Stream (Pos);          --  here Integer (J) <= I <= 255
            Pos := Pos + 1;
            C (I)           := C (Integer (J));
            C (Integer (J)) :=
              (if H (I - 207) = 0 then Plus_One else Minus_One);
         end if;
      end loop;
   end Sample_In_Ball;

   ---------------------------------------------------------------------------
   --  RejNTTPoly  (FIPS 204 Algorithm 30)
   --  Output is ALREADY in NTT domain — do not call NTT on it.
   ---------------------------------------------------------------------------
   procedure Rej_NTT_Poly
     (Seed : Byte_Array;
      P    : out Poly)
     with Global => null
   is
      Stream : constant Byte_Array :=
        XOF (Seed, Rate_SHAKE128, Rej_Stream_Bytes);
      --  Stream'First = 0, Stream'Last = Rej_Stream_Bytes - 1 = 4095.
      Pos        : Natural := 0;
      Filled     : Natural := 0;
      D          : Integer;
      B0, B1, B2 : Integer;
   begin
      P := (others => 0);

      --  Each iteration consumes a 3-byte group; the guard keeps Pos, Pos+1,
      --  Pos+2 within the buffer and Filled within 0 .. 255.
      while Filled < 256 and then Pos + 2 <= Stream'Last loop
         pragma Loop_Invariant (Filled <= 255);
         pragma Loop_Invariant (Pos + 2 <= Stream'Last);
         pragma Loop_Variant (Increases => Pos);

         B0 := Integer (Stream (Pos));
         B1 := Integer (Stream (Pos + 1));
         B2 := Integer (Stream (Pos + 2));
         Pos := Pos + 3;

         --  d := b0 + 256*b1 + 65536*(b2 mod 128)   (23-bit value in 0..2^23-1)
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
      Seed : Byte_Array (0 .. 33) := (others => 0);
   begin
      for R in 0 .. 5 loop
         for S in 0 .. 4 loop
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
