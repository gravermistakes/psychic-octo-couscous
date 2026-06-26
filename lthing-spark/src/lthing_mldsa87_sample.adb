------------------------------------------------------------------------------
--  LTHING.MLDSA87.Sample (body) — ExpandA + SampleInBall (FIPS 204), L5
--
--  Mirror of LTHING_MLDSA_Sample for ML-DSA-87:
--    * Sample_In_Ball: tau = 60 (loop 196..255), sign bits H(I-196).
--    * Expand_A: matrix k x l = 8 x 7.
--    * Count_Nonzero: unchanged helper.
--
--  The squeeze-on-demand / bounded escalation architecture is identical to
--  the Level-3 sibling.  SPARK_Mode (On); proof target AoRTE + flow.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Keccak;      use LTHING_Keccak;
with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;

package body LTHING_MLDSA87_Sample is

   Q_Const : constant := 8_380_417;

   subtype Rate_Range is Positive range 1 .. 200;

   Max_Need  : constant := 1_048_576;
   subtype Need_Range is Positive range 1 .. Max_Need;

   Base_Need : constant := 1088;
   Max_Round : constant := 2;

   ---------------------------------------------------------------------------
   --  XOF helper
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

   Plus_One  : constant Fq := 1;
   Minus_One : constant Fq := Q_Const - 1;

   ---------------------------------------------------------------------------
   --  Sample_In_Ball  (FIPS 204 Algorithm 29)  — tau = 60
   --  Loop range: for I in 256-60 .. 255 = 196 .. 255
   --  Sign bit index: H (I - 196), drawn from the first 64 bits of the stream.
   ---------------------------------------------------------------------------
   procedure Sample_In_Ball
     (C_Tilde : Byte_Array;
      C       : out Poly)
   is
      H : array (0 .. 63) of Integer;

      Pos   : Natural;
      J     : Byte;
      Found : Boolean;
      Done  : Boolean;
   begin
      Rounds :
      for Round in 0 .. Max_Round loop
         pragma Loop_Invariant (Round in 0 .. Max_Round);

         declare
            Need   : constant Need_Range := Base_Need * (2 ** Round);
            Stream : constant Byte_Array :=
              XOF (C_Tilde, Rate_SHAKE256, Need);
         begin
            C := (others => 0);

            for B in 0 .. 63 loop
               H (B) := (Integer (Stream (B / 8)) / (2 ** (B mod 8))) mod 2;
            end loop;

            Pos  := 8;
            Done := True;

            --  tau = 60: for i in 256-60 .. 255 = 196 .. 255
            for I in 196 .. 255 loop
               J     := 0;
               Found := False;
               while Pos <= Stream'Last loop
                  pragma Loop_Variant (Increases => Pos);
                  J   := Stream (Pos);
                  Pos := Pos + 1;
                  if Integer (J) <= I then
                     Found := True;
                     exit;
                  end if;
               end loop;

               if not Found then
                  Done := False;
                  exit;
               end if;

               C (I)           := C (Integer (J));
               C (Integer (J)) :=
                 (if H (I - 196) = 0 then Plus_One else Minus_One);
            end loop;
         end;

         exit Rounds when Done;
      end loop Rounds;
   end Sample_In_Ball;

   ---------------------------------------------------------------------------
   --  RejNTTPoly  (FIPS 204 Algorithm 30) — unchanged from Level 3
   ---------------------------------------------------------------------------
   procedure Rej_NTT_Poly
     (Seed : Byte_Array;
      P    : out Poly)
   is
      Pos        : Natural;
      Filled     : Natural;
      D          : Integer;
      B0, B1, B2 : Integer;
   begin
      Rounds :
      for Round in 0 .. Max_Round loop
         pragma Loop_Invariant (Round in 0 .. Max_Round);

         declare
            Need   : constant Need_Range := Base_Need * (2 ** Round);
            Stream : constant Byte_Array := XOF (Seed, Rate_SHAKE128, Need);
         begin
            Filled := 0;
            Pos    := 0;
            P      := (others => 0);

            while Filled < 256 and then Pos + 2 <= Stream'Last loop
               pragma Loop_Invariant (Filled < 256);
               pragma Loop_Invariant (Pos <= Stream'Last + 1);
               pragma Loop_Variant (Increases => Pos);

               B0 := Integer (Stream (Pos));
               B1 := Integer (Stream (Pos + 1));
               B2 := Integer (Stream (Pos + 2));
               Pos := Pos + 3;

               D := B0 + 256 * B1 + 65536 * (B2 mod 128);

               if D < Q_Const then
                  P (Filled) := Fq (D);
                  Filled := Filled + 1;
               end if;
            end loop;

            exit Rounds when Filled = 256;
         end;
      end loop Rounds;
   end Rej_NTT_Poly;

   ---------------------------------------------------------------------------
   --  Expand_A  (FIPS 204 Algorithm 32) — k=8, l=7
   --  seed := rho(0..31) & byte(s) & byte(r);  A(r,s) := RejNTTPoly(...)
   ---------------------------------------------------------------------------
   procedure Expand_A
     (Rho : Byte_Array;
      A   : out Matrix)
   is
      Seed : Byte_Array (0 .. 33) := (others => 0);
   begin
      for R in 0 .. 7 loop
         for S in 0 .. 6 loop
            for I in 0 .. 31 loop
               Seed (I) := Rho (Rho'First + I);
            end loop;
            Seed (32) := Byte (S);
            Seed (33) := Byte (R);
            Rej_NTT_Poly (Seed, A (R, S));
         end loop;
      end loop;
   end Expand_A;

end LTHING_MLDSA87_Sample;
