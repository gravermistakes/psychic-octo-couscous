------------------------------------------------------------------------------
--  LTHING.Keccak (body) — FIPS 202 Keccak-f[1600] + sponge.
--
--  SPARK-clean by construction:
--    * lanes are modular Unsigned_64 -> no arithmetic overflow;
--    * rho+pi writes a real permutation into B (never a no-op);
--    * chi reads from B and writes A -> no in-place corruption;
--    * every byte XOR/extract uses a single checked offset (Pos/8, Pos mod 8),
--      never multi-register addressing, never an uninitialised shift count;
--    * the squeeze is a definite loop over Output'Range, so the OUT parameter
--      is provably fully initialised.
--
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

package body LTHING_Keccak is

   subtype Lane_Range is Natural range 0 .. 24;
   subtype Coord      is Natural range 0 .. 4;
   subtype Rot_Amount is Natural range 0 .. 63;

   --  Round constants RC[0..23] (FIPS 202).
   RC : constant array (0 .. 23) of Unsigned_64 :=
     (16#0000000000000001#, 16#0000000000008082#, 16#800000000000808A#,
      16#8000000080008000#, 16#000000000000808B#, 16#0000000080000001#,
      16#8000000080008081#, 16#8000000000008009#, 16#000000000000008A#,
      16#0000000000000088#, 16#0000000080008009#, 16#000000008000000A#,
      16#000000008000808B#, 16#800000000000008B#, 16#8000000000008089#,
      16#8000000000008003#, 16#8000000000008002#, 16#8000000000000080#,
      16#000000000000800A#, 16#800000008000000A#, 16#8000000080008081#,
      16#8000000000008080#, 16#0000000080000001#, 16#8000000080008008#);

   --  Rotation offsets rho[x][y] (FIPS 202).
   Rho : constant array (Coord, Coord) of Rot_Amount :=
     ((0,  36, 3,  41, 18),
      (1,  44, 10, 45, 2),
      (62, 6,  43, 15, 61),
      (28, 55, 25, 21, 56),
      (27, 20, 39, 8,  14));

   ---------------------------------------------------------------------------
   --  Keccak_F1600
   ---------------------------------------------------------------------------
   procedure Keccak_F1600 (A : in out State) is
      C : array (Coord) of Unsigned_64;
      D : array (Coord) of Unsigned_64;
      --  Zero-init so flow analysis sees B fully initialised before chi reads
      --  it; the rho+pi loop is a permutation that overwrites all 25 lanes.
      B : State := (others => 0);
   begin
      for Rnd in 0 .. 23 loop
         --  theta
         for X in Coord loop
            C (X) := A (X) xor A (X + 5) xor A (X + 10)
                       xor A (X + 15) xor A (X + 20);
         end loop;
         for X in Coord loop
            D (X) := C ((X + 4) mod 5)
                       xor Rotate_Left (C ((X + 1) mod 5), 1);
         end loop;
         for Y in Coord loop
            for X in Coord loop
               A (X + 5 * Y) := A (X + 5 * Y) xor D (X);
            end loop;
         end loop;

         --  rho + pi  (real permutation into B)
         for Y in Coord loop
            for X in Coord loop
               B (Y + 5 * ((2 * X + 3 * Y) mod 5)) :=
                 Rotate_Left (A (X + 5 * Y), Rho (X, Y));
            end loop;
         end loop;

         --  chi  (read B, write A)
         for Y in Coord loop
            for X in Coord loop
               A (X + 5 * Y) :=
                 B (X + 5 * Y)
                   xor ((not B (((X + 1) mod 5) + 5 * Y))
                          and B (((X + 2) mod 5) + 5 * Y));
            end loop;
         end loop;

         --  iota
         A (0) := A (0) xor RC (Rnd);
      end loop;
   end Keccak_F1600;

   ---------------------------------------------------------------------------
   --  Sponge
   ---------------------------------------------------------------------------
   procedure Sponge
     (Input  : Byte_Array;
      Rate   : Positive;
      Domain : Byte;
      Output : out Byte_Array)
   is
      St : State := (others => 0);

      --  XOR one message byte into the state at byte position Pos (< 200).
      procedure Xor_Byte (Pos : Natural; Val : Byte)
        with Global => (In_Out => St),
             Pre    => Pos < 200
      is
         Lane : constant Lane_Range := Pos / 8;
         Sh   : constant Natural    := (Pos mod 8) * 8;
      begin
         St (Lane) := St (Lane) xor Shift_Left (Unsigned_64 (Val), Sh);
      end Xor_Byte;

      --  Extract one output byte from the state at byte position Pos (< 200).
      function Get_Byte (Pos : Natural) return Byte
        with Global => (Input => St),
             Pre    => Pos < 200
      is
         Lane : constant Lane_Range := Pos / 8;
         Sh   : constant Natural    := (Pos mod 8) * 8;
      begin
         return Byte (Shift_Right (St (Lane), Sh) and 16#FF#);
      end Get_Byte;

      N         : constant Natural := Input'Length;
      Off       : Natural := 0;    --  message bytes consumed
      Remaining : Natural;
   begin
      --  Absorb full rate-sized blocks.
      while N - Off >= Rate loop
         pragma Loop_Invariant (Off <= N - Rate);
         pragma Loop_Variant (Decreases => N - Off);
         for I in 0 .. Rate - 1 loop
            Xor_Byte (I, Input (Input'First + Off + I));
         end loop;
         Keccak_F1600 (St);
         Off := Off + Rate;
      end loop;

      --  Final block + pad10*1 with the domain suffix: Domain at the message
      --  end, 0x80 at byte (rate-1). If they coincide the byte is their XOR.
      Remaining := N - Off;
      for I in 0 .. Remaining - 1 loop
         Xor_Byte (I, Input (Input'First + Off + I));
      end loop;
      Xor_Byte (Remaining, Domain);
      Xor_Byte (Rate - 1, 16#80#);
      Keccak_F1600 (St);

      --  Squeeze: one state byte per Output element, permuting after each full
      --  rate-block. Definite loop over Output'Range => Output fully written.
      declare
         Pos : Natural := 0;   --  byte offset within the current block
      begin
         for I in Output'Range loop
            pragma Loop_Invariant (Pos < Rate);
            Output (I) := Get_Byte (Pos);
            if Pos = Rate - 1 then
               Keccak_F1600 (St);
               Pos := 0;
            else
               Pos := Pos + 1;
            end if;
         end loop;
      end;
   end Sponge;

end LTHING_Keccak;
