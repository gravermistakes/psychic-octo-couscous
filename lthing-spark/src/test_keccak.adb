------------------------------------------------------------------------------
--  test_keccak — KAT gate for the pure Ada/SPARK Keccak/SHAKE core.
--
--  Written before the implementation: this is the gate the asm path never had.
--  Every expected value is authoritative (FIPS 202 / Python hashlib), embedded
--  verbatim:
--    * keccak_f1600(0) lane0 = f1258f7940e1dde7         (FIPS 202 anchor)
--    * SHA3-512("") / SHA3-256("")                       (domain 0x06)
--    * SHAKE256("") / ("abc") / SHAKE128("")             (domain 0x1F)
--    * SHAKE256("") 64B  -- crosses the squeeze-permute block boundary
--  The rate-72 sponge that LTHING's "SHAKE512" uses is validated by the
--  SHA3-512 KAT (SHA3-512 is rate 72); the final gate exercises that exact
--  configuration (rate 72, domain 0x1F) for determinism.
--
--  Exits non-zero on any failure so a `test` target / CI fails the build.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

with LTHING_Keccak;   use LTHING_Keccak;
with LTHING_Types;    use LTHING_Types;
with Interfaces;      use Interfaces;
with Ada.Text_IO;     use Ada.Text_IO;
with Ada.Command_Line;

procedure Test_Keccak is

   Fails : Natural := 0;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then
         Put_Line ("[PASS] " & Name);
      else
         Put_Line ("[FAIL] " & Name);
         Fails := Fails + 1;
      end if;
   end Chk;

   function Eq (Got, Want : Byte_Array) return Boolean is
   begin
      if Got'Length /= Want'Length then
         return False;
      end if;
      for I in 0 .. Got'Length - 1 loop
         if Got (Got'First + I) /= Want (Want'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Eq;

   ---------------------------------------------------------------------------
   --  Authoritative expected values (hashlib / FIPS 202).
   ---------------------------------------------------------------------------
   KAT_SHA3_512_Empty : constant Byte_Array (0 .. 63) :=
     (16#A6#, 16#9F#, 16#73#, 16#CC#, 16#A2#, 16#3A#, 16#9A#, 16#C5#,
      16#C8#, 16#B5#, 16#67#, 16#DC#, 16#18#, 16#5A#, 16#75#, 16#6E#,
      16#97#, 16#C9#, 16#82#, 16#16#, 16#4F#, 16#E2#, 16#58#, 16#59#,
      16#E0#, 16#D1#, 16#DC#, 16#C1#, 16#47#, 16#5C#, 16#80#, 16#A6#,
      16#15#, 16#B2#, 16#12#, 16#3A#, 16#F1#, 16#F5#, 16#F9#, 16#4C#,
      16#11#, 16#E3#, 16#E9#, 16#40#, 16#2C#, 16#3A#, 16#C5#, 16#58#,
      16#F5#, 16#00#, 16#19#, 16#9D#, 16#95#, 16#B6#, 16#D3#, 16#E3#,
      16#01#, 16#75#, 16#85#, 16#86#, 16#28#, 16#1D#, 16#CD#, 16#26#);

   KAT_SHA3_256_Empty : constant Byte_Array (0 .. 31) :=
     (16#A7#, 16#FF#, 16#C6#, 16#F8#, 16#BF#, 16#1E#, 16#D7#, 16#66#,
      16#51#, 16#C1#, 16#47#, 16#56#, 16#A0#, 16#61#, 16#D6#, 16#62#,
      16#F5#, 16#80#, 16#FF#, 16#4D#, 16#E4#, 16#3B#, 16#49#, 16#FA#,
      16#82#, 16#D8#, 16#0A#, 16#4B#, 16#80#, 16#F8#, 16#43#, 16#4A#);

   KAT_SHAKE256_Empty : constant Byte_Array (0 .. 31) :=
     (16#46#, 16#B9#, 16#DD#, 16#2B#, 16#0B#, 16#A8#, 16#8D#, 16#13#,
      16#23#, 16#3B#, 16#3F#, 16#EB#, 16#74#, 16#3E#, 16#EB#, 16#24#,
      16#3F#, 16#CD#, 16#52#, 16#EA#, 16#62#, 16#B8#, 16#1B#, 16#82#,
      16#B5#, 16#0C#, 16#27#, 16#64#, 16#6E#, 16#D5#, 16#76#, 16#2F#);

   KAT_SHAKE256_Abc : constant Byte_Array (0 .. 31) :=
     (16#48#, 16#33#, 16#66#, 16#60#, 16#13#, 16#60#, 16#A8#, 16#77#,
      16#1C#, 16#68#, 16#63#, 16#08#, 16#0C#, 16#C4#, 16#11#, 16#4D#,
      16#8D#, 16#B4#, 16#45#, 16#30#, 16#F8#, 16#F1#, 16#E1#, 16#EE#,
      16#4F#, 16#94#, 16#EA#, 16#37#, 16#E7#, 16#8B#, 16#57#, 16#39#);

   KAT_SHAKE128_Empty : constant Byte_Array (0 .. 31) :=
     (16#7F#, 16#9C#, 16#2B#, 16#A4#, 16#E8#, 16#8F#, 16#82#, 16#7D#,
      16#61#, 16#60#, 16#45#, 16#50#, 16#76#, 16#05#, 16#85#, 16#3E#,
      16#D7#, 16#3B#, 16#80#, 16#93#, 16#F6#, 16#EF#, 16#BC#, 16#88#,
      16#EB#, 16#1A#, 16#6E#, 16#AC#, 16#FA#, 16#66#, 16#EF#, 16#26#);

   KAT_SHAKE256_Empty64 : constant Byte_Array (0 .. 63) :=
     (16#46#, 16#B9#, 16#DD#, 16#2B#, 16#0B#, 16#A8#, 16#8D#, 16#13#,
      16#23#, 16#3B#, 16#3F#, 16#EB#, 16#74#, 16#3E#, 16#EB#, 16#24#,
      16#3F#, 16#CD#, 16#52#, 16#EA#, 16#62#, 16#B8#, 16#1B#, 16#82#,
      16#B5#, 16#0C#, 16#27#, 16#64#, 16#6E#, 16#D5#, 16#76#, 16#2F#,
      16#D7#, 16#5D#, 16#C4#, 16#DD#, 16#D8#, 16#C0#, 16#F2#, 16#00#,
      16#CB#, 16#05#, 16#01#, 16#9D#, 16#67#, 16#B5#, 16#92#, 16#F6#,
      16#FC#, 16#82#, 16#1C#, 16#49#, 16#47#, 16#9A#, 16#B4#, 16#86#,
      16#40#, 16#29#, 16#2E#, 16#AC#, 16#B3#, 16#B7#, 16#C4#, 16#BE#);

   --  Inputs
   Empty : constant Byte_Array (1 .. 0) := (others => 0);  --  null range
   Abc   : constant Byte_Array (0 .. 2) := (16#61#, 16#62#, 16#63#);  --  "abc"

   Zero_State : State := (others => 0);
   O32  : Byte_Array (0 .. 31);
   O64  : Byte_Array (0 .. 63);
   O64b : Byte_Array (0 .. 63);
begin
   --  GATE 1: the permutation itself (FIPS 202 anchor).
   Keccak_F1600 (Zero_State);
   Chk ("keccak_f1600(0) lane0 = f1258f7940e1dde7",
        Zero_State (0) = 16#F1258F7940E1DDE7#);

   --  GATE 2: SHA3-512("") -- authoritative validation of the RATE-72 sponge
   --  (the rate LTHING's "SHAKE512" digest uses).
   Sponge (Empty, Rate_SHA3_512, Domain_SHA3, O64);
   Chk ("SHA3-512(empty) [rate 72 anchor]", Eq (O64, KAT_SHA3_512_Empty));

   --  GATE 3: SHA3-256("") -- rate 136, domain 0x06.
   Sponge (Empty, Rate_SHAKE256, Domain_SHA3, O32);
   Chk ("SHA3-256(empty)", Eq (O32, KAT_SHA3_256_Empty));

   --  GATE 4-5: SHAKE256 (rate 136, domain 0x1F).
   Sponge (Empty, Rate_SHAKE256, Domain_SHAKE, O32);
   Chk ("SHAKE256(empty)", Eq (O32, KAT_SHAKE256_Empty));
   Sponge (Abc, Rate_SHAKE256, Domain_SHAKE, O32);
   Chk ("SHAKE256(abc)", Eq (O32, KAT_SHAKE256_Abc));

   --  GATE 6: SHAKE128("") -- rate 168.
   Sponge (Empty, Rate_SHAKE128, Domain_SHAKE, O32);
   Chk ("SHAKE128(empty)", Eq (O32, KAT_SHAKE128_Empty));

   --  GATE 7: SHAKE256("") 64 bytes -- crosses the squeeze-permute boundary.
   Sponge (Empty, Rate_SHAKE256, Domain_SHAKE, O64);
   Chk ("SHAKE256(empty) 64B multi-block squeeze",
        Eq (O64, KAT_SHAKE256_Empty64));

   --  GATE 8: LTHING "SHAKE512" config (rate 72, domain 0x1F) -- determinism.
   Sponge (Abc, Rate_SHA3_512, Domain_SHAKE, O64);
   Sponge (Abc, Rate_SHA3_512, Domain_SHAKE, O64b);
   Chk ("SHAKE512(rate72) deterministic: same input -> same digest",
        Eq (O64, O64b));

   New_Line;
   if Fails = 0 then
      Put_Line ("KECCAK GATE PASSED: f[1600] + SHA3/SHAKE128/256/512 KAT-correct");
   else
      Put_Line ("KECCAK FAILURES:" & Fails'Image);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Keccak;
