--  test_xof_cap — MEASUREMENT harness (not a fail-closed gate).
--
--  Confirms the escalating-squeeze schedule's Round 0 (Base_Need = 1088 bytes)
--  always suffices in practice, by replicating the SampleInBall (Alg. 29) and
--  RejNTTPoly (Alg. 30) consumption logic against the real Keccak Sponge and
--  reporting the MAXIMUM number of stream bytes consumed across many seeds.
--
--  Reported max bytes (this run) must stay well under 1088 -> Round 0 suffices,
--  escalation is effectively dead, behaviour on real inputs is unchanged.
pragma SPARK_Mode (Off);
with LTHING_Keccak;       use LTHING_Keccak;
with LTHING_Types;        use LTHING_Types;
with Interfaces;          use Interfaces;
with Ada.Text_IO;         use Ada.Text_IO;
with Ada.Command_Line;
procedure Test_XOF_Cap is

   Base_Need : constant := 1088;
   Q_Const   : constant := 8_380_417;

   Fails : Natural := 0;

   --  RejNTTPoly consumption: bytes consumed to fill 256 coeffs (= final Pos),
   --  or Natural'Last if 1088 bytes were insufficient.
   function Rej_Consumed (Seed : Byte_Array) return Natural is
      Stream : Byte_Array (0 .. Base_Need - 1);
      Pos    : Natural := 0;
      Filled : Natural := 0;
      D      : Integer;
   begin
      Sponge (Input => Seed, Rate => Rate_SHAKE128,
              Domain => Domain_SHAKE, Output => Stream);
      while Filled < 256 and then Pos + 2 <= Stream'Last loop
         D := Integer (Stream (Pos)) + 256 * Integer (Stream (Pos + 1))
              + 65536 * (Integer (Stream (Pos + 2)) mod 128);
         Pos := Pos + 3;
         if D < Q_Const then Filled := Filled + 1; end if;
      end loop;
      if Filled = 256 then return Pos; else return Natural'Last; end if;
   end Rej_Consumed;

   --  SampleInBall consumption: final Pos after placing i in 207..255, or
   --  Natural'Last if the 1088-byte stream was exhausted first.
   function Sib_Consumed (C_Tilde : Byte_Array) return Natural is
      Stream : Byte_Array (0 .. Base_Need - 1);
      Pos    : Natural := 8;
      J      : Byte;
      Found  : Boolean;
   begin
      Sponge (Input => C_Tilde, Rate => Rate_SHAKE256,
              Domain => Domain_SHAKE, Output => Stream);
      for I in 207 .. 255 loop
         Found := False;
         while Pos <= Stream'Last loop
            J := Stream (Pos); Pos := Pos + 1;
            if Integer (J) <= I then Found := True; exit; end if;
         end loop;
         if not Found then return Natural'Last; end if;
      end loop;
      return Pos;
   end Sib_Consumed;

   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;

   Trials   : constant := 5000;
   Max_Rej  : Natural := 0;
   Max_Sib  : Natural := 0;
   Rej_Over : Natural := 0;
   Sib_Over : Natural := 0;
   Seed     : Byte_Array (0 .. 33);
   Ct       : Byte_Array (0 .. 47);
   --  Cheap deterministic LCG so the run is reproducible.
   State : Unsigned_64 := 16#243F6A8885A308D3#;
   function Next_Byte return Byte is
   begin
      State := State * 6364136223846793005 + 1442695040888963407;
      return Byte (Shift_Right (State, 56) and 16#FF#);
   end Next_Byte;
begin
   for T in 1 .. Trials loop
      for I in Seed'Range loop Seed (I) := Next_Byte; end loop;
      for I in Ct'Range loop Ct (I) := Next_Byte; end loop;

      declare
         R : constant Natural := Rej_Consumed (Seed);
         S : constant Natural := Sib_Consumed (Ct);
      begin
         if R = Natural'Last then Rej_Over := Rej_Over + 1;
         elsif R > Max_Rej then Max_Rej := R; end if;
         if S = Natural'Last then Sib_Over := Sib_Over + 1;
         elsif S > Max_Sib then Max_Sib := S; end if;
      end;
   end loop;

   Put_Line ("trials                       :" & Integer'Image (Trials));
   Put_Line ("RejNTTPoly  max bytes used   :" & Integer'Image (Max_Rej));
   Put_Line ("RejNTTPoly  Round-0 overflows:" & Integer'Image (Rej_Over));
   Put_Line ("SampleInBall max bytes used  :" & Integer'Image (Max_Sib));
   Put_Line ("SampleInBall Round-0 overflows:" & Integer'Image (Sib_Over));

   Chk ("RejNTTPoly: Round 0 (1088 B) suffices for every trial",
        Rej_Over = 0);
   Chk ("SampleInBall: Round 0 (1088 B) suffices for every trial",
        Sib_Over = 0);
   Chk ("RejNTTPoly: max consumption < Base_Need", Max_Rej < Base_Need);
   Chk ("SampleInBall: max consumption < Base_Need", Max_Sib < Base_Need);

   if Fails = 0 then Put_Line ("ALL PASS");
   else Put_Line ("FAILURES:" & Integer'Image (Fails));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_XOF_Cap;
