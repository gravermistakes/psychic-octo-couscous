with LTHING_Types; use LTHING_Types;
with LTHING_Hash;  use LTHING_Hash;
with Ada.Text_IO;  use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;   use Interfaces;

procedure Test_Hash is
   Fails : Natural := 0;
   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;
   function Eq (A, B : Digest) return Boolean is
   begin
      for I in Digest_Index loop
         if A (I) /= B (I) then return False; end if;
      end loop;
      return True;
   end Eq;

   M1   : constant Byte_Array (0 .. 4) := (16#01#, 16#02#, 16#03#, 16#04#, 16#05#);
   M2   : constant Byte_Array (0 .. 4) := (16#01#, 16#02#, 16#03#, 16#04#, 16#06#);
   Prev : constant Digest := (others => 16#AA#);
   Art  : constant Byte_Array (0 .. 7) := (others => 16#5A#);
   D1, D2, DA, DB : Digest;
   Concat : Byte_Array (0 .. 71);
begin
   SHAKE512 (M1, D1);
   SHAKE512 (M1, D2);
   Chk ("SHAKE512 deterministic", Eq (D1, D2));

   SHAKE512 (M2, D2);
   Chk ("SHAKE512 input-sensitive", not Eq (D1, D2));

   --  Chain_Hash(prev,art) must equal SHAKE512(prev || art).
   Chain_Hash (Prev, Art, DA);
   for I in Digest_Index loop Concat (I) := Prev (I); end loop;
   for I in Art'Range loop Concat (64 + (I - Art'First)) := Art (I); end loop;
   SHAKE512 (Concat, DB);
   Chk ("Chain_Hash = SHAKE512(prev||artifact)", Eq (DA, DB));

   New_Line;
   if Fails = 0 then
      Put_Line ("HASH GATE PASSED: SHAKE512 + Chain_Hash (relational)");
   else
      Put_Line ("HASH FAILURES:" & Fails'Image);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Hash;
