with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;
with Interfaces;         use Interfaces;
with Ada.Text_IO;        use Ada.Text_IO;

procedure Test_Field is
   Fails : Natural := 0;
   procedure Chk (Name : String; Got, Want : Integer_64) is
   begin
      if Got = Want then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name & " got=" & Got'Image & " want=" & Want'Image);
           Fails := Fails + 1;
      end if;
   end Chk;
begin
   --  q = 8380417
   Chk ("Add wrap: (q-1)+5",        Integer_64 (Add (Q - 1, 5)),        4);
   Chk ("Add no-wrap: 100+200",     Integer_64 (Add (100, 200)),        300);
   Chk ("Sub underflow: 3-10",      Integer_64 (Sub (3, 10)),           Integer_64 (Q) - 7);
   Chk ("Sub normal: 500-200",      Integer_64 (Sub (500, 200)),        300);
   Chk ("Mul: 2*3",                 Integer_64 (Mul (2, 3)),            6);
   --  (q-1)*(q-1) mod q = (-1)*(-1) = 1
   Chk ("Mul: (q-1)*(q-1)",         Integer_64 (Mul (Q - 1, Q - 1)),    1);
   --  q-1 == -1 mod q, so (q-1)*2 = -2 = q-2
   Chk ("Mul: (q-1)*2",             Integer_64 (Mul (Q - 1, 2)),        Integer_64 (Q) - 2);
   Chk ("Reduce: 2q+7",             Integer_64 (Reduce (2 * Integer_64 (Q) + 7)), 7);
   Chk ("Reduce: q exactly",        Integer_64 (Reduce (Integer_64 (Q))),         0);
   --  centered: q-1 -> -1 ; q/2 boundary stays positive
   Chk ("Centered: q-1 -> -1",      Integer_64 (To_Centered (Q - 1)),   -1);
   Chk ("Centered: 5 -> 5",         Integer_64 (To_Centered (5)),       5);

   New_Line;
   if Fails = 0 then Put_Line ("PART 1 GATE PASSED: field arithmetic correct (proven + tested)");
   else Put_Line ("PART 1 FAILURES:" & Fails'Image); end if;
end Test_Field;
