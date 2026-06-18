--  test_field — Z_q field arithmetic, relational (representation-independent)
--  facts that FAIL if Add/Sub/Mul/Reduce/To_Centered are wrong. No frozen values.
with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;
with Interfaces;         use Interfaces;
with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Command_Line;
procedure Test_Field is
   Fails : Natural := 0;
   procedure Chk (Name : String; Cond : Boolean) is
   begin
      if Cond then Put_Line ("[PASS] " & Name);
      else Put_Line ("[FAIL] " & Name); Fails := Fails + 1; end if;
   end Chk;
begin
   --  Additive group
   Chk ("Add(Q-1,1) = 0",        Add (Q - 1, 1) = 0);
   Chk ("Add commutes",          Add (111_111, 222_222) = Add (222_222, 111_111));
   Chk ("Sub(a,a) = 0",          Sub (1_234_567, 1_234_567) = 0);
   Chk ("Sub(0,1) = Q-1",        Sub (0, 1) = Q - 1);
   --  Multiplicative (representation-independent: 0, commutativity, distributivity)
   Chk ("Mul(x,0) = 0",          Mul (1_234_567, 0) = 0);
   Chk ("Mul commutes",          Mul (123_456, 654_321) = Mul (654_321, 123_456));
   Chk ("Mul distributes over Add",
        Mul (314_159, Add (271_828, 161_803)) =
        Add (Mul (314_159, 271_828), Mul (314_159, 161_803)));
   --  Wide reduction (plain mod q)
   Chk ("Reduce(Q) = 0",         Reduce (Wide (Q)) = 0);
   Chk ("Reduce((Q-1)^2) = 1",   Reduce (Wide (Q - 1) * Wide (Q - 1)) = 1);
   --  Centered representative
   Chk ("To_Centered(0) = 0",    To_Centered (0) = 0);
   Chk ("To_Centered(1) = 1",    To_Centered (1) = 1);
   Chk ("To_Centered(Q-1) = -1", To_Centered (Q - 1) = -1);
   Chk ("To_Centered low half > 0",  To_Centered ((Q - 1) / 2) > 0);
   Chk ("To_Centered high half < 0", To_Centered ((Q + 1) / 2) < 0);

   New_Line;
   if Fails = 0 then Put_Line ("FIELD GATE PASSED: Z_q arithmetic (relational)");
   else Put_Line ("FIELD FAILURES:" & Fails'Image);
        Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Field;
