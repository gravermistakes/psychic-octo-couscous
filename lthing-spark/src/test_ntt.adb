with LTHING_MLDSA_NTT;   use LTHING_MLDSA_NTT;
with LTHING_MLDSA_Field; use LTHING_MLDSA_Field;
with Interfaces;         use Interfaces;
with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Command_Line;

procedure Test_NTT is
   Fails : Natural := 0;

   function Eq (A, B : Poly) return Boolean is
   begin
      for I in A'Range loop
         if A (I) /= B (I) then return False; end if;
      end loop;
      return True;
   end Eq;

   --  deterministic pseudo-random fill (LCG), values in [0,q-1]
   procedure Fill (P : out Poly; Seed : in out Integer_64) is
   begin
      for I in P'Range loop
         --  small-multiplier LCG kept well within Integer_64
         Seed := (Seed * 1_103_515_245 + 12_345) mod 8_380_417;
         if Seed < 0 then Seed := Seed + 8_380_417; end if;
         P (I) := Fq (Seed);
      end loop;
   end Fill;

   A, B, Acopy : Poly;
   Na, Nb, Prod_NTT, Prod_School : Poly;
   Seed : Integer_64 := 12345;
begin
   --  GATE A: roundtrip identity  INTT(NTT(a)) = a
   Fill (A, Seed);
   Acopy := A;
   NTT (A);
   Inv_NTT (A);
   if Eq (A, Acopy) then Put_Line ("[PASS] Gate A: INTT(NTT(a)) = a (roundtrip)");
   else Put_Line ("[FAIL] Gate A: roundtrip identity broken"); Fails := Fails + 1; end if;

   --  GATE B (the strong one): NTT-domain multiply = schoolbook negacyclic product
   Fill (A, Seed); Fill (B, Seed);
   Prod_School := Schoolbook_Mul (A, B);
   Na := A; Nb := B;
   NTT (Na); NTT (Nb);
   Prod_NTT := Pointwise (Na, Nb);
   Inv_NTT (Prod_NTT);
   if Eq (Prod_NTT, Prod_School) then
      Put_Line ("[PASS] Gate B: NTT multiply = schoolbook mod (x^256+1) -- CORRECT FIPS 204 NTT");
   else
      Put_Line ("[FAIL] Gate B: NTT does not match negacyclic convolution");
      Fails := Fails + 1;
   end if;

   --  GATE C: a second independent product (different seed) for confidence
   Seed := 999983;
   Fill (A, Seed); Fill (B, Seed);
   Prod_School := Schoolbook_Mul (A, B);
   Na := A; Nb := B; NTT (Na); NTT (Nb);
   Prod_NTT := Pointwise (Na, Nb); Inv_NTT (Prod_NTT);
   if Eq (Prod_NTT, Prod_School) then Put_Line ("[PASS] Gate C: second product vector matches");
   else Put_Line ("[FAIL] Gate C: second product mismatch"); Fails := Fails + 1; end if;

   New_Line;
   if Fails = 0 then Put_Line ("PART 2 GATE PASSED: NTT verified correct via negacyclic convolution");
   else Put_Line ("PART 2 FAILURES:" & Fails'Image);
        Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_NTT;
