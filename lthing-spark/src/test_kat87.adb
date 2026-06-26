------------------------------------------------------------------------------
--  test_kat87 -- authoritative ML-DSA-87 sigVer KAT gate (FIPS 204).
--
--  Drives LTHING_MLDSA87.Verify against the 15 external/pure sigVer vectors
--  (tcId 61..75) sourced from kat/mldsa87_sigver.json and committed verbatim
--  into the MLDSA87_KAT_Vectors package (src/mldsa87_kat_vectors.ads). No
--  vector is hand-invented here; every byte comes from that package.
--
--  Gate logic:
--    if LTHING_MLDSA87.Arithmetic_Core_Complete then
--       result must equal the vector's Expected (3 accept / 12 reject);
--    else  -- arithmetic core stubbed: fail-closed, Verify rejects everything
--       result must be False for every vector.
--  Arithmetic_Core_Complete is currently False (Level-5 body not yet
--  implemented), so this is the NEGATIVE gate: every call must return False.
--  Once the body is implemented and passes all 15 vectors, flip the flag.
--
--  CONTEXT / M' NOTE: Verify takes a dedicated Context parameter --
--  Verify (PK, Message, Context, Sig) -- and forms the FIPS 204 prefix
--  M' = 0x00 || len(ctx) || ctx || msg internally (single-byte context
--  length, 0..255). This runner passes V.Msg and V.Ctx straight through;
--  it does NOT pre-construct M'.
--
--  Exits non-zero on any failure so a CI/test target fails the build.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

with LTHING_MLDSA87;
with MLDSA87_KAT_Vectors;
with LTHING_Types;     use LTHING_Types;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line;

procedure Test_KAT87 is

   package M87 renames MLDSA87_KAT_Vectors;

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

   --  Run one KAT vector through the verifier and apply the gate.
   procedure Run (Id : Natural; V : M87.Vector) is
      --  Verify takes a dedicated Context parameter; the verifier forms
      --  M' = 0x00 || len(ctx) || ctx || msg internally (FIPS 204 Alg. 3).
      --  We re-base the 1-indexed V.Msg/V.Ctx into 0-based Byte_Arrays and
      --  pass them straight through.
      Msg : Byte_Array (0 .. (if V.Msg_Len = 0 then 0 else V.Msg_Len - 1));
      Ctx : Byte_Array (0 .. (if V.Ctx_Len = 0 then 0 else V.Ctx_Len - 1));

      Result : Boolean;
   begin
      for I in 1 .. V.Msg_Len loop
         Msg (I - 1) := V.Msg (I);
      end loop;
      for I in 1 .. V.Ctx_Len loop
         Ctx (I - 1) := V.Ctx (I);
      end loop;

      Result := LTHING_MLDSA87.Verify
                  (PK      => V.PK,
                   Message => Msg (0 .. V.Msg_Len - 1),
                   Context => Ctx (0 .. V.Ctx_Len - 1),
                   Sig     => V.Sig);

      if LTHING_MLDSA87.Arithmetic_Core_Complete then
         Chk ("tcId" & Natural'Image (Id), Result = V.Expected);
      else
         Chk ("tcId" & Natural'Image (Id) & " (stub rejects)",
              Result = False);
      end if;
   end Run;

begin
   Put_Line ("ML-DSA-87 sigVer KAT gate -- "
             & Natural'Image (M87.Count) & " vectors (tcId 61..75)");
   if LTHING_MLDSA87.Arithmetic_Core_Complete then
      Put_Line ("  mode: FULL gate (Result must equal Expected)");
   else
      Put_Line ("  mode: NEGATIVE gate (stub: Verify must reject all)");
   end if;

   Run (61, M87.V61);
   Run (62, M87.V62);
   Run (63, M87.V63);
   Run (64, M87.V64);
   Run (65, M87.V65);
   Run (66, M87.V66);
   Run (67, M87.V67);
   Run (68, M87.V68);
   Run (69, M87.V69);
   Run (70, M87.V70);
   Run (71, M87.V71);
   Run (72, M87.V72);
   Run (73, M87.V73);
   Run (74, M87.V74);
   Run (75, M87.V75);

   New_Line;
   if Fails = 0 then
      Put_Line ("ALL PASS (" & Natural'Image (M87.Count) & " vectors)");
   else
      Put_Line ("FAILURES:" & Natural'Image (Fails));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_KAT87;
