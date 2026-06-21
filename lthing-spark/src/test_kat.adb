------------------------------------------------------------------------------
--  test_kat -- authoritative ML-DSA-65 sigVer KAT gate (FIPS 204).
--
--  Drives LTHING_MLDSA65.Verify against the 15 external/pure sigVer vectors
--  (tcId 31..45) sourced from kat/mldsa65_sigver.json and committed verbatim
--  into the MLDSA_KAT_Vectors package (src/mldsa_kat_vectors.ads). No vector is
--  hand-invented here; every byte comes from that package.
--
--  Gate logic:
--    if LTHING_MLDSA65.Arithmetic_Core_Complete then
--       result must equal the vector's Expected (3 accept / 12 reject);
--    else  -- arithmetic core stubbed: fail-closed, Verify rejects everything
--       result must be False for every vector.
--  Arithmetic_Core_Complete is now True (the FIPS 204 Alg. 8 core is
--  implemented), so this is the FULL gate: each vector must match Expected.
--  Result: accepts tcId 31/32/33, rejects 34..45 => 15/15 [PASS].
--
--  CONTEXT / M' NOTE: Verify now takes a dedicated Context parameter --
--  Verify (PK, Message, Context, Sig) -- and forms the FIPS 204 prefix
--  M' = 0x00 || len(ctx) || ctx || msg internally (single-byte context length,
--  0..255). This runner therefore passes V.Msg and V.Ctx straight through; it
--  does NOT pre-construct M'. (Earlier revisions, before the Context parameter
--  landed, built M' here and passed it as Message -- that step is gone.)
--
--  Exits non-zero on any failure so a CI/test target fails the build.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

with LTHING_MLDSA65;
with MLDSA_KAT_Vectors;
with LTHING_Types;     use LTHING_Types;
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line;

procedure Test_KAT is

   package M renames MLDSA_KAT_Vectors;

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
   procedure Run (Id : Natural; V : M.Vector) is
      --  T10 added a dedicated Context parameter to Verify; the verifier now
      --  forms M' = 0x00 || len(ctx) || ctx || msg internally (FIPS 204
      --  Alg. 3). We pass Message and Context straight through. Both V.Msg and
      --  V.Ctx are 1-based (1 .. Len); Verify uses 'First, so the bounds carry.
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

      Result := LTHING_MLDSA65.Verify
                  (PK      => V.PK,
                   Message => Msg,
                   Context => Ctx (0 .. V.Ctx_Len - 1),
                   Sig     => V.Sig);

      if LTHING_MLDSA65.Arithmetic_Core_Complete then
         Chk ("tcId" & Natural'Image (Id), Result = V.Expected);
      else
         Chk ("tcId" & Natural'Image (Id) & " (stub rejects)",
              Result = False);
      end if;
   end Run;

begin
   Put_Line ("ML-DSA-65 sigVer KAT gate -- "
             & Natural'Image (M.Count) & " vectors (tcId 31..45)");
   if LTHING_MLDSA65.Arithmetic_Core_Complete then
      Put_Line ("  mode: FULL gate (Result must equal Expected)");
   else
      Put_Line ("  mode: NEGATIVE gate (stub: Verify must reject all)");
   end if;

   Run (31, M.V31);
   Run (32, M.V32);
   Run (33, M.V33);
   Run (34, M.V34);
   Run (35, M.V35);
   Run (36, M.V36);
   Run (37, M.V37);
   Run (38, M.V38);
   Run (39, M.V39);
   Run (40, M.V40);
   Run (41, M.V41);
   Run (42, M.V42);
   Run (43, M.V43);
   Run (44, M.V44);
   Run (45, M.V45);

   New_Line;
   if Fails = 0 then
      Put_Line ("ALL PASS (" & Natural'Image (M.Count) & " vectors)");
   else
      Put_Line ("FAILURES:" & Natural'Image (Fails));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_KAT;
