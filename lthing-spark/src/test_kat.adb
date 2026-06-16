------------------------------------------------------------------------------
--  test_kat -- authoritative ML-DSA-65 sigVer KAT gate (FIPS 204).
--
--  Drives LTHING_MLDSA65.Verify against the 15 external/pure sigVer vectors
--  (tcId 31..45) emitted into MLDSA_KAT_Vectors from kat/mldsa65_sigver.json
--  by tools/gen_kat_vectors.py. No vector is hand-invented here; every byte
--  comes from that generated package.
--
--  Gate logic (per tasks/kat.md):
--    if LTHING_MLDSA65.Arithmetic_Core_Complete then
--       result must equal the vector's Expected (3 accept / 12 reject);
--    else  -- arithmetic core stubbed: fail-closed, Verify rejects everything
--       result must be False for every vector.
--  Today Arithmetic_Core_Complete = False, so this is a NEGATIVE gate:
--  all 15 vectors must report reject => 15 [PASS]. Once T10 lands the full
--  arithmetic core, the same runner becomes the FULL gate against Expected.
--
--  CONTEXT / M' CAVEAT (to reconcile with T10, the verify agent):
--  Verify's signature is presently Verify (PK, Message, Sig) with NO Context
--  parameter. The external/pure FIPS 204 interface mixes the context into the
--  message as the prefix  M' = 0x00 || len(ctx) || ctx || msg  (single-byte
--  context length, 0..255). We construct M' here and pass it as Message. When
--  T10 adds a dedicated Context parameter to Verify, this construction MUST be
--  removed and (PK, Msg, Ctx, Sig) passed through directly -- flagged so the
--  reconciliation is explicit and the gate stays authoritative.
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
      --  M' = 0x00 || len(ctx) || ctx || msg  (FIPS 204 external/pure).
      --  Ctx_Len is 0 .. 255 across all 15 vectors, so it fits in one byte;
      --  M' therefore always has length >= 2, satisfying Verify's
      --  Pre => Message'Length > 0.
      Msg_Prime : Byte_Array (0 .. V.Msg_Len + V.Ctx_Len + 1) :=
        (others => 0);

      Result : Boolean;
   begin
      --  V.Ctx / V.Msg are 1-based (1 .. Len); M' is 0-based.
      Msg_Prime (0) := 0;
      Msg_Prime (1) := Byte (V.Ctx_Len);
      for I in 1 .. V.Ctx_Len loop
         Msg_Prime (1 + I) := V.Ctx (I);
      end loop;
      for I in 1 .. V.Msg_Len loop
         Msg_Prime (1 + V.Ctx_Len + I) := V.Msg (I);
      end loop;

      Result := LTHING_MLDSA65.Verify
                  (PK      => V.PK,
                   Message => Msg_Prime,
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
