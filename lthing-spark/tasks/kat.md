# Agent task T7 — orphaned 15-vector ML-DSA sigVer KAT runner

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md`. Edit ONLY your files.
`export PATH=/root/.alire/bin:$PATH`.

This wires the authoritative gate. `kat/mldsa65_sigver.json` has 15 vectors
(tcId 31..45), keys per test: `pk` (1952 B hex), `message` (hex), `context`
(hex), `signature` (3309 B hex), `expected` (bool; 3 true / 12 false).

Files: `tools/gen_kat_vectors.py` (new), `src/mldsa_kat_vectors.ads` (generated, committed),
`src/test_kat.adb` (new).

## Steps
1. `tools/gen_kat_vectors.py`: read the JSON; emit `src/mldsa_kat_vectors.ads`
   exposing the 15 vectors as Ada constants. Suggested shape:
   ```ada
   with LTHING_Types; use LTHING_Types;
   package MLDSA_KAT_Vectors is
      type Vector (Msg_Len, Ctx_Len : Natural) is record
         PK       : Byte_Array (0 .. 1951);
         Sig      : Byte_Array (0 .. 3308);
         Msg      : Byte_Array (0 .. Msg_Len - 1);
         Ctx      : Byte_Array (0 .. Ctx_Len - 1);
         Expected : Boolean;
      end record;
      --  one constant function or accessor per tcId, plus a way to iterate.
   end MLDSA_KAT_Vectors;
   ```
   Simplest robust form: generate 15 named constants `V31 .. V45` (each a fully
   constrained record with its own Msg_Len/Ctx_Len) and a procedure-style
   dispatch in the test, OR emit a flat list of accessor functions. Avoid access
   types. Byte arrays as `(16#..#, …)` aggregates.
2. Run: `python3 tools/gen_kat_vectors.py` (writes the `.ads`); commit the `.ads`.
3. `src/test_kat.adb`: `with LTHING_MLDSA65; with MLDSA_KAT_Vectors;`. For each
   vector call `LTHING_MLDSA65.Verify` (pass `PK, Msg, Sig` and — once T10 adds it —
   `Ctx`; coordinate the parameter with the verify agent). Gate logic:
   ```
   if LTHING_MLDSA65.Arithmetic_Core_Complete then
      Chk ("tcId" & id, Result = V.Expected);
   else
      Chk ("tcId" & id & " (stub rejects)", Result = False);
   end if;
   ```
   Print `[PASS]/[FAIL]` per vector; `Ada.Command_Line.Set_Exit_Status(Failure)` on any fail.
4. Build+run:
   `gnatmake -q -D /tmp/k -aIsrc -o /tmp/k/test_kat src/test_kat.adb && /tmp/k/test_kat`
   - With the current stub (`Arithmetic_Core_Complete = False`) this is a NEGATIVE
     gate: every vector must report reject → all 15 `[PASS]`.
   - After T10 lands, it becomes the FULL gate: 15/15 against `expected`
     (3 accept, 12 reject).

## Done
`git checkout -b claude/ralph-kat`, commit (incl. generated `.ads`),
`git push -u origin claude/ralph-kat`. Report branch + test_kat output.

NOTE on Verify's signature: today it is `Verify (PK, Message, Sig)`. The KAT is
the external/pure interface WITH a context. Coordinate with T10 (verify agent),
which will add a `Context` parameter. Until then, you may build M' yourself
(`Byte(0) & Byte(Ctx'Length) & Ctx & Msg`) and pass as `Message` — but flag this
clearly so T10 reconciles it.
