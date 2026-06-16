# Agent task: wire LTHING_Hash → proven SPARK Keccak, add test_hash

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md` first. Rules: NO frozen/
self-derived digest constants (relational/property tests only); SPARK_Mode (On);
preserve fail-closed. Toolchain: `gnatmake` on PATH; `gnatprove` at
`/root/.alire/bin` (`export PATH=/root/.alire/bin:$PATH`).

You own ONLY these two files. Do NOT touch anything else (no judicial, no gpr,
no CI, no asm).

## 1. Replace `src/lthing_hash.adb` with EXACTLY this
```ada
------------------------------------------------------------------------------
--  LTHING.Hash (body) — SHAKE512 over the pure Ada/SPARK Keccak sponge.
--  GPL-3.0-or-later.
------------------------------------------------------------------------------

pragma SPARK_Mode (On);

with LTHING_Keccak; use LTHING_Keccak;

package body LTHING_Hash is

   procedure SHAKE512
     (Input  : Byte_Array;
      Output : out Digest)
   is
      Buf : Byte_Array (0 .. 63);
   begin
      --  LTHING "SHAKE512" = Keccak sponge at rate 72 with the SHAKE domain.
      Sponge (Input, Rate_SHA3_512, Domain_SHAKE, Buf);
      for I in Digest_Index loop
         Output (I) := Buf (I);
      end loop;
   end SHAKE512;

   procedure Chain_Hash
     (Previous_Seal : Digest;
      Artifact      : Byte_Array;
      Output        : out Digest)
   is
      Concat_Len : constant Natural := 64 + Artifact'Length;
      Concat     : Byte_Array (0 .. Concat_Len - 1) := (others => 0);
      J          : Natural := 0;
   begin
      for I in Digest_Index loop
         Concat (I) := Previous_Seal (I);
      end loop;
      J := 64;
      for I in Artifact'Range loop
         pragma Loop_Invariant
           (J = 64 + (I - Artifact'First) and then J < Concat_Len);
         Concat (J) := Artifact (I);
         J := J + 1;
      end loop;
      SHAKE512 (Concat, Output);
   end Chain_Hash;

end LTHING_Hash;
```

## 2. Create `src/test_hash.adb` with EXACTLY this
```ada
with LTHING_Types; use LTHING_Types;
with LTHING_Hash;  use LTHING_Hash;
with Ada.Text_IO;  use Ada.Text_IO;
with Ada.Command_Line;

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
```

## 3. Ralph loop — repeat until BOTH pass (do not stop early)
```sh
export PATH=/root/.alire/bin:$PATH
cd lthing-spark
rm -rf /tmp/ha && mkdir -p /tmp/ha
gnatmake -q -D /tmp/ha -aIsrc -o /tmp/ha/test_hash src/test_hash.adb && /tmp/ha/test_hash
gnatprove -P lthing.gpr -u lthing_hash.adb -u lthing_keccak.adb --level=2 --report=all
```
Done = (a) `test_hash` prints 3 `[PASS]` and exits 0; (b) gnatprove `Total` line
shows 0 in the Unproved column. If a build/proof error appears, fix it and
re-run. Don't stop until both hold.

## 4. Commit AND PUSH (so the work survives)
```sh
git checkout -b claude/ralph-hash
git add -A && git commit -m "Wire LTHING_Hash to pure-SPARK Keccak sponge; add test_hash"
git push -u origin claude/ralph-hash
```
Report: the branch name, the `test_hash` output, and the gnatprove `Total` line.
