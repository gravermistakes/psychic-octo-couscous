# Agent task: Hash integration (wire LTHING_Hash → proven Keccak)

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md` first. Obey the
fail-closed and **no-frozen-vectors** rules.

## Goal
Make `LTHING_Hash` use the proven `LTHING_Keccak.Sponge` instead of the asm FFI,
and add `test_hash.adb` with relational/property gates (no magic digests).

## Files you own
- `src/lthing_hash.adb`  (edit)
- `src/test_hash.adb`    (create)
Do not touch `lthing_judicial.*`, `tests.gpr`, CI, or other agents' files.

## Steps
1. In `src/lthing_hash.adb`: drop `with LTHING_Crypto_FFI` and the
   `Keccak_State`/`SHAKE_Absorb`/`SHAKE_Squeeze` calls. Implement `SHAKE512` as:
   ```ada
   with LTHING_Keccak; use LTHING_Keccak;
   ...
   procedure SHAKE512 (Input : Byte_Array; Output : out Digest) is
      Buf : Byte_Array (0 .. 63);
   begin
      Sponge (Input, Rate_SHA3_512, Domain_SHAKE, Buf);
      for I in Digest_Index loop
         Output (I) := Buf (I);
      end loop;
   end SHAKE512;
   ```
   Leave `Chain_Hash` as-is (it calls `SHAKE512`).
2. Create `src/test_hash.adb` (a main, like the other `test_*.adb`). Gates —
   **relational/property only**:
   - **Chain_Hash correctness:** pick a `Prev : Digest` and `Art : Byte_Array`;
     compute `Chain_Hash (Prev, Art, Got)`. Independently build
     `Concat (0..63) := Prev`, `Concat (64..) := Art` and `SHAKE512 (Concat, Want)`.
     Assert `Got = Want`. (Validates the concat/length logic against the primitive.)
   - **Determinism:** `SHAKE512 (M, D1)`, `SHAKE512 (M, D2)`, assert `D1 = D2`.
   - **Sensitivity:** two different inputs give different digests.
   Print `[PASS]/[FAIL]`; `Set_Exit_Status (Failure)` if any fail. NO hard-coded
   digest constants.
3. Ralph loop until green (see below).

## Ralph loop (repeat until BOTH hold)
```sh
export PATH=/root/.alire/bin:$PATH
gnatmake -q -D /tmp/ha -aIsrc -o /tmp/ha/test_hash src/test_hash.adb && /tmp/ha/test_hash
gnatprove -P lthing.gpr -u lthing_hash.adb -u lthing_keccak.adb --level=2 --report=all
```
- (a) `test_hash` prints all `[PASS]` and exits 0;
- (b) `gnatprove` reports **0 unproved** for `lthing_hash` (and keccak stays 0).
Iterate on failures; don't stop until both hold. If genuinely stuck after
~6 iterations, write what's blocking you and stop.

## Done
Commit everything to branch `claude/ralph-hash` with a clear message; report the
branch name and the final `test_hash` + `gnatprove` summary lines.
