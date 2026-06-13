# Agent task: Judicial constant-time compare in SPARK (retire the FFI)

Read root `CLAUDE.md` and `lthing-spark/CLAUDE.md` first. **Fail-closed is
sacred** — do not weaken any judicial postcondition or change any gate's
accept/reject logic. You are only replacing *how digests are compared*.

## Goal
Replace the `Compare_CT` asm-FFI call in `Digest_Equal` with a pure-SPARK
constant-time comparison, so `test_judicial` builds and runs with **no asm
library** at all, and the judicial unit still proves.

## Files you own
- `src/lthing_judicial.adb`  (edit `Digest_Equal` and its `with` clauses)
Do not touch `lthing_hash.*`, `tests.gpr`, CI, or other agents' files.
(`lthing_crypto_ffi.ads` may be left untouched even if it becomes unused.)

## Steps
1. Rewrite `Digest_Equal` as a constant-time OR-accumulator (no early exit, no
   data-dependent branch):
   ```ada
   function Digest_Equal (A, B : Digest) return Boolean
     with Global => null
   is
      Diff : Interfaces.Unsigned_8 := 0;
   begin
      for I in Digest_Index loop
         Diff := Diff or (A (I) xor B (I));
      end loop;
      return Diff = 0;
   end Digest_Equal;
   ```
   Add `with Interfaces;` if needed; remove `with LTHING_Crypto_FFI;` and the
   `Interfaces.C` use if they become unused. Keep the comment noting the
   constant-time property.
2. Confirm `test_judicial` now links with **no** `-llthing_crypto_asm`:
   `gnatmake -q -D /tmp/ju -aIsrc -o /tmp/ju/test_judicial src/test_judicial.adb`
3. Ralph loop until green.

## Ralph loop (repeat until BOTH hold)
```sh
export PATH=/root/.alire/bin:$PATH
gnatmake -q -D /tmp/ju -aIsrc -o /tmp/ju/test_judicial src/test_judicial.adb && /tmp/ju/test_judicial
gnatprove -P lthing.gpr -u lthing_judicial.adb --level=2 --report=all
```
- (a) `test_judicial` prints all 4 `[PASS]` and exits 0, with NO asm lib linked;
- (b) `gnatprove` reports **0 unproved** for `lthing_judicial` (postconditions
  must still be `proved`).
Iterate; don't stop until both hold. If stuck after ~6 iterations, report the blocker.

## Done
Commit to branch `claude/ralph-judicial`; report the branch and final
`test_judicial` + `gnatprove` summary lines, and confirm no asm lib was needed.
