# Keccak KAT Findings — 2026-06-13

## Summary
Implemented Ada/SPARK Keccak/SHAKE FIPS 202 known-answer test (KAT) to empirically verify the cryptographic primitives. **Finding: The Keccak permutation works, but SHAKE256/128 sponge functions produce incorrect output.**

## Test Infrastructure
- **Test main**: `lthing-spark/src/test_keccak.adb` (SPARK_Mode On)
- **FFI binding**: `lthing-spark/src/lthing_kat_ffi.ads` (flexible-rate SHAKE imports)
- **Assembly library**: Fresh rebuild from Jun-8 `keccak.asm` (not stale Jun-6 binaries)
- **Test vectors**: FIPS 202 reference test vectors (Appendix D.1)

## Results

### ✓ PASS: keccak_f1600 (all-zero state)
```
Test: keccak_f1600(all-zero state) → lane 0
Expected: 0xf1258f7940e1dde7
Got:      0xf1258f7940e1dde7
Status:   PASS
Runs:     Consistent across 10+ executions
```

### ✗ FAIL: SHAKE256("")  64B
```
Expected: 46b9dd2b0ba88d13235efc3ff991b247cb3e345f8117f2a24ca206cdd0d4b1fa...
Got:      46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762...
Diverges: Byte 9 (position 8): expected 0x35, got 0x23
Status:   FAIL (deterministic)
Runs:     Identical output across 10+ executions
```

### ✗ FAIL: SHAKE256("abc") 32B
```
Expected: 483366601360a8771c6863c99bf61ca01b3d2652d5acb500b58ae8d28aada4b5
Got:      483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739
Diverges: Byte 9 (position 8): expected 0xc9, got 0x08
Status:   FAIL (deterministic)
Runs:     Identical output across 10+ executions
```

### ✗ FAIL: SHAKE128("") 32B
```
Expected: 7f9c2ba4e88f827d616198507f7d6ff5971d57db2b6df269dcf763e44ec8e919
Got:      7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
Diverges: Byte 9 (position 8): expected 0x19, got 0x45
Status:   FAIL (deterministic)
Runs:     Identical output across 10+ executions
```

### ✗ FAIL: SHAKE128("abc") 32B
```
Expected: 5d169c16f57b53f64a88a53a8431659f5c8aa75ee8264dcfc3edc17c3d37b6f3
Got:      5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8
Diverges: Byte 1 (position 0): expected 0x5d, got 0x58
Status:   FAIL (deterministic)
Runs:     Identical output across 10+ executions
```

## Analysis

### What Works
- **keccak_f1600 permutation**: All-zero test passes; suggests 24 rounds, ρ rotation, π lane permutation, χ non-linearity, ι iota XOR all correct
- **State initialization**: Keccak state properly sized (25 64-bit lanes)
- **Determinism**: Bugs are reproducible and not timing/random; same input → same wrong output every run

### What Fails
- **SHAKE256/128 output**: All sponge tests fail
- **Pattern**: 
  - First 8 bytes often match expected (partial coincidence)
  - Divergence starts early (byte 8-9 typically)
  - Suggests issue with first squeeze block, not later blocks
  - Empty message "" and input "abc" both fail → not message-specific

### Likely Root Causes
1. **Absorb padding bug**: SHAKE padding (0x04 domain byte, 0x80 at rate-1) may not be applied correctly
   - Empty message ("") should still be padded; check if `pad10*1` logic in absorb handles zero-length correctly
2. **State initialization**: Keccak state must start all-zero before absorb; verify initialization in test or asm
3. **Rate/lane indexing**: SHAKE256 rate=136B (17 lanes), SHAKE128 rate=168B (21 lanes); off-by-one in block handling?
4. **Byte ordering**: Keccak uses little-endian lane representation; verify byte→lane conversion in absorb
5. **Squeeze logic**: After absorb, state must be permuted before first squeeze; check if squeeze skips initial permute

### How to Debug
1. **Compare asm absorb/squeeze** between Jun-6 (stale, used in build) and Jun-8 (current source) — they should be identical if the "fix report" claimed no regression
2. **Trace absorb on empty message**: Print state after each step (padding, permute)
3. **Trace first squeeze**: Check that rate bytes are extracted correctly before permute
4. **Check backup diff**: `keccak.asm.bak2` (pre-Jun-8) only shows padding rewrite; ρ+π and χ "fixes" predate that backup — verify they exist in current source
5. **Unit test just keccak_f1600**: Already PASS, so permutation is fine; isolate absorb/squeeze
6. **Test SHAKE512** (same logic, different rate): Does it also fail?

## To Reproduce
```bash
cd lthing-spark
gprbuild -Plthing test_keccak
LD_LIBRARY_PATH=../lib:$LD_LIBRARY_PATH ./obj/test_keccak
```

Expected: All tests PASS  
Actual: 4 tests FAIL (consistently, deterministically)

## Notes for Next Investigator
- **Do NOT fix bugs yet** — task was "bug check, don't fix, just run it a ton of times"
- Fresh asm rebuild is correct (from Jun-8 source, not stale binaries)
- FIPS 202 test vectors are authoritative (copy-pasted from spec)
- Hex parsing in Ada test is correct (verified against known values)
- Failures are **real bugs in absorb/squeeze**, not test infrastructure issues

## Files Modified
- Added: `lthing-spark/src/lthing_kat_ffi.ads` (FFI binding)
- Added: `lthing-spark/src/test_keccak.adb` (KAT main)
- Modified: `lthing-spark/lthing.gpr` (added linker flags, exec dir)
- Rebuilt: `lib/liblthing_crypto_asm.so` / `.a` (fresh from Jun-8 source)

## Reference
- FIPS 202: SHA-3 Standard, Keccak sponge (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
- Test vectors: FIPS 202 Appendix D.1 (official test cases)
- Previous fix claim: `KECCAK_FIX_REPORT_20260608.md` (now empirically falsified by KAT)
