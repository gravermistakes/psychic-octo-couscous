# CLAUDE.md — lthing-spark (Ada/SPARK layer)

SPARK control layer + NIST COMPLIANY CRYPTOGRAPHY IN ADA SPARK 


## Units
| Unit | SPARK | Role |
|------|-------|------|
| `lthing_types` | On | `Byte`, bounded `Byte_Array` (0..1 MiB), `Digest` (64B), `Verified_Record` + predicate |
| `lthing_keccak` | On | Keccak-f[1600] + `Sponge(Input, Rate, Domain, Output)`. **Proved (51 checks, 0 unproved).** KAT in `test_keccak`. |
| `lthing_hash` | On | `SHAKE512` (rate 72, domain `0x1F`) + `Chain_Hash`. |
| `lthing_judicial` | On | `Parse_Unverified` / `Parse_And_Verify` (fail-closed; postconditions proved). |
| `lthing_crypto_ffi` | On (decls) | asm FFI; bodies SPARK_Off. Being retired from the hash path. |
| `lthing_mldsa_field` | On | Z_q arithmetic (proved). |
| `lthing_mldsa_ntt` | Off | NTT (tested via convolution gate). |
| `lthing_mldsa65`, `lthing_mldsa_sample` | — | spec-only stubs (no body yet). |

## Keccak/SHAKE API (use this, not the FFI)
```ada
with LTHING_Keccak; use LTHING_Keccak;   --  Byte/Byte_Array come from LTHING_Types
--  rates: Rate_SHAKE128=168, Rate_SHAKE256=136, Rate_SHA3_512=72
--  domains: Domain_SHAKE=16#1F# (SHAKE/"SHAKE512"), Domain_SHA3=16#06#
Sponge (Input => M, Rate => Rate_SHA3_512, Domain => Domain_SHAKE, Output => Buf);
```
LTHING "SHAKE512" = `Sponge(_, Rate_SHA3_512, Domain_SHAKE, <64-byte Buf>)`.

## Commands
```sh
export PATH=/root/.alire/bin:$PATH
gnatmake -q -D /tmp/b -aIsrc -o /tmp/b/<main> src/<main>.adb && /tmp/b/<main>
gnatprove -P lthing.gpr --level=2 --report=all -j0            # whole project
gnatprove -P lthing.gpr -u <unit>.adb --level=2 --report=all  # one unit
```
Authoritative KAT values come from NIST site ONLY
