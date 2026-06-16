# SPARK proof gaps — ML-DSA core (after `SPARK_Mode (On)` everywhere)

Context: the verifier core (`lthing_mldsa_ntt`, `lthing_mldsa_sample`, `lthing_mldsa65`)
was `SPARK_Mode (Off)` and excluded from analysis — the old "0 unproved" was rigged.
With those units flipped to `On`, gnatprove `--level=2` reports **454 checks, ~31 unproved
(28 source lines), 0 legality errors**. The code is SPARK-legal; these are undischarged
AoRTE/flow obligations. None is a demonstrated bug (math is KAT-correct) — they need
invariants, contracts, guards, or small refactors. Skeleton below; fill in the specs.

Re-run: `gnatprove -P lthing.gpr -u lthing_mldsa_ntt.adb -u lthing_mldsa_sample.adb -u lthing_mldsa65.adb --level=2 --report=all -j0`

---

## A. `lthing_mldsa_ntt.adb` — 8 checks (butterfly loop bounds + global state)

Root cause: the Cooley-Tukey / Gentleman-Sande loops mutate over computed strides;
SPARK can't bound the loop counters/indices without invariants. Fix = `Loop_Invariant`s
pinning the ranges of `K`, `Start`, `Len`, `J` (all provably in `0..255` / `1..128`).

- [ ] `:75:23` overflow `K + 1` — invariant: `K in 1 .. 255` across the layer loop.
- [ ] `:76:31` array index — follows from `K` bound above.
- [ ] `:77:40` overflow `Start + Len` — invariant: `Start + Len <= 256`.
- [ ] `:78:40` overflow `J + Len` — invariant: `J in Start .. Start+Len-1`, `J+Len <= 256`.
- [ ] `:106:23` range `K - 1` (lower bound) — Inv_NTT: invariant `K >= 1` before `K-1`.
- [ ] `:108:39` array index — follows from `K`/`J` bounds.
- [ ] `:110:27` array index — follows from `J`/`Len` bounds.
- [ ] `:111:47` array index — follows from `J+Len` bound.

> Spec to write: range invariants for the nested `Len/Start/J/K` loops in `NTT` and
> `Inv_NTT`. Strides are powers of two; `Len ∈ {1,2,4,…,128}`, `Start` steps by `2*Len`.

## A′. `lthing_mldsa65.adb` — NTT global zeta state (2 HIGH, the architectural one)

- [ ] `:161:10` HIGH `"lthing_mldsa_ntt.zetas" must be in Global aspect of "Verify"`
- [ ] `:161:10` HIGH `"lthing_mldsa_ntt.initialized" must be in Global aspect of "Verify"`

> Root cause: NTT lazily initializes a mutable package-level `Zetas` table guarded by an
> `Initialized` flag. SPARK requires that hidden state be threaded through every caller's
> `Global` contract. **Recommended fix: make `Zetas` an elaboration-time `constant`**
> (precompute, drop `Initialized`). Then NTT has no global state, the 2 HIGH errors vanish,
> and no `Global =>` threading is needed through `Verify`. Spec: declare the zeta table
> `constant` with its value (or an expression function), remove the lazy-init path.

---

## B. `lthing_mldsa_sample.adb` — 15 lines (XOF, grow-buffer overflow, indices, init)

### B1. XOF helper precondition / range
- [ ] `:36:07` range check — XOF `Rate` parameter range.
- [ ] `:38:07` HIGH `precondition might fail, cannot prove Rate <= 200` — the `Sponge` call's
      `Rate <= 200` Pre. Fix: constrain XOF's `Rate` formal to a subtype `<= 200` (or
      `1 .. 200`) so callers (`168`, `136`) discharge it statically.

### B2. Grow-on-exhaustion buffer arithmetic
Root cause: the "double `Need` and re-squeeze" strategy uses unbounded `Natural` arithmetic.
Fix = cap `Need`/`N` with a subtype or explicit `<= Max` guard before doubling.
- [ ] `:53:20` overflow `N + 1`
- [ ] `:98:31` overflow `Need * 2`
- [ ] `:99:23` length check (the re-squeeze output length)
- [ ] `:130:17` overflow `Pos + 2` — bound `Pos` so `Pos+2 <= Stream'Last` (guarded read).
- [ ] `:132:28` overflow `Need * 2`
- [ ] `:133:20` length check

### B3. Array index checks (follow from B2 bounds)
- [ ] `:87:39` array index
- [ ] `:101:28` array index
- [ ] `:137:33` array index   (Rej_NTT_Poly 3-byte read `b0`)
- [ ] `:138:37` array index   (`b1`)
- [ ] `:139:37` array index   (`b2`)

### B4. Expand_A seed assembly
- [ ] `:168:43` overflow `Rho'First + I`  — invariant/precondition `Rho'Length = 32`.
- [ ] `:168:43` HIGH array index check     — follows from the `Rho` length fact.
- [ ] `:172:27` `"Seed" might not be initialized` — REAL flow gap: initialize `Seed`
      fully (e.g. `Seed : … := (others => 0)`) or prove every element is written before read.

---

## C. `lthing_mldsa65.adb` (Verify) — 3 more (besides A′)

- [ ] `:76:07` range check — `M_Prime : Byte_Array (0 .. Message'Length + Context'Length + 1)`;
      bound the upper index (needs `Message'Length + Context'Length + 2 <= Index_Range'Last`,
      i.e. a precondition on `Message'Length`, since `Context'Length <= 255` already).
- [ ] `:135:10` range check — the `Tr_Mp`/`Mu` buffer sizing (same family as `:76`).
- [ ] `:212:50` precondition `W1 (I) <= M_Bins - 1` — `W1_Encode` Pre; prove each
      `Use_Hint` result is in `0 .. 15` (M_Bins-1) via a postcondition on `Use_Hint`
      (it already returns `r1 mod 16` — surface that as a `Post` so the caller discharges it).
- [ ] `:256:40` overflow `Hint_Weight + Natural (H (R) (I))` — `Hint_Weight` accumulator;
      invariant `Hint_Weight <= R*256 + I` (bounded by `K_Dim*256 = 1536 < Natural'Last`).

---

## Suggested order
1. **C / A′ zeta-constant refactor** — kills both HIGH global-state errors, simplest high-value win.
2. **B1 Rate subtype** + **B4 Seed init** — small real fixes (one HIGH, one flow gap).
3. **A NTT loop invariants** — the bulk; mechanical but the classic effort.
4. **B2/B3 grow-buffer bounds** + **C ranges/postconditions** — fall out once subtypes/invariants land.

Each `[ ]` is one undischarged VC. Goal: `gnatprove -P lthing.gpr --level=2` → **0 unproved**
with every unit `On` — i.e. an honest 0, not a scoped one.
