# ADR: function walks without a depth limit

Status: engine side done; radare2 side partly upstreamed (differential target)

This ADR has two halves. The engine's own walk (`r2ssa::body`, driven by
`r2engine::discovery`) is what this repo runs. radare2's `fcn_recurse` in
`libr/anal/fcn.c` is the differential target, and the changes to it are
upstream pull requests, one idea each.

## Decision

**The engine walk** (`crates/r2ssa/src/body.rs`):

- It is a worklist over instruction addresses (`Walk::run`), with no
  recursion and no depth limit. Each address is decoded at most once
  (`decoded`), so the work is linear in the bytes decoded plus the edges.
- It carries no path state: no running stack delta, last compare or list of
  `lea` candidates is inherited from whichever path reached a block first.
  Stack deltas and compares are dataflow facts of the SSA, derived later.
- An indirect branch is followed only to the arms that a previous pass proved
  it reads (`dispatched`). Otherwise it is recorded as unresolved, and the
  body is an honest partial body.
- Nothing is decoded where the program maps no execute permission. A direct
  branch to another function's entry (`Program::is_entry`) is a tail call and
  ends the body. A call returns unless `Program::returns` says otherwise.
- Discovery (`crates/r2engine/src/discovery.rs`) is the least set of addresses
  closed under "walk it and take where it transfers", starting from what the
  image states, together with the least fixpoint of which functions return.
  Both are worklists that only grow over a finite image.

**radare2's walk, as the oracle reads it:**

- `anal.depth` (default 128, clamped to 192 by
  `R_ANAL_FCN_RECURSE_STACK_LIMIT`) bounds the depth-first chain, which is a
  property of the function's shape, not its size. It exists only to protect
  the C stack, at about 5.5 KB per frame at `-O0`.
- Running out of depth leaves edges into addresses that no block covers. A
  differential disagreement on a switch-heavy or long-chain function may be
  radare2's truncation, not the engine's defect.
- The entry stack delta, `anal->cmpval` and `anal->leaddrs` are path state in
  globals, so a block reached by two paths takes the first-walked path's
  value. Jump-table detection is therefore order-dependent.
- `fcn_recurse`'s return value is the rightmost assigning child's outcome,
  which sometimes leaks a byte count, and `__core_anal_fcn` branches on it.

## Done

- Engine: the body walk and discovery as worklists, with no depth limit.
- radare2 PR 26717 (open): `fcn_recurse` de-recursed with explicit
  `Enter`/`Exit` frames that replay the recursion's order exactly, so output
  is identical except for functions the old walk truncated. Nested switch-case
  walks keep their own frame vector. `anal.depth` is kept, because
  `r_core_anal_fcn` still uses it for callee recursion. Under `anal.jmp.indir`,
  an indirect jump's targets are walked after its block finishes. The
  frame-pointer fix found on the way (26718) is merged; the CFA location kind
  (26719) is open.

## Left (upstream radare2, each one PR in this order)

1. Give `ret` a definition. Measured on master with no payoff, not taken: no
   walk returns a byte count since it became non-recursive (`aa` returns
   ERROR/END/NOP: vim 2603/2029/74, libstdc++ 1626/3959/52, ls-m1 22/29/83), and
   `br`'s NOP as END moved nothing on ls-m1, libstdc++, TestApp.ios, 3 blocks on vim.
2. One read-ahead cache per walk instead of one per frame. Result-preserving;
   measured in IO reads per function. Open as radare2#26986: `aa` reads 109,762
   to 36,583 on 0pack, 94,428 to 23,866 on vim, CPU unchanged on local files.
3. Carry the predecessor in the frame. Measured with no CPU payoff, not taken:
   `try_get_jmptbl_info`'s block scan is 0 to 1 of 1746 to 2506 walk samples on
   vim, 0pack and libstdc++.
4. Edge-labelled path state with a join: the entry delta, the last compare and
   the live `lea` candidates become forward dataflow facts, where unequal
   labels become unknown. Result-changing, so it is measured separately; needs design.
5. Derive the cap on `r_core_anal_fcn`'s callee recursion the same way (not yet taken).
