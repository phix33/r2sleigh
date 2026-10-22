# ADR: control structure is the dominator tree; everything else is an edge spelling

Status: done; quality rewrites are ROADMAP SD

## Decision

The old structurer recognised shapes, fell back through seven placement
mechanisms, and proved coverage afterwards with a boolean-formula equality
exponential in nesting depth. Placement is now total and linear, and one
certificate checks the output text against the CFG without knowing how the
text was built.

### §3 The certificate

Reading the rendered body as a program gives a labelled graph `R` over block
*occurrences* (one rendered copy of a block), with `π` mapping each to its
block in `G`. The control certificate `I_S` is:

- (i) every block has an occurrence, and the body starts at the entry's first;
- (ii) at every occurrence of `b`, the labelled multiset of out-edges equals
  `b`'s in `G` (`Normal`, `True`/`False`, a switch arm's case-value set,
  `Default`);
- (iii) an `if` tests `b`'s certified predicate with the polarity its arms
  say, and a `switch` tests `b`'s certified selector.

Consequences of `I_S`: rendered paths equal machine paths, so rendered control
domains equal canonical ones without building a formula; loop body, latches
and exits are implied; a `ControlTransfer` obligation is discharged iff (ii)
holds at every occurrence, a `ControlPredicate` iff (iii). An unconditional
transfer rendered by adjacency is rendered, not elided. A block written twice
is admitted when each copy carries the full out-edge set.

The extractor models every implicit C transfer, or a rewrite could invent
one: adjacency, an `if` without `else`, `case` fall-through, `break` (loop *or*
switch), `continue` (passes through a switch), `goto`, `return`, the loop-end
back edge. A `Gap` reads as the block's declared out-edges. A block with
terminator `None` must end with no out-edge, so a call ends an occurrence only
when the prologue declares the callee `__attribute__((noreturn))`; a trap is
the target's builtin. Fabricating a `return` is not acceptable.

A compound test (a condition chain) is `&&`, `||` and `!` over atoms that each carry the marker of the block whose
test they are, the head's own included, so a `!` is the chain's and never the lowering's. The checker reads the
DAG of those blocks from the CFG: each is a two-way branch, every block past the head owes the program nothing but
its branch (`SemanticObligationInventory::owes_only_its_branch`), is entered only from the chain and is written
nowhere else, and the DAG has two exits. It requires the DAG's exit function to equal the test's by BDD identity:
the test evaluates its atoms left to right and skips the decided ones, so its trace is the reduced ordered BDD of
its function under that order, and the DAG is that trace only if every edge runs forward in the order and no atom
decides nothing. At most 16 atoms and 512 BDD nodes; past either the chain is refused with a typed `ChainFault`
and nothing is written. The head's edges are then the chain's exits, read exactly: no inversion is read into its
arms. The checker never infers a chain; it reads the markers the rewrite put there.

A test of one such atom is read the same way, which is how a rotated loop's polarity is certified: the loop's test is
its block's atom, `!atom` where the machine leaves on the true edge, and an edge back to the lone block is an exit.
A test the lowering wrote carries no marker and is judged by its edges exactly; a swapped pair of labels is a
violation, not an inversion (the certificate used to admit it, so `while (c)` and `while (!c)` certified alike for a
plain test; a stage that dropped a negation was kept). One text change follows the final certificate:
`respell_negations` turns a `!` over a marked integer comparison into the opposite comparison (`Eq`/`Ne`, `Lt`/`Ge`,
`Le`/`Gt`); a table test evaluates all six rows against the negation on every 8-bit pair and the edges of 16, 32 and
64 bits, signed and unsigned, and a float comparison, false on a NaN, has no opposite and keeps its `!`.

Two facts decide whether a block may be a member of a chain, and each has one owner. r2ssa states what the block owes
(`owes_only_its_branch`: no load, store, call, trap or unknown effect; a zero-op native span owes nothing the text
writes, since the rendering elides it); the certificate asks it of every member because it cannot see how the text
was built. The rewrite also needs the block's text to be its test and nothing else, which only the text states: D2
writes a value the function keeps as a statement of its own, so `sub esi, 5; jne` with `esi` returned is a test of its
own though r2ssa calls its block inert (`a_second_test_joins_the_chain_only_if_it_computes_nothing_the_function_keeps`).
Neither implies the other. Weaken the text shape and the fact alone still refuses the load of
`a_second_test_that_reads_memory_is_a_test_of_its_own`; replace the fact by `true` and the text shape alone refuses it,
because D2 writes every effect as its own statement, which is why that replacement moves 0 of 1,822 renderings.

A selection `x = c ? a : b;`, written by the readability stage for an `if`
whose arms each assign `x` once, is read as that `if`. The statement carries
the test block's markers and each value its arm block's (one block, or none for
an arm that is the edge itself); that block's occurrence is entered on the
arm's edge. The rewrite records the statement as a selection. The checker
refuses one whose test is not a conditional branch, whose target is not a plain
variable, or whose value writes: that write is a second effect of the arm.

### §4 Placement

Every block except the entry is placed by its immediate dominator `x`. With
`Λ(y)` the natural loops containing `x` but not `y`: if `Λ(y)` is empty, `y`
is placed inline at the arm reaching it (when its only forward in-edge is from
`x`) or as a labelled merge child of `x`; otherwise it goes in the exit list of
the outermost loop in `Λ(y)`, and its whole dominator subtree moves with it
(exit subtrees are whole). A loop header wraps its body in `for (;;)`. An edge
is `continue` to the innermost enclosing header, inline adjacency, or `goto`.
Merge children and exits are written in ascending RPO.

An exit `y` of loop `L` with one forward way in (the edge from its immediate dominator `x`) whose
dominator subtree no edge leaves (*closed*) is written where that edge leaves `L`, not after it,
unless `break` reaches it: the first exit of one loop stays after the loop. `Placement::inlines` is
the one predicate `compute` (the exit lists) and `edge` (the arms) share. A closed subtree holds no
loop another block belongs to, so the text it adds inside `L` leaves no `continue`, `break` or label.
Closedness is the preorder interval of the subtree holding the extremes of its blocks' successors'
positions, `O(B + E)`. The difference-on-tree count over `idom` answers how many edges leave a
subtree and needs the lowest common ancestor of each edge (`O((B + E) log B)`, a lifting table);
only whether any edge leaves is asked, so it is not built.

This writes each block exactly once, satisfies `I_S` for any graph,
reducible or not, runs in `O(|B| + |E|)` after the dominator tree, and makes
every backward `goto` target a loop header or an irreducible-cycle entry.
Every arm ends every path in a transfer. An indirect branch with declared
successors is a `switch` on its own target value (a `SwitchCertificate` with
`cases = {(addr, addr)}`); with none, or an unrenderable target, it is a gap.
An irreducible cycle needs nothing special: its closing edges are `goto`s,
and it has a complete obligation inventory, only no loop certificate.

### §5 The quality layer

Every readability improvement is a rewrite `AST → AST` that must preserve
`I_S`, proven by re-running the checker on its result; a rewrite that fails is
not applied. Each stage must also keep every observed occurrence, since the
certificate is blind to an `if` rebuilt without its observation chain; the
gate checks both and names the failing stage. Asking the plan for an
expression is itself an observation, so merge-write decisions come from
dispositions and expressions are asked for only when written. Preference among
rewrites is fixed: fewest labels, then fewest duplicated blocks, then shortest
text. `break` never crosses a `switch` to reach a loop. `LoopCertificate::condition`
is a rendering choice, not a certificate fact; it stays only for `for_loop`
until that certificate names its exit edge. The stages run in `render::structured`, each kept only while the
control certificate still holds: condition chains (on the tree as placed, where every merge is a `goto` and
every exit is a bare transfer or a block only the chain reaches), `shape`, the latch's copies, loop rotation. The
certificate holds each stage to the machine's edges with their labels, so a stage that changes a test's polarity says
so on a marked atom or is refused (§3).

A terminal tail is a run of at most four expression statements from a label, through the sibling
blocks the text falls into, to a `return`, a call to a callee declared never to return, or a `goto`
to another run (a cycle of jumps has none); it holds no residual or gap, because a copy would be a
second site of one unproven cell (the skipped-block copy asks the same predicate, `tails::copyable`,
so a skipped block holding a residual stays one). Each `goto` to a tail is replaced by a fresh copy (every marker
minted anew), and a tail nothing falls into and no `goto` names goes with the blocks it ran through
(`structure/tails.rs`). A copy carries its blocks' whole out-edge sets, which `I_S` already asks of a
block written twice, so a copy where the edge did not go is refused by the certificate. The pass
runs after the skipped-block copy, which needs the jumps the tail copies replace: `bi_windup`'s
`put_byte` is a block the compiler merged out of two arms and the copy into those arms is the source's
shape, where a tail copied first leaves it shared. The preference order of this section holds: a tail
copy removes a label, so it outranks the duplicate block it costs.

A `return` whose value is a merge of the return's own block, and whose inputs are pairwise-distinct
canonical terms, is copied into every arm end of the conditional that falls into it. That is the
one place a block is duplicated without a label to remove, so it needs a fact the CFG states and a
join does not: the edges carry values no other edge carries (`Values::returns_distinct_merge`, `O(1)`
per return block, over the graph's phi and the canonical terms, never names or spelled text). A
side effect before the return, a label something still jumps to, a merge that carries itself or one
two edges give the same term are not this shape. The assignment before each copy stays
(`x = a; return x;`); folding it touches the merge's ledger accounting and is its own step.
The unguarded form (any `return` after a conditional with two falling arms, `return;` too) was
measured and not shipped: the CFG does not say a source wrote two returns where it wrote one, and
`return a || b` compiles to the same merge of `1` and `b` as `if (a) return 1; return b`.

### §6 Decided branches

Preparation runs sparse conditional constants in `SccpMode::Decide`
(`r2ssa::optimize`, audit D13). A branch whose condition the lattice proves
constant becomes the edge it takes; the edge it leaves, the blocks only that
edge reached and their merge sources go before the seal, so the dead arm owes
no obligation (`mov eax, 0; test rax, rax; je; call rax` through a weak
undefined symbol the linker resolved to 0). No operand is rewritten, which
keeps the provenance the pdd path turned `Propagate` off for. `O(n + e)` once
per round; a round that decides nothing ends the loop.

## Done

- S0: the checker over the old tree; `R2DEC_CONTROL_CERTIFICATE` prints one `control-certificate` line per function (and on the refusal-evidence channel).
- S1: placement in `structure/place.rs`, the certificate in `structure/certify.rs`; the region builders, domain proofs, linearizer, structuring deadline and every `safety_reason` deleted; noreturn prototypes spelled; irreducible cycles keep a complete inventory.
- S2, in part: jump-to-next and unreferenced-label elision, `break`/`continue` to the innermost loop header and the first block after it, and the checker. The rest of the original S2 was in the legacy cleanup pass `structure/rewrite.rs`, deleted with the legacy decompiler in 51b9d6a9 (2026-10-10) and not replaced: while and do-while rotation (the certificate supports both, the writer emits only `for(;;)`), switch-tail absorption, bounded tail duplication of returns, short-circuit `if`, and return into arms. 2026-10-22 measurement on DecBench (`tests/decbench/RESULT-2026-10-17.md`): this is why 40.2% of r2s's scored functions end in a goto.
- S3: DecBench read 680 of 860, every mean above the previous run.
- S2, four of the five (2026-10-22, B5): short-circuit `if` as condition chains (`structure/condition.rs`), `while` and
  `do-while` rotation (`structure/rotate.rs`) with the latch's copies written before its test (`structure/latch.rs`),
  return into arms (`tails::join_returns`) and bounded tail duplication of returns (`tails::inline_tails`); switch-tail
  absorption is still not replaced. See "the recoveries together" below.

- S4 (2026-10-22): the recoveries below, each checked by `I_S` on its result.

## Left

- Labels over functions the old structurer handled exceed what it rendered. Exit: no more labels than before over that set.
- Node splitting of irreducible entries. Exit: gated by the checker.
- Whether lexical ancestry equals dominance retires `region_does_not_dominate_occurrence`. Exit: placement census measured (post-dominance hoisting and `goto` into scope may move the refusal rather than remove it).

## 2026-10-22: what the gotos cost and what recovers it

A classification of all 1,054 DecBench goto functions (8,353 gotos; 150 bodies read by hand against the source and
the other three tools, a parser classifier over all of them, GED scored with DecBench's own code) found:

- A goto is invisible to GED (labels and gotos add no block). GED scores the block graph. Removing the 40.8% of gotos
  that target a terminal block cuts the goto share from 38.4% to 24.0% and gains one perfect function. The loss is
  the CFG features a goto marks: a missing `&&`/`||` (5 per condition), a shared return where the source has several
  (5 for two returns), `while` against `for(;;)` rotation (3 to 5), and the latch's phi copies (3).
- Rule 8 (never invent control) is the cause of none of the classes but one (a loop exit into a shared open tail,
  4% of gotos, no goto-free spelling). Dominators, loop headers, phi inputs, edge copies and selector constants
  already give the facts every other recovery needs.
- Ranked by measured gain: (1) return into arms at a fallthrough join when the returned value is a phi fed by distinct
  edge copies (+15 perfect with 0 lost; +48 net unguarded, 7 lost); (2) bounded duplication of a terminal block at a
  goto site (-2,590 gotos, +16 with (1)); (3) condition chains as `&&`/`||` by BDD identity of the chain's exit
  function (ceiling 29); (4) inlining a sole-predecessor exit at its edge when its dominator subtree is closed
  (-371 gotos, GED-neutral); (5) hoisting a rotated loop's latch copies (ceiling +17). The join classes (48% of gotos)
  are not worth direct work: another tool is perfect on 3 of 567.
- Replication into fallthrough arms conflicts with section 5 (fewest labels, then fewest duplicated blocks) unless it
  is guarded by the phi-of-distinct-edge-copies condition; amend section 5 or ship only the guarded form.

## 2026-10-22: the recoveries together

Two branches landed on one base and stack in this order: condition chains, `while`/`do-while` and the latch's
copies written before its test (B5-b), then joined returns, terminal tails, sole closed exits and a callee's
declaration read in address order (B5-a). The marker table is one type, `shape::Occurrences`, which implements
`condition::Marks`, so a block's text copied by any stage is an occurrence of that block the certificate reads. In
`render` the order is: placement (a sole closed exit is written where its edge leaves the loop), condition chains
(a stage), `shape` (jumps to the next position, joined returns, the skipped-block copy, terminal tails), the
latch's copies (a stage) and loop rotation (a stage). A stage stands only while the control certificate holds,
`shape`'s copies are certified at the end, and `respell_negations` is the one change after the certificate.

Measured on the mined set (bzip2, zlib and grep at O2 and O2-noinline: 1,570 functions, 1,305 scored in all three
builds) with DecBench's own GED. One method for the three builds: the renderings come from each build on the Mac and
are scored on contabo. These are mined-set numbers.

| Build | Perfect | Mean GED | Total GED | Gotos | Functions with a goto |
|---|---|---|---|---|---|
| base `cb16ec2e` | 203 | 46.095 | 60,154 | 4,654 | 623 |
| chains, rotation, latch copies `0a654255` | 197 (0 newly, 6 lost) | 45.195 | 58,980 (-1,174) | 4,578 | 615 |
| and the tails, the stack's head | 206 (10 newly, 1 lost against the step before) | 43.795 | 57,153 (-1,827 more, -3,001 in all) | 2,661 | 426 |

Held out (23 of radare2's test ELFs, 1,834 functions, none of them mined): rendered 1,496 and refused 338 in every
build, the same 338 functions, none crashed; gotos 2,941, 2,915 and 2,100. One function gains gotos over the base:
freebsd-ls `0x205b40`, 0 to 2. Its skipped block holds a residual cell and the base wrote it into two arms, two
residual sites for one unproven cell; `tails::copyable` is asked of every copy, so the block is written once and the
two arms jump to it. That is the visible residual rule 8 prefers to a duplicated one, and the one case the tails'
own held-out sweep ("no function gains a goto") did not see, since it ran before the rule reached the skipped-block
copy. The equivalence gate on the stack's head holds all 828 baseline records on x86-64 (744 equal, 63
residual-trap, 1 slow, 20 unsupported) and on AArch64 (750, 57, 1, 20) with none differing. Release `pdd` on the
largest functions of 0pack and pumasim stays within 0.1% instructions retired and the same peak footprint.

**Kept costs.** The chains cost 0.2 mean GED and win none on the set they were measured on, and the latch's copies
take 438 loops to `do-while` for 0.98 less mean GED at the price of 5 perfect (a single-block source `for` scores
better as a `for (;;)`); the three stages together are 197 perfect for 203 and 0.9 mean GED fewer on this set. Both
are kept for the reason in the section below: they spell the machine's test and loop as the CFG proves them, nothing
was tuned to the score, and the benchmark rewards the source's spelling, which the binary does not state. The tails
win the perfect count back (10 newly perfect, 1 lost) and take 1,917 gotos away. No recovery is added or dropped to
move the sum.

**Ledgered, not fixed here.** ROADMAP D58: a rendering decision must not depend on the order blocks are written
(a callee's declaration was fixed; whether a name reads as a value or as a NeverAssigned residual is still the text
written so far, which no write order makes right for a loop-carried merge whose entry copy is a gap; 0pack
`0x476982`), and a copy's statements are not asked of the certificate per occurrence. ROADMAP D59: a chain whose exit
is a `continue` to its own head faults `ExitCount` and reverts every chain of the function (bash `0x2e540`, still
reproduced on the stack's head).

**Left**, by when:

- Next: the assignment before a copied or joined return, folded at the owner that spells the edge copy
  (`return a;`); the exit edge's copies after a loop whose only exit is the latch (about 140 loops); D58 and D59.
- Conditional: the four-statement bound and the skipped-block-first order were chosen on the mined set, so they move
  with a measurement on projects the analysis did not mine; the unguarded join (+17, 2 lost), only with a CFG fact that
  separates `return a || b` from two returns; a `while` whose exit arm is not a bare `break` (34 loops), once the exit
  is the only way out.
- Deferred: chains whose DAG is not read-once (a selection between two tests); splitting a chain around a block that
  renders text; node splitting of irreducible entries; tails of five to sixteen statements (133 gotos) and jumps over
  a block no rule closes (588); the AArch64 mined set, not measured.
- Unnecessary: the lowest-common-ancestor count for closedness, whose answer the O(B + E) interval extremes give.

## 2026-10-22: condition chains, loop rotation and latch copies

Three of the recoveries the goto analysis ranked landed in this order, each a stage kept only while the control
certificate holds. Measured on the mined set (bzip2, bzip2recover, zlib's libz, example and minigzip, grep; O2 and
O2-noinline; 1,050 functions, 438 with a non-degenerate source CFG), scored with DecBench's own GED (`vj_ged`,
Joern CFGs), which reproduces the 2026-10-17 run's value for 435 of the 438. These are mined-set numbers.

| Step | Renderings changed | Gotos | Mean GED (scored) | Better / worse | Perfect |
|---|---|---|---|---|---|
| base (`d4792d55`) | | 4,143 | 49.11 | | 60 |
| condition chains | 251 | 4,080 | 49.31 | 14 / 51 | 60 (0 newly, 0 lost) |
| while and do-while | +21 loops | 4,080 | 49.31 | 0 / 0 | 60 |
| latch copies | +438 do-whiles | 4,080 | 48.33 | 72 / 12 against the step before | 55 (0 newly, 5 lost) |

Counting each function once (zlib's code also sits in `example` and `minigzip`): 302 scored, mean 47.97, then
48.14 after chains, 47.13 at the end; perfect 48 to 45.

**Condition chains.** Invariant: a decision DAG of blocks that render nothing but their test, two exits, the test
equal to the DAG's exit function by BDD identity. Owner: `structure/condition.rs` (derivation, BDD, check) with
r2ssa stating which blocks owe only their branch. O(statements) with at most 16 blocks per head. Rejected: matching
the nested `if` text alone (it cannot see a shared test reached by `goto`, and the checker would infer the chain), and
a name or flag-pattern check for the blocks. The GED got worse, not better: Joern builds a node for each operand of
`&&` and `||` and one for the whole test, so a collapse costs a node and pays only where the source spelled `&&` and
everything else about the function already matches; 13 functions rose by exactly 3. The text is the machine's graph
and reads as the source's (`gate_three`, `bounded_fetch`, `BZ2_bzWriteOpen`'s five-way `||`); the benchmark does not
reward it on this set (analysis ceiling 29 newly perfect, measured 0). Only the DAGs that are read-once collapse:
`a ? (b ? X : Y) : (c ? X : Y)` is refused as `NotShortCircuit`.

**While and do-while.** Invariant: the body is just the header's marked `if` with a bare `break` on one arm, or ends
in the latch's with nothing else going back to the top. Owner: `structure/rotate.rs`, O(statements). The 21 loops
that rotated are GED-neutral. 747 `for (;;)` remain: 450 have an exit arm that is not a bare `break` (many carry the
exit edge's merge copies), 137 a staying arm that is more than copies, 90 copies the next recovery's conditions
refuse, 34 a header `if` with no bare `break` arm.

**Latch copies.** Invariant: the staying arm is plain assignments, the test calls and writes nothing and reads none
of them, nothing of the function outside the loop reads them, no `continue` would reach the test. Owner:
`structure/latch.rs`; the proof is the text's own def-use. Rejected: an r2ssa liveness fact (it is per SSA value, and D2
folds single-use values into the test and names them as C objects, which only the text states). 438 loops become
`do-while`; fnv1a32 and djb2 read as the source's loop. Against the source's `for` it is mixed (each function once):
44 functions improve (22 by exactly 3, the analysis's micro case, up to 34) and 8 worsen, and 3 functions that were perfect are not
(`uInt64_to_double`, `prepare_new_block`, `init_block`): Joern scores a `for` as a cycle of the test and the body, and
a `for (;;)` with the copies on the staying arm is the same two-node cycle, while a `do-while` over one block is a
single node, so a single-block `for` source scores worse as a `do-while` and a multi-block one better.

**Decision: both are kept.** Chains cost 0.2 mean GED (49.11 to 49.31) and win none (13 unique functions rise by
exactly 3; the analysis ceiling was 29 newly perfect, measured 0). `do-while` over a single-block source `for` loses 5
perfect across all binaries (3 unique) while winning 44 functions (22 by exactly 3) and 0.98 mean GED (49.31 to 48.33).
They spell the machine's test and loop as the CFG proves them, nothing was tuned to the score, and the benchmark
rewards the source's spelling, which the binary does not state. The cost is the price of the machine's graph, not a
regression to chase: the next reader should not rediscover it, and no recovery is added or dropped to move it.

What is left of the chains is in "the recoveries together".

## 2026-10-22: terminal tails, joined returns and sole exits

The goto analysis above ranked what the gotos cost on DecBench: GED scores the block graph, a label
adds no block, and the loss is a shared return where the source has several, a missing `&&`/`||`,
`while` against `for (;;)`, and a latch arm's copies. These three landed on top of the chains, each with a
unit test that fails without it, a counter-test where it must not fire, a behaviour test through
the engine (compiled and run) and a `tests/db/cmd/structure` golden on a real function:

- Joined returns (`tails::join_returns`, evidence `Values::returns_distinct_merge`).
- Terminal tails at their jumps, through the blocks after them and through jumps to other tails
  (`tails::inline_tails`), after the skipped-block copy.
- Sole closed exits (`Placement::inline_exits`, `closed_subtrees`).

Measured with the tails alone on the base before the stack, on bzip2, zlib and grep at O2 and
O2-noinline (1,305 to 1,313 binary-function pairs scored in both, 552 distinct functions): these are
projects the analysis mined, so the numbers are mined-set numbers. The stack's are above. Perfect is GED 0 under DecBench's own code, run on contabo over the tip
build's output and each step's (the tip reproduces the 2026-10-17 run's GED on 1,308 of 1,313):

| step | perfect | total GED against the tip | gotos | functions with a goto |
|---|---|---|---|---|
| tip | 203 | 0 | 4,654 | 623 |
| joined returns | 207 (+5, 1 lost) | -213 | 4,654 | 623 |
| tails at their jumps, first order | 199 (+5, 9 lost) | -1,833 | 3,474 | 499 |
| sole closed exits | 199 | -1,835 | 3,460 | 497 |
| skipped block first | 211 (+9, 1 lost) | -1,759 | 3,472 | 497 |
| runs through blocks and jumps | 212 (+10, 1 lost) | -1,937 | 2,694 | 426 |

The 212 are 102 distinct functions of 552 (96 at the tip); the ten new are seven (level, function)
pairs, `BZ2_bzCompressEnd` and `BZ2_bzDecompressEnd` at both levels, `myfeof`, `buf_has_encoding_errors`
and `inflateUndermine` at one (the zlib ones in four binaries); the one lost is `skip_devices`, whose
source is `return a || b`. The unguarded join on the first step: 218 perfect (+17, 2 lost), total GED -452.
Over the 558 distinct functions the goto classes of the analysis go from 2,214 to 1,356: TR1 487 to 22,
TR4 246 to 23, FW 580 to 237; left are JN 305 and JNB 283 (a jump over a block no rule closes), FW 237,
LX 139 (an exit that is not closed), TR16 133 (a tail of five to sixteen statements), SP 86, CC 68,
IR 57.

What is left of the tails is in "the recoveries together".

## 2026-10-23: what the chain and latch passes cost

Review of #328 asked for both passes' bounds. Counted inside the passes on the 5,688 functions that reach the chain
stage (bash, ls-toybox, pigz and libc-2.32.so, of the 6,144 `afl` lists) and on 0pack's 0x58e3d0 and 0x62ecf0 and
fifty of pumasim's largest: 148,668 sequences, the longest 5,743 statements.

**Condition chains: a sequence is indexed once.** Invariant: the statements a chain removes are the regions it
consumes, and no position in a sequence moves while it is walked. Owner: `structure/condition.rs`. `Pass::sequence`
read every statement again to find the regions after each chain (k chains in n statements read O(k·n), and
`Vec::remove` shifted the tail for each region), so 200 sibling chains read 81,200 statements before and 1,200 now.
The index is built once; a chain takes the labels it consumes out of it, their statements stay where they are, and one
pass drops them when the sequence ends, so a sequence costs O(n) plus its chains' own text. Iteration stays ascending,
since descending can change which chains collapse. On the corpus the claim was real and bounded: 1,365 sequences held
a chain and none held two, so the re-reading was 9,011 of 885,426 statement reads (1.0%), at most 1,532 in one function
(libc 0x97e10). A consumed region is skipped, not read for chains of its own (the old removal made that so;
`a_consumed_region_is_not_read_for_chains_of_its_own` pins it).

**Latch copies: the reads are counted once.** Invariant: a loop's copies are written before its test only when every
read of each is inside the loop. Owner: `structure/latch.rs`. `may_hoist` counted the reads of the whole loop body for
each candidate latch, so a statement was counted once per enclosing candidate (O(n·d) for depth d): 50 nested loops
counted 8,100 expressions and 100 counted 31,200 (450 and 900 now). One scan counts the reads of the function and, for
each `for (;;)`, takes the reads of its copies inside the loop as the count at its exit less the count at its entry; a
second walk writes the loops the scan allowed, in the order the scan met them. The scan reads each expression once and
the walk touches no expression, whatever the depth. The scan takes the latch's shape before the loop's body is
rewritten, where the old pass took it after the inner loops were: `live`, `parts` and `continues` stop at a nested
loop and a rewrite only moves statements, so the shape and the counts agree (the census, byte for byte, is the check).
On the corpus the claim was real and bounded: a candidate loop sits at most 5 loops deep (4,993 of 5,688 functions have
no candidate, then 492, 158, 30, 13 and 2 by the deepest one's depth), and the per-latch rescans were 366,432 of
7,704,538 expression visits (4.8%). The worst function, libc 0x16b210, has 16 candidates side by side, which repeat
nothing: only nesting repeats a statement.
