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
- S2, two of the five (2026-10-22, B5-b): short-circuit `if` as condition chains (`structure/condition.rs`) and `while`
  and `do-while` rotation (`structure/rotate.rs`), with the latch's copies written before its test (`structure/latch.rs`);
  switch-tail absorption, bounded tail duplication of returns and return into arms are still not replaced. See the
  section below.

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

**Left**, by cost: the exit edge's copies after a loop whose only exit is the latch (about 140 loops, next); a `while`
whose exit arm is not a bare `break` (34, conditional on the exit being the only way out); chains whose DAG is not
read-once (a selection between two tests), refused for now; splitting a chain around a block that renders text; a
chain whose exit is a `continue` to its own head, which `exits` reads as an edge inside the chain, so its `ExitCount`
fault reverts every chain of the function (ROADMAP D58).
Equivalence cells at risk: `branchy`, `hashes`, `shapes` and `values` at O0, O1 and O2 under both compilers (every
function with a chain or a rotated loop).

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
