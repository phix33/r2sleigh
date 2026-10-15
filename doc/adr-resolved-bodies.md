# ADR: One resolved body per function (P6)

Status: accepted, done (P6a, P6c1, P6c2, SM2); Summaries in progress.

## Context

A root function is walked, read for dispatch tables, walked again through
them, prepared, restated and prepared again. A callee gets none of that:
`prepare_callee` walks it once with no arms and prepares it against its
imports alone. So a callee's switch arms are never seen, a callee knows
nothing of its own callees, and a parameter a body hands to another body is
never followed (Q3e found the forwarding path unreachable). Two
preparations exist for one function, and which one a function gets depends
on who asked.

## Decision

One function has one resolution, whoever asks: walk through its dispatch
tables (`Walked`), prepare, restate, prepare again (`Native::resolve`). A
root resolves against its callees' answers; a callee resolves against its
imports, and against the callees that own its result (below).

### Demand: results only

Measured 2026-10-06: one callee resolved against its imports costs about
10.5 ms; pumasim `main` reaches 1949 functions (2.5 s to walk them, 21 s to
resolve them), 0pack `main` 1287 (13 s). Demand for parameters prunes
nothing: an argument a body hands on is invisible until the callee's
interface exists, and an unread slot sits beside almost every call. So
demand is for results only:

- r2ssa's interface recovery states `result_owners`: where the result is
  unproven, the direct callees whose unstated result owns it (a tail target
  no prototype describes, or a call whose result reaches an exit).
- `Resolved(f)` is `f` resolved alone where it has no owner; otherwise it is
  `f` resolved again with each owner outside `f`'s demand cycle resolved,
  and only where some owner then states its result.
- `Demand(f)` is the cycle of result demands `f` is in, by Tarjan over the
  owners; members of one cycle read each other resolved alone.
- A callee whose interface mints no call contract, its result unproven or
  its parameters a floor, is stated instead (`CalleeStatement`): a call to it
  reads the registers the caller provably wrote, at least as many as the
  callee's own body proves it reads, and takes the result the body proves.

Parameters a body proves alone are a floor wherever an argument register
reaches a call of unproven arity untouched or unseen: recovery, with no
interface yet, counts any untouched slot as one it may hand on. A caller then
passes what it wrote; past the floor, a slot the count cannot see (a merge)
refuses the call where the caller writes that register on some path, and
ends the count where only arrivals and call clobbers merge there. Before,
recovery stopped silently at the untouched slot and minted an exact
zero-argument contract: gcc -O2 hashes `main` called `combined()` without the
buffer it reads, and crashed. A caller that hands its own untouched slot on to
a floor callee is still counted as ending there; closing that costs C++
methods their calls and waits on prototypes for mangled imports (LP).

The first preparation recovers the interface; a restated one is handed it,
so the owners are taken from the first.

Known refusals this brings to the 300-function samples (pumasim refusals
27 -> 27, 0pack 36 -> 37): one observation-journal `ConflictingValue` on a
merge carrier in 0pack, which R deletes the journal for.

### Caller reads

A body that writes both convention result registers on a path to a return
(RAX and XMM0 on x86-64: vectorized integer code, or a double function whose
loop test leaves RAX written) does not say which is its result. r2ssa's
recovery makes it unproven and says why (`result_ambiguous`), where it
returned RAX before and miscompiled `avg`.

Each call decides it for itself. The callee's interface keeps its exact
parameters and names the two registers (`result_carriers`); r2ssa reads the
caller's own lifted code after the call (`caller_reads::reads_after_call`):
the first touch of each result register up to the next transfer is a read
(the caller takes what the call left there), a write, or nothing. One register
read decides the call's result, a float at the read's width; r2types types it
there (`call_result_type`). Both or neither leave the call without a contract.
The cost is one scan of the call's block, O(ops after the call).

After `aa`, the function's own rendering asks every call in the program: the
walked bodies whose trace calls it (`Survey`, inverted once, O(call edges)),
each lifted without preparation. Every reading call agreeing on one register
decides it; none, or calls that disagree, leave it unproven. Only the
rendered root is prepared again with that evidence (`SourceResultReads`); a
callee read for its caller never asks.

Reading callers surveys the whole program, so a fresh open reads the body
alone and its open result stays a residual. On pumasim, `pdd @ 0x4baf30`
takes 4.6 s alone and 10.3 s with the survey (contabo, 2026-10-13). `aa`
surveys once and sets `Callers::Read`, which every analysis, sealing and
rendering key carries, so a session's answers never depend on which command
first ran the survey. Census, certification, the coverage sweep and
equivalence run `aa` first.

The evidence is as strong as the body's own writes: a compiler reads a
clobbered register after a call only as the callee's result. A caller that
hands the value straight back without reading it (`return f();`) is no
evidence. A void function whose callers read nothing stays unproven, except
in a closed world, below.

### Closed world

An unproven result that every call writes before reading, in each result
register, is read by no call the image shows. It is void only if those calls
are every way into the function: the void rests on `Premise::ClosedWorld`,
which r2engine grants only under `aa` and r2dec spells on the proof line
("no call reads the result (assuming closed-world)"). A proven result is
never made void this way: a helper whose callers ignore its value keeps it.

A call overwrites a result register when its writes cover every byte of it
before any byte is read: `xor eax, eax` lifts to a 4-byte write and a
zero-extension that covers RAX. The float register must be overwritten only
where the body writes it.

`SourceResultReads.exhaustive` states that the calls read are every way in.
r2engine sets it where all of these hold:

1. Every caller the survey found was walked and lifted, and the reference
   index claims exactly as many calls to the function as were read.
2. No reference other than a call names the entry: no jump from another
   function (a tail call), no computed address (`lea`, `adrp`+`add`, a
   loader write). A jump to a function's own entry is a loop.
3. The container states no other entry there: no entry point, initialiser
   or finaliser, and no export (ELF's dynamic table, any non-local Mach-O
   symbol).
4. No mapped file word names it (`Escapes`): every pointer-wide window, and
   on a 64-bit machine every 32-bit one (`imm32`, `.long`), with bit 0
   cleared. This catches a non-PIE vtable or function table, which holds
   absolute words with no relocation and no code reference.
5. The index read every body, and every code byte the file holds is in a
   walked body, a linkage section, or filler: zeros, instructions that lift
   to no operation, traps, or direct transfers to code discovery knows (the
   `bl abort` after a call that never returns). Code no walk decoded, past an
   unresolved transfer or never reached, may call or name anything, so any
   other byte refuses, named on the refusal. The sections the container
   states as code are read, else its executable segments: AArch64's R-X
   segment also holds the headers, `.rodata` and `.eh_frame`. This replaced
   refusing on any unresolved transfer, which crt's `br x16` tail calls
   through the GOT made true of every program (2026-10-13).
6. The machine is x86-64 or AArch64, whose addresses an index claim or a
   word holds whole. `movw`/`movt` and `lui`+`addi` split one across
   immediates and hide it from both. The format is ELF or Mach-O, and the
   function's language C, C++ or Rust: Swift, Objective-C, Go and .NET reach
   functions through tables of relative offsets.

AArch64's large code model builds an address with `movz`/`movk`, which item
6 does not catch. No compiler in the corpus emits it.
x86 `int3` lifts to a software interrupt, an indirect call and a return, so
lld's `int3` padding between functions refuses the closed world; GNU ld pads
with no-operation instructions. Code in a gap is read instruction by
instruction, so an `adrp`+`add` there that names a function is missed, the
large-code-model limit of item 6 in unreachable code.

Cost: `Escapes` is computed once per program under `aa`: one pass over the
references, symbols and entries, and one over the mapped file bytes, with a
range check per word and a search per word in range: O(R + S + B log F).

Two shapes stay residual, measured at #215: a call whose next instruction is
another call (`call crc32_init; call fnv1a32`), where the block-local read
stops at the transfer, and a later call to a stripped local function, which
has no stated interface. Deciding them needs the caller's liveness past later
calls and their callees' entry reads.

### Arity (ROADMAP P7)

A function's arity is `Exact(n)` or `AtLeast(n)` (`r2source::SourceArity`),
stated apart from its result: a callee whose result is unproven keeps an exact
arity, and a call to it hands on exactly its `n` arguments. Recovery states a
floor where its reads cannot see every argument: a transfer the walk did not
follow, a supervisor call, the argument area read past an incomplete register
prefix, or an argument slot handed to a call of unproven arity.

The last cause alone is one the callee's statement can lift: recovery names
those calls' direct callees, its arity owners (none where one such call names
no callee). Under `aa` (`Callers::Read`), `Resolved` waits on arity owners as
on result owners: `Component` is Tarjan over both edges, bottom-up, and a
function is resolved again where an owner outside its component states an
exact arity. Members of one component read each other alone, so an argument a
cycle hands on stays a floor; a fixpoint inside the component costs a
preparation per member per round and waits on its measurement. Without `aa`, a
request demands results only, as above, and pays no closure (D23): measured on
0pack `0x62ecf0`, demanding arity on a cold `pdd` took 20.0 to 36.5 G
instructions, pumasim `0x23fdf0` 18.1 to 21.2 G.

### Summaries (ROADMAP SM, D23)

**The fact.** `Summary(f)` is what a caller reads of a body: its interface
(arity `Exact` or `AtLeast`, result), what it does through each parameter
(`PreparedCalleeSummary`), the registers it preserves, its signature, and the
callees that own what it leaves open. It is `CalleeReads(f)`, `f` resolved
against its imports, and `Resolved(f, demand)`, `f` resolved again against
the summaries of the owners outside `Component(f, demand)`, read bottom-up;
members of one component read each other alone. Key: entry, instruction set,
demand. Owner: r2engine's database; r2ssa states the interface, summary and
owners, r2types the signature. `Retention::Held`, a program-wide fact
computed once (adr-memory-model, decision 2). A prepared body is never held:
it costs about 8 ns per byte to compute again, a summary microseconds.

**Measured (2026-10-15).** The summary is already one held answer per body,
per demand, per session (`two_callers_of_one_callee_prepare_it_once`).
Resolutions by what asked for them:

| Run | Resolutions / bodies | Alone | Again with owners | Root | Root and summary |
|---|---|---|---|---|---|
| sort, all 234 `pdd` | 329 / 234 | 90 | 5 | 234 | 85 |
| pumasim census session, 50 `pdd` | 745 / 649 | 609, each once | 86 | 50 | 10 |
| pumasim `0x23fdf0` | 121 / 93 | 92 | 28 | 1 | 0 |
| gzdoom, 60 sampled `pdd` | 281 / 208 | 148 | 9 | 60 | 17, and 64 restated |

**Two grades, by construction.** A root resolves against every direct
callee's summary, a summary against its owners only. One resolution for both
gives every callee its callees, the transitive closure D23 forbids (pumasim
`main` reaches 1949 bodies, about 21 s), or takes callee evidence from the
root. So a sweep resolves each body once as a root and once as a summary,
and once more where an owner outside its component proves its result or
arity.

**The per-request double, removed.** `Native::resolve` prepared a body in
full, then again where the first folded text it points at (AArch64's
`adrp`+`add`) or the program's calls read an ambiguous result; the second
read none of the first's facts unless a declared frame was restated off
them. The first preparation stops at its seal (`r2ssa::TrustedSeal`: the
machine context, the owners, the folded table), and its facts are collected
only where they are the answer or a declared frame reads them. Discovery's
handed functions and the dispatch tables read a seal built against the
convention, recovering nothing: a constant that reaches a call's argument or
a table is the body's, which no interface decides. Output md5-identical, and
`aa; afl` identical on radare2's 309 ELF and 137 Mach-O test binaries:
gzdoom `0x10070695c` `pdd` 46.5 to 41.4 G instructions (672 to 618 MB);
`aa; afl` 0pack 77.9 to 43.2 G, pumasim 64.0 to 40.6 G, gzdoom 191.6 to
138.1 G; `aa; pdd` 0pack `0x62ecf0` 96.5 to 62.0 G, pumasim `0x23fdf0` 83.6
to 60.3 G.

**Invalidation and eviction.** A summary records what it read: the walk's
bytes, the names and stubs, its owners' summaries and its component; a write
recomputes exactly what read the written range. `Shared` compares by
identity, so a recomputed summary is never backdated and a write that moves
nothing still recomputes its dependents: P8's, under Q.

**Memory bound.** One summary per body asked, O(Σ summaries): the census
session (50 `pdd`, 649 summaries) peaks at 149.8 MB of heap against
121.9 MB for its largest function alone, so its held summaries cost at most
28 MB, about 43 KB each.

**Complexity.** Per body per demand: one construct and seal, one fact pass
where its facts are read, one more resolution where an owner outside its
component proves. Components: Tarjan, O(V + E) over the owner edges.

**What is left.**

- Callee reads stay 46% of sort `0x3f50` `pdd` against SM's 10%: one
  preparation per callee already (59 over 54 bodies), whose 39.4 points are
  construct 25.3 (recovery 15.7) and seal and facts 12.2. That is recovery's
  fact pass collected again by the seal (P4, LX4) and F2's single
  representation.
- Arity on a cold `pdd`: demanded everywhere it cost 0pack `0x62ecf0`
  16.5 G; under `aa`, where it is demanded, it closes 9 of pumasim
  `0x23fdf0`'s 317 floor gaps and 3 `may-hand-on` gaps of 0pack `0x62ecf0`,
  none on 0pack `0x58e3d0`, sort `0x3f50` or gzdoom `0x10070695c`. The rest
  chain through local Qt constructors to a slot handed on (`may-hand-on`,
  LP) or an indirect call (an indirect call's arity, SM). Conditional on
  those.
- Alone, then with owners: of the bodies with owners on pumasim `0x23fdf0`,
  28 resolve again and 8 do not cold, 89 and 6 under `aa`. Sealing alone,
  and collecting only where no owner proves, saves a fact pass per body
  resolved again and costs a construct per one not: about 5% of callee
  preparation cold, 13% under `aa`. Next.
- One preparation on AArch64: fold literal addresses before recovery, so
  folded text is captured once. The seal folds after boundary constants,
  copy forwarding and demand release, with prep facts; a fold before
  recovery has none of them, so it is a semantic change until the literal
  sets are shown equal over the AArch64 census and a gzdoom sample. Next,
  measured first.

### Budget

Resolution follows result demands only, so a request resolves what its
unproven results need; the 300-function samples cost 8% more (pumasim 9.1
to 9.9 s). A stopped owner stops the answer (`Hold::Stopped`); every held
answer is a function of the program alone.

## Complexity

Walks: one per function asked, held. Resolutions: one per callee asked,
plus one per function whose result an owner then proves; a resolution's
first seal is collected only where it is read (Summaries). Components:
Tarjan, O(V + E) over the owner edges the demand names, each component deposited once.

## Steps

- P6a: `Walked` is a query and the root analysis reads it.
- P6b: `Component` and the closure measured on 0pack and pumasim.
- P6c1: a callee runs the root's resolution, on its `Walked`, against its imports.
- P6c2: `result_owners`, `Demand` and `Resolved`; an unproven callee states how many arguments it reads.
- P6d, declined: `read_callees` is the one loop a root reads its callees through. The database
  answers it with `Resolved`; a plain `Program` (tests/engine/native.rs, the model integration test)
  with each callee resolved alone, through the same `resolved_alone`.
- SM2 (2026-10-15): a first seal no second preparation reads is never collected; discovery's
  handed functions and the dispatch tables read the convention's seal.
