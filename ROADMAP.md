r2sleigh Roadmap
================

The one ordered list: what is left, who owns it, how its exit is checked, and
in what order. Design lives in the ADRs each row links; the why in
[doc/engine-vision.md](doc/engine-vision.md); the working rules in
[AGENTS.md](AGENTS.md). Where this file and an ADR disagree, this file wins and
the disagreement is a defect. Done work and dated measurements live in
[doc/roadmap-history.md](doc/roadmap-history.md) and the commits, not here.

`r2s` is the tool: one engine (discovery, lifting, SSA, memory, types, a
certifying decompiler) under radare2's command language, a visual mode, and an
agent surface. It prints C only where checked facts justify it; otherwise a
counted residual or a refusal that says why.

Rows cite the [end-to-end audit](doc/reviews/2026-10-end-to-end-audit.md) as
`audit W1` (correctness), `M` (missing), `D` (design), `P` (performance), `B`
(build) and `T` (tests): always with the word, since the roadmap uses the same
letters. Each audit row has exactly one owning item (table at the end).

Gates
-----

In order of authority. A benchmark score is never proof; output is read by
hand before a quality claim. The third column is what the gate cannot see
today; GT closes it.

| Gate | Question | Blind spot (audit) |
|------|----------|--------------------|
| Equivalence (`tests/equiv`) | Does the C compute what the machine code computes? The north star. | `residual-trap` compares no state before the trap (T1); stripped builds only, so the DWARF route is never run (T5) |
| Census (`tests/db`, every coverage, pinned and stripped function) | Did any rendering move? A structural change is byte-identical or names each moved line. | — |
| Certification (`scripts/certify_render.py`) | Does every rendering read only what it assigns, and never panic? | grades 98 of 1,492 functions, none stripped; cannot see invented arguments (T6) |
| Source-gold (`scripts/differential_truth.py`) | Are signatures what the source declared, or marked? | soundness 43% and 21% (W49); `frame_agree.py` in no gate (T21) |
| Coverage (`tests/coverage`) | How much of a binary renders; does any regress? | stale baseline; clang other than 17 ungated (T19) |
| Differential (`scripts/diff_r2.py`) | Where discovery, naming, decoding disagree with radare2, and who is right. | not in CI and red; radare2-only values score as agreement (T4) |
| Dylints (`tools/dylints`) | Does the code keep the structural rules? | 87 of 89 warn-only; at least 12 aim at deleted paths (T3) |
| Structure (`scripts/structure-report.sh`) | Did nesting, length, arguments or clones rise? | — |

Where this stands (2026-10-14, master 98dd6e06)
-----------------------------------------------

| Measure | Value |
|---------|-------|
| Equivalence (blessed baselines) | x86-64 678 of 756 equal, aarch64 685; no `differs`, `ub`, `uninit` or compile error; the rest `residual-trap` (57, 50), `unsupported` (20) and `slow` (1) |
| Tests | 2,414 workspace tests, none flaky over 7 runs; Kani 20 of 20 |
| Rendering | `pdd` renders 94% of `ls` and 79% of static glibc; r2dec 18.1k lines |
| Robustness | about 6,000 hostile and fuzzed runs, one panic (broken pipe, audit W52); every rerun, call order, session against fresh open and Mac against Linux byte-identical |
| Wrong output (audit: 166 rows, 63 of them wrong output; 18 high: 15 wrong output, M1, P5, P6) | container facts (PE mapping and imports, ET_REL), AArch64 lift semantics, invented call arguments, functions absorbed across CFI-only starts |
| Cost | large x86 `pdd` 13 to 26 G instructions and 188 to 256 MB, callee preparation 47 to 84% of it; pumasim `afl` 20 G and 158 MB; worst cases gzdoom aarch64 51 s (audit P5) and r2pay `init1` 1.02 GB (audit P6) |
| Structure | `long_comments` 2609, `excessive_nesting` 460 |

The 2026-10-04 review rated the code 4/10 for weak algorithms and structure,
hence algorithms and structure before features. The 2026-10-14 audit adds
that the inputs are not yet right: container facts and lift semantics feed
every view, so they go first.

Decisions
---------

| | Decision | State |
|-|----------|-------|
| D1 | Restructure, not rewrite: one item per branch replaces its owner and deletes the old path in the same branch; the gates run once at the item's exit, where the census diff is read | standing |
| D2 | Stable identity before more facts | done (F1) |
| D3 | Stages are types | done (F1) |
| D4 | Provenance on every fact, as `Fact<T>` | C |
| D5 | Gates are blessed in CI, never on a laptop | standing |
| D6 | Equivalence runs on arm64 too | standing |
| D7 | The visual mode never calls the engine while drawing | done (V1) |
| D8 | The observation journal is replaced by D, not kept | done (D) |
| D9 | Location SSA is superseded | done |
| D10 | DecBench is measured again only where PyPI is reachable | standing |
| D11 | No new iteration off the fixpoint driver or a stated worklist; no silent cap; no entity-keyed map; no cache outside the query database. Dylints enforce each as its owner lands | standing |
| D12 | One IR, indexed once ([one-ir](doc/adr-one-ir.md)) | F2 |
| D13 | One query database ([query-database](doc/adr-query-database.md)) | Q |
| D14 | One frame model ([frame-model](doc/adr-frame-model.md)) | P4 |
| D15 | One machine profile from the trusted Sleigh bundle; no architecture-name match below the lifter ([machine-profile](doc/adr-machine-profile.md)) | M |
| D16 | One byte relation ([byte-relation](doc/adr-byte-relation.md)) | B |
| D17 | No new crates: a layer boundary inside a crate is a module boundary enforced by a Dylint; the IR depends on neither the lifter nor type inference | standing; L6 meets its second clause |
| D18 | Untrusted input is bounded: a read stops at the bytes the file holds, and every pass states its cost | standing (H) |
| D19 | Performance is a gate: release time, peak RSS and allocation count budgeted on named workloads in CI | standing (PF) |
| D20 | The decompiler is rewritten, not refactored ([decompiler-rewrite](doc/adr-decompiler-rewrite.md)) | done (D) |
| D21 | The source language is a profile; the IR, facts and proof name no language ([language-profile](doc/adr-language-profile.md)) | LP |
| D22 | Every pass is an index with a stated bound: `O((V + E) · h)` or says at its definition why not ([next-pass](doc/adr-next-pass.md)) | LX |
| D23 | Summaries compose over the call graph: a body is prepared once per session and held; no `pdd` pays a transitive closure | SM |
| D24 | The lift is a query per address over a compact IL | LF |
| D25 | Types are one monotone system: union-find, one meet per class, incremental | T |
| D26 | Allocation is budgeted: one arena per function, indexes sized at the seal, the allocator chosen by measurement | PF, MM |
| D27 | Contract first, then the layers behind it, on one integration branch | done (`rebuild` merged, #142) |
| D28 | A defect in a vendored Sleigh specification is fixed in `vendor/` with an `r2il::eval` regression and listed in `vendor/README.md`; it is reported upstream, or resynced where upstream already fixed it (the `addv` precedent, c886c13c) | VC |
| D29 | Every refusal is a record: an analysis that stops (convention, capture, walk, image) yields a typed reason the verbs print and `pddj` carries, exit status 0; never a bare `Err` string | RF |
| D30 | A gate grades what it claims or it is red: a check that compares nothing, a lint aimed at a deleted path, a silent skip and an unjudged disagreement are defects in the gate | GT |
| D31 | Every layer has an executable oracle: the container against radare2 and DWARF, the lift against the CPU, each IR rewrite against `r2il::eval` before and after it, the C against the machine. A layer without one is not admitted to render (2026-10-14) | standing (GT, VC) |
| D32 | `pdd` renders an architecture only where an equivalence target grades it; elsewhere the listing, discovery and references work and `pdd` refuses with that reason (2026-10-14: ARM32 and RISC-V 64 refuse until LS and M give them targets) | standing (RF refuses; M, LS add targets) |

The Sleigh crates (`libsla`, `libsla-sys`, `sleigh-config`) are vendored (`vendor/`).

The program
-----------

Items by owner, from the bytes up. **Done** is one line; the history has the
rest. **Exit** is what a gate checks. Closed, with nothing left: F1 (stable
ids, stage types), P1.7 (entry lanes), MF (its rest is F2's, SM's and LX's),
R (superseded by D), T1c (one solve per function since T step 4, #227), the
staged merges of PR #67 (finished items land on master).

### Container (`r2image`, `r2abi` data)

| Item | Done | Left | Exit |
|------|------|------|------|
| **H** Hostile input | every read clamped to the file; `hostile-gate` in CI (887 of 887 within budget) | the open file truncated under a session kills it with SIGBUS (audit W53): read through owned bytes or a guarded map | — |
| **I** Every container fact stated | init, fini, preinit arrays and `DT_INIT`/`DT_FINI` as entries; RELRO as sealed ranges; CFI starts seed discovery | PE: a section with execute or write but no read is mapped (one read gate for `read`, `read_unpatched`, `read_upto`, `write`; audit W1); import and export directories as per-slot `WriteKind::Import` and symbols (M1); TLS callbacks (M8); `PointerToRawData` rounded (W35). ELF: ET_REL relocation records and CFI at the placed section base (W5, container half; the engine half is FS); a damaged section table falls back to program headers (M4); one `DT_SYMTAB` reader for symbols and relocations (M6); `PT_DYNAMIC` init arrays (M7); the CIE `S` flag (W31). Mach-O: one entry derivation (W33); arm64e threaded and signed binds (W34); dSYM base and file ranges (W39). COFF: bits from the address size (W38); absolute symbols (W37). All: raw bytes, architecture and fat-slice selection, and container verbs that work where the machine is unmapped (M5); a posture record (nx, pic, relro, interp, static) for `i` and `il` (M18); LSDA landing pads as statements about their functions. Cost: DWARF read on demand, each DIE decoded once (P12); one section-name index (P14); tables sized exactly (P28) | `diff_r2.py` judged clean on the elf, mach0 and pe corpora in CI (GT); no corpus PE refuses at an entry radare2 maps; `ir` non-empty on every ET_REL object |

### Lift (`r2sleigh-lift`, `vendor/sleigh-config`, `r2il`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **LS** Lifted semantics are the machine's | — | `r2il::eval` executes float, guarded and linked operations through one IEEE evaluator, so LS0's float cases run. The specification fixes and LS0 are VC's. Multi-register `tbl` and NEON user operations. In r2sleigh-lift: nested branches rewritten innermost-first, a forced refusal poisoning every guarded op (`fccmp`, `casp`: W20); AArch64 LL/SC as `LoadLinked`/`StoreConditional` (M2); `cmpxchg` as `AtomicCAS` (M13); in r2il, division not speculatable (`is_speculatable_value`, W22); `ud2` noreturn (W23); `ArchSpec.alignment` filled (W25); big-endian ARM decoded as such (W26); a `globalset` aimed at another address stays out of the continued run's context, and each run's mode comes from `$t`/`$a` (W2, W3); ARM32 refuses `pdd` (D32) until these and an ARM32 equivalence target land | no `Unimplemented` left in place of a branch; ARM32 decodes Thumb after a backward `blx` as radare2 does |
| **VC** The vendored core is right and cheap (D28) | `addv`; the Go cspecs; PF0 and PF1; LS0, the oracle (379 AArch64 cases an arm64 CPU ran, replayed through the trusted lift on every host) with `r2il::eval` running IEEE binary32 and binary64; resynced from Ghidra master (`ldpsw`, `ldapr`, `ldar`, `stlr`, scalar `fmadd` and the reductions' zero-fill, GP-7313's `eor3`/`bcax`/`rax1`/`xar`); W15, W17, W18 (scalar), W19 and M15 fixed, the oracle's list 99 to 43 cases; every local change on a 0verflowme fork pull request (`vendor/README.md`), and Ghidra pull requests #9893 to #9896 and issue #9897 for what master still gets wrong. Measured and not worth it (2026-10-14): inline operands in libsla's emit (+3% instructions on pumasim `afl`), reserving its op list (no change), inflating the `.sla` in Rust (+2% instructions, +20 MB) | the cost: B1 to B4; P13's lever is fewer processes per harness and one AArch64 profile (D8, M), not the decode; vector `frint`/`fcvt` still truncate; fused `fmsub`/`fmla` round twice (p-code has no fused multiply-add) | the oracle lists only stops it names (float saturation, unmodelled operations, the lift's in-instruction branches: LS); every local change names its fork pull request |
| **M** One machine profile | M0 to M5 (M1d's float lanes included); RV64 admitted (M6a) | M6 rest: RISC-V 64 an equivalence target (qemu-user), which admits its `pdd` under D32, and its 10 frame-base refusals; one tuple-to-profile table, so AArch64 discovery and the trusted lift share one profile (audit D8); MIPS and RV32 profiles or a named refusal (with I's M5) | one Sleigh parse per architecture per process |
| **LF** Lift once | the Sleigh context persists; the compact IL; one parse per thread | `Lifted(address, mode)` for the walk and the trusted lift (inside SM); the spec decode and libsla's allocations are VC's; discovery translates operations it never reads (audit P18); block lifting copies the rest of the block per instruction (P24) | spec load under 20 ms; `afl` decode under 50% of its time |
| **L** Layering | L1 to L4 | L5 r2ssa's IR and facts layers as modules with a Dylint boundary; L6 r2ssa off the lifter: it depends on r2sleigh-lift only for the trust types (`TrustedLiftedFunction`, `GenuineLiftedFunction`, its authority), which puts the C++ chain on 51% of the release and 74% of the debug critical path (audit D9, B5); the types move to r2il and a Dylint lets only r2sleigh-lift mint them, so no crate is added (D17) | r2ssa builds without libsla-sys; the critical path no longer runs through it |

### IR and analysis (`r2ssa`, `r2rewrite`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **K** One fixpoint driver | r2ssa on the driver; an exhausted pass refuses, typed | `address.rs` provenance onto the driver; the optimiser's round budget and address provenance keep a partial result only the trace shows (audit §5.4): refuse or name it on the proof line; the depth-8 walks (`FOLD_DEPTH`, `frame_address`, induction); a Dylint for a `fixpoint::*` result matched to a default; the unbudgeted-loop Dylint fatal in r2engine (D11); the written-lane capture's `while` over every block until nothing moves, onto the driver | no budget keeps a partial result unnamed |
| **B** One byte relation | B0, B1, B3 by lane | the forward lane relation reads a byte shift as data; B3's rest, a recovered interface's float slots, is P7's (W11); B4 measured, no instance yet; liveness over locations (B2) is F2.2's one model; residual traps in bytes the declared result never reads (`release_undemanded_bytes` by `of_returning`, audit W13); NEON and FP values carried in 256-bit z roots (D7) | — |
| **P5** Values as an index | lane views, low-lane values, read-only loads folded | the renderer reads the views for lane carriers; a return slot reached as a wider root; a reloaded bounded index as one value, so `bomb`'s `phase_3` table resolves (audit M14); a load whose literal address SSA folds (aarch64 `adrp`/`ldr`) captured on the restated preparation; `NEON_uaddlv` | — |
| **F2** One IR, indexed once | F2.0, F2.3, F2.6; one operation encoding after the seal (MM.6) | F2.1 `FunctionIndex` on `Sealed`; F2.2 one byte-granular liveness, the one owner (B2 included); F2.4 the builder with incremental def-use (one graph build); F2.5 the machine projection and term arena as indexes | one representation of a function at the render peak |
| **LX** Linear per function | LX1 (boundaries, obligation table, `Arch` once, sparse `call_results`, on-demand rewrite walks), LX3 (`ReachingStorage`) | measured fixes first: liveness skips literal constants (audit P6: r2pay `init1` 1,017 to 553 MB, output identical), then undefined Ram values, exact sizing and one build; evidenced spans by range (P2: a range patch measured 12 to 13.5% fewer instructions; an interval index gives `O(log n)`); AArch64 SP reads through `ReachingStorage` with one path stack (P5: 51 s on gzdoom). Then `Import::producers` as a dense index, not a memo (P3); one multi-storage `ReachingStorage` per function (P19); `declarable_stack_object` once (P20); dense rename identities and block-indexed domtrees (P21); block facts keyed by `BlockId`, and `entity_keyed_map` widened to `u64` block keys and wrapped keys (D15); `liveout`, `liveness` and `promote` at their bound, and `DeadPhis`, formals, `FunctionLiveOut`, `class_values` and `ValueViews` computed once; operand iterators, not fresh `Vec`s (P22); 96-byte obligations (P25); O(1) refusal evidence and lazy trace strings (P29, P30); interior-mutability memos into the database (D11). LX4 with F2.4: recovery collects the fact pass the seal collects again (P4). LX2: D27's adapter deleted, D0 reading T's and F2's dense indexes, and the entity-keyed map debt (65 sites in 44 allowed items; r2ssa's 12 function-wide allows narrowed to statements) moved to dense indexes | `census.py exponent` at most instructions^1.05 over 300+ instruction functions; peak RSS linear in instructions |
| **MM** Memory as a linear budget ([memory-model](doc/adr-memory-model.md)) | held answers newest-only; one encoding of each operation; compact dispositions; the image mapped | MM.6 a compile-time sealed type, and the `formal_*` maps keyed by `VarId`; MM.4 the fixed cost (loader writes, unwind frames, symbol layout); MM.7 obligation identities; MM.8 the projection's interned types and value geometries; MM.9 a collect at phase boundaries; MM.3 seal-only facts (conditional); `MachineBuilder` sized from a bound (audit P31) | `c ≤ 600 B` per operation, then `≤ 300 B` |

### Engine (`r2engine`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **Q** One query database | Q0 to Q5; the reference index, renderings, machines as queries | a write that moves nothing re-runs nothing: an evicted entry is not "moved" (audit P8: 18.07 to 13.52 G on a no-op write, output identical); `aa` keys only result-ambiguous functions (P9); `afb` and `agf` from `Walked`, the listing's def-use held (P10); lazy ARM32 modes and machines (P11); one name table at open (P15); a text-only held rendering for revisits (P16); incremental discovery after a write (P17); the reference index from survey facts with one lift (P7: first `axt` 6.6x `afl`) | first `axt` within 2x `afl`; a no-op write recomputes nothing |
| **FS** One owner for function starts and bodies | — | one index of container-stated starts (entries, symbols, CFI outside linkage) read by both discovery and the walk's `is_entry` (audit D1, W4: bash, `ls`, gnome-extensions absorb CFI-only functions); no function at unmapped or non-code addresses (W29); `LC_FUNCTION_STARTS` checked before seeding (W30); one containing-function query for the verbs and the visual mode, never an entry mid-instruction (W45, D2); overlapping instructions stated or refused typed, no absorption at misaligned offsets (W6); the ET_REL engine half: a target read from loader-written bytes comes from the relocation or is refused, never certified (with I's W5); `/as` at a function's first instruction and without vetoes from failed bodies (W40, W41); `axt` keeps direct calls when def-use fails (W42); the survey reads dispatch tables so `afl`, `afb`, `afi`, `ax`, `axt` agree, `aflj size` as radare2 (D6); indexed table accesses as references (M12); IBT `endbr64` as a weaker start candidate where no frame states one; the remaining jump-table shapes resolve or refuse. Absorbs W's discovery exit: `afl` finds every function radare2 does | the sweep (W) and `diff_r2.py` judged clean on function sets; `afl`, `afb`, `afi`, `axt` agree on every corpus function |
| **RF** Refusals are records (D29) | sealing and r2dec refusals typed | analysis-phase refusals (Go ABI0, `Capture`, `Convention`, the walk) as `Rendering` records, `afi`/`afv` keeping the facts that do not depend on the convention (audit D4); r2ssa's return coherence at `ret` justifying each live-value-producer refusal (W43: 17% of static glibc); typed `ImageError` and `r2source` errors with `Display`, no `{:?}` (D14); in r2il, allocation evidence as `Option` (W63); D32's admission: `pdd` on an architecture with no equivalence target refuses with that reason | no verb exits 1 on an analysis refusal; `pddj` emits JSON for every function |
| **SM** Summaries | `CalleeReads` held; demand stops at direct callees; SM1 measured (a summary grade saves at most 3 points) | a body prepared once per session and read by every root (audit P1: callee preparation is 47 to 84% of a cold `pdd`); `Summary(f)` held, over P7's call-graph components; the summary-grade r2types run; an indirect call's arity from the common prototype of its table's entries | a sweep prepares each body once; callee reads under 10% of sort `0x3f50` `pdd`; Q3's rest and P6's remainder closed |
| **P6** One resolved body per function | P6a, P6c1, P6c2 | its remainder is SM | — |
| **P11** Names and listings | the ELF sweep judged (`diff_r2_judged.toml`); the strongest binding names an address; Sleigh spelled as radare2 writes it; fat-slice offsets | x86-32 negative displacements signed (audit W27); conditional ARM aliases (W28); `entry.initN` by array slot (W36); preemptible PLT stubs named; `main` named in stripped binaries; one spelling per function; symbol flags filtered as radare2 filters them; a section-less object's stubs; conditional: a section table past the file's end, ET_REL listings and NOBITS placement, `e_entry` 0 in a static-pie; the mach0 corpus's unjudged rows (`px` 9, `pd` 8, `iS` 8, `is` 6, `ie` 3); the upstream radare2 pull requests | every disagreement judged on elf, mach0 and pe |

### Calls, frames and types (`r2ssa` boundaries, `r2types`, `r2abi`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **P7** Call contracts | Darwin variadic tail; float results beside integer registers; caller evidence behind `aa`; the closed world under `aa` | arity `Exact(n)` or `AtLeast(n)` computed bottom-up over call-graph components on the driver (P7 builds the components; SM reuses them); slots past a floor are residuals, never proven arguments (audit W7); `call [GOT]` resolved to its import through one `CallSlot` transfer when the slot is sealed, the four private readers deleted, one "arguments proven" verdict read by r2engine and r2dec (W8, D3); i386 stack parameters placed and a call clobbering the outgoing area (W9); ObjC runtime rows in a Darwin scope, upstream too (W10); float parameters and results recovered, no invented `(void)` (W11); the parameter prefix past an unread slot (W12); the variadic tail and the `al` input (W14); a gap names its callee (M3); a proven syscall named (M16); noreturn facts: `__`-prefixed keys, `DW_AT_noreturn`, `rt_sigreturn`, `longjmp`, `_Unwind_Resume`, `__cxa_rethrow` (W24); one case-preserving callee identity on address and typed linkage (D10); `crc32_init`/`fill` and aarch64 gcc-O1 `mixed_touch`; the closed world's x1 (`result_register_written`) aligned with pairs (`written_on_every_return`); the float path owning XMM0 before `body_proven_result` excludes it; printf's stack tail on x86-64; a conditional tail jump as an exit; conditional: lld's `int3` padding under the closed world, and `__libc_start_main`'s `main` as `int (*)(int, char**, char**)` | no invented or dropped argument on the certification arity check (GT); W7 to W11's repros render a refusal or the true prototype |
| **P4** One frame model | one partition, escape analysis, promotion as an SSA rewrite | reopened: `afv` and `pdd` disagree on every frame offset (`frame_agree.py` 0 of 582, audit T21); DWARF-declared slots refused promotion (D5: `-g` promotes 0 locals where stripped promotes 22); a protector behind a trampoline (W48); a select of two frame addresses no offset places refuses the whole frame (`shape_byte_indexed_buffer`); the promotion predicate a proof or a mutation target | `frame_agree.py` gated |
| **T** Types as one monotone system | T1, T2, steps 1 to 5: one union-find solve, one signedness map, one projection; the scored struct, array and global systems deleted | one parameter declaration fact for `afv`, `afi` and `pdd`, caller declarations equal to callee definitions (audit W46); an unproven return marked, the float carrier kept (W47); widths and float kinds from reads, not demanded bytes (W49); a narrow DWARF parameter's extension (W50); `param_type`/`ret_type` strings typed; `type_name_is_generic` replaced by the lattice order; `named_blocks()` copies and the name-keyed def maps deleted; `FunctionTypeFacts` and `FunctionRenderFacts` as dense indexes (before LX2) | one declaration per function across verbs; source-gold soundness reported per gate run |
| **P9** Types over the graph ([aggregates](doc/adr-aggregates.md)) | a parameter's fields laid out as a structure; member access as byte copies | declared aggregates' members; callers' declarations of an inferred structure; arrays of structures; recursive and polymorphic types; conditional: one reach pass over `fixpoint::sparse` with a parameter mask, once formals share closures | a struct pointer rendered as its struct or refused with the reason |
| **P8** Data objects and strings | — | `iz` calibrated: Mach-O C-string sections, no strings from pointer tables or debug sections (audit W32); address constants passed as arguments name their object (M17); r2ssa's `source_string_literals`, a second copy of the string table, deleted | `iz` agrees with radare2, disagreements judged |
| **C** Provenance ([provenance](doc/adr-provenance.md)) | C0; C1 types; C4 references carry `Basis` | C1 r2dec reads the grade; C2 the convention, locals and syscalls as `Fact`s, JSON with confidence; C3 r2types on `Basis`; C4's Dylint | — |
| **LP** Language profiles ([language-profile](doc/adr-language-profile.md)) | LP0; LP1's engine half (Go ABIInternal); LP2's Go stack check; LP3's Go panics | LP1's boundary half (several results, two-register values, Rust scalar pairs; with LX); assembly functions declared `<ABIInternal>`; `runtime.(*moduledata).textAddr` refuses where it rendered; LP2 Rust and C++ checks, and the frame ADR restated against the profile's premise; LP3 pclntab's `funcID` as the stronger statement of `gopanic`, `morestack` and the rest, Rust `core`, C++ ABI, demangling; LP4 Rust, Go and C++ equivalence corpora on both arches | a Go or Rust function renders under its own convention or refuses with that reason |
| **PE** Written-lane result widths | result widths | the rest is B | — |

### Decompiler (`r2dec`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **D** Decompiler rewrite | D0 to D5; the old r2dec deleted | `uncompress2` and `deflateInit2_` read by hand; the rendered function named by its entry, not its loop header's `root()` (audit W44) | — |
| **SD** Structuring and readability ([structure-dominator-tree](doc/adr-structure-dominator-tree.md)) | the dominator-tree structurer | inverted empty thens, merges spliced into the parent, dead reloads proved, constant branches decided before preparation (audit D13); condition chains and irreducible entries behind a BDD identity check | no more labels or nesting than today on the census, each moved line judged |

### Surface (`r2s`, `r2s-tui`, `r2sleigh-cli`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **S1** Verb table, `?`, `e` | done | `j` on every verb from typed engine payloads (audit M9) | `diff_r2.py` covers the `j` forms |
| **S2** `@@`, search, pipes ([scripting-surface](doc/adr-scripting-surface.md)) | — | address expressions, relative seek, `@@` (M10, W60); `/x`, `/`, `/w`, `/v` (M11) | — |
| **S3** Shell hygiene | — | a closed pipe ends the command quietly (audit W52); `q <n>` exits `n`, `q!` (W61); `ax` and `axf` as radare2 has them, one error prefix (M20) | no exit status 101 on any hostile run |
| **V7** Visual state from engine facts | — | the panes ask FS's containing-function and instruction-starts queries, never guess (W59, D2's TUI half); a seek moves the decompiler pane (W56); pane switches keep the seek (W57); keys give one screen at any typing speed (W58); re-entry and signals restore the terminal (W54, W55); `scr.color` respected (W62); the xrefs pane keeps axt's caveats (M19); requests cancel (P32) | a scripted key run settles to one screen across 5 speeds |
| **V1–V6, E, A** | V1, V2 done; V3 shell completion | V1's worker asks Q; V2's `eco` themes; V3 visual hints and palette; V4 linked cursors; V5 `agf`/`agc`/`agx` through one renderer, layout off the UI thread; V6 annotation as user facts; E emulation checked against host-compiled renderings; A the agent surface with determinism tests | — |
| **CL** `r2sleigh-cli` | — | `compile` reads its input (audit W51); `test-arch` and `run --action dec` (M21); a spawn test (T13) | — |

### Gates, CI and build

| Item | Left | Exit |
|------|------|------|
| **GT** Gates grade what they claim (D30, D31) | a pass-level differential: `r2il::eval` runs a function before and after each rewriting pass (optimiser, promotion, the rewrite import) over random inputs in the test suite, so a wrong rewrite fails at its pass, not at equivalence; equivalence compares state at the trap and ratchets the compared count (audit T1), with a DWARF route dimension (T5) and causes that describe their record (T20); the Dylints retargeted at live paths, a test that every path filter exists, the warning count ratcheted (T3); `diff_r2.py` in CI against a pinned radare2, values paired by column, radare2-only values counted, `ir iz iee i f` added (T4); certification enumerates `aflj`, skips `extern`, fails on 0 rendered, checks arity against the resolved prototype as a ratchet until P7 (T6) and states a read of a variable a gap defines; Kani, mutants and machete in CI, tiered (T2); `frame_agree.py` gated as a ratchet until P4 (T21); coverage measures a given binary and pins its clang cells (T19); `census.py`'s CPU fit and size axis (T23); explicit skips on macOS (T10); a `px` golden (T12); doctests compile (T14); behaviour tests for `arrays.rs`, `text.rs`, `expressions.rs` (T8) | every confirmed audit row that a gate could have caught is caught by one |
| **G0** Gates real | a timing verdict where the base refuses and the head renders; tests on `[profile.ci]` (audit T15); a nextest timeout (T16); the Dylint lock committed and its tools pinned (T17); per-allocator feature sets in Clippy and tests (T9); `unittest discover` for the harness tests with named exclusions; `SelfTestSuite` and `PipelineTests` stay removed (T11, T18); rendered C in shard artifacts (T22) | — |
| **W** Real-binary sweep gate ([sweep](doc/reviews/2026-10-real-binary-sweep.md)) | coreutils and zlib with DWARF as a CI gate against radare2, objdump and DWARF; its discovery exits are FS's | the sweep runs in CI |
| **BD** Build cost | the vendored crates' build cost (audit B1 to B4) is VC's; an `iter` profile (B6); r2engine's tests one binary (B7: 106 to 20 s user); per-processor spec units (B8); thin LTO or `dist` in the README (B9); unused dependencies (B10) | clean release build critical path under 4 minutes on a quiet machine |
| **PF** Performance foundation | done: PF0 to PF4. Left: the purge delay (D26, the maintainer's: audit P26); C++ heap reported beside the Rust heap peak (P27); one arena per function, with F2 | — |
| Hygiene | dead plumbing deleted (`reg_type_hints`, `merge_type_hint`, half of `r2il::allocation`, `memory_mirrored_carriers`, `register_identity_census`; audit D12), and `PreparedFunctionFacts::string_literal_for_value`, never filled; `samply_collapse.py` keeps the impl type (D16); README, BUILDING, `command-gap.md` and `tests/equiv/README.md` say what the code does (M22); `long_comments` falls at each item's exit; "where this stands" generated from CI artifacts; a file-length ratchet; pinned containers for gate results independent of the runner; macOS arm64 equivalence | — |

Order
-----

The dependency path; nothing jumps it. Items on different crates run beside
each other, each on its own branch and stacked (AGENTS.md).

1. **VC, the vendored core first**: every crate in `vendor/` is under every
   view, so its wrong output and its cost go before anything that reads it.
   LS0's oracle, then the specification fixes (audit W15 to W19, W21, M15),
   then its cost (B1 to B4, P13, P23); each lands upstream (VC row).
   VC's moved renderings are graded by LS0 and judged line by line in the
   census.
2. **Measured fixes** that move no output, one PR each, any time: liveness
   skips constants (audit P6), the span range (P2), the no-op write (P8), B7.
3. **GT, the gates the next steps are graded by**, before any other baseline
   is blessed again: the Dylints at live paths (T3), `diff_r2.py` in CI (T4,
   grades I and FS), certification over `aflj` with the arity check as a
   ratchet (T6, grades P7), state compared at the trap (T1, grades LS and
   P7). Then the measured fixes that move output, census judged: `ud2` (W23),
   the ObjC rows (W10), the broken pipe (W52).
4. **I**: container facts, the inputs every view reads; easiest to verify
   (container in, statement out).
5. **FS** and **RF**: one owner for starts and bodies, every refusal a record.
6. **LS**'s rest: the lift normalisation in r2sleigh-lift (W20, M2, M13,
   W22, W23, W25, W26) and the Thumb context (W2, W3).
7. **P7**, with T's one declaration fact (W46, W47): invented arguments are an
   AGENTS blocker and the most common wrong C left.
8. **The cost path**: LX's AArch64 quadratic (P5), then LX's other passes,
   SM (P1), F2.1 and F2.2, LX4 with F2.4, F2.5, T's dense indexes, LX2, MM;
   Q's reuse rows beside them.
9. **The rest of analysis**: P4 reopened, T, P9, P8, B, P5, C, LP2 to LP4,
   P11, SD, K.
10. **Surface**: V7 after FS's containing-function query, S3, S1, S2, CL; then
   V3 to V6, E, A.

Beside the path, when a step waits on CI: BD, L5 and L6, M's rest, LF, PF, H,
G0, W, D's rest, hygiene. PE's rest is B's; P6's is SM's.

Every item replaces what it owns and deletes the old path in its own branch
(D1); at its exit it deletes more than it adds or says why, names each moved
census line, meets D19's budgets, and violates nothing in D11.

Upstream radare2 (differential target,
[radare2-function-walk](doc/adr-radare2-function-walk.md)): `ret` given one
definition, one read-ahead cache per walk, predecessor in the frame,
edge-labelled path state, the callee-recursion cap derived; the defects P11's
sweep judged (stub naming, PLT entry sizes, Thumb bits, `SHN_ABS`, BE8); the
ObjC prototypes (audit W10). Each its own pull request, measured alone.

After the program, each only once its consumers exist: binary diffing over
callee summaries, exception-handler recovery, the techniques of #65 (switch
prover harness, SAILR idioms as r2rewrite rules, library identification,
Retypd after P9), static rewriting, deobfuscation, trace recording.

Open questions
--------------

- AGENTS.md gotcha 7 says the call-target parser rule is Dylint-enforced; the
  lint aims at deleted paths (audit T3) until GT retargets it, which is GT's
  first change, and the text stays as the rule it will be (2026-10-14).
- AGENTS.md's Validation Bar still names the `rebuild` exemption (D27), which
  ended when `rebuild` merged.

Issues
------

| Issue | State | Owner |
|-------|-------|-------|
| #47, #50 | one liveness model in r2ssa; consumers remain | F2 |
| #58 | widths fixed; pointee types open | P9 |
| #61 | 85 of 98 traps | P4, P7 |
| #63 | fixed on CI | close after review |
| #65 | slice library and switch prover landed | after the program |

Standing debt
-------------

- A reload certified as the stored value binds as a copy of the stored temporary (three census functions; D).
- Listing claims follow the demand release, valid only for the function's meaning; annotations must read the index before it (F2).
- `def_use_graph` seals a raw function to answer a listing (F2.1, in LX).
- `seal_body_proven_interface` rewrites the format parameter after the build (C1).
- Entry condition flags cannot be booleans until the specification carries a flag fact.
- `StackObjectRefusal::ParameterHomeWidthMismatch`: shown genuine or deleted.
- Address-proven formals change no test or census function: P7 proves their use or deletes them.
- Partition-first's conservatism (read closure, `CallRestore`, return carrier, call-use reads) and the semantic-kernel ADR's rewrite fold into D's ADR.
- x87 80-bit floats refuse ([floating-point](doc/adr-floating-point.md)).

Audit rows by item
------------------

Every row of the [audit](doc/reviews/2026-10-end-to-end-audit.md) has one owner.

| Item | Audit rows |
|------|------------|
| H | W53 |
| I | W1, W5, W31, W33, W34, W35, W37, W38, W39, M1, M4, M5, M6, M7, M8, M18, P12, P14, P28 |
| VC | W15, W16, W17, W18, W19, W21, M15, T7, B1, B2, B3, B4, P13, P23 |
| LS | W2, W3, W20, W22, W23, W25, W26, M2, M13 |
| M | D8 |
| LF | P18, P24 |
| L | D9, B5 |
| K | — (audit §5.4's budgets) |
| B | W13, D7 |
| P5 | M14 |
| LX | P2, P3, P4, P5, P6, P19, P20, P21, P22, P25, P29, P30, D11, D15 |
| MM | P31 |
| Q | P7, P8, P9, P10, P11, P15, P16, P17 |
| FS | W4, W6, W29, W30, W40, W41, W42, W45, D1, D2, D6, M12 |
| D | W44 |
| RF | W43, W63, D4, D14 |
| SM | P1 |
| P7 | W7, W8, W9, W10, W11, W12, W14, W24, M3, M16, D3, D10 |
| P4 | W48, D5 |
| T | W46, W47, W49, W50 |
| P8 | W32, M17 |
| P11 | W27, W28, W36 |
| SD | D13 |
| S1 | M9 |
| S2 | W60, M10, M11 |
| S3 | W52, W61, M20 |
| V7 | W54, W55, W56, W57, W58, W59, W62, M19, P32 |
| CL | W51, M21, T13 |
| GT | T1, T2, T3, T4, T5, T6, T8, T10, T12, T14, T19, T20, T21, T23 |
| G0 | T9, T11, T15, T16, T17, T18, T22 |
| BD | B6, B7, B8, B9, B10 |
| PF | P26, P27 |
| Hygiene | M22, D12, D16 |
