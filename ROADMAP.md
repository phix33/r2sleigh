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
| Equivalence (`tests/equiv`) | Does the C compute what the machine code computes? The north star. | before a residual inside the body, only the output is compared, not memory (T1's rest: `pddj` states no residual's position but `unproven-return`'s); stripped builds only, so the DWARF route is never run (T5) |
| Census (`tests/db`, every coverage, pinned and stripped function) | Did any rendering move? A structural change is byte-identical or names each moved line. | — |
| Certification (`scripts/certify_render.py`) | Does every rendering read only what it assigns, and never panic? | grades 98 of 1,492 functions, none stripped; cannot see invented arguments (T6) |
| Source-gold (`scripts/differential_truth.py`) | Are signatures what the source declared, or marked? | soundness 43% and 21% (W49); `frame_agree.py` in no gate (T21) |
| Coverage (`tests/coverage`) | How much of a binary renders; does any regress? | stale baseline; clang other than 17 ungated (T19) |
| Differential (`scripts/diff_r2.py`) | Where discovery, naming, decoding disagree with radare2, and who is right. | in CI against radare2 6.2.4 on elf, mach0 and pe, every disagreement judged and radare2-only values ratcheted; `ir iz iee i f` not yet compared (T4) |
| Dylints (`tools/dylints`) | Does the code keep the structural rules? | 77 of 79 warn-only, their count ratcheted in CI; every path filter names a live path, tested (T3) |
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
| **H** Hostile input | every read clamped to the file; `hostile-gate` in CI (887 of 887 within budget); a body walk stops at `BODY_INSTRUCTIONS` (65,536) with a named `Budget` stop and analysis refuses such a body (`BodyError::Oversized`), and the stub walk reads no section whose first exit jumps within itself (#250: maxsecW7.exe `pdd` >120 s and 4.1 GB to 1.3 s and 142 MB), only file-backed sections and no run past 16 instructions; PE import tables are walked in slot order, stopping at a slot already stated, and a name holding a control character names nothing (#249: manyimportsW7.exe 61 s and 6.3 GB to 0.8 s, virtgap.exe and 65535sects.exe 60 s to under 0.5 s); the sweep 917 of 917 within budget on `pdd` and `afl` at #252 | the open file truncated under a session kills it with SIGBUS (audit W53): read through owned bytes or a guarded map | — |
| **I** Every container fact stated | init, fini, preinit arrays and `DT_INIT`/`DT_FINI` as entries; RELRO as sealed ranges; CFI starts seed discovery; a segment with any access is mapped (`Permissions::mapped`, #248, audit W1: PE refusing at its entry 200 to 10 of 312); PE imports per address table slot with their DLL (`WriteKind::Import { library }`, `Symbol.library`) and exports by name (#249, M1: imports listed in 3 to 235 of the 263 PE files radare2 lists, 227 with its count); ELF ET_REL records at the placed section, typed (`Applies`, `Encoding::{Word, FromPlace, Typed}`), with a stub per import and a slot per GOT symbol past `.bss` and the common symbols, and CFI read through them (W5's container half: `ir` non-empty on 0 to 20 of the 22 corpus objects; bfile_o's 53 `.eh_frame` starts placed at their functions, the 53 radare2 lists); a PE mapped as its loader maps it, headers, flat low alignment, raw pointers rounded to 0x200, VirtualSize 0, entries wherever mapped, and its directories (delay-load too) read through that mapping (W35: pe px agree 238 to 255, `iS` radare2-only 7318 to 385); Mach-O's entry from one reader (W33), an object's sections where it states them, Thumb from `n_desc` and function starts, a dSYM mapping only the bytes it holds (W39's file ranges); COFF absolute records (W37), `STT_TLS` and `STB_GNU_UNIQUE`, `N_INDR` aliases unlisted | PE: TLS callbacks (M8); `ir` for a PE image; Windows API prototypes, which r2abi has none of (a cited Windows scope, next to P7); the Corkami export directory inside the header and negative ordinals (conditional). ELF: W5's rest, an ET_REL import a PC-relative or absolute record reads stated as the import's place rather than an `ImportStub` (code is claimed only from a branch or PLT record; the rendering already reads it as `extern` data); a preemptible definition's default read as proof only under a premise r2engine grants and the proof line names, as `UbFreeSource` is (a decision: shared objects and ET_REL weak symbols alike); AArch64 and ARM instruction-field encoders (CALL26, ADRP/LO12, MOVW/MOVT; three corpus objects refuse at their entry until then), i386 PIC `GOTPC`/`GOTOFF`, `SHN_X86_64_LCOMMON`, DWARF read through an object's relocations; a damaged section table falls back to program headers (M4); one `DT_SYMTAB` reader for symbols and relocations (M6); `PT_DYNAMIC` init arrays (M7); the CIE `S` flag (W31). Mach-O: arm64e threaded and signed binds (W34); dSYM base (W39). COFF: bits from the address size (W38). All: raw bytes, architecture and fat-slice selection, and container verbs that work where the machine is unmapped (M5); a posture record (nx, pic, relro, interp, static) for `i` and `il` (M18); LSDA landing pads as statements about their functions. Cost: DWARF read on demand, each DIE decoded once (P12); one section-name index (P14); tables sized exactly (P28) | `diff_r2.py` judged clean on the elf, mach0 and pe corpora in CI (GT); no corpus PE refuses at an entry radare2 maps; `ir` non-empty on every ET_REL object |

### Lift (`r2sleigh-lift`, `vendor/sleigh-config`, `r2il`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **LS** Lifted semantics are the machine's | an instruction's local branches if-converted, one predicate per block, a branch that cannot be converted poisoning every op it guards (#254, W20: `fccmp`, `frinta`, `frintn` agree with the CPU; `stxp`/`stlxp` and `cpuid`'s guarded user operations refuse whole); integer division never speculated, under a predicate dividing by one where the block does not run (W22); x86 `ud0`/`ud1`/`ud2` traps (W23: `dwarf_rust_bubble` 18 to 45 noreturn functions); `cmpxchg` on r/m8 to r/m64 run by `r2il::eval` as the SDM states, its store guarded by ZF (M13; `cmpxchg8b`/`16b` and eval past `LOCK` are left); AArch64 `casp`'s X form at `[Xn]` in either byte order (vendored, sleigh-config#13, Ghidra #9900); `ArchSpec.alignment` from the specification through libsla's `getAlignment` (W25: AArch64 4, ARM, MIPS, RISC-V 2); AArch64 LL/SC as `LoadLinked`/`StoreConditional` and `clrex` as `ClearExclusive`, run by `r2il::eval` with one thread's monitor, `stxp`/`stlxp` back with Rt2 under the store's success (M2; the load-exclusives' `SetExclusiveMonitors` vendored, its fork pull request owed); every AArch64 acquire and release stated by the vendored specification in the Arm ARM's terms (`LoadAcquire`, `LoadAcquirePC`, `StoreRelease`, after the load or before the store; `ldlar`/`stllr` keep Ghidra's LORegion `LOAcquire`), lifted to fences eval runs as no-ops and folded into the exclusives' own ordering, Relaxed without a mark, so r2dec assigns a linked load's value beside its gap (M2's rest; fork pull request owed); LS0's oracle 43 to 27 listed cases, none `wrong` beyond `fmsub_s` and `fmla_elem`, 23 acquire/release cases added | a typed atomic read-modify-write for LSE and `cas` (rendered today as a fence, a plain load and a plain store); the conditional store's success and a guarded load's value spelled beside their gaps as the linked load's is; big-endian ARM decoded as such (W26); a `globalset` aimed at another address stays out of the continued run's context, and each run's mode comes from `$t`/`$a` (W2, W3); ARM state's own 4-byte alignment, since the specification states Thumb's 2; `cmpxchg8b`/`16b` zero-extending EAX/EDX on failure in 64-bit mode (vendored); eval past `LOCK`; multi-register `tbl` and NEON user operations; conditional: a purity table for user operations so a guarded one predicates instead of refusing (`cpuid`), only if a graded function needs it; ARM32 refuses `pdd` (D32) until these and an ARM32 equivalence target land | no `Unimplemented` left in place of a branch; ARM32 decodes Thumb after a backward `blx` as radare2 does |
| **VC** The vendored core is right and cheap (D28) | `addv`; the Go cspecs; PF0 and PF1; LS0, the oracle (379 AArch64 cases an arm64 CPU ran, replayed through the trusted lift on every host) with `r2il::eval` running IEEE binary32 and binary64; resynced from Ghidra master (`ldpsw`, `ldapr`, `ldar`, `stlr`, scalar `fmadd` and the reductions' zero-fill, GP-7313's `eor3`/`bcax`/`rax1`/`xar`); W15, W17, W18 (scalar), W19 and M15 fixed, the oracle's list 99 to 43 cases; every local change on a 0verflowme fork pull request (`vendor/README.md`), and Ghidra pull requests #9893 to #9896 and issue #9897 for what master still gets wrong. Measured and not worth it (2026-10-14): inline operands in libsla's emit (+3% instructions on pumasim `afl`), reserving its op list (no change), inflating the `.sla` in Rust (+2% instructions, +20 MB). The cost (#241): libsla-sys in parallel (B1), the spec compiler at `-O3` (B2), specifications `static` (B3) and only the 7 languages the lift reads (B4): a clean release lift build 108 to 82 s on 4 cores, the SLA compile 29 to 4.6 s, `r2s` 23.11 to 18.03 MB; every fork pull request merged (the fork mains are the vendored text) | P13's lever is fewer processes per harness and one AArch64 profile (D8, M), not the decode; the unsigned scalar `fcvt*u` conversions wrap past their range where AArch64 saturates (`fcvtzu_ws`'s "wrong x0" in the oracle; next, with its fork and Ghidra pull requests); vector `frint`/`fcvt` still truncate; P23's in-repo half, `translate_pcode`'s ~4 allocations per p-code op (r2sleigh-lift, r2il) and the copies in `r2s::Source::read` and `load_instruction_bytes`; fused `fmsub`/`fmla` round twice (p-code has no fused multiply-add) | the oracle lists only stops it names (float saturation, unmodelled operations, the lift's in-instruction branches: LS); every local change names its fork pull request |
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
| **LX** Linear per function | LX1 (boundaries, obligation table, `Arch` once, sparse `call_results`, on-demand rewrite walks), LX3 (`ReachingStorage`); a literal holds no liveness segment (#243, audit P6: r2pay `init1` 1,018 to 553 MB, 12% fewer instructions, output identical); a stack address finds its evidenced container by an ordered range (#244, P2: 0pack 12.4 and 13.9% fewer instructions); an AArch64 call reads sp from the function's one `ReachingStorage`, and cycle blocks come from one SCC pass (#252, P5: gzdoom `_Load_Version_4_5` 652.6G to 50.7G instructions, 34.9 to 3.3 s, output identical) ; phi pruning asks the liveness bit matrix rather than a set built for every block (#258, P21: gzdoom 50.9G to 44.5G instructions, 6.3 to 4.8 s) | P6's rest: undefined Ram values (23% of the segments), exact sizing and one build; P2's interval index where a function's tail below the root shows. Then `Import::producers` as a dense index, not a memo (P3); one multi-storage `ReachingStorage` per function (P19, deferred: 1.6% of gzdoom's `pdd` after P5); `declarable_stack_object` once (P20); dense rename identities and block-indexed domtrees (P21); block facts keyed by `BlockId`, and `entity_keyed_map` widened to `u64` block keys and wrapped keys (D15); `liveout`, `liveness` and `promote` at their bound, and `DeadPhis`, formals, `FunctionLiveOut`, `class_values` and `ValueViews` computed once; operand iterators, not fresh `Vec`s (P22); 96-byte obligations (P25); O(1) refusal evidence and lazy trace strings (P29, P30); interior-mutability memos into the database (D11). LX4 with F2.4: recovery collects the fact pass the seal collects again (P4). LX2: D27's adapter deleted, D0 reading T's and F2's dense indexes, and the entity-keyed map debt (65 sites in 44 allowed items; r2ssa's 12 function-wide allows narrowed to statements) moved to dense indexes | `census.py exponent` at most instructions^1.05 over 300+ instruction functions; peak RSS linear in instructions |
| **MM** Memory as a linear budget ([memory-model](doc/adr-memory-model.md)) | held answers newest-only; one encoding of each operation; compact dispositions; the image mapped | MM.6 a compile-time sealed type, and the `formal_*` maps keyed by `VarId`; MM.4 the fixed cost (loader writes, unwind frames, symbol layout); MM.7 obligation identities; MM.8 the projection's interned types and value geometries; MM.9 a collect at phase boundaries; MM.3 seal-only facts (conditional); `MachineBuilder` sized from a bound (audit P31) | `c ≤ 600 B` per operation, then `≤ 300 B` |

### Engine (`r2engine`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **Q** One query database | Q0 to Q5; the reference index, renderings, machines as queries | a write that moves nothing re-runs nothing (audit P8: 18.07 to 13.52 G on a no-op write): a `Newest` entry a still-retained reader read keeps its tombstone, so the eviction rule counts retained readers, not only held ones (#211's rule, revisited; next); `aa` keys only result-ambiguous functions (P9); `afb` and `agf` from `Walked`, the listing's def-use held (P10); lazy ARM32 modes and machines (P11); one name table at open (P15); a text-only held rendering for revisits (P16); incremental discovery after a write (P17); the reference index from survey facts with one lift (P7: first `axt` 6.6x `afl`) | first `axt` within 2x `afl`; a no-op write recomputes nothing |
| **FS** One owner for function starts and bodies | one held `program::starts::Stated` query read by discovery and the walk's `is_entry`, a frame's CFI stating whether control enters it as a call leaves it (`FrameEntry`), so a `.cold` fragment begins no function by itself (#255, D1, W4: `true` `afi @ 0x3ff0` 15 blocks to 1, gnome-extensions 1327 blocks to 943, radare2 949); a function begins only in code the file holds bytes for, the rest kept with their reason (W29: crackme0x05's `fcn.00000000` gone, elf9 298 to 24); the ET_REL engine half (W5): every instruction decodes through `stated::code`, the bytes the loader leaves, and a field whose value is unstated stops the walk as `Relocated` (pngrutil_o `afl` 444 to 34, radare2's 34; 549 certified annotations from unrelocated bytes to 0) | `LC_FUNCTION_STARTS` checked before seeding (W30, which needs D6's table read: `udf` decodes); the `afb`/`afi` block-count drift (ls 0x4070: 300 against 298); conditional: fragment frames no body holds (the static-glibc `_dl_runtime_*` trampolines) seeded after discovery, if the sweep wants them; one containing-function query for the verbs and the visual mode, never an entry mid-instruction (W45, D2); overlapping instructions stated or refused typed, no absorption at misaligned offsets (W6); `Relocated` and the other entry refusals as D29 records; `/as` at a function's first instruction and without vetoes from failed bodies (W40, W41); `axt` keeps direct calls when def-use fails (W42); the survey reads dispatch tables so `afl`, `afb`, `afi`, `ax`, `axt` agree, `aflj size` as radare2 (D6); indexed table accesses as references (M12); IBT `endbr64` as a weaker start candidate where no frame states one; the remaining jump-table shapes resolve or refuse. Absorbs W's discovery exit: `afl` finds every function radare2 does | the sweep (W) and `diff_r2.py` judged clean on function sets; `afl`, `afb`, `afi`, `axt` agree on every corpus function |
| **RF** Refusals are records (D29) | sealing and r2dec refusals typed; analysis-phase refusals (Go ABI0, `Capture`, `Convention`, the walk, W5's unstated field) as `NativeRefusal` records `pdd`, `pddj` (`refused.kind`), `pddo`, `pdf`, `afb`, `afi` and `afv` print, `afi` keeping the walk's facts (audit D4: 1798 exit-1 statements to 0 over 3197 functions of 15 binaries); D32's admission, one table in `route.rs` (x86-64 and AArch64, little-endian); typed `ImageError` and `r2source` errors (D14); allocation evidence as `Option` (W63) | r2ssa's stack balance at every `ret`, so stack-pointer producers are elided or refused by name and each live-value-producer refusal names every obligation it leaves (W43: 65 of 866 static-glibc functions, down from 17%); `afi` on a sealing refusal and `agf` on a walk refusal as records; the sealing refusal's reason carried typed to `pddj`, not re-parsed from its comment | no verb exits 1 on an analysis refusal; `pddj` emits JSON for every function |
| **SM** Summaries | `CalleeReads` held; demand stops at direct callees; SM1 measured (a summary grade saves at most 3 points); SM2 ([resolved-bodies](doc/adr-resolved-bodies.md), "Summaries"): the summary measured as one held answer per body, per demand, per session, and root and summary as two grades by construction (sort's 234-function sweep: 329 resolutions, 85 bodies as both); a first seal no second preparation reads is never collected, and discovery's handed functions and the dispatch tables read the convention's seal (gzdoom `0x10070695c` `pdd` 46.5 to 41.4 G; `aa; afl` 0pack 77.9 to 43.2 G, pumasim 64.0 to 40.6 G, gzdoom 191.6 to 138.1 G; output identical) | a body resolved alone, then with its owners, sealed once and collected once (pumasim `0x23fdf0`: 28 of 36 owned bodies resolve again, 89 of 95 under `aa`; about 5 and 13% of callee preparation; next); one AArch64 preparation, literal addresses folded before recovery once their sets are shown equal to the seal's (64 of 281 resolutions in a gzdoom sample are the second; next); the summary-grade r2types run; an indirect call's arity from the common prototype of its table's entries; arity on a cold `pdd`, conditional on LP's `may-hand-on` and that indirect arity (where `aa` demands it, it closes 9 of pumasim `0x23fdf0`'s 317 floors and 3 gaps on 0pack `0x62ecf0`); callee reads' share is P4's, LX4's and F2's (46% of sort `0x3f50`, one preparation per callee already) | a sweep prepares each body once; callee reads under 10% of sort `0x3f50` `pdd`; Q3's rest and P6's remainder closed |
| **P6** One resolved body per function | P6a, P6c1, P6c2 | its remainder is SM | — |
| **P11** Names and listings | the ELF sweep judged (`diff_r2_judged.toml`); the strongest binding names an address; Sleigh spelled as radare2 writes it; fat-slice offsets; an address with its top bit set bound to its claim and written unsigned (#266: ibknoreloc64's import calls named) | x86-32 negative displacements signed (audit W27); conditional ARM aliases (W28); `entry.initN` by array slot (W36); preemptible PLT stubs named; `main` named in stripped binaries; one spelling per function; symbol flags filtered as radare2 filters them; a section-less object's stubs; conditional: a section table past the file's end, ET_REL listings (an unmapped stub's operand spelled by its name), `e_entry` 0 in a static-pie; the mach0 corpus's unjudged rows (`px` 9, `pd` 8, `iS` 8, `is` 6, `ie` 3); the upstream radare2 pull requests | every disagreement judged on elf, mach0 and pe |

### Calls, frames and types (`r2ssa` boundaries, `r2types`, `r2abi`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **P7** Call contracts | Darwin variadic tail; float results beside integer registers; caller evidence behind `aa`; the closed world under `aa`; the ObjC runtime declared as objc4 declares it, `objc_msgSend` variadic (#257, W10; radare2#26975); arity `SourceArity::{Exact, AtLeast}` apart from the result, a floor its callees own resolved under `aa` bottom-up over the call graph's components (the `Component` query SM reuses), a slot past a floor a residual (#264, W7: certification 9 invented arguments to 0 on the census binaries); `call [GOT]` through one `CallSlot` transfer when the slot is sealed, three private readers deleted, one `arguments_proven` verdict r2ssa owns (W8, D3); `pddj`'s `calls`, graded by certification; a call gap names its callee and r2ssa's typed `CallBoundaryRefusal` (#269, M3: no `UnsupportedInstruction` call gap left in the census) | the cost P7 took, measured: a cold `pdd` does not demand arity (it took 0pack 0x62ecf0 from 20.0 to 36.5 G), so a call to a callee whose arity is a floor is a residual (pumasim 0x23fdf0 74 to 1,009 call gaps: 610 floors, 330 counted off registers alone, 347 of them indirect; pumasim +2.9%, gzdoom +4.8% as it renders 1,000 more calls); next, import arity from a declaration and never from the PLT stub's body, with cited Itanium C++ ABI and runtime rows (293 of pumasim's floors are `_Znwm`, 98 of 0pack's 103 gaps are imports; under way); then an indirect call's slot named in its gap, the "`aa` may resolve it" hint once a floor states whether it has owners, demanding arity on a cold `pdd` only where the root writes past a floor (SM; measured there: where `aa` demands it, it closes 9 of pumasim `0x23fdf0`'s 317 floors, so it waits on LP's `may-hand-on` and indirect arity), a fixpoint inside a cycle, AArch64 `bl g; bl f` with g's x0 ending the count; general demangling scoped as `AtLeast(explicit)` plus variadic only (mangling states neither `this` nor the return, and legacy Rust mangling with no bare-function-type states no arity); the 41 "disagrees with its declaration" gaps, conditional; i386 stack parameters placed and a call clobbering the outgoing area (W9); a message send's fixed count from its selector's method type encoding, stated by r2image from the Mach-O ObjC metadata (W10's rest: hello-objc's six sends are residuals until then); float parameters and results recovered, no invented `(void)` (W11); the parameter prefix past an unread slot (W12); the variadic tail and the `al` input (W14); a proven syscall named (M16); noreturn facts: `__`-prefixed keys, `DW_AT_noreturn`, `rt_sigreturn`, `longjmp`, `_Unwind_Resume`, `__cxa_rethrow` (W24); one case-preserving callee identity on address and typed linkage (D10); `crc32_init`/`fill` and aarch64 gcc-O1 `mixed_touch`; the closed world's x1 (`result_register_written`) aligned with pairs (`written_on_every_return`); conditional on P7 and P9 closing: `afs`, `afts` and `afc` print the signature and the cited convention `pdd` proves (command-gap rank 4), never a second inference; the float path owning XMM0 before `body_proven_result` excludes it; printf's stack tail on x86-64; a conditional tail jump as an exit; conditional: lld's `int3` padding under the closed world, and `__libc_start_main`'s `main` as `int (*)(int, char**, char**)` | no invented or dropped argument on the certification arity check (GT); W7 to W11's repros render a refusal or the true prototype |
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
| **SD** Structuring and readability ([structure-dominator-tree](doc/adr-structure-dominator-tree.md)) | the dominator-tree structurer | inverted empty thens, merges spliced into the parent, dead reloads proved, constant branches decided before preparation (audit D13); condition chains and irreducible entries behind a BDD identity check; whether lexical ancestry equals dominance, which would retire `region_does_not_dominate_occurrence` (measured on the placement census) | no more labels than the old structurer rendered over the functions it handled (doc/adr-structure-dominator-tree.md), and no more labels or nesting than today on the census, each moved line judged |

### Surface (`r2s`, `r2s-tui`, `r2sleigh-cli`)

| Item | Done | Left | Exit |
|------|------|------|------|
| **S1** Verb table, `?`, `e` | done | `j` on every verb from typed engine payloads (audit M9); `pi`, `p8`, `pD`, `pr` as flags of `pd` and `px`, not verbs (command-gap rank 3: `pi` 236, `p8` 213 checked), and `pdc` printing `pdd` (rank 5, 79); conditional, one commit each when a user asks (rank 7 to 12, parity): `ii`, `iI`, `iD` from r2image, `CL` from DWARF, `ps` and `pv` enriching `px` (`pv` typed once T lands), `ts` and `pf.name` over P9's inferred layouts | `diff_r2.py` covers the `j` forms |
| **S2** `@@`, search, pipes ([scripting-surface](doc/adr-scripting-surface.md)) | — | address expressions, relative seek, `@@` (M10, W60); `/x`, `/`, `/w`, `/v` (M11) | — |
| **S3** Shell hygiene | a closed pipe ends the shell with SIGPIPE's status 141, as radare2's, never a panic (#256, W52) | `q <n>` exits `n`, `q!` (W61); `ax` and `axf` as radare2 has them, one error prefix (M20) | no exit status 101 on any hostile run |
| **AO** Per-instruction facts ([command-gap](doc/command-gap.md) rank 2) | — | `ao`/`aoj` from the lifted IL, not a hand-written string per opcode: size, bytes, mnemonic, the registers read and written, and the IL `pdil` prints (radare2 checks 338 calls: `ao` 311, `aoj` 27); the reads and writes are r2il's statement of each op, the verb one entry in r2s | `diff_r2.py` compares size, bytes and the register sets, each disagreement judged: radare2's ESIL can be the wrong side, and a Sleigh one is VC's, fixed upstream (D28); the semantics field is gated by the lift's own tests, never by text equality with ESIL |
| **V7** Visual state from engine facts | — | the panes ask FS's containing-function and instruction-starts queries, never guess (W59, D2's TUI half); a seek moves the decompiler pane (W56); pane switches keep the seek (W57); keys give one screen at any typing speed (W58); re-entry and signals restore the terminal (W54, W55); `scr.color` respected (W62); the xrefs pane keeps axt's caveats (M19); requests cancel (P32) | a scripted key run settles to one screen across 5 speeds |
| **V1–V6, E, A** | V1, V2 done; V3 shell completion | V1's worker asks Q; V2's `eco` themes; V3 visual hints and palette; V4 linked cursors; V5 `agf`/`agc`/`agx` through one renderer, layout off the UI thread; V6 annotation as user facts; E emulation checked against host-compiled renderings, and `ae`, `ar`, `aer`, `aes` over `r2il::eval` (command-gap rank 1: 1,063 checked calls, `ar` 711), gated by eval and E's originals, radare2 compared only on a general register after a step through flag-free code (Sleigh states each flag as a register, ESIL derives `rflags`); A the agent surface with determinism tests | — |
| **CL** `r2sleigh-cli` | — | `compile` reads its input (audit W51); `test-arch` and `run --action dec` (M21); a spawn test (T13) | — |

### Gates, CI and build

| Item | Left | Exit |
|------|------|------|
| **GT** Gates grade what they claim (D30, D31) | done: certification over `aflj`, one process per binary, `extern` skipped, red on nothing rendered, 80 binaries in CI (#246, T6: 434 functions graded, was about 25); the Dylints aimed at live paths, a test that every path filter exists, the warning count ratcheted (#247, T3: 89 to 79 lints, 19 to 12 warnings; gotcha 7's lint fires). the radare2 differential in CI against a pinned 6.2.4 over elf, mach0 and pe, values paired by column, radare2-only values ratcheted, every disagreement judged (#261, T4: 111 judgments); equivalence grades a residual trap on the output and memory it reached, its baseline naming each record's owner and site (#267, T1, T20: 4 to 4,906 of 4,906 vectors compared, no record moved); the arity check on `pddj`'s `calls` (#264). Left: the full-corpus certification tier (every function) beside the per-push one; a pass-level differential: `r2il::eval` runs a function before and after each rewriting pass (optimiser, promotion, the rewrite import) over random inputs in the test suite, so a wrong rewrite fails at its pass, not at equivalence; memory before a residual inside the body, which needs `pddj` to state each residual's position (T1's rest); a DWARF route dimension (T5); `ir iz iee i f` in the differential (T4's rest); a ratchet holding calls graded beside invented and dropped; a `slow` record whose status follows host load (review.c `fact` at clang-O2 on aarch64 read `equal` at #273 once 3 vectors the original overran under qemu were dropped): vectors dropped and the budget decided by a count the host cannot move, such as qemu's `-icount` (next); conditional: the runtime's trap handler made async-signal-safe (`backtrace`, `fflush`), only if a graded program starts threads before `main` (a deadlock would grade `slow`, which the ratchet reports); certification states a read of a variable a gap defines; Kani, mutants and machete in CI, tiered (T2); `frame_agree.py` gated as a ratchet until P4 (T21); coverage measures a given binary and pins its clang cells (T19); `census.py`'s CPU fit and size axis (T23); explicit skips on macOS (T10); a `px` golden (T12); doctests compile (T14); behaviour tests for `arrays.rs`, `text.rs`, `expressions.rs` (T8) | every confirmed audit row that a gate could have caught is caught by one |
| **G0** Gates real | a timing verdict where the base refuses and the head renders; tests on `[profile.ci]` (audit T15); a nextest timeout (T16); the Dylint lock committed and its tools pinned (T17); per-allocator feature sets in Clippy and tests (T9); `unittest discover` for the harness tests with named exclusions; `SelfTestSuite` and `PipelineTests` stay removed (T11, T18); rendered C in shard artifacts (T22) | — |
| **W** Real-binary sweep gate ([sweep](doc/reviews/2026-10-real-binary-sweep.md)) | coreutils and zlib with DWARF as a CI gate against radare2, objdump and DWARF; its discovery exits are FS's | the sweep runs in CI |
| **BD** Build cost | done: r2engine's tests one binary (#245, B7: 95.5 to 14.4 s user, 1.7 GB to 85 MB, the same 405 tests); the vendored crates' build cost (B1 to B4) is VC's. Left: an `iter` profile (B6); per-processor spec units (B8); thin LTO or `dist` in the README (B9); unused dependencies (B10) | clean release build critical path under 4 minutes on a quiet machine |
| **PF** Performance foundation | done: PF0 to PF4. Left: the purge delay (D26, the maintainer's: audit P26); C++ heap reported beside the Rust heap peak (P27); one arena per function, with F2 | — |
| Hygiene | dead plumbing deleted (`reg_type_hints`, `merge_type_hint`, half of `r2il::allocation`, `memory_mirrored_carriers`, `register_identity_census`; audit D12), and `PreparedFunctionFacts::string_literal_for_value`, never filled; `samply_collapse.py` keeps the impl type (D16); README, BUILDING, `command-gap.md` and `tests/equiv/README.md` say what the code does (M22); `long_comments` falls at each item's exit; "where this stands" generated from CI artifacts; a file-length ratchet; pinned containers for gate results independent of the runner; macOS arm64 equivalence | — |

Order
-----

The dependency path; nothing jumps it. Items on different crates run beside
each other, each on its own branch and stacked (AGENTS.md).

1. **VC, the vendored core first** (done, #241): every crate in `vendor/` is under every
   view, so its wrong output and its cost go before anything that reads it.
   LS0's oracle, then the specification fixes (audit W15 to W19, W21, M15),
   then its cost (B1 to B4, P13, P23); each lands upstream (VC row).
   VC's moved renderings are graded by LS0 and judged line by line in the
   census.
2. **Measured fixes** that move no output, one PR each, any time: liveness
   skips constants (audit P6, #243), the span range (P2, #244), B7 (#245),
   done; the no-op write (P8) needs Q's eviction rule rethought, so it is Q's.
3. **GT, the gates the next steps are graded by** (T6 #246 and T3 #247 done; T4
   and T1 under way), before any other baseline
   is blessed again: the Dylints at live paths (T3), `diff_r2.py` in CI (T4,
   grades I and FS), certification over `aflj` with the arity check as a
   ratchet (T6, grades P7), state compared at the trap (T1, grades LS and
   P7). The measured fixes that move output are done: `ud2` (W23, #254),
   the ObjC rows (W10, #257), the broken pipe (W52, #256).
4. **I**: container facts, the inputs every view reads; easiest to verify
   (container in, statement out). W1 (#248) and M1 (#249) done, W5's x86-64 half (#259); its AArch64 and ARM field encoders are left.
   W1 exposed a hostile walk with no bound, closed by H's body budget (#250).
5. **FS** and **RF**: one owner for starts and bodies (#255 done), every
   refusal a record (RF under way).
6. **LS**'s rest: W20, W22, W23, M13 and W25 done (#254), M2 and its ordering
   done; W26, the Thumb context (W2, W3) and a typed atomic RMW left. Then
   **AO**, the first surface item, because it is a gate: each instruction's
   register reads and writes diffed against radare2 find lift and spec defects.
7. **P7**, with T's one declaration fact (W46, W47): invented arguments are an
   AGENTS blocker and the most common wrong C left.
8. **The cost path**: LX's AArch64 quadratic (P5, #252) and P21's liveness half (#258) done, its dense rename identities and domtrees left (LX);
   callee preparation is now the largest cost (gzdoom: `recover_interface`
   36% of `pdd`), so SM (P1) after P7's components, F2.1 and F2.2, LX4 with F2.4, F2.5, T's dense indexes, LX2, MM;
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
ObjC prototypes (audit W10, radare2#26975 open). Each its own pull request, measured alone.

After the program, each only once its consumers exist: binary diffing over
callee summaries, exception-handler recovery, the techniques of #65 (switch
prover harness, SAILR idioms as r2rewrite rules, library identification,
Retypd after P9), static rewriting, deobfuscation, trace recording.

Not taken (command-gap sections 2 and 3, each against a rule): shell escapes and
file-system verbs (`!`, `rm`, `o`, `prj`), analysis triggers and hand-made
functions (`aa`, `af+`; discovery owns them), zignatures (`z`; a name- or
signature-owned summary), `tk` (a stringly store), hints (`ah`; a second owner
for a derived fact, unless it returns as an assumed scope), the assembler
(`pa`, `wa`), custom graphs (`agg`), `ab` (a flag on `afb`) and `as` (debugger
work). The debugger is [debugger](doc/debugger.md)'s design; D, which it
waited for, has merged (#122).

Open questions
--------------

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
- r2dec names a Sleigh temporary by its unique-space offset (`tmp_24c00_1`), so any specification edit renames temporaries across the census with no change in meaning (VC, 2026-10-14): a name should follow the value's role, not an allocator's offset (SD).
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
