# r2s end-to-end audit (2026-10-14, `toolchain-1.99` at 31dedc12)

Nineteen probes (8 correctness `c-*`, 6 performance `p-*`, 5 round-two `r2-*`), every finding adversarially verified. IDs (W correctness, M missing, D design, P performance, B build, T tests) are what [ROADMAP.md](../../ROADMAP.md) cites; each row there owns the rows it lists.
The probe artifacts (flamegraphs, logs, probe-built fixtures under `$P`, `$A`, `$E` and the other `$X` roots, the `<audit>` tree) were not retained: a repro naming one rebuilds it from the probe's description, and the radare2 test bins sit at `../radare2/test/bins`.

## 1. Executive summary

1. **State:** stable and deterministic. ~6,000 hostile and fuzzed runs gave one real panic (EPIPE); every rerun, call-order, session-vs-fresh and Mac-vs-Linux comparison was byte-identical. pdd renders 94% of `ls` and 79% of static glibc; the equivalence gate has 678/756 equal and 0 `differs`. The wrong output is at three seams: container facts, the vendored AArch64 Sleigh semantics, and call-boundary arity. After verifier correction nothing is `critical`.
2. **Problem 1:** PE sections with EXECUTE but no READ read as "nothing mapped" (174–200 of ~275 corpus PEs), and the PE import/export directories are never stated (W1, M1).
3. **Problem 2:** AArch64 lift semantics are wrong and render confident C: W-form sign-extending loads, `ldpsw`, W-destination LSE/CAS, FP rounding as `TRUNC`, `fccmp`/`casp`; LL/SC is never mapped (W15–W20, M2).
4. **Problem 3:** invented call arguments and arity: callee floors, unresolved `call [GOT]`, unplaced i386 cdecl prototypes, a 2-argument `objc_msgSend`, `(void)` FP prototypes (W7–W11).
5. **Problem 4:** ET_REL objects are analysed unrelocated, with call-to-next printed "(certified)", pdd dropping calls with "0 refused", and phantom FDE functions (W5).
6. **Problem 5:** control-flow ownership. Tail jumps and fall-throughs absorb functions stated only by CFI (W4); Thumb code after a backward `blx` decodes as ARM (W2); overlapping instructions end in a shell error (W6).
7. **Perf 1–2:** a cold pdd fully prepares every direct callee, 47–84% of pdd (P1, ROADMAP SM). Liveness treats constants as live from entry, so r2pay `init1` reaches 1.02 GB RSS; skipping them measured 553 MB with identical output (P6).
8. **Perf 3–5:** AArch64 `reaching_abi_value_before` is quadratic (gzdoom: 39.5M retired per instruction, 51 s; P5). The span scan in `object_for_address_value` is 25–32% of the big 0pack pdds; a patch measured −12/−13.5% instructions (P2). The first `axt` builds a 133G-instruction index (P7). Build: serial libsla-sys plus an -O0 spec compiler, and ~5 MB of duplicated or unreachable SLAs (B1–B4).
9. **Gates missed most of this:** residual-trap records compare no state (T1); the Dylint gate warns only and ≥12 of its lints are dead (T3); diff_r2 is not in CI and is red (T4); certify grades 98 of 1,492 functions (T6).
10. **Counts:** 228 filed, 224 confirmed (many with corrections), 0 disputed, 4 refuted; merged into 166 rows (Appendix B).

## 2. Correctness — wrong / crash / hang / nondeterministic

**Rules used throughout.**
- **Severity** is the verifier-corrected value. When two verifiers disagreed, the lower one is used and the disagreement is noted (`fin:` gives the finder's value when it differs).
- **Status** is one of `confirmed` (every verifier agreed and the claim is unchanged), `confirmed (corrected)` (the headline holds but a verifier changed the cause, scope or numbers), or `partially-confirmed` (a sub-claim was refuted). The data has no DISPUTED status. Refuted findings are in §7.
- **Merged rows** list every probe that reported the same root cause. Counts in a row come from the verifier where one re-measured; otherwise they are marked "finder's count".

Repro: the table shows a short command. The full verbatim repro for every row is in **Appendix A**, under the same ID.

### 2.1 Table

| ID | Sev | Title | Component | Owner | Repro (short; full in App. A) | Status / probes |
|---|---|---|---|---|---|---|
| W1 | high (fin: critical) | PE sections with EXECUTE or WRITE but no READ are treated as unmapped; pd/pdd/afl/w refuse at the entry of 174–200 corpus PEs | pd, pdd, pdf, afi, afb, w on PE | r2image (`Image::read` gate, `section_permissions`/`map_permissions`) | `target/release/r2s -qc 'iS;pd 2' ../radare2/test/bins/pe/normal64.exe` | confirmed (corrected) — c-info, c-analysis, c-robustness, c-missing |
| W2 | high (fin: critical) | Thumb code after a backward `blx` is decoded and lifted as ARM; pd, afb, pdil, pdf and pdd each go wrong in different ways; a bogus `fcn.00a71c42` appears | pd, afb, pdil, pdf, pdd on ARM32 | r2sleigh-lift (`resume`/Continuation keeps the `globalset` aimed at the target) + r2engine (mode from `$t`/`$a`) | `target/release/r2s -qc 'pd 6 @ 0x46e; ?e --fresh--; pd 3 @ 0x476' $E/special-sym-with-dot.bin` | confirmed (corrected) — c-listing |
| W3 | low | A derived ARM mode at a `blx` target overrides the Thumb mode of all code above it (`thumb_at` half-open range); pdf shows ARM text carrying Thumb semantics | pd, afb, pdf | r2engine `View::thumb_at` | patched libarm.so, `s 0x2a338; wx fff7fcef; pd 3 @ 0x2a338` | confirmed (corrected) — c-listing |
| W4 | high | A tail jump or fall-through into a function start stated only by CFI absorbs that function: shared blocks in afb/afi, pdd renders another function's code, axt undercounts | afb, afi, pdf, pdd, axt | r2engine (`is_entry`/`definitions()` ≠ `stated_functions()`) | `target/release/r2s -qc 'afb @ 0x3ff0' ../radare2/test/bins/elf/true` | confirmed (corrected) — c-listing, c-analysis |
| W5 | high | ELF relocatable objects are analysed unrelocated: `ir` is empty (16/16 corpus .o/.ko), calls decode as call-to-next and are printed "(certified)", pdd drops calls with "0 refused", and unrelocated `.eh_frame` pc_begin values become phantom functions (bfile_o 53/106) | ir, pdf, pdd, afl on ET_REL | r2image (loader returns no records for `ObjectKind::Relocatable`; unwind uses `sh_addr` 0) + r2engine (certifies loader-written instruction bytes) | `target/release/r2s -qc 'ir; pdf; pdd' ../radare2/test/bins/elf/x86_64-common-code.o` | confirmed — c-architecture, c-info, c-analysis, c-listing |
| W6 | high | x86 overlapping instructions (glibc `je +1; lock cmpxchg`) and bodies that absorb foreign code at misaligned offsets produce `InvalidFunctionImage`. pdd, pddj, afi, afv and pddo exit 1 with a bare error, and the second such line ends a newline script | pdd, pddj, afi, afv, pddo | r2engine body walk (`into_body`) + refusal policy (`NativeRefusal::Capture`); r2source contract | `target/release/r2s -qc 'aa; pddj @ 0x0041be10' ../radare2/test/bins/elf/static-glibc-2.27` | confirmed (corrected: not a panic) — c-robustness, r2-whole-program |
| W7 | high | Call-site arity is filled from registers the caller wrote. Callees whose arity is only a floor get invented arguments, so one function carries two prototypes in one session (e.g. `shape_bool_caller` declared with 3 parameters, defined with 2; `crc32_init(0x402060, 61)`) | pdd | r2ssa (`convention_call_boundary`, `CalleeStatement`, `reads_past_parameters`) + r2engine (callee resolved alone) | `target/release/r2s -qc 'aa; pdd @ main' tests/coverage/pinned/shapes_gcc_x64_O0` | confirmed (corrected) — c-decompiler |
| W8 | high | `call [GOT slot]` (-fno-plt, Mach-O non-lazy pointers) is never resolved to its import. It renders as a raw pointer call whose arity comes from whichever registers are live (strrchr called with 4 then 2 arguments in one function). ls: 513 sites, 30 contradict the prototype. pd says "arguments unproven" while pdd renders the arguments | pdd, pddj | r2engine (`body::transfer_of` records no slot call; identity never reaches `CalleeResolutionFacts`) + r2dec (`described \|\| own_interface` relaxation) | `target/release/r2s -qc 'aa; pdd @ 0x6ee0' ../radare2/test/bins/elf/ls` | confirmed (corrected) — r2-whole-program, r2-render-corpora |
| W9 | high | i386 cdecl: r2abi prototypes are never placed (Placement only knows registers), so they are dropped silently. Promoted stack slots carry values across calls, and those values become extra arguments (`printf(0x804866b, 0x8048668, frame+36)`) | pdd, afi, afv on i386 | r2engine `declared::Placement` + r2ssa (`reaching_stack_slot_value` promoted path) | `target/release/r2s -qc 'pdf @ sym.parell;pdd parell' ../radare2/test/bins/elf/crackme0x05` | confirmed (corrected) — c-missing, r2-render-corpora, r2-whole-program |
| W10 | high | r2abi ships radare2's wrong ObjC runtime prototypes: `objc_msgSend(void*, char*)` is not variadic, so set argument registers are dropped silently; `objc_storeStrong(void*, int)` truncates `id` to int32 | pdd on ObjC | r2abi `data/types.sdb.txt:2990-3006` (and upstream radare2) | `target/release/r2s -qc 'pd 3 @ 0x100000e75; aa; pdd @ main' ../radare2/test/bins/mach0/hello-objc` | confirmed — r2-render-corpora |
| W11 | high | Without DWARF, floating-point parameters and results are not recovered. Calls render as `void tan(void); tan();`; `tanf(float)` is cut to `tanf(void)`; x86 `_scale` becomes `void _scale(void){return;}` | pdd on AArch64 and x86-64 | r2ssa `recover_interface` (only `argument_slots`) + r2dec `call_expr` (invents `(void)`) + r2abi (tgmath `arithmetic` rows) | `target/release/r2s -qc 'aa;pdd @ sym._use_tan' $P/probe/libm_arm` | confirmed (corrected) — r2-aarch64 |
| W12 | medium | The parameter prefix stops at the first unread slot. Reads of later slots become residuals and the signature says `(void)` or too few parameters (operator new, ObjC setters, Gui ctor; 63/801 functions) | pdd, afv, afi | r2ssa `recover_interface.rs` `in_order`/`map_while` (by design, test-pinned) | `target/release/r2s -qc 'pdf @ 0x1258; pdd @ 0x1258' ../radare2/test/bins/elf/demangle-test-cpp` | confirmed (known ROADMAP D follow-up) — r2-render-corpora, r2-aarch64 |
| W13 | medium (fin: high) | Residual traps sit in bits or lanes the declared result never reads. rv_O0g `sext` and float_compares `floor_at` raise SIGTRAP on every input | pdd | r2ssa (seal-time `release_undemanded_bytes` uses `DemandedBytes::of`, not `of_returning`; no lane-value release) | `cd $A && venv/bin/python ... sext(5)` (App. A) | confirmed (corrected) — c-decompiler |
| W14 | medium | A SysV variadic callee is recovered as 6 fixed parameters. It traps on entry (the `al`-guarded save area), and callers pass stale registers or residuals | pdd | r2ssa `recover_interface` (no variadic tail); LanguageProfile (`al` input) | `target/release/r2s -qc 'aa; pdd @ sym.vfold' tests/coverage/pinned/shapes_gcc_x64_O0` | confirmed (known P7) — c-decompiler |
| W15 | high | AArch64 W-form sign-extending loads are wrong: `ldursb`/`ldtrsb` W zero-extend the byte, and every other `ldrsb`/`ldrsh`/`ldursh` W form sign-extends into all 64 bits. Renders `return (uint64_t)(uint8_t)p[-1]` | pdd, pdil | vendored `AARCH64base.sinc:3249-3415` (read by r2sleigh-lift) | `target/release/r2s -qc 'aa;pdil @ sym._prev_char;pdd @ sym._prev_char' $P/probe/probe2` | confirmed (corrected) — r2-aarch64 |
| W16 | high | `ldpsw` loads its second word from base+8 instead of base+4 | pdd, pdil | vendored `AARCH64base.sinc:3052` (upstream Ghidra already fixed it) | `target/release/r2s -qc 'aa;pdil @ sym._pairsum;pdd @ sym._pairsum' $P/probe/probe_nolse` | confirmed (corrected: resync, don't upstream) — r2-aarch64 |
| W17 | high | W/H/B-destination LSE atomics, CAS and `ldapr` write only `w`, leaving x[63:32] stale (cas32 leaks the caller's upper bits). `ldsmin`/`ldsmax` H/B compare a zero-extended value as 32-bit signed. 22 sites | pdd, pdil | vendored `AARCH64base.sinc` (`aa_Wt =`/`aa_Ws =` writes, `ls_opc_smin`) | `target/release/r2s -qc 'aa;pdil @ sym._cas32;pdd @ sym._cas32' $P/probe/probe_nolse` | confirmed (corrected) — r2-aarch64 |
| W18 | high | FP rounding is lifted as `TRUNC`: `frint*` writes integer bits into a register that should hold FP, `fcvt{a,m,n,p}s` truncate, `fcvtzu` is signed, `fmax`/`fmin` ignore NaN and ±0, `fmaxnm` equals `fmax`, `fminnm` is an opaque op. pdd renders `lround` as `(int64_t)x` | pdd, pdil | vendored `AARCH64neon.sinc` (~6565, 7037-7055, 10764) | `target/release/r2s -qc 'aa;pdil @ sym._rnd;pdd @ sym._rnd;...' $P/probe/probe_nolse` | confirmed (corrected: `FLOAT_ROUND` is not ties-away) — r2-aarch64 |
| W19 | medium | `stlxp` (64-bit pair) stores its second register at addr+4 instead of addr+8. `stxp` is correct | pdil, pdd | vendored `AARCH64base.sinc:5726` | `a64harness ... ldaxp_stlxp` | confirmed (corrected: only stlxp) — r2-aarch64 |
| W20 | high (fin: medium; verifier raised) | `fccmp` and `casp` lift with `Unimplemented` in place of the outer branch, and the guarded ops then run unconditionally. pdd for `x>3 && a<b` drops `x>3` and all parameters. 454 fccmp in gzdoom | pdd, pdil | r2sleigh-lift `internal_control.rs` (nested branches handled outer-first; line 93) | `target/release/r2s -qc 'aa;pdil @ sym._fl;pdd @ sym._fl' $P/probe/probe2` | confirmed (corrected cause) — r2-aarch64 |
| W21 | medium | Scalar `fmadd`/`fmsub` (D/S/H, 6 constructors) leave bytes 8..31 of the vector register stale (no `zext_z*`) | pdil | vendored `AARCH64neon.sinc` 7274-7299, 9561-9587 | `a64harness ... fmadd_d` | confirmed — r2-aarch64 |
| W22 | medium | Integer division counts as speculatable, so the `b==0 ? 0 : a/b` guard is lifted as an unconditional division followed by a Select. The C divides before the zero test | pdd, pdil | r2il `R2ILOp::is_speculatable_value` (opcode.rs:740) + r2sleigh-lift `internal_control` | `target/release/r2s -qc 'aa;pdil @ sym._sdv;pdd @ sym._sdv' $P/probe/probe_nolse` | confirmed — r2-aarch64 |
| W23 | medium (fin: high) | `ud2` (`invalidInstructionException`) is treated as an unresolved indirect branch, so Rust panic paths never end. All 227/227 ud2 are affected; `core::panicking::panic` is not proven noreturn | pdf, pdd, afi | r2sleigh-lift `disasm/user_operation.rs` NAMED table (missing x86 row) | `target/release/r2s -qc 'pdf @ 0x25930' ../radare2/test/bins/elf/dwarf_rust_bubble` | confirmed (corrected: fix is one table row; 18→45 noreturn) — r2-render-corpora |
| W24 | medium | Noreturn facts are missing. r2abi keys are `assert_fail`/`cxa_throw` without the `__` prefix. `DW_AT_noreturn` on definitions is never consulted (15/21 missed in Rust bubble). `rt_sigreturn` is not marked noreturn. `longjmp`, `_Unwind_Resume` and `__cxa_rethrow` have no rows. Bodies run on into padding | afb, pdf, pdd, afi | r2abi data + r2engine `native::declared_return` (imports only) | `target/release/r2s -qc 'pdf @ sym.ZopfliCalculateBitLengths; afb @ ...' $E/pigz` | confirmed (corrected) — c-listing, r2-render-corpora, c-analysis |
| W25 | medium | `ArchSpec.alignment` is never filled (always 1), so the listing and the stub walk step 1 byte past undecodable ARM, AArch64 and RISC-V words. libverifyPass's `memcpy` stub is left unnamed | pd, stub naming | r2sleigh-lift `sleigh.rs::extract_architecture` (r2il field) | `target/release/r2s -qc 'pd 6 @ 0x112fc' $E/arm1.bin` | confirmed — c-listing |
| W26 | medium | Big-endian ARM (BE32, no EF_ARM_BE8) is decoded as little-endian, and pdd renders executable C for `bx lr` | pd, afl, pdil, pdd | r2image (code byte order) → r2engine machine selection → r2sleigh-lift (no `ARM:BE:32`) | `target/release/r2s -qc 'i~endian; afl; pd 6 @ 0x8000034' $E/arm-thumb-movw-be.o` | confirmed (corrected) — c-listing |
| W27 | low | x86-32 negative disp32 is spelled unsigned (`[ebx + 0xfffffffc]`), and `number_spans` reads it as an address | pd, pdf | r2sleigh-lift `disasm/syntax.rs` (spec uses `imm32`) | `target/release/r2s -qc 'pd 2 @ 0x8048405' $E/crackme0x05` | confirmed — c-listing |
| W28 | low | ARM alias spelling skips conditional forms (`cpyeq`, `ldmiaeq sp!`). radare2 also renames `cs`/`cc` to `hs`/`lo` | pd | r2sleigh-lift `syntax.rs::arm_alias` | `target/release/r2s -qc 'pd 1 @ 0x26568' $E/arm1.bin` | confirmed — c-listing |
| W29 | medium | Unmapped or garbage addresses become 0-block functions: a dead `call 0x0` in frame_dummy (23 corpus files), init_array words read from a corrupt `sh_size` (fuzzed elf9: 481 init/fini rows, 191 at 0 blocks), ARM misdecodes | afl, iee, afi | r2engine discovery (`offer` has no `holds_code` check) + r2image `initialisers` (no `executable()` gate or segment bound) | `target/release/r2s -qc 'afl~0x00000000; afi 0' ../radare2/test/bins/elf/crackme0x05` | confirmed (corrected: direct `call 0x0`, not the GOT) — c-listing, c-analysis, c-missing, c-info |
| W30 | low | Mach-O `LC_FUNCTION_STARTS` entries that are jump tables become 4-byte `udf` functions (107 instances in 12 arm64 binaries) | afl | r2engine (`stated_functions` seeds `Declared` without checks) | `target/release/r2s -qc 'pd 4 @ 0x1000061ac; afb 0x1000061ac' ../radare2/test/bins/mach0/ls-m1` | confirmed (corrected owner) — c-analysis |
| W31 | medium | The glibc signal-frame FDE (pc one byte before `__restore_rt`) becomes a function decoded at the wrong boundary, and `/as` prints `?` for rt_sigreturn. Even started at the right address the walk falls through, because rt_sigreturn is not marked noreturn | afl, afb, /as | r2image (drops the CIE "S" flag) + r2engine `stated_functions` + r2abi `Syscalls::returns` | `target/release/r2s -qc 'pdf 0x45a95f' ../radare2/test/bins/elf/static-glibc-2.27` | confirmed (corrected) — c-analysis |
| W32 | medium (fin: high) | The `iz` floor is miscalibrated in both directions: S_CSTRING_LITERALS strings are dropped (ired 3 vs 46), a 1-byte "string" is read out of a `.got.plt` pointer, and `.stabstr`/`__DWARF` count as program strings | iz, f str.* | r2engine `naming::name_strings`/`chance_run_length` + r2image `roles` (debug/discardable) | `target/release/r2s -qc iz ../radare2/test/bins/mach0/ired` | confirmed (corrected counts) — c-info |
| W33 | medium (fin: high) | Mach-O: the `LC_MAIN` entryoff is probed as a vaddr, so entry0 is wrong (BatteryLife.arm_32.0). The duplicate `CMain` entry keeps the Thumb bit, giving `main` at an odd address (9 ARMv7 files) | ie, i, f, afl | r2image `Image::open` entry derivation (two owners) | `target/release/r2s -qc 'ie;s entry0;pd 3' ../radare2/test/bins/mach0/BatteryLife.arm_32.0` | confirmed (corrected) — c-info |
| W34 | medium | arm64e binds are lost. Threaded binds are unnamed (empty ordinal table), and signed chained binds are `Applies::Unknown`, so they get no `reloc.*` flags and `__auth_stubs` are not recognised as stubs: `uint64_t free(void)` renders, and coverage counts 84 stubs as rendered | ir, f, pdd | r2image `loader/macho.rs` (`threaded`, `SignedBind` → `WriteKind::Unknown`) | `target/release/r2s -qc 'ir' ../radare2/test/bins/mach0/ls-m1` | confirmed (corrected cause) — c-info, r2-whole-program |
| W35 | medium | PE `PointerToRawData` is not rounded down to 0x200, so shifted bytes are mapped (3 Corkami files). radare2 is also wrong on weirdsord | iS, ie, mapping | r2image PE file range | `target/release/r2s -qc 'iS;ie' ../radare2/test/bins/pe/unaligned_sec_paddr.exe` | confirmed — c-info |
| W36 | low | `entry.initN`/`finiN` are numbered by target address, not by array slot (19 binaries) | f, afl, iee | r2engine `naming` (use `stated_at`) | `target/release/r2s -qc 'iee;f~entry.' $B/gnome-extensions` | confirmed — c-info |
| W37 | low | COFF absolute symbols are listed at vaddr 0 (display only) | is | r2image `read_symbol` | `target/release/r2s -qc 'is' ../radare2/test/bins/pe/crackme0x00.exe` | confirmed — c-info |
| W38 | medium (fin: low) | COFF AMD64 objects report `bits 32`. This also selects the i386 cdecl convention and a 4-byte pointer width | i, analysis of COFF | r2image `map_architecture` (`is_64()` is false for COFF) | `target/release/r2s -qc 'i' ../radare2/test/bins/coff/coff.obj` | confirmed (corrected) — c-info, c-missing |
| W39 | low | Mach-O dSYM: baddr is derived from `__LINKEDIT`, and sections at offset 0 are file-backed with their size clamped (iz scans header bytes) | i, iS, iz | r2image `held`/`base_address` | `target/release/r2s -qc 'i~baddr;iS' ../radare2/test/bins/mach0/core.dwarf` | confirmed — c-info |
| W40 | medium | `/as` never reports a supervisor call that is a function's first instruction (16 libnx wrappers missed) | /as, supervisor map | r2engine `body::Walk::start` | `target/release/r2s -qc '/as' ../radare2/test/bins/elf/switch-hello-world.elf` | confirmed — c-analysis |
| W41 | medium | `/as`: bodies that fail to prepare (InvalidFunctionImage) veto the number other bodies prove, so `0x44a235` (munmap) shows `?` | /as | r2engine `requests::syscalls` merge | `target/release/r2s -qc '/as' ../radare2/test/bins/elf/static-glibc-2.27` | confirmed (corrected: vetoes are 0x41a870, 0x490220) — c-analysis |
| W42 | medium | `axt` drops every reference in a body whose def-use failed, direct calls included (0pack: 60 "unread"; `call oid_to_string` at 0x62f5ab is missed) | axt, ax | r2engine `requests::claimed_by` (`Unread::NoSsa`) + r2ssa `def_use_graph` | `target/release/r2s -qc 'axt 0x58e3d0' ../radare2/test/bins/elf/0pack` | confirmed — p-scaling |
| W43 | low (fin: medium) | A live-value-producer obligation left unaccounted at `ret` refuses the whole function: 17% of static glibc, 11% of libc-2.32, 4% of ls | pdd, pddj | r2ssa (return-boundary coherence at `ret`) + r2dec (no fate recorded) | `R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'aa; pddj @ 0x0044ba80' ...static-glibc-2.27` | confirmed (corrected: not a perf issue) — p-scaling, r2-whole-program |
| W44 | medium | An unnamed function whose entry is a loop header is named `fcn_ffffffffffffffff`, which disagrees with its callers, afl and pddj `name` | pdd, pddj | r2dec `render` (uses `root()` instead of `entry()`) | `target/release/r2s -qc 'pdd @ 0x11b0' tests/fixtures/rv_O0g` | confirmed — c-robustness |
| W45 | medium | Address→function resolution has two policies. The verbs treat any address as an entry, including mid-instruction (`0x11aa` → `fcn_11aa`). Visual `containing_entry` snaps to the holder but invents `fcn_<seek>` at padding | pdd, pdf, afi, afb, V | r2engine (one containing-function query); delete `r2s visual.rs::containing_entry` | `target/release/r2s -qc 'pdf @ 0x11aa;pdd @ 0x11aa' tests/fixtures/rv_O0g` | confirmed — c-robustness, r2-tui |
| W46 | medium | Signature views disagree. afv/afi spell `arg1..` while pdd uses `arg0..`. Struct pointers, signedness and DWARF types are dropped in pdd. Caller declarations differ from callee definitions (41/234). Import stubs show carrier types in afv/afi while the pdd extern carries the r2abi prototype. frame_agree: 0/582 offsets | afv, afi, pdd, pddj | r2types (one parameter declaration fact) — r2dec re-admits types itself; r2s and r2dec invent fallback names (~15 sites) | `target/release/r2s -qc 'afv @ 0x8dac0; pdd @ 0x8dac0' ../radare2/test/bins/elf/libstdc++.so.6` | confirmed (corrected) — c-decompiler, r2-render-corpora, r2-equiv-ci, r2-whole-program |
| W47 | medium | pdd/pddj declare an unproven return with no mark, while afi marks it `/* unproven */`. A stripped double result is declared `uint64_t` even though r2ssa recorded xmm0 as a competing carrier | pdd, pddj | r2types `ReturnTypeFact::unproven` (falls back to RAX) | `target/release/r2s -qc 'afi @ sym._ZN7MyClassC1Ev; pdd @ ...' ../radare2/test/bins/elf/ClassCpp.out` | confirmed (corrected) — r2-render-corpora |
| W48 | low | A stack protector reached through a `je ok; jmp fail` trampoline is not decided (C++ -O0 with EH cleanup) | pdd | r2ssa `stack_protector::check` | `target/release/r2s -qc 'pd 4 @ 0x131f; pdd @ main' ../radare2/test/bins/elf/ClassCpp.out` | confirmed (corrected: honest residual) — r2-render-corpora |
| W49 | medium | Stripped type inference states confident wrong types: an int narrowed to `uint8_t`, a void function claimed `uint32_t`, a double pointee typed as an integer. differential_truth soundness is 43% (review) and 21% (branchy) | pdd, afv | r2ssa (width from demanded bytes; spills not counted as reads) + r2types (float kind not propagated) | `target/release/r2s -qc 'aa; afv @ 0x146d; pdd @ 0x146d' tests/fixtures/rv_O0g_stripped` | confirmed (corrected) — r2-render-corpora, r2-equiv-ci |
| W50 | medium | Debug info costs an equal: with DWARF, `sext`'s `int8_t` parameter turns EDI bits 8..31 into a residual (gcc-O0, clang-O2). There are 14 improvements and 2 regressions over 384 keys | pdd with DWARF | r2abi (narrow-argument extension row) + r2engine `declared/graph.rs` + r2ssa (demanded bits) | `gcc -g ... review.c ...; r2s -qc "s 0x$A; pdd"` (App. A) | confirmed (corrected) — r2-equiv-ci |
| W51 | medium | `r2sleigh compile` never reads its input. It picks a hard-coded test spec by substring-matching the filename (`media` → `ia` → x86) and exits 0, even for a missing `arm.slaspec` | r2sleigh-cli compile | r2sleigh-cli `cmd_compile` (r2sleigh-lift test builders exposed) | `$C compile media.slaspec -o comp_media.r2il` | confirmed — r2-equiv-ci |
| W52 | medium (fin: high) | Broken pipe panics: `r2s ... \| head` exits 101 | every verb with output beyond 64 KiB | r2s `main.rs:85,111,168` | `RUST_BACKTRACE=1 target/release/r2s -qc izz ../radare2/test/bins/elf/bash` piped to `head -1` | confirmed — c-robustness |
| W53 | medium | Truncating the open binary kills the session with SIGBUS; radare2 reads the cut bytes as 0xff | any read after truncation | r2image `held.rs:25` (mmap; the SAFETY comment is false) | `px 16 @ 0x15e0` after `: > file` (App. A) | confirmed — c-architecture |
| W54 | medium | `:V` inside visual mode leaves the outer visual in cooked mode on the main screen | V | r2s-tui `run`/`Screen` (no re-entry guard) | `vpty.py ... ':V\rqjjj\r'` | confirmed — c-robustness |
| W55 | low | SIGINT, SIGTERM and SIGHUP leave the terminal raw, on the alternate screen, with mouse capture on | V | r2s-tui `Screen` (restores only in Drop) | `sig.py SIGTERM .../bomb` | confirmed — r2-tui |
| W56 | medium (fin: high) | The decompiler pane keeps showing the previous function's C after a seek into another function (min..max line-address span; ls: 60/268 renderings) | V decompiler and split panes | r2s-tui `HeldRendering::covers`/`App::wanted`; the fact belongs to r2engine | `venv/bin/python repro_stale_dec.py` | confirmed — r2-tui |
| W57 | medium (fin: high) | Switching panes drops the seek: the highlight differs from the title, the next key jumps backwards, and a hex edit writes at the stale top+cursor | V p/P, hex `i` | r2s-tui `App::switch`/`step`/`edit_nibble` | `cursor.py .../bomb 's main' 'jjjjjjjjjj' 'pp' '<right>' 'P'` | confirmed — r2-tui |
| W58 | medium | The same keys give different screens depending on typing speed: decompiler j/k are dropped before an answer arrives, and disassembly J/K are netted (5 runs, 3 states) | V | r2s-tui `step`/`pending_lines` | `fast.py .../pumasim 's 0x4baf30' 'pjjjjjjjjjj' 3` | confirmed (corrected) — r2-tui |
| W59 | low (fin: medium) | Scrolling up in x86 disassembly shows misdecoded instructions (96/372 addresses) because r2s-tui guesses instruction boundaries; up to 15×rows decodes per window fetch | V k/K | r2s-tui `worker.rs::line_before`; the fact belongs to the r2engine listing | `vdrive.py .../bomb 'kkkkkkkk' 's 0x401197'` | confirmed — r2-tui |
| W60 | low | Seek grammar: `s +16` silently seeks to absolute 0x10 (also `pd @ +16`); `010` is decimal; `s -8`, `$$`, `main+4` and `0b101` are rejected | s, @, every address argument | r2s `commands::parse_number` | `cmp.sh tests/fixtures/rv_O0g 's 0x1000;s +16;s'` | confirmed — c-robustness, c-missing |
| W61 | low | `q 3` exits 0, and `q!` is unknown | q | r2s `main.rs` (stringly `Err("quit")`) | `target/release/r2s -qc 'q 3' tests/fixtures/rv_O0g; echo $?` | confirmed — c-robustness |
| W62 | low | The visual chrome ignores `scr.color=0` (107 colour SGRs remain) and the terminal's capabilities; radare2's V emits 0 | V | r2s-tui `view.rs` styles; the decision should come from r2s | `venv/bin/python repro_color.py` | confirmed — r2-tui |
| W63 | low | `prepare-held`/`collect-phase` evidence prints "0 bytes" in builds without alloc-count; `is_counting()` has no callers | R2DEC_TRACE_REFUSAL | r2il `allocation` (type should be `Option`) + r2ssa emit sites | `R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'pdd @ 0x1e2450' ...pumasim` | confirmed — p-memory |

### 2.2 High-severity rows: cause and fix direction

**W1 — PE sections that are execute-only or write-only are unmapped.** `crates/r2image/src/lib.rs` `section_permissions` (~1205) and `map_permissions` (~1228) take `read` from `IMAGE_SCN_MEM_READ` only. `Image::read` (821), `read_unpatched` (850), `read_upto` (890) and `write` (909) then refuse any segment where `!permissions.read`. That gate was written for Mach-O `__PAGEZERO`. Verifiers counted 200/312 PE files failing `pd 1` at the entry. Setting READ on the X-only sections fixes 189–190 of them; the other 10 have no stated entry or an entry in the header, which is a different cause. Almost all are Corkami hand-made PEs, and MSVC and mingw set READ, which is why severity is high, not critical. ELF *segments* take PF_R literally, so execute-only ELF segments have the same latent bug. The error text "nothing mapped" is false for a section that is mapped. *Fix in r2image:* keep the stated flags (so `iS` stays honest) and change the read gate to "has any access" (R, W or X) or to an explicit `mapped` fact; `__PAGEZERO` (prot 0) still refuses. Use one gate for all four read paths. Add an r2image test with a 0xa0000000 COFF section and an execute-only ELF segment. The two `-rw-` code-section cases (Lab01-03.exe, pe.exe) are a separate low-priority policy question: NX_COMPAT should become a typed fact.

**W2 — Thumb after a backward `blx` decodes as ARM.** The Thumb `blx` constructor runs `globalset(ThArmAddr23, TMode)` with TMode=0. libsla's `setContextChangePoint` applies that value from the target up to the next change point, so every later decode at a higher address in a continued run (`resume()` keeps context when `after.end == addr`; `query/decode.rs` and `body.rs:521` pass `Continuation` along) reads ARM. Forward targets are harmless. pdf is wrong too: it only resyncs at a block start. The same mechanism explains the judged libverifyPass and libflutter "1-byte stepping" entries. Instance counts: libflutter 1,806 sites, r2pay-arm32 166. ARM32 is not a graded architecture, so the severity is high. *Fix:* in r2sleigh-lift, a continuation keeps only context committed at `inst_next`. A `globalset` aimed at another address must not reach the continued run's persistent context; report it as a typed per-target fact instead. In r2engine, seed each run's mode from the `$t`/`$a` mapping symbols and entry modes. Regression test: `blx` at 0x472 in special-sym, then 0x476 must decode as `mov.w lr`.

**W4 — CFI-only function starts are not walk boundaries.** `body.rs:591` `transfer()` and `:606` `continues()` stop only at `Program::is_entry`. `view.rs:208` answers from import stubs plus `definitions()` (program/mod.rs:628), which is container entries and function symbols only. `stated_functions()` (requests.rs:888) also seeds every FDE start, so `afl` and the walk use two different definitions of "a function begins here". Examples: bash `fcn.00034640` sits inside 3 callers; `ls` 0x6580 sits inside 24 wrappers; gnome-extensions 0x3b40 has 591 blocks against radare2's 211. The static-glibc case is a fall-through after a call whose return is unproven. The a.exe and cpp-msvc instances do not belong here, because those targets are not stated anywhere. *Fix in r2engine:* build one index of container-stated starts (entries, function symbols, FDE starts outside linkage) that both `is_entry` and discovery read. Discovered starts must **not** become boundaries (discovery.rs:218 relies on fixed boundaries for determinism). State an explicit rule for `.cold` fragments. Add a native.rs test: a wrapper that `jmp`s to an FDE-only function ends at the `jmp`.

**W5 — ET_REL processed unrelocated.** `crates/r2image/src/loader/mod.rs:31-37` returns `Vec::new()` relocations for `ObjectKind::Relocatable`; only `linked()` ranges become `WriteKind::Unknown` writes. r2engine consults loader writes only for data, so instruction displacements under an unapplied relocation set call targets and RIP-relative addresses, and those get stamped "(certified)". Examples: on x86_64-common-code.o pdd loads from the call instruction's own bytes; on a clang -O1 .o pdd stores into main's code bytes. `unwind.rs` bases `.eh_frame` at `sh_addr` 0 and applies no relocations, so FDE pc_begin values become `fcn.00000020…`. The listing spelling is a judged deferral (P11). The certified annotations, the dropped calls, the empty `ir` and the phantoms are not judged anywhere. *Fix:* r2image reads ET_REL relocation records (symbol, addend, width, a typed origin) and reads CFI at the placed section base through those relocations, or refuses unrelocated FDEs. In r2engine decode and certification, check each instruction's encoding against loader writes; a target taken from loader-written bytes comes from the stated relocation or is refused, never certified.

**W6 — Overlapping instructions and misaligned absorbed bodies.** `body.rs::into_body` (788-820) splits blocks only at instruction ends or leaders. Two overlapping decodings give two overlapping blocks with no stated overlap and no successor edges. The r2source `is_structurally_valid` check (lib.rs:663) correctly rejects the result. `NativeRefusal::Capture` is a "refusal to start", so it reaches the shell as rc=1. Only `pdf` falls back to the plain walk. Half of the sampled cases are not the lock-skip idiom: the body walks into foreign code about 4 KB away at a misaligned offset (0x48abe0 → 0x48bc78). Counts: 35/874 functions in static glibc, 7/3,203 in libc-2.32. The per-failure cost is just the `aa` baseline. *Fix:* the r2engine walk either refuses up front with a typed "branch into instruction X" refusal, or states the overlap (both streams, a leader at the shared tail, fallthrough edges) under an r2source contract widened to allow it. Separately, stop the walk from absorbing code at misaligned offsets. Every capture failure becomes a `refused` record (rc=0).

**W7 — Arity filled from caller-written registers.** Example: for `shape_bool_caller`, `mint_recovered_call_site_interface` refuses because `reads_past_parameters` is set. That flag is itself spurious: the probe callee's interface was missing when the caller was recovered. `convention_call_boundary` (semantic/boundaries.rs) then counts every register written before the call and sets `arguments_proven=true`, so r2dec renders a closed prototype. `CalleeStatement::of` also turns a callee whose arity is exact but whose result is unproven (`crc32_init`, `fill`) into a floor. Indirect calls ignore a pointee prototype that Source declares (rv_O0g `dispatch`). Runtime equivalence still holds under SysV, but this is fabricated C that AGENTS.md lists as a blocker. *Fix:* compute callee arity bottom-up over the call graph (an SCC fixpoint in `r2ssa::fixpoint`). `CalleeStatement` should carry `Exact(n)` or `AtLeast(n)` separately from the result. Slots past a floor become visible residuals, never `arguments_proven=true`. Indirect calls take the declared pointee prototype.

**W8 — GOT `call [slot]` unresolved.** Only direct calls and tail jumps get a `Transfer` in `transfer_of` (body.rs ~891). The slot→import mapping exists in four private readers (`import_at`, `native::called_name`, `body::called_slot`, annotate) but never reaches `CalleeResolutionFacts`. The proof also has two owners. `query/proved.rs:64` requires `described`; r2dec `render/calls.rs:329` accepts `described || own_interface`, which renders the arity read off live registers. *Fix:* r2engine records a `CallSlot` transfer when `import_at(slot)` names a loader import write *and* the slot is sealed (RELRO or `__DATA_CONST`; lazy slots stay indirect). The callsite then gets the import identity and prototype. Delete the private readers. Have one "arguments proven" verdict in the r2ssa certificate, read by both proved.rs and r2dec, and drop the r2dec relaxation.

**W9 — i386 prototypes and invented arguments.** `declared::Placement::placed_prefix` (declared/mod.rs:149/188) breaks at the first parameter when the convention has no argument registers. `placed()` returns None, and `declare_imports` (native.rs:774) silently skips every import with parameters; only zero-argument rows survive (37/39 stubs in true32). Separately, `reaching_stack_slot_value` (boundaries.rs ~640) lets a promoted slot's value cross a call ("a call does not disturb it"), so `[esp+4]` and `[esp+8]` stored for `sscanf` reach the later `printf` and `exit` as arguments. The `prototype_arguments=None` trace line is not specific to i386: `AdvisoryCallPrototype` is never constructed anywhere. *Fix:* Placement places stack parameters from the cspec's stack area, or emits refusal evidence. In r2ssa, a call clobbers the callee-owned outgoing argument area; with no prototype, count only stores made since the previous call, or report the arity as unproven.

**W10 — ObjC prototypes.** `types.sdb.txt:2990-3006` declares `objc_msgSend` and `objc_msgSendSuper2` with `args=2` and no `,...`, and `objc_storeStrong(void*, int)` returning `void*`. `r2types callee.rs:633 non_variadic_known_arity` then caps the arguments. These records also break `data/README.md`'s rule for the portable table: libobjc is not one of the scoped C libraries. *Fix:* move them to a Darwin or libobjc scope with Apple's declarations (variadic `msgSend`, `void objc_storeStrong(void**, void*)`), add a native test where a third argument register survives, and send the data fix upstream to radare2.

**W11 — FP boundaries.** `recover_interface.rs` (~1589) builds parameters only from `slots.argument_slots()`, and `float_argument_slots()` is never consulted. A float result is recovered only from caller reads. For undeclared callees, `boundaries.rs:864` counts only integer slots. r2dec `call_expr` always emits `CExternDecl { params: Some(..), ret: Void }`: an invented `(void)` prototype, and silent truncation of a declared arity (`tanf(void)`). r2abi reads `arithmetic tan(arithmetic)` as Opaque, and `Placement::class` refuses it. Missing FP-parameter recovery is already tracked in ROADMAP P7; the fabricated `(void)` is not. *Fix:* recover and count parameters over both slot classes; when a call's arity is unproven, render a gap instead of `(void)`; refuse when a declared arity exceeds the planned arguments; state the math.h rows at their C types.

**W15–W18, W20 — AArch64 Sleigh semantics.** These all sit in vendored `vendor/sleigh-config/.../AARCH64*.sinc`, compiled by `build.rs`.
- W15: `Rt_GPR64 = sext/zext(*:N)` in the 32-bit load forms.
- W16: `addrPairIndexed + 8`. Upstream Ghidra master already has `+ 4`, so resync rather than send upstream.
- W17: 22 `aa_Wt =`/`aa_Ws =` writes of the 4-byte alias, plus `ls_opc_smin` comparing a zero-extended value against the full 32-bit `aa_Ws`.
- W18: `trunc()` with Ghidra's own `AUNIT --status fail "nofpround"` notes. One constructor serves all eight `fcvt` variants, so `fcvtzs` must stay as it is. `FLOAT_ROUND` is floor(x+0.5), not ties-away, so `frinta`/`fcvta*` need a named CALLOTHER.
- W20: `normalize_instruction_local_control` handles the outer branch first. Its skipped range still holds the inner, unrewritten CBRANCH, so line 93 replaces only that branch with `Unimplemented` and leaves the guarded ops in place.

*Fix:* local vendor changes listed in `vendor/README.md`, following the `addv` precedent (c886c13c), each with a lift-level `r2il::eval` regression and an upstream report. For W20, rewrite branches innermost-first in r2sleigh-lift. When a refusal is unavoidable, poison every op the branch guarded.

## 3. Missing (features, formats, archs, docs) — ranked by user value

| Rank | ID | Sev | Missing | Owner | Repro (short) | Status / probes |
|---|---|---|---|---|---|---|
| 1 | M1 | high | **PE import and export directories are never stated.** `is`/`ir` are empty on 241–280 of the PE files that have imports; IAT calls are anonymous and lack prototypes; DLL exports are missing (kernel32: 1,607 per radare2). `import_table()` is read, but only for write ranges (`pe_writes`) and DLL names (`pe_needed`); `export_table` is never read | r2image loader PE arm (mod.rs:46-47) → `WriteKind::Import` per IAT slot, exports as symbols | `target/release/r2s -qc 'is;ir;pdf @ entry0~call;pdd @ entry0' ../radare2/test/bins/pe/a.exe` | confirmed (corrected) — c-info, c-analysis, c-missing |
| 2 | M2 | medium (fin: high) | **AArch64 LL/SC never becomes `LoadLinked`/`StoreConditional`.** `rewrite_exclusive_access` only knows the ARM32 names. AArch64 `stxr` lifts to Unimplemented plus an unconditional store; `ldxr` has no marker in the spec at all, and the store shape differs from ARM32 | r2sleigh-lift `internal_control.rs:1047-1087` (+ spec marker for the load side) | `target/release/r2s -qc 'aa;pdil @ sym._fetch_add;pdd @ sym._fetch_add' $P/probe/probe2` | confirmed (corrected) — r2-aarch64 |
| 3 | M3 | medium (fin: high) | **Calls vanish into `UnsupportedInstruction` residuals that never name the callee.** 139/557 in pumasim 0x4baf30; 103/231 in 0pack 0x62ecf0. Cause: `convention-arity-unproven` → `boundary.complete=false` → inventory `UnsupportedUnknown`; `GapMarker` has no callee field | r2ssa `obligation.rs` (typed `CallBoundaryIncomplete`) → r2dec gap kind | `target/release/r2s -qc 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim` | confirmed (corrected) — r2-render-corpora |
| 4 | M4 | medium | **A damaged or absent section table, or a tiny or odd PE optional header, refuses the whole file**, even `px` and `?e`. Counts: ELF 6, PE 27, Mach-O 2, COFF 1 that radare2 opens. `object::File::parse` is all-or-nothing at `lib.rs:407` | r2image `Image::held` (fallback to program headers, clamp NumberOfRvaAndSizes) | `target/release/r2s -qc 'i' ../radare2/test/bins/elf/elf_stripped` | confirmed (corrected counts) — c-analysis, c-missing, c-robustness |
| 5 | M5 | medium | **No raw-bytes, architecture or fat-slice selection, and an unmapped architecture refuses container verbs too.** Shellcode cannot be loaded; `e` has only 2 keys; the universal `/bin/ls` always opens arm64e. MIPS32/64 and RV32 (and 93 of 971 sweep files) fail `i` and `iS` because `map_architecture` refuses during the container parse. The README/BUILDING table implies MIPS and RV32 work. Java `.class` is misread as fat Mach-O | r2image (raw image, slice choice, state the machine without refusing) + r2sleigh-lift profile table + r2engine refusal; r2s CLI flags | `target/release/r2s -qc 'pd 3' /tmp/sc.bin` | confirmed (corrected) — c-missing, c-robustness, c-analysis |
| 6 | M6 | medium | **An ELF without section headers exposes no dynamic symbols.** libarm64.so's 1,176-byte export `Java_o__003dc_e` is never found (afl: 1 function vs radare2's 10). `loader/elf.rs` already reads DT_SYMTAB, but only for relocations | r2image (`Symbols::Dynamic` shared with the symbol list) | `target/release/r2s -qc 'aa; afl' ../radare2/test/bins/elf/libarm64.so` | confirmed — c-analysis, r2-whole-program |
| 7 | M7 | medium | **ELF initialisers are read only from typed section headers.** DT_INIT_ARRAY and DT_FINI_ARRAY in PT_DYNAMIC are ignored (sht_null_symbols, libarm64, libshella), so discovery roots are lost | r2image `initialisers` → PT_DYNAMIC | `target/release/r2s -qc 'iee' ../radare2/test/bins/elf/sht_null_symbols` | confirmed — c-info |
| 8 | M8 | medium | **PE TLS callbacks are missing from `iee` and from discovery** (27 files) | r2abi `EntryKind::Tls` + r2image TLS directory | `target/release/r2s -qc 'iee' ../radare2/test/bins/pe/hello_world_stripped.exe` | confirmed (27, not 25) — c-info |
| 9 | M9 | medium | **JSON exists only for `aflj` and `pddj`.** `ij isj iSj iej izj irj afij afbj afvj axtj axj fj pdj pdfj agfj` are unknown. Already ROADMAP S1. `aflj` builds untyped `json!` maps in r2s | r2engine typed payloads + r2s VERBS | `target/release/r2s -qc 's main; ij' ../radare2/test/bins/elf/crackme0x05` | confirmed — c-missing |
| 10 | M10 | medium | **No address expressions** (`main+4`, `$$`, `0x..+0x10`), no `@@`, no relative seek. `@@` gives a misleading error. ADR scripting-surface §3.4/§7 plans this; shell `\|` is refused on purpose | evaluator crate (ADR) bound by r2s; `parse_number` today | `target/release/r2s -qc 's main+4; s' ../radare2/test/bins/elf/crackme0x05` | confirmed (corrected) — c-missing |
| 11 | M11 | medium | **No byte or value search** (`/x`, `/`, `/w`, `/v`). command-gap.md Tier 3 conflicts with ROADMAP S2 | r2engine search query + r2s verbs | `target/release/r2s -qc '/x 5589e5' ../radare2/test/bins/elf/crackme0x05` | confirmed — c-missing |
| 12 | M12 | medium | **Indexed accesses to a global table produce no reference, while pdd names the object.** Two owners: annotate.rs claims, and `native.rs data_symbols()` collects any constant | r2engine `query/annotate.rs` (typed `Indexes` claim); data_symbols reads it | `target/release/r2s -qc 'axt 0x2020; pdd 0x13b0' tests/fixtures/rv_O2` | confirmed — c-analysis |
| 13 | M13 | medium | **`cmpxchg` (every form, plus `cmpxchg8b`/`16b`) lifts with UNIMPLEMENTED in place of the conditional store.** It is an if/else diamond; the equal arm is deleted as dead code. `R2ILOp::AtomicCAS` exists but is never emitted | r2sleigh-lift `internal_control.rs` (diamond normalisation) | `s sym.phase_1; wx f0480fb10ec3; pdil @ sym.phase_1` on bomb | confirmed (corrected) — c-listing |
| 14 | M14 | low | **The `bomb` `phase_3` jump table is unresolved** (the index is bounded in a stack slot, then reloaded): 5 blocks vs 16. r2ssa has no load-equivalence fact | r2ssa memory/values | `target/release/r2s -qc 'aa; afb @ sym.phase_3' $E/bomb` | confirmed (corrected) — c-listing |
| 15 | M15 | low | **Other AArch64 lift gaps:** `msr`/`mrs nzcv` are disconnected from NG/ZR/CY/OV; `crc32*` emits `Load{space:Const}` (invalid per validate.rs); multi-register `tbl` and frequent NEON user-ops are not modelled | r2sleigh-lift (+ vendored sinc) | `a64harness ... msr_nzcv` | confirmed — r2-aarch64 |
| 16 | M16 | low | **System calls render as anonymous gaps although `/as` proves the number.** Today's facts justify naming the number (`getpid`), not inventing arguments, and `exit_group` is followed by a `return` | r2ssa `supervisor_calls` as a prepared fact + r2abi | `target/release/r2s -qc 'aa; pdd @ 0x401010' tests/fixtures/syscalls_static_O2` | confirmed (corrected) — c-decompiler |
| 17 | M17 | low | **Address constants passed as arguments are not symbolized** (`find(0x4040, ...)` should be `g_table`; `dispatch(0x11a9)` should be `add`) | r2dec render (globals/terms), with pointer provenance from r2ssa/r2types | `target/release/r2s -qc 'aa; pdd @ main' tests/fixtures/rv_O0g` | confirmed (corrected owner) — c-decompiler |
| 18 | M18 | low | **`i` lacks triage fields** (nx, pic, relro, interp, static), and `il`/`iI` are missing; `needed()` is private to language detection | r2image posture record + r2s `il` | `target/release/r2s -qc 'i;il' ../radare2/test/bins/elf/crackme0x05` | confirmed — c-missing |
| 19 | M19 | low | **The xrefs pane drops axt's "absence is not proof" caveats** (`Host::list` has no slot for them), and a query error becomes an empty `(0)` | r2s visual.rs + r2s-tui Host contract | `vdrive.py .../bomb 'x' 's 0x400dc2'` | confirmed (corrected) — r2-tui |
| 20 | M20 | low | **`ax` help says "references from an address" but `ax` refuses the argument; `axf` is missing; errors are prefixed `r2s: r2s:`** (4 sites) | r2s commands.rs | `target/release/r2s -qc 'ax 0x08048342' ../radare2/test/bins/elf/crackme0x05` | confirmed (corrected) — c-missing |
| 21 | M21 | low | **The r2sleigh-cli surface:** `test-arch mips32be` is rejected by an error that lists it as supported, there is no aarch64 row, and `run --action dec` prints Rust `Debug` structs | r2sleigh-cli main.rs/export.rs | `$C test-arch mips32be -o /tmp/m.r2il` | confirmed — r2-equiv-ci, c-tests |
| 22 | M22 | low | **Doc drift:** README calls ARM32 pdd "not admitted" yet it renders (ROADMAP:552 states the policy); README lists RISC-V as lift-only although it renders; BUILDING says "abort on panic" but the profile uses `unwind`; README says afl shows "why each is believed" but it does not; command-gap.md says 38 names (now 37) with `aa` out of scope; equiv README says no aarch64 CI job exists (one does), and its status table omits `slow` | README.md, BUILDING.md, doc/command-gap.md, tests/equiv/README.md | `grep -n 'abort on panic' BUILDING.md` | confirmed — c-missing, r2-equiv-ci |

## 4. Bad design / architecture-rule violations

| ID | Sev | Violation (AGENTS rule) | Where (file:line) | Owner | Fix direction | Probes |
|---|---|---|---|---|---|---|
| D1 | medium | **"Function begins here" has two owners** (NN1). `afl`/discovery seed CFI starts, but the body walk's `is_entry` does not (→ W4) | r2engine `program/mod.rs:628` `definitions()`, `program/requests.rs:888` `stated_functions()`, `view.rs:208` | r2engine | One container-stated start index read by both | c-listing, c-analysis |
| D2 | medium | **Address→containing function is computed in r2s and r2s-tui** (NN2, r2s-tui "no program facts") (→ W45, W56, W59) | `crates/r2s/src/visual.rs:84-115` `containing_entry`; `crates/r2s-tui/src/app.rs:171-191, 636-639` `HeldRendering::covers`/`span`; `crates/r2s-tui/src/worker.rs:180-203` `line_before` | r2engine | Typed `containing_function(vaddr)` + instruction-starts-before query; the TUI consumes them | c-robustness, r2-tui |
| D3 | medium | **Callee resolution for `call [slot]` has 4 private owners and none on the decompile path; "arguments proven" has 2 owners** (NN1) (→ W8) | `r2engine/src/body.rs` `called_slot`, `transfer_of` (~891); `native.rs:2002` `called_name`; `query/proved.rs:64` vs `r2dec/src/render/calls.rs:329-331` | r2engine + r2ssa | One `CallSlot` transfer feeding `CalleeResolutionFacts`; one verdict in the r2ssa certificate | r2-whole-program, r2-render-corpora |
| D4 | medium | **Analysis-phase refusals are `Err` strings, not refusal records.** Go ABI0 (40/40 dwarf_go_tree functions), `Capture`, `Convention` and walk refusals print to stderr and pddj emits no JSON; only sealing and r2dec refusals are typed | `r2engine/src/program/analysis.rs` `Rendered::compute` (flattens `Analysed` Err to String); `native.rs:1033`; `tests/language.rs:44,53` pin `expect_err` | r2engine | Turn every non-stop refusal into a `Rendering` with `refused:{reason}`; afi/afv return the facts that do not depend on the convention | r2-render-corpora, c-robustness |
| D5 | medium | **Debug info makes the C worse:** slots declared in DWARF are refused promotion (`is_declared`), a leftover from the legacy renderer. With `-g`, rv_O0g promotes 0 locals; stripped promotes 22 | `crates/r2ssa/src/slot_promotion.rs:695-699` | r2ssa | Drop `is_declared` as a refusal reason; name promoted values through `stack_object_name` | c-decompiler |
| D6 | medium | **The survey walk ignores dispatch tables**, so `afl` size/nbbs and `ax`/`axt` disagree with `afi`/`afb` (108/330 sampled functions). `aflj` `size` holds realsz, unlike radare2. afi also counts the prepared graph after r2ssa has removed the canary blocks | `r2engine/src/program/requests.rs:563-573` `function_extents` (comment points to P6); `info.rs::blocks(artifact)` | r2engine | One resolved body (P6a `Walked`) read by afl, afb, afi, ax and axt; emit `aflj size`=max−min plus `realsz` | c-analysis, p-scaling |
| D7 | medium | **Every NEON/FP value is carried in 256-bit SVE z-register structs** (mem_scan2: 2,294 lines, 675 `r2sleigh_bits_256` assignments). The zero-fill writes widen the register-family root to z, which adr-register-identity §2 calls a known mistake | `r2ssa/src/function/mod.rs:4089` `RegisterFamilyInfo::with_program_roots`; `r2sleigh-lift translate.rs split_odd_register_zeroes` | r2ssa (`lanes::Written`) | Root extent from data-written lanes, not every touched varnode; fold Subpiece across calls and phis | r2-aarch64 |
| D8 | medium | **AArch64 has two Sleigh profiles for one machine:** discovery uses AppleSilicon and the trusted lift uses Aarch64Le, so each process parses two specs (+0.49G instructions, +26 MB) and the two can decode the same bytes differently | `r2sleigh-lift/src/disasm/mod.rs:300` `from_tuple`, `:1655`/`:1764` `selection`, `:1874` cache keyed by profile | r2sleigh-lift | One tuple→profile table; AArch64 twin of `an_embedded_machine_shares_the_trusted_profile_s_parse` | r2-whole-program |
| D9 | medium | **Every analysis crate waits behind the C++ toolchain:** r2ssa depends on r2sleigh-lift (and so on libsla and sleigh-config) for 3 trust types, which puts the C++ chain on 51% of the release and 74% of the debug critical path | `crates/r2ssa/Cargo.toml`; `r2ssa/src/lib.rs:167`, `function/mod.rs:22` | r2sleigh-lift (split a libsla-free core) | A core crate with the sealed types and translation; a backend crate links libsla. Feature gates do not help because features unify | p-build |
| D10 | low | **Callee and import name canonicalisation is implemented 5 times live (6 in total), with different rules.** Typed linkage is spelled `sym.imp.` and parsed back. The lowercase plus `_<digits>` key merges distinct functions (`png_get_uint_16/31/32`), and `HashMap` collect order picks the surviving prototype on collision (latent; not reproduced) | `r2engine/src/library.rs:19,290,300`; `route.rs:24` (dead); `r2types/src/callee.rs:763`; `r2dec/src/ast.rs:1868`; `r2abi/src/runtime.rs:19`; `r2types/src/function_facts/prepared.rs:1160` | r2engine (typed identity) | Key on address plus typed linkage plus the bare import name; one case-preserving presentation function; delete `plain_function_name` | c-architecture |
| D11 | low | **Interior-mutability memos outside the query database** (D11): `natural_loops` OnceLock reset by hand, `direct_reads` RefCell, a leaked global `Mutex<HashMap>` interner, the thread-local spec cache. The lint scope is r2engine only; this is staged per ROADMAP D11, and the interner is already ROADMAP PF | `r2ssa/src/function/mod.rs:1812, 2835`; `r2ssa/src/name.rs:84-104`; `r2sleigh-lift/src/disasm/mod.rs:1875`; lint `tools/dylints/.../lib.rs:6274-6279` | r2ssa / r2engine | Build `natural_loops` eagerly at seal; serve `direct_reads` from `CalleeReads`; widen the lint as owners land | c-architecture, p-memory |
| D12 | low | **Dead plumbing:** `reg_type_hints` (stringly `HashMap<String,TypeHint>`) in 4 public request types, never read; `merge_type_hint` has no callers; half of `r2il::allocation` (`SAMPLED` never written, `BY_SIZE` paid per allocation); `memory_mirrored_carriers` and `register_identity_census` have zero callers since 51b9d6a9 | `r2engine/src/lib.rs:622,638,756,765`; `r2types/src/prepare.rs:29`; `r2il/src/allocation.rs:27-72,109-126`; `r2ssa/src/mirror.rs` | each crate | Delete them (NN9; "dead outputs get deleted") | c-architecture, p-memory, c-tests |
| D13 | low | **Readability:** an empty then-arm instead of an inverted condition (801/192 functions); one nesting level per join (31 levels in a loop-free function); 5 `(void)` reloads per x86 RMW (Sleigh reads `*rm32` once per flag); `>> 0U`; `(uint8_t)` condition casts; constant `if ((uint8_t)1U)` (the pdd path turns SCCP off); 128-bit `idiv` expansion | `r2dec/src/render/control.rs` `block_region`/`arm()`; `codegen.rs:955-967`; `r2ssa/src/optimize.rs:56` | r2dec (structure) + r2ssa (load equivalence, branch decision, lane fold) | Splice merges into the parent, invert empty thens, prove dead loads, decide constant branches before prepare | c-decompiler, r2-render-corpora |
| D14 | low | **Error messages leak internals:** the `r2s: r2s:` prefix (4 sites); write refusals labelled "unrecognised binary"; `{:?}` spellings (`format Elf`, `[Unknown, Unknown, …]` 522 bytes, `InvalidFunctionImage`); raw OS errors for a directory or no TTY | `r2s/src/commands.rs:647,654,670,697`; `r2image/src/lib.rs:31,905-912,1080`; `commands.rs:496`; `r2source/src/lib.rs:959` | r2image, r2source, r2s | Typed `ImageError` variants with Display; one prefix | c-robustness, c-missing |
| D15 | low | **BTreeMap monomorphisation is 45.6% of r2ssa's LLVM IR.** Dense-id keys are only about 9% of it; the real gap is block-address (`u64`) keyed per-function facts that the `entity_keyed_map` lint misses (it also misses wrapped keys such as `MemoryObjectKey`) | `r2ssa/src/semantic/reaching.rs:20-22`, `values.rs:200`, `obligation.rs:558`, `cfg.rs:97`; `semantic/facts.rs:262` | r2ssa (LX2) | Re-key block facts by `BlockId`; widen the lint | p-build, p-cpu-mac |
| D16 | low | **`scripts/samply_collapse.py` strips the impl type**, so `<::of`/`<::from_iter` merge unrelated functions, and with `--match r2` every impl method disappears | `scripts/samply_collapse.py:42-56` | tooling | Strip only generic groups after an identifier | p-cpu-mac |

## 5. Performance

All figures are retired instructions (`/usr/bin/time -l` on r2s itself, **not** wrapped in `timeout`, which counts only the wrapper's ~18M) or sample shares, because wall clocks were noisy on the shared Mac (load averages of 20–70). Linux figures come from the contabo VM (`perf stat -r3`, frame-pointer `perf record`).

### 5.1 Where the time goes, by workload and phase

| Workload | Cost | Phase shares | Main cause |
|---|---|---|---|
| Process start (any command that decodes) | ~0.49G instructions, ~45 ms, +35 MB above `i`; AArch64 +0.49G / +26 MB more | spec load 43–92% of a small pdd (`SleighBase::decode` ~77%, zlib ~22%) | P13 spec decode per process; D8 two AArch64 profiles; P11 Thumb spec eager on ARM32 |
| Open with DWARF (`i`, `q`) | libc-2.26-debug: 1.90G vs 0.35G without DWARF; `i` 54.7 ms vs 9.2 ms; RSS 38.5 vs 16.7 MiB | `r2image::debug::read` 89–97% | P12 eager DWARF; per-attribute DIE re-decode (not the `chain()` clone, ~3%) |
| Open, 80k-section COFF | `i` 0.16–0.19 s | `section_by_name` ~33% | P14 linear name lookups; DWARF sections loaded twice |
| `afl`/`aa` (discovery) | pumasim 20.1G, 3.5 s CPU, 158 MB (radare2 `aa`: 74 s user); 0pack 13.6G | lift 77–80% (Sleigh p-code 47%, `translate_pcode` 24%); discovery engine ~17%; allocator 17% | Linear in text bytes (slope 0.96). Lifts thrown away (P18) |
| First `axt` (reference index) | pumasim 133G (6.6× afl), 432 MB; libc-2.23 69.9G (7.6×) | `listed_by_block` 74%, `def_use_graph` 44.6%, re-lift 12.7%, third decode 15.6% | P7. One-time per session (Held); radare2 `aaa` costs 86.6G on libc |
| pdd, large x86 functions | pumasim 0x23fdf0 18.7–20.1G; 0x4baf30 13.4G; 0pack 0x58e3d0 26.0G; 0x62ecf0 23.3G; RSS 188–256 MB | ssa-analysis 61–77%, ssa-build 5.5–14%, lift 6–13%, rewrite 1.6–22% (22% only on 0x58e3d0), render 0.5–2.6%, types 1.3–2.2% | Callee reads 55–84% (P1); spans scan 25–32% (P2); producers 13–19% (P3); double collection ~18% ×2 (P4) |
| pdd, AArch64 call-dense | gzdoom `_Load_Version_4_5`: 1,060–1,072G, 51–58 s, 1.08–1.24 GB (39.5M/insn vs 0.74–6.8M typical) | 84.5% in `reaching_abi_value_before` | P5 |
| pdd, flattened AArch64 | r2pay `entry.init1` (2,491 blocks): RSS 1,017 MB, heap peak 602 MB; init0 409 MB | 402.65 MB at `liveness.rs:558` | P6 |
| pdf / afi / afb | pdf 13.2G, afi 13.4G vs pdd 13.4G on 0x4baf30; `pd 1784` 1.22G | analysis 82–88%; callee_read ~50% | P10 (contract for pdf and afi; waste for afb) |
| Session, 50-function SESSION | 109.3G vs 171.2G fresh; real cross-function reuse ~10%, the rest is startup | callee reads 40–47% | P1, P16 |
| Session, 6,406 libc requests | RSS 378 MB at ~1,200 requests, levelling at 414–424 MB | — | Bounded; second pass not cheaper (Newest) |
| Visual mode | key→draw <1 ms; settled 20–40 ms (moves), 78 ms graph, 0.38 s median decompile (cold 2–4.4 s); RSS 286→326 MB over 4 rounds | engine thread busy 23% in alternation, 70% of that `Analysed::compute` | P16 revisits; no cancellation (P32) |
| Build (clean release) | 374 s wall, 614 s user (load 30–62); debug 264 s | critical path: libsla-sys 87.8 s → sleigh-compiler → spec compile 66.5 s → lift → r2ssa 153 s (120 s codegen) → … → link 20 s | B1–B5 |

Flamegraphs and logs:
- p-cpu-mac: `p-cpu-mac/pdd_puma_4baf30.q.svg`, `pdd_puma_23fdf0.q.svg`, `pdd_0pack_58e3d0.q.svg`, `pdd_0pack_62ecf0.q.svg`, `session50.q.svg`, `afl_puma.svg`, `aa_puma.svg`, `i_libcdbg.q.svg`, `is_gzdoom.q.svg`, `is_coffbig.q.svg`, plus `*.q.report`.
- p-linux: `p-linux/fp/{0pack-58e3d0,pumasim-23fdf0,pumasim-session,pumasim-afl,pumasim-afl-pdf23fdf0,tiny}.svg`, `p-linux/stat.log`, `p-linux/audit-exponent.{log,tsv}`, `p-linux/evidenced_spans_range.patch`.
- p-scaling: `p-scaling/prof-{0pack-0x58e3d0,0pack-0x62ecf0,pumasim-0x23fdf0,pumasim-0x489690,axt-libc}.svg`, `p-scaling/fit.txt`, `afl_scaling.txt`, `axt_cost.txt`, `session_reuse.txt`, `callee_sums.txt`.
- p-memory: `p-memory/jeprof_peak_4baf30.svg`, `census_heap_big4.txt`, `alloc-count.txt`, `allocbench2_summary.txt`, `purge_summary.txt`.
- p-session: `p-session/*.json.gz` + `*.cpu.folded`.
- Elsewhere: `r2-aarch64/perf/gz_load.svg`, `gz30.svg`; `r2-render-corpora/prof/dwarf_pdd.svg`; `r2-tui/prof_alt.svg`, `prof_page.svg`; `r2-whole-program/prof/stub.folded`; `p-build/timings_*.html`, `llvm_lines_aggregated.txt`.

### 5.2 Performance findings

| ID | Sev | Cost | Why | Owner | Measured / estimated gain | Status / probes |
|---|---|---|---|---|---|---|
| P1 | medium (fin: high) | A cold pdd fully prepares every direct callee (SSA, interface, seal, type analysis): **47–84% of pdd** (0x4baf30: 107 bodies; main 0x1dc0a0, 300 instructions → 12.8G). The callee's preparation is not reused when that callee is later rendered as the root (A;B = A+B−base) | `callee_read`→`resolved_alone`→`Native::resolve`. Two thirds of it is construct and `recover_interface`; `seal` is 15–33 pts; r2types 1–3% | r2engine (SM/D23) + r2ssa (F2, LX4) | A summary-grade tier is capped at ~3 pts (ROADMAP SM1 measured this). The lever is preparing once per session plus a cheaper build; target "callee reads <10%" | confirmed (corrected) — p-cpu-mac, p-linux, p-memory, p-scaling, p-session |
| P2 | medium (fin: high) | `ObjectModelBuilder::object_for_address_value` scans every evidenced span for each address value: 25–32% of 0pack 0x58e3d0 and 0x62ecf0 (4,674 spans) | `semantic/facts.rs:1697-1708` filter+`max_by_key`; siblings at `facts.rs:1871`, `shared.rs:2085/2112` (cold). The model is built in both `recover` and `seal` | r2ssa | Range patch measured **−11.9% / −13.5% instructions, identical md5** (it keeps a linear tail). A disjoint-segment index would give O(log n) | confirmed (corrected: the map is intrinsic to 0x58e3d0, not the callee view) — p-cpu-mac, p-linux, p-scaling |
| P3 | medium | `Import::producers` re-walks the transitive substitution chain for each absorbed operand: 13–19% of 0x58e3d0; 7.6M producer inserts over 7,799 distinct (×976) | `r2rewrite/src/import.rs:296-308`, `driver.rs:140-167`; callers `r2dec/src/render/values.rs:281,1036,1851` | r2rewrite | A per-value memo measured −4.4% instructions but **+72% RSS → rejected**. Need an O(n) dense forest index or interval | confirmed — p-cpu-mac, p-linux, p-scaling |
| P4 | medium | Every interface-less preparation collects all 14 fact phases twice (`recover` ~18%, then `seal` ~18%) | `recover_interface.rs:1253` + `stage.rs:341` | r2ssa | Only control_domains, assumptions and the non-return certificates (~2–3%) can be skipped in recover; more needs reuse of the interface-independent phases (LX4/F2.4) | confirmed (corrected) — p-cpu-mac, p-linux |
| P5 | high | AArch64 call-dense functions are quadratic or worse: each `bl` walks back to the SP definition with a fresh memo and clones the path map (`clone_subtree` 33%) | `rename.rs:786-800` (no CallRestore, intended); `semantic/shared.rs:641,968,996,1131`; caller `certificates/stack.rs:1506` | r2ssa | Read SP through the existing `ReachingStorage` built at `stack.rs:200` (one owner); one mutable path stack. Expected ~13× on gzdoom wall time | confirmed (corrected) — r2-aarch64 |
| P6 | high | Liveness stores one 12-byte segment per (value, live block). 76% of them are literal constants and 23% are Ram values with no definition, treated as live from entry: 17.7M segments, a 2²⁵-capacity Vec (402 MB, 47% slack), **built twice** | `r2ssa/src/liveness.rs:418-444, 527-575`; `semantic/mod.rs:299-305` (kept alive past last use) | r2ssa | Skipping constants measured **1017 → 553 MB** (init1) and 409 → 279 MB (init0), byte-identical pdd over 28k lines. Also drop after `StorageSpans`, size exactly, build once | confirmed (corrected cause) — p-memory, r2-whole-program |
| P7 | medium | The first `axt`/`ax` builds the whole reference index: re-lifts every body, runs the full listing path (3rd decode), and builds lazy SSA def-use for ~14% of bodies (44% of time) | `r2engine/src/program/requests.rs:701-773` `indexed`/`claimed_by` | r2engine (LF/PF1) + r2ssa (fates-only def-use) | Keep flow targets from the survey; lift once (`Lifted` query); def-use without seal. Bounded by about 7× → ~2× afl (estimate) | confirmed (corrected) — p-scaling, p-session |
| P8 | medium | Any write (even a no-op `wx 00`) re-runs the analysis of a function with callees (+4.7G on 0x4baf30): the `Walked` entry was evicted, and an absent entry counts as "moved" | `r2engine/src/query/db.rs:527-543` `Table::bound`, `~675` `verify`; Newest reading Newest | r2engine query db | Patched build measured **18.07G → 13.52G** with identical output. The leftover ~0.14G is the Held `Names` recompute on any write | confirmed (corrected) — p-session |
| P9 | low | `aa` changes every analysis key (`Callers::Read`), so the newest-held function recomputes once (~7.9G) for identical output | `program/mod.rs:385` `analysis_key`; `requests.rs:545` | r2engine | Read caller evidence as a tracked input only for result-ambiguous functions; ADR-documented trade-off | confirmed (corrected scope) — p-session |
| P10 | medium | pdf, afi and afb cost as much as pdd. afb discards the proved listing it built, and visual `containing_entry` does the same. The listing is not a query: each repeat rebuilds a raw-lift def-use graph (+0.8G per pdf) | `requests.rs:397-500` `listed_body`/`proved_listing`; `query/records.rs:153-161` OnceCell (lint allow); `r2s/src/function.rs` `blocks()` | r2engine | afb/agf from `Walked` alone (~10–15% of today's cost); hold the raw-lift def-use/fates as a query | confirmed (corrected: pdf/afi analysis is by contract) — p-session, p-linux |
| P11 | medium | On ARM32 any code read, even `pd 1`, runs the whole-program survey (BatteryLife 5.68G vs 0.055G for `i`). `is` loads the full `Machines` bundle (spec plus Thumb plus convention assembly) when only the primary decoder is needed (arm-init: 44% of `is` is the unused Thumb spec) | `program/view.rs:49-58` `View::new(db,true)`; `requests.rs:855-884` `Modes`; `program/mod.rs:69-122,756-762` | r2engine | Lazy modes (stated mapping symbols first); lazy Thumb and assembly units | confirmed (corrected) — p-session, p-cpu-mac |
| P12 | medium | Open parses all DWARF eagerly (open is 93% of `i` on libc-debug; 11.5–13.6% of a DWARF-typed pdd) | `r2image/src/lib.rs:635` `debug::read` in `Image::held` | r2image + r2engine query db | `Declarations` as a query forced only by declared/native paths; decode each DIE once per chain | confirmed (corrected) — p-cpu-mac, p-scaling, p-session, r2-render-corpora |
| P13 | low | Every process decodes the embedded Sleigh spec (~0.49G, ~45 ms, ~35 MB on x86-64) | `r2sleigh-lift/src/disasm/mod.rs:1528` `LoadedSpecification::load` | r2sleigh-lift + harnesses | Embed the spec uncompressed (−~20%); run many functions per process in census, certify and diff | confirmed (corrected magnitudes) — p-linux, p-scaling |
| P14 | low | Language detection and DWARF loading look up sections by name with a linear scan (80k-section COFF: ~33% of `i`); DWARF sections are loaded twice | `r2image/src/language.rs:43,142,144,254,257,279`; `debug.rs:48`; `unwind.rs:48` | r2image | One name index per image; one `DwarfSections` load | confirmed (corrected %) — p-cpu-mac |
| P15 | low | The name table is built twice at open (`start()` then `Names`) | `r2engine/src/program/mod.rs:313-326` | r2engine | A decoder-free `naming::entry0(&Container)` (do **not** route through `Names`, which loads machines: 63 vs 172 ms) | confirmed (corrected fix) — p-session |
| P16 | low | Revisiting a function re-runs its walk, analysis, seal and render (~40% of the first visit) because of one-slot Newest retention plus one TUI slot | `program/analysis.rs:49,103,203,270` | r2engine | ADR decision #169. A text-only Rendered (~600 KB) passes the ADR's own cost-per-byte test (0.7 µs/B vs 8 ns/B) | confirmed (corrected) — p-session, r2-tui |
| P17 | low | A one-byte write anywhere that discovery read (code or `.data`, even a same-value write) re-runs the whole survey (+19.1G); there is no incremental discovery | `requests.rs:788` `SurveyQuery` (`Key=()`) | r2engine | Per-function walks, with SCCs keyed on the fixpoint | confirmed — p-session |
| P18 | low | Discovery lifts every instruction to canonical r2il and then drops the lift; a later pdd re-lifts the target body (~2–4% of that pdd) | `r2engine/src/body.rs:287,432,521` | r2engine / r2sleigh-lift | Not worth caching (RSS). A reduced decode for the survey (skip `translate_pcode` and canonicalisation, ≤31% of afl) | confirmed (corrected magnitude) — p-cpu-mac, p-session |
| P19 | medium | `ReachingStorage` is rebuilt per consumer and per storage (one per convention argument register in `callee_write_spans`); a binary search per op: 3–6% of pdd | `semantic/shared.rs:1552`; `frame_reach.rs:614`; `certificates/stack.rs:200`; `interproc/dependence.rs:106`; `supervisor.rs:43`; `reaching.rs:72` | r2ssa | One lazy multi-storage owner per prepared function; walk instruction runs in order | confirmed (corrected: mostly argument registers) — p-linux |
| P20 | low | `declarable_stack_object` scans all accesses for each query (17,814 calls on 0x58e3d0; 3.4%) | `r2ssa/src/function/mod.rs:1349-1386` | r2ssa | Compute once in `collect_prepared_function_certificates` | confirmed (corrected multiplier) — p-linux |
| P21 | low | SipHash is 4.5–6% of pdd, mostly String-keyed `RenameIdentity` and `u64` block maps | `r2ssa/src/rename.rs:39`; `phi.rs:23`; `domtree.rs:45,62,262` | r2ssa | Dense identity ids, block-id-indexed domtree | confirmed (corrected attribution) — p-cpu-mac, p-linux |
| P22 | medium | Allocation churn: 10–25M allocations per pdd (232–376 per decoded instruction); the allocator is 13–18% of CPU on afl and the session. Operand accessors return a fresh `Vec` (14–21% of allocations), and `RenameIdentity` String clones 4–8% | `r2ssa/src/op.rs:1292` `sources`; `r2il/src/opcode.rs:913,1043`; `phi.rs:20`; `frame_reach.rs:470` | r2ssa, r2il | Iterator accessors; interned identity. ~1–2% CPU, ~20% fewer allocations (estimate) | confirmed (corrected) — p-memory, p-linux, p-cpu-mac |
| P23 | low | `translate_pcode` makes ~4 heap allocations per p-code op (56% of `aa`'s 24.9M allocations); `Source::read` copies from the mmapped image; `load_instruction_bytes` copies twice | `r2sleigh-lift/src/disasm/mod.rs:2490,2554,3795`; `translate.rs:226`; `vendor/libsla/src/sleigh.rs:555`; `r2s/src/session.rs:72` | r2sleigh-lift, r2il, vendored libsla | ~42% fewer allocations in-repo; ~6–8% of `aa` CPU | confirmed — p-memory |
| P24 | low | Block lifting copies the rest of the block for each instruction: O(L²) bytes, 530 MB per 0pack function (0.33% CPU; a latent cliff) | `r2sleigh-lift/src/disasm/mod.rs:2341` `remaining.to_vec()` | r2sleigh-lift | Borrow, pad only below 16 bytes | confirmed — p-memory |
| P25 | low | Each obligation is 136 B with an 80 B identity and its own `inputs` Vec (14.95 MB block at the 0x62ecf0 peak; ~98k allocations) | `r2ssa/src/obligation.rs:409-421,1080,1119` | r2ssa | ~96 B realistic → ~4.4 MB (3%) | confirmed (corrected) — p-memory |
| P26 | low | Allocator trade-off: mimalloc is fastest, but its footprint is 13–26% above jemalloc on pdd; purge-delay 0 recovers 6–12% (macOS footprint only, RSS unchanged) | `crates/r2s/src/allocator.rs` | r2s | `mi_option_purge_delay` 100 ms: −3–9% footprint, +≤0.5% instructions. Already recorded as PF2/D26 | confirmed (corrected) — p-memory, p-linux |
| P27 | low | ~29 MB of libsla C++ heap is invisible to dhat, alloc-count and the 1.05× heap gate (the RSS gate at 1.3× still sees it) | `r2s/src/allocator.rs`; `vendor/libsla-sys` | r2s + census.py | Report `phys_footprint` next to the Rust heap peak | confirmed (corrected) — p-memory |
| P28 | low | Image tables keep their doubling slack (symbols: 65,536 slots for 22,620) | `r2image/src/lib.rs:601-623,661`; `loader/elf.rs:128`; `loader/mod.rs:116` | r2image | Size exactly at construction; **`shrink_to_fit` raised RSS by 3.3 MB under mimalloc** | confirmed (corrected) — p-memory |
| P29 | low | `R2DEC_TRACE_REFUSAL` makes 0pack 0x62ecf0 run >180 s (sys 101–257 s): whole span maps are printed per root through unbuffered stderr (296 KB lines) | `semantic/shared.rs:2091-2095`; `r2il/src/refusal_evidence.rs:43-55` | r2ssa, r2il | O(1) evidence per root; one write per record | confirmed — p-cpu-mac |
| P30 | low | Trace strings are built eagerly outside `refusal_evidence!` (0.2–0.44% CPU) | `r2ssa/src/deadphi.rs:79-89`; `recover_interface.rs:517-535` | r2ssa | Typed roots; build inside the macro | confirmed — p-linux |
| P31 | low | `MachineBuilder::nodes` grows by doubling during projection (shrunk before the peak; build-time churn only) | `r2ssa/src/machine/mod.rs:3413` | r2ssa | Reserve from a graph bound | confirmed (corrected; GraphInst already exact) — p-memory |
| P32 | medium | The TUI engine thread has no cancellation: an abandoned `axt` (~8 s) or render blocks every pane behind it (7.9 s vs 0.07 s) | `r2s-tui/src/worker.rs:126-136`; `app.rs:561-569`; r2s `visual.rs` never calls `begin_request` | r2s-tui + r2s + r2engine (`ReferenceIndex` ignores control) | Wire the existing `EngineCancellationToken`; newest fetch per slot | confirmed (corrected: the engine API exists) — r2-tui |

### 5.3 Build

| ID | Sev | Cost | Cause | Owner | Measured gain | Status |
|---|---|---|---|---|---|---|
| B1 | medium | libsla-sys compiles ~37 C++ and C files one at a time, at the head of every clean build | `vendor/libsla-sys/Cargo.toml` has no `cc` `parallel` feature | vendor build | Build-script **4–8× faster** (28–57 s → 6–11 s at load 3–19; ~15 s on a quiet machine) | confirmed — p-build |
| B2 | medium | The spec compiler runs at -O0 (build-override default), so the SLA compile costs ~27 s CPU against ~6 s optimised; libsla-sys is built twice | root `Cargo.toml` profiles | workspace Cargo.toml | `[profile.*.package.{libsla-sys,sleigh-compiler}] opt-level=3`: 27 → 6–7 s CPU, total user unchanged, identical .sla files. A global build-override costs +93 s CPU (−) | confirmed (corrected fix) — p-build |
| B3 | low | Every reachable spec is embedded twice in non-LTO release builds (2.47 MB, 12%) | `vendor/sleigh-config/build.rs:55,70,86,102,114,119` emit `pub const` blobs and tables | vendor build / r2sleigh-lift | `static` for the blobs **and** for `SLAS`/`FILES`/`*_DATA` → −2.47 MB (a `static` blob alone still gives 2 copies) | confirmed (corrected fix) — p-build |
| B4 | low | 16 of 23 embedded SLAs are unreachable (2.61 MB, 12.6%) and cost about 51–58% of spec-compile CPU | build.rs compiles every `.slaspec`; `Bundle` references all of `SLAS` | r2sleigh-lift (per-language features) | Slim build −2.62 MB, 44/44 outputs identical | confirmed — p-build |
| B5 | medium | r2ssa → r2sleigh-lift → libsla (D9) | — | r2sleigh-lift split | Estimated −85 s release / −40 s debug critical path (schedule estimate) | confirmed — p-build |
| B6 | low | Release rebuild after a one-line r2ssa edit takes ~300 CPU-s and 1–1.5 min wall; incremental release takes 2.6–19 s but costs +2.9–3.8% instructions | `[profile.release]` not incremental | Cargo.toml | A separate `iter` profile | confirmed (corrected) — p-build |
| B7 | medium | Workspace tests link 81 binaries (2.3 GB); 24 r2engine test files each compile the engine generics (~4.5–6 s user each) | `crates/r2engine/tests/*.rs` | test layout | One binary: 106 → 20 s user, 15 → 9 s wall, 1.6 GB → 120 MB | confirmed (corrected: not link time) — p-build |
| B8 | low | `--all-features` rebuilds the Sleigh chain (MIPS from r2sleigh-lift's own feature, plus alloc-count and dhat) | feature unification | Cargo features | Per-processor spec units | confirmed (corrected) — p-build |
| B9 | low | Release has no LTO: dist is 25% smaller and runs 5.9–6.5% fewer instructions | `[profile.release] lto=false` | Cargo.toml / README | README build line → `--profile dist`, or thin LTO | confirmed — p-build |
| B10 | low | Dependency hygiene: unused `serde_json` (r2types, r2engine), unused `workspace.package` fields, mimalloc unused under dhat-heap, 2 syn majors, 3 hashbrowns, petgraph for one type, 109 home paths in the binary | manifests; `r2ssa/src/cfg.rs` | manifests + r2ssa | Small | confirmed — c-architecture, p-build |

### 5.4 Scaling results

- **pdd vs function size** (330 functions, pumasim + 0pack, minus a base of 1.01G/0.90G): retired instructions vs own instruction count slope **1.00, R² 0.81**; allocations slope 0.92. Against own plus direct-callee instructions (50 functions): slope **0.92, R² 0.91**, so callee closure explains the scatter (p-scaling `fit.txt`). Heap is a flat 9–13 KB per instruction above 100 instructions. Typical cost: ~2.0M retired instructions per machine instruction on x86 (0.74–6.8M gzdoom, 1.0–1.1M r2pay).
- **census.py exponent** (Linux, 80 functions): instructions ^0.90 R² 0.47 (pumasim 0.80/0.34, 0pack 0.99/0.65); **CPU ^1.17 R² 0.09, which is unusable** (single noisy `afl` base, 6 rows floored at 0.1 ms); RSS ^0.60 R² 0.21.
- **afl vs code size** (35 x86-64 ELFs, 632 B–15 MB): slope 0.96, about 5k instructions per text byte. `aa` costs nothing extra over `afl`.
- **Outliers:**
  - pumasim main 0x1dc0a0 (300 instructions → 12.8G; 47 bodies prepared);
  - 0x1e2450 (81 instructions → 6.1G; callee 0x1fafb0 with 5,375 instructions);
  - 0x489690 (197 instructions → 5.5–6.2G; 23 callees);
  - 0x50a9f0 (448 instructions → 8.5G);
  - 0pack wrappers 0x6c2c70 (7 instructions → 78% of decompiling its callee) and 0x58b2a0/0x62ecf0 (oid_to_string as callee, 121 MB heap);
  - gzdoom `_Load_Version_4_5` (39.5M per instruction);
  - r2pay init1 (1 GB);
  - static glibc: an 8-function cluster at ~30G each (`result_reads`→`ReferenceIndex`).
- **Whole-program tail** (1,492 fresh functions, minus `aa`): instructions p50/p90/p99/max 0.10/0.85/5.56/33.07G; RSS p50 60 MB, max 1,017 MB; wall p99 0.68 s, max 2.2 s. No budget or cap refusal fired on any of 330 traced functions. From the source, the optimize loop (`optimize.rs:111-124`) and address provenance (`address.rs:401-423`) budgets trip only after quadratic work and keep a partial result that only the trace shows; this was not observed.

## 6. Tests & CI gaps

| ID | Sev | Gap | Where | Owner | Fix direction | Status / probes |
|---|---|---|---|---|---|---|
| T1 | medium (fin: high) | **`residual-trap` grades nothing that ran before the trap.** 103 of 107 blessed residual-trap records compared no state on any vector, 4 of 4,906 vectors were graded, and the reason is only the helper name. A synthetic wrong global write before a residual grades exactly like a correct one, and so do mixed records (wrong only on trapping vectors). It is latent: the return-patch probe found no hidden `differs` in 18/57 records, and 39 records with mid-body residuals cannot be checked that way | `tests/equiv/gate.py` `classify`/`reason`/`floor`; `tests/equiv/rt/equiv_rt.c` `compare_runs`/`child_fault` | equivalence gate | Snapshot at trap time. Always compare stdout as a prefix; compare memory only for a residual in return position, as stated by pddj evidence (not inferred from DWARF). Ratchet the compared count | confirmed (corrected) — r2-equiv-ci |
| T2 | medium (fin: high) | **Kani (20 harnesses, all `#[cfg(kani)]`), cargo-mutants, machete and udeps run only in local `scripts/quality-gate.sh`; no CI job calls them.** The script exits 127 when tools are missing (by design) | `.github/workflows/ci.yml`; `scripts/quality-gate.sh` | CI | A Kani job (same discovery loop) on full plans; mutants and machete tiered or nightly | confirmed (corrected: Dylint does run) — c-tests |
| T3 | medium (fin: high) | **The Dylint gate:** 87 of 89 lints are warn-only (documented staging); the CI run exits 0 with 19 standing hits (r2dec reads `certificates().switches`, `starts_with("reloc.")`, `display_names` feeding callee identity). **At least 12 r2dec lints, including the gotcha-7 call-target parser lint, are gated on paths deleted in 51b9d6a9 (`fold/op_lower/`, `consumer_*.rs`, …) and cannot fire.** The UI fixtures recreate those dead paths | `tools/dylints/r2sleigh_lints/src/lib.rs` (`is_r2dec_op_lower_path` ~6383); `ci.yml:152` | lint crate + CI | Retarget the path filters; a test that every `contains("crates/…")` path exists; ratchet the warning count; drop "Dylint-enforced" from AGENTS gotcha 7 until it is true | confirmed (corrected counts) — c-tests, c-architecture |
| T4 | medium | **The radare2 differential gate (`diff_r2.py`) never runs in CI and is red today:** 16 unjudged disagreements and 7 stale judgments on the first 30 ELF bins. Values mode ignores values only radare2 reports (PE `is`: 243/275 silent misses scored as agreement) and compares as a flat set, so column swaps pass (BatteryLife). It covers only `px pd ie iS is` | `scripts/diff_r2.py` `differences()`, `COMMANDS`; `scripts/diff_r2_judged.toml` | gate | A CI job with pinned radare2; pair values by column; count radare2-only values; add `ir iz iee i f`; judge the r2s-right classes (Mach-O odd ARM data symbols, .NET entries, Lab01-03, SHN_ABS, fat slice) | confirmed — c-tests, c-info |
| T5 | medium | **The equivalence gate renders only stripped binaries, so the DWARF route is never executed** (W50's sext trap appears only with `-g`) | `tests/equiv/build.py:90-115`; `run_equiv.py:148` | equivalence gate | A `-dwarf` route dimension in records and the baseline | confirmed (corrected: `dispatch` is not a divergence) — c-decompiler, r2-equiv-ci |
| T6 | medium | **certify_render.py** grades only `is` FUNC symbols (98 of 1,492 functions: 0 on stripped glibc, true32 and Mach-O; 25 functions in the CI shape). Block-scope `extern` reads are flagged as undefined (rv_O0g and anal-globals fail). Stripped binaries pass with "rendered 0". It cannot see invented arguments. The lint is O(declarations × lines) | `scripts/certify_render.py` `functions()` (61), `DECLARATION` (96-99), `undefined_reads` | gate | Enumerate with `aflj`; skip `extern`; fail when 0 are rendered; a typed arity check against the resolved prototype and pddj's unproven-arguments fact | confirmed — c-decompiler, r2-whole-program |
| T7 | medium | **`r2il::eval` executes no Float\*, Guarded, Linked or CallOther ops** (by design), and `tests/oracle.rs` runs no AArch64 code, so none of W15–W22 could be caught in-tree | `crates/r2il/src/eval.rs:396-449,656-698`; `crates/r2engine/tests/oracle.rs` | r2il + r2engine tests | One IEEE evaluator (shared with r2rewrite's); Guarded and Linked memory; AArch64 literals in oracle.rs; the probe's native harness (`r2-aarch64/harness`, `oracle/`) as a starting point | confirmed (corrected: the division part is W22) — r2-aarch64 |
| T8 | medium | **Large under-tested production code:** `r2types/src/analysis/arrays.rs` 14.6% coverage (on the array-certificate render path), `r2sleigh-lift/src/text.rs` 17%, `certificates/expressions.rs` 51%. Public APIs with zero callers: `memory_mirrored_carriers`, `register_identity_census` | llvm-cov `c-tests/cov.json` | r2ssa, r2types, r2image | Behaviour tests through the pipeline (external struct-pointer indexing, loop-phi certificates, PE32, Mach-O threaded); delete dead APIs | confirmed — c-tests |
| T9 | low (fin: medium) | Tests exercise a dhat-allocator r2s (+10.5% instructions). Clippy and Dylint never compile the mimalloc or Counting allocator. Nothing enforces the `allocations:` line | `crates/r2s/src/allocator.rs:4-14`; `ci.yml:113,123` | r2s + CI | Explicit feature sets per allocator; an alloc-count test | confirmed (corrected) — c-tests |
| T10 | low (fin: medium) | Silent skips on macOS: review.rs `ulimit -v` fails and the test still passes; pddj's GCC check finds Apple clang and skips with no message | `crates/r2s/tests/review.rs:26-38`; `pddj.rs:323-330,445` | r2s tests | Measure peak RSS portably; print an explicit skip, or fail when `R2S_REQUIRE_GCC` is set | confirmed — c-tests |
| T11 | low | The `equivalence-harness` job runs a hand-written list of 8 test classes (TargetTests never runs). SelfTestSuite and PipelineTests were removed on purpose (ROADMAP G); the comment is stale | `ci.yml:387-398` | CI | `unittest discover` with named exclusions | confirmed (corrected) — c-tests |
| T12 | low | `px` has no happy-path test; diff_r2 uses only `px 64`; the default counts differ (px 64 B vs radare2's 256; pd 16 vs 80) | `commands.rs:1239` `hexdump` | r2s | A `tests/db` golden; decide the default | confirmed — c-tests |
| T13 | low | r2sleigh-cli has no spawn test (7 command functions never run) | `crates/r2sleigh-cli/src/main.rs` | r2sleigh-cli | `tests/cli.rs` | confirmed — c-tests |
| T14 | low | All 5 ignored doctests fail to compile when un-ignored (3 have real API drift) | `r2sleigh-lift/src/lib.rs:14`; `disasm/mod.rs:2085,2135`; `sleigh.rs:428,460` | r2sleigh-lift | `no_run` with a hidden `main` | confirmed (corrected) — c-tests |
| T15 | low | Suite CPU is dominated by spawns of a debug, dhat-allocating r2s (golden 175 s CPU; the pddj review test 45 s); the existing `[profile.ci]` is unused for tests | `ci.yml` nextest step | CI | `--cargo-profile ci` (4–5× on spawning tests) | confirmed (corrected: CPU-bound, not one critical test) — c-tests |
| T16 | low | No nextest config: a hung test waits out the 20-minute job | `.config/nextest.toml` absent | CI | `[profile.ci] slow-timeout terminate-after` | confirmed — c-tests |
| T17 | low | The Dylint crate's `Cargo.lock` is gitignored, and cargo-dylint is unpinned | `.gitignore:5`; `ci.yml` install-action | lint crate / CI | Commit the lock; pin versions | confirmed — c-tests |
| T18 | low | `tests/test_setup_corpus.py` runs in no gate (`merge_audit.py` is a tool, not a test) | `ci.yml` Harness contracts | CI | `unittest discover -s tests` | confirmed (corrected) — c-tests |
| T19 | low | run_coverage.sh always rebuilds (it cannot measure a given binary); the baseline is stale (5 narrowed gaps in gated pinned cells); compiled cells are ungated on any clang other than 17 (siphash24 went rendered→refused under clang 21 and was not gated) | `tests/coverage/run_coverage.sh:42`; `report_coverage.py:223,277,308` | coverage gate | `--r2s`; re-bless; pin clang-built cells | confirmed — r2-whole-program |
| T20 | low | Baseline causes that do not describe their record pass the ratchet: `sext` carries `gate_three`'s setcc text, and two placeholder causes exist | `tests/equiv/baseline*.json`; `gate.py:557` | equivalence gate | A structured owner/site tag; a placeholder blocklist | confirmed — r2-equiv-ci |
| T21 | low | `frame_agree.py` runs in no gate (0/582 offsets today), and ROADMAP:105 says P4 is done with "afv agrees with pdd" | `scripts/frame_agree.py`; ROADMAP.md | gate + ROADMAP | Ratchet it, or reopen P4 | confirmed — r2-equiv-ci |
| T22 | low | Shard artifacts keep no rendered C (`work/**/rendering.c` is not uploaded) | `ci.yml` shard upload | CI | Add `code` to the records | confirmed — r2-equiv-ci |
| T23 | low | census.py's exponent CPU-time fit is unusable (R² 0.09), and its size axis ignores callees; `afi` sizing costs ~2.7 min | `scripts/census.py:325-387` | gate | Median base, or drop CPU; `ninstrs` from a walk-only count | confirmed (corrected) — p-linux |

## 7. Refuted findings (don't re-investigate)

| Probe | Claim | Why refuted |
|---|---|---|
| c-architecture | "Entity-keyed map debt is 106 allowances, larger than ROADMAP's LX2 count, and omits r2types" | Only 44 allowances carry a `debt:` reason, which matches ROADMAP exactly. The other 62, including all 7 in r2types, are scoped exceptions with stated reasons. ROADMAP's 35/19/11 counts sites (65), not items |
| p-memory | "Prepared semantic facts take 4–6× the bytes of the IR and graph" | The `prepare-held` "function+graph" field is the net change in live bytes across `Prepared::seal`, after `drop_operations` frees 5.3 or 12.4 MB. Absolute sizes: facts ≈ IR (1.06× and 0.91×). The evidence line is misleading (see W63) |
| r2-equiv-ci | "Aggregate-return definitions render as a single uint64_t and drop RDX; the gate hides it" | The repro omits `aa`. Every gate session runs `aa` first, and with `aa` all 16 records render as `__uint128_t` with both halves; the gate's proof totals match the `aa` renderings. What remains: before `aa`, the callee shows RAX with an "open" note (documented), and `spec.py` does not grade aggregate returns (a low coverage gap) |
| r2-tui | "The graph pane and agf draw a refused walk of data as a CFG (bomb 0x4022b4)" | bomb's `.rodata` sits in the r-x LOAD0 segment, so the bytes are executable per the container. radare2 `af @ 0x4022b4` builds the same function (213 afb lines). Drawing the plain walk under a refusal note is the documented `FunctionGraph` contract. What remains: the refusal reason is the opaque `InvalidFunctionImage` |

Sub-claims refuted inside confirmed findings, recorded so nobody chases them:
- A **summary-grade callee tier** saves at most ~3 points (ROADMAP SM1). A memo of `producers` costs +72% RSS. `shrink_to_fit` on image tables raises RSS under mimalloc. Routing `start()` through `Names` loads the decoder (2.7×).
- **Root causes that were wrong as filed:**
  - the 0pack span-map blow-up is intrinsic to 0x58e3d0 (not callee 0x4691ec);
  - `aa` does not re-analyse every function (only the newest-held one);
  - the `fcn.00000000` seed is a direct `call 0x0`, not a GOT slot;
  - `diff_r2_judged` PE "agree" counts are 243, not 241;
  - `/as` vetoes come from 0x41a870 and 0x490220, not 0x41a5b0;
  - `ldpsw` is already fixed upstream.
- **Claims that do not hold:**
  - `pdf` is not "the only correct view" for the Thumb bug;
  - fccmp is not refused "because of flag writes" (the cause is the nested CBRANCH);
  - `stxp` is correct (only `stlxp` is wrong);
  - ldursh W sign-extends (it does not zero-extend);
  - `FLOAT_ROUND` is not ties-away;
  - eval stopping on division by zero is correct (W22's cause is the speculation);
  - "afl lists why each function is believed" is false only in the README.

## 8. Coverage

**Exercised.**
- **Formats and architectures:** about 3,000 corpus files (radare2 test bins: elf 323, mach0 146–313, pe 275–314, coff, fuzzed 610, plus other formats) and the repo fixtures. x86-64, i386, AArch64 (ELF and Mach-O arm64/arm64e), ARM32/Thumb, RV64.
- **Verbs:** all 36 verb forms × 23 hostile inputs (1,725 runs); ~6,000 fuzz/hostile runs with 0 signals and 0 timeouts; ~90 radare2 commands on one binary.
- **Differential:** c-info `infodiff` (~2,700 verb runs per tool); diff_r2 on 3 corpora; ~16k pd instruction pairs; afb on 166 binaries; afl against radare2 on 41 binaries; `ax` on 13.
- **Decompile:** 366 fixture functions (census twice); 1,492 whole-program functions fresh plus 5 sessions plus a 6,406-request libc session; ~1,200 language-corpus functions (C++, Rust, Go, Zig, ObjC); 4 large functions by hand.
- **Semantics:** 14 rv_O0g functions × 20k vectors; manual_limits O0+O2 × 20k; 112,500 AArch64 native-oracle runs (375 cases).
- **Gates:** the equivalence CI records (1,512) and 4 contabo runs (repro shard, return patch, DWARF, symtab); certify_render; run_coverage; frame_agree and differential_truth for the first time.
- **Profiling and build:** samply (~40 profiles), Linux perf + heaptrack + cachegrind; dhat (7 profiles), alloc-count (18), allocator benchmark (150 runs), jemalloc profile; clean, incremental, LTO and experiment builds.
- **Test suite:** 2,414 tests ×7 runs for flakiness (0 flaky); Kani (20/20 pass); TSan on r2s-tui.
- **Visual mode:** ~3,400 scripted keys.
- **Determinism checks** (all byte-identical):
  - 90 cases × 5 runs;
  - 179 functions × 4 call orders;
  - 1,456 functions session vs fresh;
  - libc pass 1 vs pass 2 (3,203);
  - TUI settled runs ×5;
  - Mac vs Linux pdd md5.

**Not covered.**
- **Architectures:** MIPS, PPC and RV32 analysis (refused); AArch64 Rust/Go/C++ rendering; SVE, crypto, PAC, MTE, ldr-literal and FPSR flags; i386 beyond 81 small functions.
- **PE:** delay and bound imports, .NET, MSVC C++ EH; WinCE ARM.
- **Real-world shapes:** C++ catch blocks beyond one cleanup pad; DWARF struct layouts against llvm-dwarfdump; Go ABIInternal beyond 30 functions.
- **Tooling coverage:** the Linux-only equivalence suites on the Mac; cargo dylint over the whole workspace in the c-tests probe (c-architecture did run it); TSan over the real `V` with libsla; real terminal emulators (pyte only); hex write flows.
- **Performance:** heap peaks per function across the corpus; patched builds measuring most proposed perf fixes (only W/P2, P6, P8 and B1–B4 were measured); `census.py exponent` on aarch64.
- **Other:** whether each live-value-producer refusal (W43) is individually justified; how the 171 GOT calls with no r2abi arity break down.

## 9. Recommended plan (ordered)

Each item names its owner, says why it comes first, and gives a rough size (S ≤ 1 day, M ≤ 1 week, L > 1 week). Every fix lands at the owner, with a behaviour test at the layer the user exercises, no fabricated C, and deterministic ordering (AGENTS.md).

1. **r2image container facts that make whole file classes wrong (W1, M1, W5 container half, M4, W33, M6, M7).** Owner: r2image (+ r2abi `EntryKind`/`WriteKind`). Why first: these are facts every view consumes. Fixing them changes the corpus more than anything else (61% of PE, all ET_REL, section-less ELF) and is the easiest kind of fix to verify (container in, statement out).
   - PE read gate on "has any access";
   - per-IAT-slot `WriteKind::Import` plus export symbols;
   - ET_REL relocation records and the CFI placed base;
   - program-header fallback with a typed `SectionTableInvalid`;
   - one Mach-O entry derivation;
   - a single DT_SYMTAB reader shared by symbols and relocations;
   - PT_DYNAMIC init arrays;
   - COFF `bits` from the address size.

   Size: L (split into ~7 S/M PRs).
2. **r2engine function-start ownership and entry hygiene (W4/D1, W29, W30, W45/D2, W6 capture refusal → record, D4).** Owner: r2engine. Why: one index of container-stated starts fixes absorption, phantom functions and the containing-function query for the verbs and the TUI at once, and capture or convention refusals become typed records. Size: M.
3. **Vendored AArch64 Sleigh plus lift normalisation (W15–W21, W16 resync, M2, W20, W23 one row, W22, W25 alignment, M13).** Owner: r2sleigh-lift / vendor/sleigh-config (r2il for `is_speculatable_value`). Why: AArch64 is graded, and these bugs feed confident wrong C. Gate them with T7 first so each fix has an oracle test. Size: M (T7) + M.
4. **Call-boundary truthfulness (W7, W8/D3, W9, W10, W11, W12, W14, M3).** Owner: r2ssa (arity `Exact`/`AtLeast`, float slots, a bottom-up SCC fixpoint), r2engine (`CallSlot` identity, i386 Placement), r2abi (ObjC, math.h rows), r2dec (stop inventing `(void)`; the gap names its callee). Why: invented arguments are an AGENTS blocker and the most common wrong C in the corpus. Size: L.
5. **r2ssa algorithmic hot spots (P6, P5, P2, P3, P19, P20).** Owner: r2ssa / r2rewrite. Why: each is a quadratic with a measured or measurable fix, output-neutral by construction. Skipping constants in liveness (−45% RSS) and the spans index (−12–13% instructions) are already proven. Size: M.
6. **Reuse in the query database (P8 tombstone, P1/SM prepare-once, P10 afb from `Walked` and the held listing, P7 index from survey facts, P11 lazy modes and machines, P12 lazy DWARF, P15).** Owner: r2engine (+ r2image for the DWARF reader). Why: this is the design lever after the algorithms; follow ROADMAP SM/D23/LF, not a separate summary grade. Size: L.
7. **Gates that would have caught the above (T1, T3, T4, T5, T6, T2, T19–T21).** Owner: tests/equiv, scripts, CI, the lint crate. Why: several confirmed bugs passed green gates; fix the gates before their baselines are re-blessed. Size: M.
8. **Build (B1, B2, B3, B4, B7, D9/B5).** Owner: vendor build.rs, root Cargo.toml, r2sleigh-lift split. Why: cheap and independent. B1+B2 together cut ~40–60 s of clean-build critical path; B3+B4 remove ~5 MB from the binary. Size: S each (D9: M).
9. **Rendering consistency and types (W46, W47, W49, W50, W13, D5, D7, D13, M16, M17).** Owner: r2types (one signature and declaration fact), r2ssa (demand root, promotion, lane roots), r2abi (narrow-argument row). Size: M.
10. **Visual mode and surface (W56, W57, W58, W59, W54, W55, P32, W62, M19, W52, W53, W60, W61, D14, M9–M11).** Owner: r2s-tui (state and keys, consuming engine facts), r2s (EPIPE, exit code, parse), r2image (mmap → owned bytes). Size: M.
11. **Docs and baselines (M22, T20, T21, ROADMAP P4 status, AGENTS gotcha 7).** Owner: docs. Size: S.

## Appendix A — Repro commands (verbatim from the probes)

Run these from the repo root `<repo>` unless the command `cd`s elsewhere. `$E` = `../radare2/test/bins/elf`. `$P` = `$AUD/r2-aarch64`. `$A` is set by each command where it is used. For merged rows, the probe whose repro is kept is named in brackets.

### Correctness (W)

**W1** [c-robustness]
```
cd <repo> && target/release/r2s -qc 'iS;pd 2' ../radare2/test/bins/pe/normal64.exe; ~/.local/bin/r2 -e scr.color=0 -qc 'iS;pd 2' ../radare2/test/bins/pe/normal64.exe; target/release/r2s -qc 'wx 90' ../radare2/test/bins/pe/normal64.exe
```
**W2** [c-listing]
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'pd 6 @ 0x46e; ?e --fresh--; pd 3 @ 0x476' $E/special-sym-with-dot.bin
target/release/r2s -qc 'pdf @ main; afb @ main; pdd @ main' $E/special-sym-with-dot.bin
target/release/r2s -qc 'pd 4 @ 0xf90; ?e --fresh--; pd 2 @ 0xf96' $E/libverifyPass.so
target/release/r2s -qc 'afb @ sym.Java_com_app_ndh_NDHActivity_print; pdil @ sym.Java_com_app_ndh_NDHActivity_print' $E/libverifyPass.so | grep -A4 'Block 0xfae'
target/release/r2s -qc 'pd 4 @ 0x7474' $E/r2pay-arm32.so
target/release/r2s -qc 'pd 3 @ 0x8000034; ?e --fresh--; pd 2 @ 0x8000038' $E/arm-abs-thumb-blx.o
objdump -d --triple=thumbv7 --start-address=0xf90 --stop-address=0xfa0 $E/libverifyPass.so
# forward blx is fine: target/release/r2s -qc 'pd 3 @ 0x1885a' $E/libarm.so
```
**W3**
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 's 0x2a338; wx fff7fcef; pd 3 @ 0x2a338; ?e --; pd 2 @ 0x2a33c' $E/libarm.so
# control (forward target): target/release/r2s -qc 's 0x2a338; wx 00f00ce8; pd 2 @ 0x2a338' $E/libarm.so
```
**W4** [c-analysis; c-listing variant below]
```
timeout 60 target/release/r2s -qc 'pd 3 @ 0x3ff0; afl~0x00003ff0,0x00003b10; afi 0x3ff0~size,minaddr,num-bbs; afb 0x3ff0' ../radare2/test/bins/elf/true; timeout 60 target/release/r2s -qc 'pd 3 @ 0x65b0; afl~65b0,6580; pdd 0x65b0' ../radare2/test/bins/elf/ls; timeout 120 target/release/r2s -qc 'axt 0x44a230' ../radare2/test/bins/elf/static-glibc-2.27 | grep 0x419228
```
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'afl~0x00034640; afb @ sym.coproc_flush; ?e --; afb @ sym.coproc_reap; ?e --; afb @ sym.coproc_dispose' $E/bash
target/release/r2s -qc 'pdd @ sym.coproc_flush' $E/bash | head -30
objdump --dwarf=frames $E/bash | grep 'pc=00034640'
target/release/r2s -qc 'afb @ 0x65b0; pdd @ 0x65b0' $E/ls
target/release/r2s -qc 'afl~0x00005fd0; afb @ 0x3b40' $E/gnome-extensions | grep -E '0x00004708|^0x00005fd0'
python3 <audit>/c-listing/absorb2.py $E/ls
```
**W5** [c-architecture; ET_REL FDE from c-analysis; COFF/ET_REL ir from c-info]
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; B=../radare2/test/bins/elf/x86_64-common-code.o; timeout 60 target/release/r2s -qc 'ir; pdf; pdd' $B; timeout 60 ~/.local/bin/r2 -e scr.color=0 -qc 'ir; pd 5 @ 0x08000040' $B; timeout 60 target/release/r2s -qc 'pdf' ../radare2/test/bins/elf/i386-crel-implicit.o; for f in ../radare2/test/bins/elf/*.o ../radare2/test/bins/elf/*.ko; do echo "$f r2s=$(timeout 60 target/release/r2s -qc ir $f 2>/dev/null | grep -c '^0x') r2=$(timeout 60 ~/.local/bin/r2 -e scr.color=0 -qc ir $f 2>/dev/null | grep -c '^0x')"; done
```
```
timeout 60 target/release/r2s -qc 'afl' ../radare2/test/bins/elf/bfile_o | head -5; timeout 60 target/release/r2s -qc 'afl' ../radare2/test/bins/elf/bfile_o | wc -l; timeout 30 target/release/r2s -qc 'afi 0x20; iS~eh_frame' ../radare2/test/bins/elf/bfile_o; ~/.local/bin/r2 -e scr.color=0 -qc 'aaa;afl' ../radare2/test/bins/elf/bfile_o | wc -l
```
**W6** [r2-whole-program; minimal repro from c-robustness below]
```
target/release/r2s -qc 'aa; pddj @ 0x0041be10' ../radare2/test/bins/elf/static-glibc-2.27; echo rc=$?
R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'aa; pdd @ 0x00400570' ../radare2/test/bins/elf/static-glibc-2.27 2>&1 | grep function-image
target/release/r2s -qc 'pd 2 @ 0x420335' ../radare2/test/bins/elf/static-glibc-2.27
target/release/r2s -qc 'aa; afb @ 0x00400570' ../radare2/test/bins/elf/static-glibc-2.27 | grep 0x0042033
target/release/r2s -qc 'aa; pddj @ sym._int_free' ../radare2/test/bins/elf/libc-2.32.so
```
```
S=<audit>/c-robustness/src; printf '    .text\n    .globl f\n    .type f,@function\nf:\n    .byte 0xeb, 0xff, 0xc0\n    ret\n    .size f, .-f\n' > $S/ov.s && clang -target x86_64-linux-gnu -c $S/ov.s -o $S/ov.o && cd <repo> && R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'pdf @ sym.f;pdd @ sym.f;afb @ sym.f' $S/ov.o
```
**W7**
```
target/release/r2s -qc 'aa; afi @ sym.shape_bool_caller' tests/coverage/pinned/shapes_gcc_x64_O0 | grep signature
target/release/r2s -qc 'aa; pdd @ main' tests/coverage/pinned/shapes_gcc_x64_O0 | grep shape_bool_caller
~/.local/bin/r2 -e scr.color=0 -qc 'pd 5 @ 0x40240f' tests/coverage/pinned/shapes_gcc_x64_O0
target/release/r2s -qc 'aa; afi @ sym.crc32_init; pdd @ main' tests/coverage/pinned/hashes_gcc_x64_O2 | grep -E 'signature|crc32_init'
target/release/r2s -qc 'aa; pdd @ main' tests/fixtures/rv_O2 | grep -E 'dispatch\(|fill\('
target/release/r2s -qc 'aa; pdd @ sym.dispatch' tests/fixtures/rv_O2
target/release/r2s -qc 'aa; pdd @ 0x1549' tests/fixtures/rv_O0g_stripped | grep fcn_1362
target/release/r2s -qc 'aa; pdd @ 0x1362' tests/fixtures/rv_O0g_stripped | grep fcn_1362
target/release/r2s -qc 'aa; pdd @ sym.dispatch; afv @ sym.dispatch' tests/fixtures/rv_O0g
target/release/r2s -qc 'aa; pdd @ entry0; pdd @ 0x401000' tests/fixtures/syscalls_static_O2
```
**W8** [r2-whole-program; Rust/Mach-O variant from r2-render-corpora]
```
target/release/r2s -qc 'aa; pdf @ 0x6ee0' ../radare2/test/bins/elf/ls | grep strrchr
target/release/r2s -qc 'aa; pdd @ 0x6ee0' ../radare2/test/bins/elf/ls | grep -n '(\*)('
target/release/r2s -qc 'ir' ../radare2/test/bins/elf/ls | grep -w strrchr
target/release/r2s -qc 'aa; pdd @ 0x65c0' ../radare2/test/bins/elf/ls
```
```
target/release/r2s -qc 'pd 1 @ 0x7c8a; ir~39fe0' ../radare2/test/bins/elf/dwarf_rust_bubble
target/release/r2s -qc 'pdd @ 0x7c70' ../radare2/test/bins/elf/dwarf_rust_bubble | grep -A1 '0x39fe0U'
target/release/r2s -qc 'ir~msgSend; pdd @ 0x1000031f0' ../radare2/test/bins/mach0/InsecurePasswordStore | grep -E 'ADD_64|0x10000c008U\);' | head -3
```
**W9** [c-missing; afv/i386 from r2-render-corpora]
```
timeout 60 target/release/r2s -qc 'pdf @ sym.parell;pdd parell' ../radare2/test/bins/elf/crackme0x05
```
```
target/release/r2s -qc 'afv @ sym.imp.printf; afi @ sym.imp.printf; pdd @ sym.imp.printf' ../radare2/test/bins/elf/crackme0x05
```
**W10**
```
target/release/r2s -qc 'pd 3 @ 0x100000e75; aa; pdd @ main' ../radare2/test/bins/mach0/hello-objc | grep -E 'rdx|objc_msgSend'
grep -n 'objc_msgSend\|objc_storeStrong' -A4 crates/r2abi/data/types.sdb.txt | head -20
target/release/r2s -qc 'pdd @ 0x1000028d0' ../radare2/test/bins/mach0/InsecurePasswordStore | grep objc_storeStrong
```
**W11**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdd @ sym._use_tan' $P/probe/libm_arm; target/release/r2s -qc 'aa;pdd @ sym._use_tan' $P/probe/libm_x86; target/release/r2s -qc 'aa;pdd @ sym._scale;pdd @ sym._rnd' $P/probe/fp_arm; target/release/r2s -qc 'aa;pdd @ 0x00077d14' ../radare2/test/bins/elf/r2pay-arm64.so | grep -n 'tan('
```
(verifier: `sym._rnd` does not exist in fp_arm; the remaining commands reproduce.)
**W12** [r2-render-corpora; AArch64 variant from r2-aarch64]
```
target/release/r2s -qc 'pdf @ 0x1258; pdd @ 0x1258' ../radare2/test/bins/elf/demangle-test-cpp | grep -vE 'static inline|__builtin|\(void\)site'
target/release/r2s -qc 'pdf @ 0x1000028d0; pdd @ 0x1000028d0' ../radare2/test/bins/mach0/InsecurePasswordStore | grep -E 'rdx|rsi|setManagedObjectContext__\(|residual|proof'
target/release/r2s -qc 'afv @ 0x23fdf0; pdf @ 0x23fdf0' ../radare2/test/bins/elf/pumasim | head -14
```
```
P=<audit>/r2-aarch64; cd <repo>; for b in gap_arm64_O0 gap_arm64_O1 gap_x86_64_O1; do target/release/r2s -qc 'aa;pdd @ sym._second_only' $P/probe/$b; done; target/release/r2s -qc 'aa;pdd @ sym._iso8859_9_wctomb' ../radare2/test/bins/mach0/gzdoom.arm_64.1
```
**W13**
```
D=$(mktemp -d); target/release/r2s -qc 'aa; pddj @ sym.sext' tests/fixtures/rv_O0g | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])' > $D/r.c; printf '#include <stdint.h>\n#include <stdio.h>\nint16_t sext(int8_t);\nint main(void){printf("%%d\\n",sext(5));return 0;}\n' > $D/t.c; clang -w $D/t.c $D/r.c -o $D/t && $D/t; echo rc=$?
D=$(mktemp -d); target/release/r2s -qc 'aa; pddj @ sym.floor_at' tests/fixtures/float_compares_zig_x86_64_O2g | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])' > $D/r.c; printf '#include <stdio.h>\ndouble floor_at(double,double);\nint main(void){printf("%%f\\n",floor_at(3.0,1.0));return 0;}\n' > $D/t.c; clang -w $D/t.c $D/r.c -o $D/t && $D/t; echo rc=$?
target/release/r2s -qc 'aa; pdd @ sym.sext' tests/fixtures/rv_O0g
target/release/r2s -qc 'aa; pdd @ 0x144c' tests/fixtures/rv_O0g_stripped
~/.local/bin/r2 -e scr.color=0 -qc 'aa; pdf @ sym.floor_at' tests/fixtures/float_compares_zig_x86_64_O2g
target/release/r2s -qc 'aa; pdd @ main' tests/fixtures/float_calls_zig_x86_64_O2g
```
**W14**
```
target/release/r2s -qc 'aa; pdd @ sym.vfold' tests/coverage/pinned/shapes_gcc_x64_O0 | head -30
target/release/r2s -qc 'aa; pdd @ sym.shape_variadic_local' tests/coverage/pinned/shapes_gcc_x64_O0
~/.local/bin/r2 -e scr.color=0 -qc 'pd 22 @ 0x4013c9; pd 18 @ 0x401515' tests/coverage/pinned/shapes_gcc_x64_O0
D=$(mktemp -d); target/release/r2s -qc 'aa; pddj @ sym.shape_variadic_local' tests/coverage/pinned/shapes_gcc_x64_O0 | python3 -c 'import json,sys;print(json.load(sys.stdin)["code"])' > $D/r.c; printf '#include <stdio.h>\n#include <stdint.h>\nuint64_t vfold(uint32_t c,uint64_t a,uint64_t b,uint64_t d,uint64_t e,uint64_t f){return c+a;}\nuint64_t shape_variadic_local(uint64_t,uint64_t);\nint main(void){printf("%%llu\\n",(unsigned long long)shape_variadic_local(1,2));return 0;}\n' > $D/t.c; clang -w $D/t.c $D/r.c -o $D/t && $D/t; echo rc=$?
```
**W15**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._prev_char;pdd @ sym._prev_char;pdd @ sym._prev_short' $P/probe/probe2   # source: int32_t prev_char(const int8_t *p){return p[-1];} -> ldursb w0,[x0,#-1]
# supporting oracle: $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt ldursb_w | head -12
```
**W16**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._pairsum;pdd @ sym._pairsum' $P/probe/probe_nolse   # source: (int64_t)p[2]+(int64_t)p[3] -> ldpsw x8,x9,[x0,#8]
# $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt ldpsw_x | head
```
**W17**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._cas32;pdd @ sym._cas32' $P/probe/probe_nolse   # source: atomic_compare_exchange_strong(p,&e,n); return e;  -> casal w1,w2,[x0]; mov x0,x1
# $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt ldset_w | head; ... ldsminh
```
**W18**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._rnd;pdd @ sym._rnd;pdil @ sym._flo;pdil @ sym._tou;pdd @ sym._tou' $P/probe/probe_nolse   # _rnd = lround(x) -> fcvtas x0,d0; _flo = floor(x) -> frintm d0,d0; _tou = (uint64_t)x -> fcvtzu
# $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt frintm_d | head; ... fcvtzu_xd, fcvtas_xd, fmax_d
```
**W19**
```
P=<audit>/r2-aarch64; $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt ldaxp_stlxp | head -30   # stlxp w4,x2,x3,[x9] = 0xc8248d22
```
**W20**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._fl;pdd @ sym._fl' $P/probe/probe2   # source: int fl(float a,float b,int x){return x>3 && a<b;} -> cmp w0,#3; fccmp s0,s1,#0,gt; cset w0,mi
```
**W21**
```
P=<audit>/r2-aarch64; $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt fmadd_d | head -12; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._fma3' $P/probe/probe_nolse
```
**W22**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._sdv;pdd @ sym._sdv' $P/probe/probe_nolse   # int32 a/b -> sdiv w0,w0,w1
# $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt sdiv_w | head -3
```
**W23**
```
target/release/r2s -qc 'pdf @ 0x25930' ../radare2/test/bins/elf/dwarf_rust_bubble | tail -2
target/release/r2s -qc 'afi @ 0x25930' ../radare2/test/bins/elf/dwarf_rust_bubble | grep -E 'signature|noreturn|end-bbs'
target/release/r2s -qc 'pdd @ 0x5270' ../radare2/test/bins/elf/dwarf_rust_bubble | grep -A1 panic_bounds_check17h8a320183c120246fE\(0x
grep -n 'UD2' vendor/sleigh-config/ghidra/Ghidra/Processors/x86/data/languages/ia.sinc
```
**W24** [c-listing; DWARF noreturn from r2-render-corpora]
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'pdf @ sym.ZopfliCalculateBitLengths; afb @ sym.ZopfliCalculateBitLengths' $E/pigz | tail -5
~/.local/bin/r2 -e scr.color=0 -qc 'aa; afi @ sym.ZopfliCalculateBitLengths~size; pdf @ sym.ZopfliCalculateBitLengths~assert' $E/pigz
target/release/r2s -qc 'afb @ 0x4070' $E/ls | tail -3
target/release/r2s -qc 'pd 3 @ 0x5ab5' $E/ls
grep -h -E '^func\.(__)?(assert_fail|cxa_throw)\.noreturn' crates/r2abi/data/*.sdb.txt
```
```
/Library/Developer/CommandLineTools/usr/bin/llvm-dwarfdump --debug-info ../radare2/test/bins/elf/dwarf_rust_bubble | grep -B9 -A1 'linkage_name.*_ZN4core9panicking5panic17h871cd04a3fc0d7bcE' | grep -E 'low_pc|noreturn'
target/release/r2s -qc 'afi @ 0x25930; afi @ 0x10930; afi @ 0x23c30' ../radare2/test/bins/elf/dwarf_rust_bubble | grep -E '^name|noreturn|signature'
```
(verifier: use `-A6` on the dwarfdump grep to see `DW_AT_noreturn`.)
**W25**
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'pd 6 @ 0x112fc' $E/arm1.bin
objdump -d --start-address=0x112fc --stop-address=0x11310 $E/arm1.bin
target/release/r2s -qc 'pd 5 @ 0x8ca4' $E/gnome-extensions
grep -n 'alignment: 1' crates/r2il/src/serialize.rs; grep -rn '\.alignment' crates/*/src | grep -v test
grep -h ^BYTES <audit>/c-listing/pd/*.log | grep 'r2s=.. r2=........$'
```
**W26**
```
source ~/.cargo/env; E=../radare2/test/bins/elf
xxd -s 0x24 -l 4 $E/arm-thumb-movw-be.o   # e_flags 05000000: EABI5, no BE8 bit
target/release/r2s -qc 'i~endian; afl; pd 6 @ 0x8000034' $E/arm-thumb-movw-be.o
objdump -d $E/arm-thumb-movw-be.o | tail -12
~/.local/bin/r2 -e scr.color=0 -qc 'pd 6 @ 0x8000034' $E/arm-thumb-movw-be.o
```
**W27**
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'pd 2 @ 0x8048405; pd 1 @ 0x80485bb' $E/crackme0x05
target/release/r2s -qc 'pd 2 @ 0x804f45a' $E/level01
objdump -d --start-address=0x80485bb --stop-address=0x80485c1 $E/crackme0x05
```
**W28**
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'pd 1 @ 0x26568; pd 1 @ 0x31ac4' $E/arm1.bin
objdump -d --start-address=0x26568 --stop-address=0x2656c $E/arm1.bin
```
**W29** [c-listing; fuzzed initialisers from c-info]
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'afl~fcn.00000000; afi @ 0' $E/crackme0x05
objdump -d --start-address=0x804846f --stop-address=0x8048474 $E/crackme0x05
target/release/r2s -qc 'afl' $E/fuzzed_elf9 | awk '$2==0' | wc -l
target/release/r2s -qc 'afl' $E/bfile_o | awk '$2==0' | head
~/.local/bin/r2 -qc 'aa; afl~0x00000000' $E/crackme0x05
```
```
source ~/.cargo/env; cd <repo>; B=tests/fixtures/fuzzed_elf9; timeout 60 target/release/r2s -qc 'iee' $B | head -6; timeout 60 target/release/r2s -qc 'iee' $B | wc -l; timeout 120 target/release/r2s -qc 'afl' $B | head -3; timeout 60 target/release/r2s -qc 'iS~ARRAY,DYNAMIC' $B; timeout 60 ~/.local/bin/r2 -e scr.color=0 -qc 'iee' $B
```
(verifier: the fuzzed file lives at `../radare2/test/bins/fuzzed/elf9`; `elf/fuzzed_elf9` does not exist.)
**W30**
```
timeout 60 target/release/r2s -qc 'pd 4 @ 0x1000061ac; afb 0x1000061ac' ../radare2/test/bins/mach0/ls-m1; ~/.local/bin/r2 -e scr.color=0 -qc 'aaa;axt @ 0x100006184' ../radare2/test/bins/mach0/ls-m1; timeout 60 target/release/r2s -qc 'pd 1 @ 0x100003cc0' ../radare2/test/bins/mach0/hello-macos-arm64-chained; ~/.local/bin/r2 -e scr.color=0 -qc 'aaa;pd 1 @ 0x100003cc0;axt @ 0x100003cc0' ../radare2/test/bins/mach0/hello-macos-arm64-chained
```
**W31**
```
timeout 120 target/release/r2s -qc 'pdf 0x45a95f' ../radare2/test/bins/elf/static-glibc-2.27 | head -5; timeout 120 target/release/r2s -qc 'aflj' ../radare2/test/bins/elf/static-glibc-2.27 | python3 -c 'import json,sys; [print(f) for f in json.load(sys.stdin) if f["addr"] in (0x45a95f,0x45a960,0x45a970)]'; timeout 300 target/release/r2s -qc 'afl' ../radare2/test/bins/elf/libc.so.6 | grep -E '0x00037dff|0x00037e00'
```
**W32**
```
source ~/.cargo/env; cd <repo>; timeout 60 target/release/r2s -qc iz ../radare2/test/bins/mach0/ired; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc iz ../radare2/test/bins/mach0/ired | sed -n 3,8p; timeout 60 target/release/r2s -qc 'iz;f~str' tests/fixtures/frame_pointer_locals_clang_O0g; timeout 60 target/release/r2s -qc iz ../radare2/test/bins/pe/b.exe | awk 'NR>2{print $6}' | sort | uniq -c
```
**W33** [both c-info rows]
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/mach0/BatteryLife.arm_32.0; timeout 60 target/release/r2s -qc 'ie;s entry0;pd 3' $B; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'ie;s entry0;pd 3' $B; otool -l $B | grep -A3 'segname __TEXT' | head -4
```
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/mach0/TestRTTI-armv7; timeout 60 target/release/r2s -qc 'f' $B | grep -w 'main\|sym._main\|entry0'; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'f~main,entry0' $B
```
**W34** [c-info; auth stubs from r2-whole-program]
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/mach0/ls-m1; timeout 60 target/release/r2s -qc 'ir' $B | sed -n 3,5p; timeout 60 target/release/r2s -qc 'f' $B | grep -c ' reloc\.'; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'ir' $B | sed -n 3,6p
```
```
target/release/r2s -qc 'aa; pddj @ sym.imp.__error' ../radare2/test/bins/mach0/cat-macos-arm64 | head -c 400
target/release/r2s -qc 'aa; pd 4 @ sym.imp.__error' ../radare2/test/bins/mach0/cat-macos-arm64
target/release/r2s -qc 'aa; pddj @ sym.imp.NSLog' ../radare2/test/bins/mach0/hello-macos-arm64-chained | head -c 300
target/release/r2s -qc 'aa; pdd @ sym.imp.free' /bin/ls
```
**W35**
```
source ~/.cargo/env; cd <repo>; for f in unaligned_sec_paddr.exe weirdsord.exe duphead.exe; do B=../radare2/test/bins/pe/$f; timeout 60 target/release/r2s -qc 'iS;ie' $B | sed -n 3p; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'iS;pd 2 @ entry0' $B | sed -n 3p; done
```
**W36**
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/elf/gnome-extensions; timeout 60 target/release/r2s -qc 'iee;f~entry.' $B; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'iee;f~entry.' $B
```
**W37**
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/pe/crackme0x00.exe; timeout 60 target/release/r2s -qc 'is' $B | grep '__size_of_stack_commit__\|___tls_start__\|__major_subsystem_version__'
```
**W38**
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/coff/coff.obj; timeout 60 target/release/r2s -qc 'i;ir;pd 2 @ 0x08000064' $B; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'ir' $B
```
**W39**
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/mach0/core.dwarf; timeout 60 target/release/r2s -qc 'i~baddr;iS' $B | head -4; otool -l $B | grep -A4 'sectname __text' | head -5; ls -l $B
```
**W40**
```
timeout 60 target/release/r2s -qc '/as' ../radare2/test/bins/elf/switch-hello-world.elf; timeout 60 target/release/r2s -qc 'pd 40 @ 0x5d8c' ../radare2/test/bins/elf/switch-hello-world.elf | grep -A1 svc; timeout 60 target/release/r2s -qc 'afl~svc' ../radare2/test/bins/elf/switch-hello-world.elf; timeout 60 target/release/r2s -qc 'pdil 0x5da0' ../radare2/test/bins/elf/switch-hello-world.elf
```
**W41**
```
timeout 300 target/release/r2s -qc '/as' ../radare2/test/bins/elf/static-glibc-2.27 | grep -E '44a235|45a967'; timeout 60 target/release/r2s -qc 'pd 3 @ 0x44a230; afb 0x41a5b0' ../radare2/test/bins/elf/static-glibc-2.27 | tail -5; timeout 60 target/release/r2s -qc 'pdd 0x41a5b0' ../radare2/test/bins/elf/static-glibc-2.27 | head -2; ~/.local/bin/r2 -e scr.color=0 -qc '/as' ../radare2/test/bins/elf/static-glibc-2.27 | grep 44a235
```
**W42**
```
cd <repo> && timeout 300 target/release/r2s -qc 'axt 0x58e3d0' ../radare2/test/bins/elf/0pack && timeout 120 target/release/r2s -qc 'pdf 0x62ecf0~oid_to_string' ../radare2/test/bins/elf/0pack && timeout 120 ~/.local/bin/r2 -e scr.color=0 -qc 'af @ 0x62ecf0; axt @ 0x58e3d0' ../radare2/test/bins/elf/0pack
```
**W43** [r2-whole-program]
```
R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'aa; pddj @ 0x0044ba80' ../radare2/test/bins/elf/static-glibc-2.27 | head -c 300
/usr/bin/time -l target/release/r2s -qc 'aa; pddj @ 0x00465a50' ../radare2/test/bins/elf/static-glibc-2.27 > /dev/null
```
**W44**
```
S=<audit>/c-robustness/src; printf '    .text\n    .globl caller\n    .type caller,@function\ncaller:\n    call .Lhelper\n    ret\n.Lhelper:\n    movl (%%rdi), %%eax\n    cmpl %%esi, %%eax\n    jne .Lhelper\n    ret\n' > $S/el3.s && clang -target x86_64-linux-gnu -c $S/el3.s -o $S/el3.o && cd <repo> && target/release/r2s -qc 'afl;pdd @ sym.caller;pdd @ 0x8000046;pddj @ 0x8000046' $S/el3.o | grep -E 'fcn|"name"' | cut -c1-200   # a prebuilt copy is $S/entryloop3.o
```
**W45** [c-robustness; V side from r2-tui]
```
cd <repo> && target/release/r2s -qc 'pdf @ 0x11aa;pdd @ 0x11aa;afi @ 0x11b0~addr,size' tests/fixtures/rv_O0g; ~/.local/bin/r2 -e scr.color=0 -qc 'aaa;pdf @ 0x11aa;afi @ 0x11b0~name,addr' tests/fixtures/rv_O0g
```
```
cd <repo>; B=../radare2/test/bins/elf/bomb; target/release/r2s -qc 's 0x400dc2;pdd' $B | head -1; target/release/r2s -qc 's 0x400dc2;afi' $B | sed -n 2,3p; ~/.local/bin/r2 -e scr.color=0 -qc 'aa;s 0x400dc2;afi~name' $B; A=<audit>/r2-tui; cd $A && venv/bin/python vdrive.py $B 'p' 's 0x400dc2' | grep -m1 'main(' ; venv/bin/python vdrive.py $B 'p' 's 0x400ed7' | grep -m1 'fcn_400ed7'
```
**W46** [r2-render-corpora; naming from c-decompiler; frame_agree from r2-equiv-ci]
```
target/release/r2s -qc 'afv @ 0x8dac0; pdd @ 0x8dac0' ../radare2/test/bins/elf/libstdc++.so.6 | grep -E '^arg|_ZNSt14error_categoryC1Ev\('
target/release/r2s -qc 'afv @ 0x13bc; pdd @ 0x13bc' ../radare2/test/bins/elf/ClassCpp.out | grep -E '^arg|_ZN7MyClassC1Ev\('
target/release/r2s -qc 'afi @ sym._ZN11QTextFormatC1Ev; pdd @ sym._ZN11QTextFormatC1Ev' ../radare2/test/bins/elf/pumasim | grep -E 'signature|_ZN11QTextFormatC1Ev\('
target/release/r2s -qc 'aa; afi @ sym.test; pdd @ sym.test' ../radare2/test/bins/elf/lab1B | grep -E 'signature|^uint32_t test'
```
```
target/release/r2s -qc 'aa; afv @ sym.shape_bool_caller; pdd @ sym.shape_bool_caller' tests/coverage/pinned/shapes_gcc_x64_O0 | head -6
target/release/r2s -qc 'aa; afv @ 0x11c1; pdd @ 0x11c1' tests/fixtures/rv_O0g_stripped | head -8
target/release/r2s -qc 'aa; pdd @ sym.shape_struct_pointer' tests/coverage/pinned/shapes_gcc_x64_O0 | grep mixed_touch
target/release/r2s -qc 'aa; pdd @ sym.mixed_touch' tests/coverage/pinned/shapes_gcc_x64_O0 | grep '^uint64_t mixed_touch'
target/release/r2s -qc 'afv @ sym.imp.printf; afi @ sym.imp.printf; pdd @ sym.imp.printf' tests/fixtures/rv_O0g | grep -E '^arg|signature|extern'
cd <repo>; python3 scripts/frame_agree.py --r2s target/release/r2s --details /tmp/fa.txt; timeout 60 target/release/r2s -qc 's 0x00401178; afv' tests/coverage/pinned/branchy_gcc_x64_O0; timeout 60 target/release/r2s -qc 's 0x00401178; pddj' tests/coverage/pinned/branchy_gcc_x64_O0
```
**W47**
```
target/release/r2s -qc 'afi @ sym._ZN7MyClassC1Ev; pdd @ sym._ZN7MyClassC1Ev' ../radare2/test/bins/elf/ClassCpp.out | grep -E 'signature|_ZN7MyClassC1Ev\(|return'
~/.rustup/toolchains/1.99.0-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/llvm-strip --strip-all -o <audit>/r2-render-corpora/types/two_units_O0g_stripped tests/fixtures/two_units_O0g
target/release/r2s -qc 'aa; afi @ 0x117c; pdd @ 0x117c; pdf @ 0x117c' <audit>/r2-render-corpora/types/two_units_O0g_stripped | grep -E 'signature|^uint64_t|return|xmm0|ret$'
```
**W48**
```
target/release/r2s -qc 'pd 4 @ 0x131f; pdd @ main' ../radare2/test/bins/elf/ClassCpp.out | grep -E 'je |jmp |FS_OFFSET|__stack_chk_fail\(\);|residual_u64\((1|2)\)'
target/release/r2s -qc 'pddj @ main' tests/fixtures/rv_O0g | grep -o '"compiler_inserted":[0-9]*'
```
**W49** [r2-render-corpora; differential_truth from r2-equiv-ci]
```
target/release/r2s -qc 'aa; afv @ 0x146d; pdd @ 0x146d' tests/fixtures/rv_O0g_stripped | grep -E '^arg|fcn_146d\('
target/release/r2s -qc 'aa; pdd @ 0x1391; afv @ 0x12ef' tests/fixtures/rv_O0g_stripped | grep -E 'fcn_1391\(|^arg|^var'
```
```
A=<audit>/r2-equiv-ci; cd <repo>; python3 scripts/differential_truth.py --r2s target/release/r2s --debug-build $A/oracle/build/review/gcc-O2/oracle/review --stripped-build $A/oracle/build/review/gcc-O2/shown/review --json /tmp/dt_review.json
```
**W50**
```
On an x86-64 Linux host: gcc -g -no-pie -fno-pie -O0 tests/gold/review.c -o /tmp/review_g -lm && strip --strip-all -o /tmp/review_s /tmp/review_g; A=$(nm /tmp/review_g | awk '/ T sext/{print $1}'); r2s -qc "s 0x$A; pdd" /tmp/review_g; r2s -qc "s 0x$A; pdd" /tmp/review_s. Saved output: <audit>/r2-equiv-ci/sext_gccO0_debug_vs_stripped.txt. Gate comparison: python3 $A/cmp_routes.py $A/ci/equivalence-38555101615-1/records.json $A/debug_records.json $A/symtab_records.json, where A is that same artifacts dir.
```
**W51**
```
cd <audit>/r2-equiv-ci/cli; C=<audit>/targets/r2-equiv-ci/release/r2sleigh; printf 'garbage not sleigh\n' > media.slaspec; $C compile media.slaspec -o comp_media.r2il; echo $?; $C compile /nonexistent/foo.slaspec -o x.r2il; echo $?
```
**W52**
```
cd <repo> && bash -c 'RUST_BACKTRACE=1 target/release/r2s -qc izz ../radare2/test/bins/elf/bash | head -1 >/dev/null; echo rc=${PIPESTATUS[0]}'   # the output must exceed the ~64 KiB pipe buffer; on small fixtures the reader takes everything before closing and rc is 0
```
**W53**
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; T=$(mktemp -d); cp tests/fixtures/rv_O2 $T/b; (echo i; sleep 2; echo 'pdd @ sym.dispatch'; sleep 1; echo q) | (timeout 30 target/release/r2s $T/b > $T/out 2>&1; echo exit=$? >> $T/out) & sleep 1; : > $T/b; wait; tail -2 $T/out; cp tests/fixtures/rv_O2 $T/c; (echo i; sleep 2; echo 'pdf @ sym.dispatch'; sleep 1; echo q) | (timeout 30 ~/.local/bin/r2 -e scr.color=0 $T/c > $T/out2 2>&1; echo exit=$? >> $T/out2) & sleep 1; : > $T/c; wait; tail -2 $T/out2
```
(verifier: a fairer radare2 comparison is `aaa`, then `px`/`pd` after the truncation; radare2 prints 0xff and exits 0.)
**W54**
```
cd <audit>/c-robustness && VLOG=$PWD/nested.raw python3 vpty.py <repo>/tests/fixtures/rv_O0g 24 80 ':V\rqjjj\r'   # the process does not exit; ':V\rq\r\rq\r' does exit, and Ctrl-C kills it
```
**W55**
```
A=<audit>/r2-tui; cd $A && for S in SIGINT SIGTERM SIGHUP; do venv/bin/python sig.py $S ~/code/radare2/test/bins/elf/bomb | grep -E 'EXIT|lflags|alt screen|mouse'; done
```
**W56**
```
A=<audit>/r2-tui; cd $A && venv/bin/python repro_stale_dec.py   # V on ls at 0x15e00, p, then g0x5ae0 / g0x6000 / g0xa000; compare: target/release/r2s -qc 's 0x5ae0;pdd' ../radare2/test/bins/elf/ls | head -1  -> void entry0(void)
```
**W57**
```
A=<audit>/r2-tui; cd $A && venv/bin/python cursor.py ~/code/radare2/test/bins/elf/bomb 's main' 'jjjjjjjjjj' 'pp' '<right>' 'P' && venv/bin/python cursor.py ~/code/radare2/test/bins/elf/bomb 's main' 'p' 'JJ' 'P' 'j'
```
**W58**
```
A=<audit>/r2-tui; cd $A && venv/bin/python fast.py ~/code/radare2/test/bins/elf/pumasim 's 0x4baf30' 'pjjjjjjjjjj' 3 && venv/bin/python fast.py ~/code/radare2/test/bins/elf/pumasim 's 0x4baf30' 'JJJJJKKKKKjjj' 3
```
**W59**
```
A=<audit>/r2-tui; cd $A && venv/bin/python vdrive.py ~/code/radare2/test/bins/elf/bomb 'kkkkkkkk' 's 0x401197' | sed -n 2,6p; <repo>/target/release/r2s -qc 's 0x401176;pd 8' ~/code/radare2/test/bins/elf/bomb   # full sweep: venv/bin/python upscroll.py ~/code/radare2/test/bins/elf/bomb 0x401600 300
```
**W60** [c-robustness; address language from c-missing]
```
cd <repo> && <audit>/c-robustness/cmp.sh tests/fixtures/rv_O0g 's 0x1000;s +16;s;s -8;s;s 010;s;s main+4;s;s $$;s 0b101'
```
**W61**
```
cd <repo> && target/release/r2s -qc 'q 3' tests/fixtures/rv_O0g; echo r2s=$?; ~/.local/bin/r2 -qc 'q 3' tests/fixtures/rv_O0g 2>/dev/null; echo r2=$?
```
**W62**
```
A=<audit>/r2-tui; cd $A && venv/bin/python repro_color.py
```
**W63**
```
cd <repo>; R2DEC_TRACE_REFUSAL=1 timeout 120 target/release/r2s -qc 'pdd @ 0x1e2450' ../radare2/test/bins/elf/pumasim 2>&1 >/dev/null </dev/null | grep prepare-held
```

### Missing (M)

**M1** [c-analysis; exports from c-info]
```
timeout 60 target/release/r2s -qc 'is' ../radare2/test/bins/pe/a.exe; timeout 60 target/release/r2s -qc 'pdf 0x401150' ../radare2/test/bins/pe/a.exe | grep call; ~/.local/bin/r2 -e scr.color=0 -qc 'ii' ../radare2/test/bins/pe/a.exe; ~/.local/bin/r2 -e scr.color=0 -qc 'aaa;pdf @ 0x401150' ../radare2/test/bins/pe/a.exe | grep call
```
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/pe/Lab05-01.dll; timeout 60 target/release/r2s -qc 'is;ir;pdf @ 0x10001000' $B | grep -m3 'call\|^nth\|^vaddr'; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'iE;pd 1 @ 0x1000102e' $B | head; timeout 60 target/release/r2s -qc 'is' ../radare2/test/bins/pe/kernel32.dll | wc -l
```
**M2**
```
P=<audit>/r2-aarch64; cd <repo>; target/release/r2s -qc 'aa;pdil @ sym._fetch_add;pdd @ sym._fetch_add;pdd @ sym._fetch_add64' $P/probe/probe2   # atomic_fetch_add built for cortex-a53 without LSE -> ldxr/stxr loop
```
**M3**
```
target/release/r2s -qc 'pdf @ 0x4baf30' ../radare2/test/bins/elf/pumasim | grep -c 'call sym._ZN11QTextFormatC1Ev'
target/release/r2s -qc 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim | grep -c '_ZN11QTextFormatC1Ev('
target/release/r2s -qc 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim | grep -E 'residual_void\((2|5)\);'
target/release/r2s -qc 'pd 2 @ 0x328cc; pdd @ 0x32888' ../radare2/test/bins/elf/ls-toybox | grep -E 'bl 0x34c80|fcn_34c80|residual_void\(1\)'
```
**M4** [c-missing; c-robustness truncation variant below]
```
timeout 60 target/release/r2s -qc 'i' ../radare2/test/bins/elf/elf_stripped ; timeout 60 target/release/r2s -qc 'i' ../radare2/test/bins/elf/analysis/no_sections.elf ; timeout 60 target/release/r2s -qc 'i' ../radare2/test/bins/pe/tiny.exe ; timeout 60 ~/.local/bin/r2 -e scr.color=0 -qc 'pd 2 @ entry0' ../radare2/test/bins/elf/elf_stripped
```
```
cd <repo> && python3 -c "import struct;d=open('tests/fixtures/rv_O0g','rb').read();o=struct.unpack_from('<Q',d,0x28)[0];open('<audit>/c-robustness/elf_trunc_shdrs','wb').write(d[:o])" && target/release/r2s -qc 'i;afl~?' <audit>/c-robustness/elf_trunc_shdrs; ~/.local/bin/r2 -e scr.color=0 -qc 'i~format;pd 2' <audit>/c-robustness/elf_trunc_shdrs
```
**M5** [c-missing ×2; c-robustness; c-analysis]
```
printf '\x55\x48\x89\xe5\x31\xc0\x5d\xc3' > /tmp/sc.bin ; timeout 20 target/release/r2s -qc 'pd 3' /tmp/sc.bin ; timeout 20 target/release/r2s -e asm.arch=x86 -qc 'pd 3' /tmp/sc.bin ; timeout 20 target/release/r2s -qc 'e' /bin/ls ; timeout 20 target/release/r2s -qc 'i~arch' /bin/ls ; timeout 20 ~/.local/bin/r2 -a x86 -b 64 -qc 'pd 3' /tmp/sc.bin
```
```
timeout 60 target/release/r2s -qc 'i' ../radare2/test/bins/elf/mips-hello ; timeout 60 target/release/r2s -qc 'i' ../radare2/test/bins/elf/analysis/mips64r2-busybox ; timeout 60 target/release/r2s -qc 'i' ../radare2/test/bins/elf/riscv-fibonacci ; grep -n 'RISC-V, MIPS' README.md ; grep -n 'mips\|RV32' BUILDING.md
```
(verifier: `elf/mips-hello` is actually `elf/analysis/mips-hello`.)
```
cd <repo> && head -c 1000 /dev/urandom > <audit>/c-robustness/rnd && target/release/r2s -qc 'px 16;?e hi' <audit>/c-robustness/rnd; echo rc=$?; ~/.local/bin/r2 -qc 'px 16;?e hi' <audit>/c-robustness/rnd
```
**M6**
```
target/release/r2s -qc 'aa; afl' ../radare2/test/bins/elf/libarm64.so
target/release/r2s -qc 'is' ../radare2/test/bins/elf/libarm64.so
~/.local/bin/r2 -e scr.color=0 -qc 'is; aa; afl' ../radare2/test/bins/elf/libarm64.so
```
**M7**
```
source ~/.cargo/env; cd <repo>; for f in sht_null_symbols libarm64.so libshella-2.10.3.1.so; do B=../radare2/test/bins/elf/$f; echo == $f; timeout 60 target/release/r2s -qc 'iee' $B | tail -n +3; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'iee' $B | tail -n +3; done
```
**M8**
```
source ~/.cargo/env; cd <repo>; B=../radare2/test/bins/pe/hello_world_stripped.exe; timeout 60 target/release/r2s -qc 'iee' $B; timeout 60 ~/.local/bin/r2 -N -e scr.color=0 -qc 'iee' $B; timeout 120 target/release/r2s -qc 'afl' $B | grep -c '401850\|4018a0'
```
**M9**
```
for c in ij isj iSj iej izj irj afij afbj afvj 'axtj main' fj 'pdj 2' pdfj agfj; do timeout 60 target/release/r2s -qc "s main; $c" ../radare2/test/bins/elf/crackme0x05; done
```
**M10**
```
timeout 60 target/release/r2s -qc 's main+4; s' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 target/release/r2s -qc 'pd 2 @ main+3' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 target/release/r2s -qc 's 0x8048540+0x10' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 target/release/r2s -qc 's $$+4' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 target/release/r2s -qc 'px 16 @@ sym.*' ../radare2/test/bins/elf/crackme0x05
```
**M11**
```
timeout 60 target/release/r2s -qc '/x 5589e5' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 target/release/r2s -qc '/ Password' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 ~/.local/bin/r2 -e scr.color=0 -qc '/x 5589e5' ../radare2/test/bins/elf/crackme0x05
```
**M12**
```
timeout 60 target/release/r2s -qc 'pd 2 @ 0x13c0; axt 0x2020; pdd 0x13b0' tests/fixtures/rv_O2 | head -24; timeout 60 target/release/r2s -qc 'pd 1 @ 0x13bb; ax~0x000013bb; axt 0x4040' tests/fixtures/rv_O0g; timeout 60 target/release/r2s -qc 'pd 1 @ 0x401b29; axt 0x4020a0' tests/fixtures/hashes_gcc_x64_O2_stripped; ~/.local/bin/r2 -e scr.color=0 -qc 'aaa;axt @ 0x2020' tests/fixtures/rv_O2
```
**M13**
```
source ~/.cargo/env; E=../radare2/test/bins/elf
for h in f0480fb10ec3 480fb10ec3 480fb1cec3 f0480fc70ec3; do target/release/r2s -qc "s sym.phase_1; wx $h; pd 1 @ sym.phase_1; pdil @ sym.phase_1" $E/bomb | grep -E 'cmpxchg|UNIMPL|RAX = COPY|STORE'; done
target/release/r2s -qc 's sym.phase_1; wx f0480fb10ec3; pdd @ sym.phase_1' $E/bomb
```
**M14**
```
source ~/.cargo/env; E=../radare2/test/bins/elf
target/release/r2s -qc 'aa; pdf @ sym.phase_3; afb @ sym.phase_3' $E/bomb
~/.local/bin/r2 -e scr.color=0 -qc 'aa; afb @ sym.phase_3' $E/bomb
target/release/r2s -qc 'pdd @ sym.phase_3' $E/bomb | grep -i indirect
```
**M15**
```
P=<audit>/r2-aarch64; for c in msr_nzcv mrs_nzcv crc32b umull_8h sminv_8h tbl_2 fminnm_d; do $P/../targets/r2-aarch64/release/a64harness $P/oracle/runs.txt $c | head -8; done; cat $P/tally/gz_mnem.txt | head -45
```
**M16**
```
target/release/r2s -qc 'aa; pdd @ 0x401010; pdd @ 0x401030' tests/fixtures/syscalls_static_O2
target/release/r2s -qc '/as' tests/fixtures/syscalls_static_O2
~/.local/bin/r2 -e scr.color=0 -qc 'pd 8 @ 0x401010' tests/fixtures/syscalls_static_O2
```
**M17**
```
target/release/r2s -qc 'aa; pdd @ main' tests/fixtures/rv_O0g | grep -E 'dispatch\(|find\('
target/release/r2s -qc 'is~g_table; afl~sym.add' tests/fixtures/rv_O0g
target/release/r2s -qc 'aa; pdd @ sym.fill' tests/fixtures/rv_O0g | grep g_table
```
**M18**
```
timeout 60 target/release/r2s -qc 'i;ii;il;iI' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 ~/.local/bin/r2 -e scr.color=0 -qc 'i~nx,pic,canary,relro,stripped,static,intrp;il' ../radare2/test/bins/elf/crackme0x05
```
**M19**
```
A=<audit>/r2-tui; cd $A && venv/bin/python vdrive.py ~/code/radare2/test/bins/elf/bomb 'x' 's 0x400dc2' | sed -n 2,4p; <repo>/target/release/r2s -qc 's 0x400dc2;axt' ~/code/radare2/test/bins/elf/bomb
```
**M20**
```
timeout 60 target/release/r2s -qc 'ax?' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 target/release/r2s -qc 'ax 0x08048342' ../radare2/test/bins/elf/crackme0x05 ; timeout 60 target/release/r2s -qc 'ax @ 0x080484c1' ../radare2/test/bins/elf/crackme0x05 | wc -l ; timeout 60 target/release/r2s -qc 'ax' ../radare2/test/bins/elf/crackme0x05 | wc -l ; timeout 60 target/release/r2s -qc 'axf' ../radare2/test/bins/elf/crackme0x05
```
**M21** [r2-equiv-ci; c-tests]
```
C=<audit>/targets/r2-equiv-ci/release/r2sleigh; $C test-arch --help | grep mips; $C test-arch mips32be -o /tmp/m.r2il; echo $?; $C run --arch x86-64 --bytes 4801f0c3000000000000000000000000 --action dec --format text | head -2
```
```
source ~/.cargo/env; cd <repo>; T=<audit>/targets/c-tests/cli; CARGO_TARGET_DIR=$T cargo build -p r2sleigh-cli --bin r2sleigh --features x86; $T/debug/r2sleigh test-arch mips32be -o <audit>/c-tests/cli/m.r2il; echo exit=$?
```
**M22** [c-missing; r2-equiv-ci]
```
grep -n 'ARM 32-bit\|RISC-V, MIPS\|why each is believed' README.md ; grep -n 'abort on panic' BUILDING.md ; grep -n 'panic' Cargo.toml ; timeout 60 target/release/r2s -qc 'i~arch;pdd @ entry0' ../radare2/test/bins/elf/analysis/arm-ls | head -12 ; timeout 60 target/release/r2s -qc 'pdd main' tests/fixtures/rv_O0g | head -3 ; timeout 60 target/release/r2s -qc 'afl' /bin/ls | head -3
```
```
cd <repo>; grep -n 'No CI job runs the aarch64' tests/equiv/README.md; grep -n 'equivalence-shard-aarch64' .github/workflows/ci.yml; grep -n 'slow' tests/equiv/gate.py | head -3; sed -n 95,110p tests/equiv/README.md
```

### Design (D) — repros where they differ from the linked W/P rows

**D4**
```
target/release/r2s -qc 'pddj @ 0x40bbb0; afi @ 0x40bbb0; afv @ 0x40bbb0; afb @ 0x40bbb0' ../radare2/test/bins/elf/dwarf_go_tree; echo rc=$?
target/release/r2s -qc 'pddj @ sym.imp.free' ../radare2/test/bins/elf/dwarf_rust_bubble | head -c 200
```
**D5**
```
target/release/r2s -qc 'aa; pdd @ 0x11c1; afv @ 0x11c1' tests/fixtures/rv_O0g
target/release/r2s -qc 'aa; pdd @ 0x11c1; afv @ 0x11c1' tests/fixtures/rv_O0g_stripped
R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'pdd @ 0x11c1' tests/fixtures/rv_O0g 2>&1 >/dev/null | grep promote-stack-slot
R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'pdd @ sym.counter' tests/fixtures/frame_pointer_locals_clang_O0g 2>&1 >/dev/null | grep promote-stack-slot
target/release/r2s -qc 'aa; afv @ sym.counter; pdd @ sym.counter' tests/fixtures/frame_pointer_locals_clang_O0g
```
**D6** [c-analysis; afl/afi/afb counts from p-scaling]
```
timeout 60 target/release/r2s -qc 'aa;afl~classify;afi 0x120a~size,num-bbs;ax~0x0000123c' tests/fixtures/rv_O0g; timeout 60 target/release/r2s -qc 'axt 0x7a0; afi 0xd7c~num-bbs' ../radare2/test/bins/elf/echo; ~/.local/bin/r2 -e scr.color=0 -qc 'aaa;axt @ 0x7a0' ../radare2/test/bins/elf/echo; timeout 60 target/release/r2s -qc 'afl~deregister; afi 0x10f0~^size' tests/fixtures/rv_O0g
```
```
cd <repo> && timeout 120 target/release/r2s -qc 'afl~0x0044c7e0;afi 0x44c7e0~bbs,realsz;afb 0x44c7e0~?' ../radare2/test/bins/elf/pumasim && timeout 120 target/release/r2s -qc 'afl~5881d0;afi 0x5881d0~bbs,realsz;afb 0x5881d0~?' ../radare2/test/bins/elf/pumasim && timeout 120 ~/.local/bin/r2 -e scr.color=0 -qc 'af@0x44c7e0;afl~44c7e0' ../radare2/test/bins/elf/pumasim
```
**D7**
```
cd <repo>; target/release/r2s -qc 'aa;pdd @ sym._mem_scan2' tests/fixtures/manual_limits_O2 | wc -l; target/release/r2s -qc 'aa;pdd @ sym.twice_half;pdd @ sym.main' tests/fixtures/float_returns_zig_aarch64_O2g | grep -c r2sleigh_bits
```
**D8**
```
for c in 'aa' 'aa; afi @ sym.imp.free'; do /usr/bin/time -l target/release/r2s -qc "$c" ../radare2/test/bins/elf/r2pay-arm64.so 2>&1 >/dev/null | grep 'instructions retired'; done
samply record --save-only --no-open --unstable-presymbolicate -o stub.json.gz target/profiling/r2s -qc 'aa; pddj @ sym.imp.free' ../radare2/test/bins/elf/r2pay-arm64.so; python3 scripts/samply_collapse.py stub.json.gz --top 30
```
**D9**
```
source ~/.cargo/env; cd <repo>; export CARGO_TARGET_DIR=<audit>/targets/p-build-clean; rm -rf $CARGO_TARGET_DIR; cargo build --release -p r2s --features sleigh --timings; python3 <audit>/p-build/parse_timings.py $CARGO_TARGET_DIR/cargo-timings/cargo-timing.html 12; grep -rn 'r2sleigh_lift' crates/r2ssa/src | grep -v tests
```
**D10**
```
cd <repo>; sed -n 17,20p crates/r2engine/src/library.rs; sed -n 289,333p crates/r2engine/src/library.rs; sed -n 24,58p crates/r2engine/src/route.rs; sed -n 8p crates/r2types/src/callee.rs; sed -n 763,810p crates/r2types/src/callee.rs; sed -n 399,425p crates/r2types/src/callee.rs; sed -n 1160,1163p crates/r2types/src/function_facts/prepared.rs; sed -n 1867,1875p crates/r2dec/src/ast.rs; sed -n 17,23p crates/r2abi/src/runtime.rs; sed -n 120,130p crates/r2engine/src/names.rs
```
**D11**
```
cd <repo>; sed -n 6273,6281p tools/dylints/r2sleigh_lints/src/lib.rs; sed -n 1808,1813p crates/r2ssa/src/function/mod.rs; grep -n 'natural_loops' crates/r2ssa/src/function/mod.rs; sed -n 84,103p crates/r2ssa/src/name.rs; sed -n 1874,1880p crates/r2sleigh-lift/src/disasm/mod.rs
```
**D12**
```
cd <repo>; grep -rn 'reg_type_hints' crates/*/src | grep -v test; grep -rn 'merge_type_hint' crates/*/src
cd <repo>; for s in allocations_by_size take_sampled_origins enable_origin_sampling reset_size_histogram reset_peak is_counting size_class_bound; do echo "$s: $(grep -rn "$s" crates | grep -v '^crates/r2il/src/allocation.rs' | wc -l)"; done; grep -n 'SAMPLED' crates/r2il/src/allocation.rs
```
**D13**
```
target/release/r2s -qc 'pdd @ 0x23fdf0' ../radare2/test/bins/elf/pumasim > /tmp/gui.c; grep -cE '\) \{$' /tmp/gui.c; awk '{match($0,/^ */); if (RLENGTH>m) m=RLENGTH} END{print m/4}' /tmp/gui.c; grep -c '(void)r2sleigh_load' /tmp/gui.c; grep -c '>> 0U' /tmp/gui.c
target/release/r2s -qc 'pdil @ sym.fill' tests/fixtures/rv_O2 | grep 'LOAD \[ram\]0x4010'
target/release/r2s -qc 'aa; pdd @ sym.mul_div' tests/fixtures/rv_O0g
```
**D14**
```
cd <repo> && target/release/r2s -qc 'wx 414;wx 4142 @ 0xfffffffffffffffe;s 0x17cc;wx 9090909090909090909090909090909090909090' tests/fixtures/rv_O0g; target/release/r2s -qc 'i~format' tests/fixtures/rv_O0g; target/release/r2s -qc i ../radare2/test/bins/fuzzed/256996efe37d69100bf09cf3a07cbffc | wc -c; target/release/r2s -qc i ../radare2/test/bins/fuzzed/elf11 >/dev/null; target/release/r2s -qc i tests; target/release/r2s -qc V tests/fixtures/rv_O0g </dev/null
```
**D15**
```
source ~/.cargo/env; cd <repo>; export CARGO_TARGET_DIR=<audit>/targets/p-build; cargo llvm-lines -p r2ssa --lib > /tmp/ll.txt; cargo bloat --profile profiling -p r2s --features sleigh --crates -n 10
```
**D16**
```
source ~/.cargo/env; cd <repo>; O=$(mktemp -d); timeout 300 samply record --save-only --no-open --unstable-presymbolicate -r 2000 -o $O/p.json.gz target/profiling/r2s -q -c 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim >/dev/null; python3 scripts/samply_collapse.py $O/p.json.gz --top 15 --match '' 2>&1 >/dev/null | sed -n '/== self/,$p'
```

### Performance (P)

**P1** [p-memory; profile from p-cpu-mac]
```
cd <repo>; P=../radare2/test/bins/elf/pumasim; for f in 0x1e2450 0x1dc0a0 0x4baf30; do timeout 300 /usr/bin/time -l target/release/r2s -qc "pdd @ $f" $P 2>&1 >/dev/null | grep -E 'instructions retired|footprint'; R2DEC_TRACE_REFUSAL=1 timeout 300 target/release/r2s -qc "pdd @ $f" $P 2>&1 >/dev/null </dev/null | grep -c prepare-held; done; timeout 60 target/release/r2s -qc 'afi @ 0x1fafb0' $P | grep num-
```
```
VM: R=/root/r2s-target-audit/r2s-release; B=/root/radare2/test/bins/elf; for c in 'pdd @ 0x23fdf0' 'pdd @ 0x2312c0' 'pdd @ 0x23fdf0; pdd @ 0x2312c0' 'pdd @ 0x1c3000' 'afl; pdd @ 0x1dc0a0' 'afl'; do perf stat -x, -e instructions:u -o /tmp/s $R -qc "$c" $B/pumasim >/dev/null 2>&1; echo "$c $(cut -d, -f1 /tmp/s | tail -1)"; done
```
(The `timeout` wrapper must sit outside `/usr/bin/time -l`; otherwise only the wrapper is counted.)
**P2** [p-linux]
```
/usr/bin/time -l target/release/r2s -qc 'pdd @ 0x0058e3d0' ../radare2/test/bins/elf/0pack > /dev/null   # Mac: 'instructions retired' ~25.95G
# fix check: git worktree add /tmp/wt HEAD && cd /tmp/wt && git apply <audit>/p-linux/evidenced_spans_range.patch && CARGO_TARGET_DIR=/tmp/t cargo build --release -p r2s --features sleigh && /usr/bin/time -l /tmp/t/release/r2s -qc 'pdd @ 0x0058e3d0' <repo>/../radare2/test/bins/elf/0pack | md5
# VM profile: perf record -F 999 -g --call-graph fp -- /root/r2s-target-audit/r2s-fp -qc 'pdd @ 0x0058e3d0' /root/radare2/test/bins/elf/0pack
```
**P3** [p-cpu-mac]
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; O=$(mktemp -d); ART=<audit>/p-cpu-mac; timeout 300 samply record --save-only --no-open --unstable-presymbolicate -r 2000 -o $O/p.json.gz target/profiling/r2s -q -c 'pdd @ 0x58e3d0' ../radare2/test/bins/elf/0pack >/dev/null; python3 $ART/tools/collapse2.py $O/p.json.gz $O/q; inferno-flamegraph < $O/q.folded > $O/q.svg; python3 $ART/tools/children.py $O/q.folded 'CanonicalRoots>::(access_)?discharges$' 1; grep 'search_tree::<r2ssa::obligation::CanonicalInstructionId' $O/q.report
```
**P4** [p-cpu-mac]
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; O=$(mktemp -d); ART=<audit>/p-cpu-mac; timeout 600 env R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim >/dev/null 2>$O/t.log; grep -o 'collect-phase at [^:]*:[0-9]*: [a-z]*@0x[0-9a-f]* addresses' $O/t.log | awk '{print $4}' | sort | uniq -c | awk '{print $1}' | sort | uniq -c; grep -o 'collect-phase at [^:]*:[0-9]*: [a-z]*@0x4baf30 [a-z_]*' $O/t.log | awk '{print $4,$5}' | uniq; timeout 300 samply record --save-only --no-open --unstable-presymbolicate -r 2000 -o $O/p.json.gz target/profiling/r2s -q -c 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim >/dev/null; python3 $ART/tools/collapse2.py $O/p.json.gz $O/q; python3 $ART/tools/children.py $O/q.folded 'recover_interface_inner$' 3 | head
```
**P5**
```
cd <repo>; F=../radare2/test/bins/mach0/gzdoom.arm_64.1; timeout 900 /usr/bin/time -l target/profiling/r2s -qc 'aa;pdd @ 0x10070695c' $F > /dev/null; timeout 900 /usr/bin/time -l target/profiling/r2s -qc 'aa;afl' $F > /dev/null   # subtract the baseline; profile: samply record --save-only --no-open --unstable-presymbolicate -o gz.json.gz target/profiling/r2s -qc 'aa;pdd @ 0x10070695c' $F
```
**P6** [r2-whole-program]
```
/usr/bin/time -l target/release/r2s -qc 'aa; pddj @ 0x00077d14' ../radare2/test/bins/elf/r2pay-arm64.so > /dev/null
CARGO_TARGET_DIR=/tmp/r2s-dhat cargo build --profile profiling -p r2s --features sleigh,dhat-heap
R2S_HEAP_PROFILE=1 /tmp/r2s-dhat/profiling/r2s -qc 'aa; pddj @ 0x00077d14' ../radare2/test/bins/elf/r2pay-arm64.so > /dev/null; python3 scripts/census.py heap --top 5 dhat-heap.json
```
**P7** [p-scaling]
```
cd <repo> && timeout 600 /usr/bin/time -l target/release/r2s -qc 'afl~?' ../radare2/test/bins/elf/pumasim 2>&1 | grep -E 'user|instructions retired|maximum resident' && timeout 900 /usr/bin/time -l target/release/r2s -qc 'afl~?;axt 0x0~?' ../radare2/test/bins/elf/pumasim 2>&1 | grep -E 'user|instructions retired|maximum resident'
```
**P8**
```
cd <repo>; F=../radare2/test/bins/elf/pumasim
/usr/bin/time -l timeout 300 target/release/r2s -qc 'pdd @ 0x4baf30; pdd @ 0x4baf30' $F >/dev/null   # instructions retired ~13.40e9
/usr/bin/time -l timeout 300 target/release/r2s -qc 'pdd @ 0x4baf30; s 0x770000; wx 00; pdd @ 0x4baf30' $F >/dev/null   # ~18.12e9
/usr/bin/time -l timeout 300 target/release/r2s -qc 'pdd @ 0x4baf30; s 0x770000; wx 00; wcr; pdd @ 0x4baf30' $F >/dev/null   # ~18.10e9
/usr/bin/time -l timeout 60 target/release/r2s -qc 'pdd @ 0x1c4dc0; s 0x770000; wx 00; pdd @ 0x1c4dc0' $F >/dev/null   # 1.159e9 vs 1.005e9 for one pdd
```
**P9**
```
cd <repo>; F=../radare2/test/bins/elf/pumasim
/usr/bin/time -l timeout 300 target/release/r2s -qc 'pdd @ 0x4baf30' $F >/dev/null        # 13.40e9 instructions
/usr/bin/time -l timeout 300 target/release/r2s -qc 'aa' $F >/dev/null                   # 20.08e9
/usr/bin/time -l timeout 600 target/release/r2s -qc 'pdd @ 0x4baf30; aa; pdd @ 0x4baf30' $F >/dev/null   # 40.34e9
timeout 600 target/release/r2s -qc 'pdd @ 0x4baf30; ?e SPLITMARK; aa; pdd @ 0x4baf30' $F > /tmp/x.txt; python3 -c "t=open('/tmp/x.txt').read().split('SPLITMARK\n'); print(t[0]==t[1], len(t[0]))"   # True 588434
```
**P10** [p-session ×2; p-linux]
```
cd <repo>; F=../radare2/test/bins/elf/pumasim
for c in 'afb @ 0x4baf30' 'agf @ 0x4baf30' 'pdf @ 0x4baf30' 'pdd @ 0x4baf30' 'pdil @ 0x4baf30'; do /usr/bin/time -l timeout 300 target/release/r2s -qc "$c" $F 2>&1 >/dev/null | grep 'instructions retired'; done
```
```
cd <repo>; F=../radare2/test/bins/elf/pumasim
/usr/bin/time -l timeout 300 target/release/r2s -qc 'pdf @ 0x4baf30' $F 2>&1 >/dev/null | grep 'instructions retired'              # 13.22e9
/usr/bin/time -l timeout 300 target/release/r2s -qc 'pdf @ 0x4baf30; pdf @ 0x4baf30' $F 2>&1 >/dev/null | grep 'instructions retired'   # 14.01e9
/usr/bin/time -l timeout 300 target/release/r2s -qc 'pdd @ 0x4baf30; agf @ 0x4baf30' $F 2>&1 >/dev/null | grep 'instructions retired'   # 14.45e9 (pdd alone 13.40e9)
samply record --save-only --no-open --unstable-presymbolicate -o pdf6.json.gz target/profiling/r2s -qc 'pdd @ 0x4baf30; pdf @ 0x4baf30; pdf @ 0x4baf30; pdf @ 0x4baf30; pdf @ 0x4baf30; pdf @ 0x4baf30; pdf @ 0x4baf30' $F
```
```
Mac, from repo root: for c in 'i' 'pd 1784 @ 0x23fdf0' 'pdf @ 0x23fdf0' 'pdd @ 0x23fdf0'; do /usr/bin/time -l target/release/r2s -qc "$c" ../radare2/test/bins/elf/pumasim 2>&1 >/dev/null | grep 'instructions retired'; done
VM: perf stat -e instructions:u /root/r2s-target-audit/r2s-release -qc 'afi @ 0x23fdf0' /root/radare2/test/bins/elf/pumasim
```
**P11** [p-session; `is` variant from p-cpu-mac]
```
cd <repo>; F=../radare2/test/bins/mach0/BatteryLife.arm_32.0
for c in 'i' 'pd 1' 'afl~?' 'pd 1; afl~?'; do /usr/bin/time -l timeout 300 target/release/r2s -qc "$c" $F 2>&1 >/dev/null | grep 'instructions retired'; done
# compare x86: pd 1 on pumasim is ~0.99e9 while afl is 20.1e9
/usr/bin/time -l timeout 60 target/release/r2s -qc 'pd 1 @ 0x4baf30' ../radare2/test/bins/elf/pumasim 2>&1 >/dev/null | grep 'instructions retired'
```
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; O=$(mktemp -d); ART=<audit>/p-cpu-mac; timeout 120 samply record --save-only --no-open --unstable-presymbolicate -r 2000 -o $O/p.json.gz target/profiling/r2s -q -c 'is' ../radare2/test/bins/mach0/gzdoom.arm_64.1 >/dev/null; python3 $ART/tools/collapse2.py $O/p.json.gz $O/q; grep -E 'Machines>::load|load_embedded_specification|SymbolTable::decode' $O/q.report
```
**P12** [p-session; p-cpu-mac; p-scaling; r2-render-corpora]
```
cd <repo>; B=../radare2/test/bins/elf
for f in libc-2.26-debug.so libstdc++.so.6 dwarf_rust_bubble pumasim; do echo $f; /usr/bin/time -l timeout 60 target/release/r2s -qc 'q' $B/$f 2>&1 >/dev/null | grep -E 'instructions retired|maximum resident'; done
samply record --save-only --no-open --unstable-presymbolicate -o open_libc.json.gz target/profiling/r2s -qc q $B/libc-2.26-debug.so
```
```
samply record --save-only --no-open --unstable-presymbolicate --rate 4000 -o <audit>/r2-render-corpora/prof/dwarf_pdd.json.gz target/profiling/r2s -qc 'pdd @ sym.d_print_comp_inner' ../radare2/test/bins/elf/libstdc++.so.6 >/dev/null
python3 scripts/samply_collapse.py <audit>/r2-render-corpora/prof/dwarf_pdd.json.gz --top 40 | grep -c 'r2image::debug::read'
```
(Run `/usr/bin/time -l` on r2s directly; under `timeout` it reports only the wrapper's ~18M.)
**P13** [p-linux; p-scaling]
```
VM: for c in 'i' 'pdd @ 0x1c3000'; do perf stat -e instructions:u /root/r2s-target-audit/r2s-release -qc "$c" /root/radare2/test/bins/elf/pumasim 2>&1 >/dev/null | grep instructions; done; perf record -F 4999 -g --call-graph fp -- /root/r2s-target-audit/r2s-fp -qc 'pdd @ 0x1c3000' /root/radare2/test/bins/elf/pumasim
Mac: /usr/bin/time -l target/release/r2s -qc 'pdd @ 0x1c3000' ../radare2/test/bins/elf/pumasim >/dev/null
```
```
cd <repo> && timeout 60 /usr/bin/time -l target/release/r2s -qc 's' ../radare2/test/bins/elf/pumasim 2>&1 | grep -E 'instructions retired|maximum resident' && timeout 60 /usr/bin/time -l target/release/r2s -qc 'pd 1 @ 0x1c3040' ../radare2/test/bins/elf/pumasim 2>&1 >/dev/null | grep -E 'instructions retired|maximum resident'
```
**P14**
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; O=$(mktemp -d); ART=<audit>/p-cpu-mac; timeout 60 target/release/r2s -qc 'iS' ../radare2/test/bins/coff/coff_bigobj.obj | wc -l; timeout 120 samply record --save-only --no-open --unstable-presymbolicate -r 2000 -o $O/p.json.gz target/profiling/r2s -q -c 'i' ../radare2/test/bins/coff/coff_bigobj.obj >/dev/null; python3 $ART/tools/collapse2.py $O/p.json.gz $O/q; grep -E 'language::read|section_by_name|ObjectSection>::name|Dwarf>::load' $O/q.report
```
**P15**
```
cd <repo>; samply record --save-only --no-open --unstable-presymbolicate -o pdd.json.gz target/profiling/r2s -qc 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim; python3 scripts/samply_collapse.py pdd.json.gz > pdd.folded; grep -o '[^;]*;[^;]*;r2engine::program::naming::of::<' pdd.folded | sort | uniq -c
```
**P16**
```
A=<audit>/r2-tui; cd $A && venv/bin/python alt.py ~/code/radare2/test/bins/elf/pumasim 0x23fdf0,0x4baf30 10; cd <repo>; P=../radare2/test/bins/elf/pumasim; /usr/bin/time -p target/release/r2s -qc 's 0x23fdf0;pdd;s 0x4baf30;pdd;s 0x23fdf0;pdd' $P >/dev/null; /usr/bin/time -p target/release/r2s -qc 's 0x23fdf0;pdd' $P >/dev/null
```
```
cd <repo>; F=../radare2/test/bins/elf/pumasim
for c in 'pdd @ 0x4baf30; pdd @ 0x23fdf0' 'pdd @ 0x4baf30; pdd @ 0x23fdf0; pdd @ 0x4baf30' 'pdd @ 0x4baf30; pdd @ 0x1c3030; pdd @ 0x4baf30'; do /usr/bin/time -l timeout 600 target/release/r2s -qc "$c" $F 2>&1 >/dev/null | grep 'instructions retired'; done
```
**P17**
```
cd <repo>; F=../radare2/test/bins/elf/pumasim
/usr/bin/time -l timeout 600 target/release/r2s -qc 'afl; afl' $F 2>&1 >/dev/null | grep 'instructions retired'   # 20.2e9
/usr/bin/time -l timeout 600 target/release/r2s -qc 'afl; s 0x5a42f0; wx 90; afl' $F 2>&1 >/dev/null | grep 'instructions retired'   # 39.3e9
```
**P18**
```
cd <repo>; F=../radare2/test/bins/elf/pumasim
for c in 'afl~?' 'pdd @ 0x4baf30' 'afl; pdd @ 0x4baf30'; do /usr/bin/time -l timeout 600 target/release/r2s -qc "$c" $F 2>&1 >/dev/null | grep 'instructions retired'; done
samply record --save-only --no-open --unstable-presymbolicate -o afl.json.gz target/profiling/r2s -qc 'afl~?' $F
```
**P19**
```
VM: perf record -F 999 -g --call-graph fp -o s.data -- /root/r2s-target-audit/r2s-fp -qc 'pdd @ 0x0023fdf0' /root/radare2/test/bins/elf/pumasim; perf script -i s.data --no-inline | inferno-collapse-perf | rustfilt | grep -c 'ReachingStorage>::at'
Then python3 p-linux/scripts/callers.py <folded> 'ReachingStorage>::at' 2
```
**P20**
```
VM: perf record -F 999 -g --call-graph fp -- /root/r2s-target-audit/r2s-fp -qc 'pdd @ 0x0058e3d0' /root/radare2/test/bins/elf/0pack; and valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes /root/r2s-target-audit/r2s-profiling -qc 'pdd @ 0x2d2200' /root/radare2/test/bins/elf/pumasim then cg_annotate --show=D1mr,Ir --sort=D1mr --auto=no cachegrind.out.* | rustfilt
```
**P21** [p-cpu-mac]
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; O=$(mktemp -d); ART=<audit>/p-cpu-mac; timeout 300 samply record --save-only --no-open --unstable-presymbolicate -r 2000 -o $O/p.json.gz target/profiling/r2s -q -c 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim >/dev/null; python3 $ART/tools/collapse2.py $O/p.json.gz $O/q; grep -E 'sip::Hasher|RandomState' $O/q.report
```
**P22** [p-memory]
```
cd <repo>; A=<audit>/p-memory; python3 $A/tools/dh2.py $A/dhat/puma_4baf30/dhat-heap.json ksite 30 1; grep -n 'pub fn sources' -A4 crates/r2ssa/src/op.rs; grep -n 'pub fn inputs(&self) -> Vec\|pub fn inputs_mut(&mut self) -> Vec' crates/r2il/src/opcode.rs
```
```
VM: R2S_ALLOCATIONS=1 /root/r2s-target-audit/r2s-count -qc 'pdd @ 0x0058e3d0' /root/radare2/test/bins/elf/0pack >/dev/null; for b in r2s-profiling r2s-dhat; do /usr/bin/time -v /root/r2s-target-audit/$b -qc 'pdd @ 0x0058e3d0' /root/radare2/test/bins/elf/0pack 2>&1 >/dev/null | grep Maximum; done; heaptrack /root/r2s-target-audit/r2s-dhat -qc 'pdd @ 0x0058e3d0' /root/radare2/test/bins/elf/0pack
(build: cargo build --profile profiling -p r2s --features sleigh,alloc-count | dhat-heap)
```
**P23**
```
cd <repo>; A=<audit>/p-memory; python3 $A/tools/dh2.py $A/dhat/puma_aa/dhat-heap.json ksite 12 2; sed -n 2486,2511p crates/r2sleigh-lift/src/disasm/mod.rs; sed -n 2547,2554p crates/r2sleigh-lift/src/disasm/mod.rs; sed -n 69,73p crates/r2s/src/session.rs
```
**P24**
```
cd <repo>; A=<audit>/p-memory; python3 -c "import json;p=json.load(open('$A/dhat/0pack_58e3d0/dhat-heap.json'));F=p['ftbl'];r=[pp for pp in p['pps'] if any('disasm/mod.rs:2341' in F[i] for i in pp['fs'][:14])];print(sum(x['tb'] for x in r),sum(x['tbk'] for x in r),max(x['mb'] for x in r))"; sed -n 2335,2345p crates/r2sleigh-lift/src/disasm/mod.rs  # to regenerate the profile: build -p r2s --profile profiling --features sleigh,dhat-heap into your own CARGO_TARGET_DIR, then R2S_HEAP_PROFILE=1 r2s -q -c 'pdd @ 0x58e3d0' ../radare2/test/bins/elf/0pack
```
**P25**
```
cd <repo>; A=<audit>/p-memory; python3 scripts/census.py heap --top 3 2148=$A/dhat/0pack_62ecf0/dhat-heap.json 300=$A/dhat/puma_1dc0a0/dhat-heap.json; sed -n 1078,1120p crates/r2ssa/src/obligation.rs; cat $A/r2ssa_zz_sizes.rs
```
**P26**
```
cd <repo>; A=<audit>; git worktree add --detach $A/wt/x HEAD && git -C $A/wt/x apply $A/p-memory/jemalloc-feature.patch && for f in '' jemalloc system-alloc; do (cd $A/wt/x && CARGO_TARGET_DIR=$A/targets/x cargo build --release -p r2s --features "sleigh $f" && cp $A/targets/x/release/r2s $A/p-memory/bin/r2s-${f:-mimalloc}); done; mv $A/p-memory/bin/r2s-jemalloc $A/p-memory/bin/r2s-jemalloc-plain; A=$A/p-memory bash $A/p-memory/tools/allocbench.sh /tmp/ab.tsv 5 mimalloc jemalloc-plain system-alloc; MIMALLOC_PURGE_DELAY=0 /usr/bin/time -l $A/p-memory/bin/r2s-mimalloc -q -c 'pdd @ 0x4baf30' ../radare2/test/bins/elf/pumasim >/dev/null; git worktree remove --force $A/wt/x   # build without --locked: the patch does not update Cargo.lock
```
**P27**
```
cd <repo>; A=<audit>/p-memory; P=../radare2/test/bins/elf/pumasim; for c in 's' 'pd 1'; do R2S_ALLOCATIONS=1 timeout 60 /usr/bin/time -l $A/bin/r2s-count -q -c "$c" $P 2>&1 >/dev/null </dev/null | grep -E 'heap peak|footprint'; done
```
**P28**
```
cd <repo>; A=<audit>/p-memory; python3 $A/tools/dh2.py $A/dhat/puma_open/dhat-heap.json gsite 8 1; timeout 60 target/release/r2s -qc 'is~?' ../radare2/test/bins/elf/pumasim; cat $A/r2abi_zz_sizes.rs
```
**P29**
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; O=$(mktemp -d); /usr/bin/time -l -o $O/time.txt timeout 180 env R2DEC_TRACE_REFUSAL=1 target/release/r2s -qc 'pdd @ 0x62ecf0' ../radare2/test/bins/elf/0pack >/dev/null 2>$O/trace.err; echo exit $?; grep -E 'real|user|sys' $O/time.txt; ls -l $O/trace.err; awk '/indexed-span-absorbs/{n++; s+=length($0)} END{print n" lines "s" bytes"}' $O/trace.err
```
**P30**
```
VM: heaptrack /root/r2s-target-audit/r2s-dhat -qc 'pdd @ 0x0058e3d0' /root/radare2/test/bins/elf/0pack; heaptrack_print -f heaptrack.*.zst -F st.txt; rustfilt < st.txt | grep -c 'SemanticObligationId as core::fmt::Debug'
Mac: samply record --save-only --no-open --unstable-presymbolicate -o /tmp/s.json.gz target/profiling/r2s -qc 'pdd @ 0x0023fdf0' ../radare2/test/bins/elf/pumasim && python3 scripts/samply_collapse.py /tmp/s.json.gz --top 80 | grep -i 'format\|ProvenProgram'
```
**P31**
```
cd <repo>; A=<audit>/p-memory; python3 $A/tools/dh2.py $A/dhat/0pack_58e3d0/dhat-heap.json gsite 6 2; sed -n 3408,3416p crates/r2ssa/src/machine/mod.rs
```
**P32**
```
A=<audit>/r2-tui; cd $A && venv/bin/python repro_hol.py
```

### Build (B)

**B1**
```
cd <repo> && for d in target/release/build/libsla-sys-*/out; do ls $d/*.o >/dev/null 2>&1 || continue; echo "== $d"; find $d -name '*.o' | while read f; do echo "$(stat -f %m "$f") $(basename $f)"; done | sort -n | awk 'NR==1{f=$1;p=$1} {printf "+%3ds step %2d %s\n", $1-f, $1-p, $2; p=$1}'; done; source ~/.cargo/env; cargo tree -e features -i cc -p r2sleigh-lift --offline | head -4
# A/B: S=<audit>; git worktree add --detach $S/wt/par HEAD; printf '\ncc = { version = "1", features = ["parallel"] }\n' >> $S/wt/par/vendor/libsla-sys/Cargo.toml; cd $S/wt/par; export CARGO_TARGET_DIR=$S/targets/par; cargo build --release -p r2sleigh-lift --features x86,arm,riscv --timings; cd <repo>; git worktree remove --force $S/wt/par
```
**B2**
```
cd <repo> && ls -d target/release/build/libsla-sys-*/ && ls -la target/release/build/libsla-sys-*/out/libsla.a
# A/B (back to back, fresh target dirs):
source ~/.cargo/env; S=<audit>; for v in base opt3; do export CARGO_TARGET_DIR=$S/targets/bo-$v; rm -rf $CARGO_TARGET_DIR; if [ $v = opt3 ]; then X='--config=profile.release.build-override.opt-level=3'; else X=''; fi; cargo build --release -p r2sleigh-lift --features x86,arm,riscv --timings $X; ls -d $CARGO_TARGET_DIR/release/build/libsla-sys-*/out; python3 $S/p-build/parse_timings.py $CARGO_TARGET_DIR/cargo-timings/cargo-timing.html 6; done
```
**B3**
```
cd <repo> && python3 - <<'EOF'
import glob,os
d=glob.glob('target/release/build/sleigh-config-*/out')[0]
b=open('target/release/r2s','rb').read()
dup=0
for f in sorted(glob.glob(d+'/*.sla')):
    s=open(f,'rb').read(); c=b.count(s); dup+=max(0,c-1)*len(s)
    print(os.path.basename(f),len(s),'copies',c)
print('duplicate SLA bytes',dup)
EOF
# compare with LTO (no duplicates): source ~/.cargo/env; export CARGO_TARGET_DIR=<audit>/targets/p-build; cargo build --profile dist -p r2s --features sleigh; size -m $CARGO_TARGET_DIR/dist/r2s | grep __const
```
**B4**
```
cd <repo> && d=$(ls -d target/release/build/sleigh-config-*/out) && ls -l $d/*.sla | awk '{n=$9; sub(".*/","",n); if (n!~/^(AARCH64_AppleSilicon|AARCH64|ARM8_le|x86|x86-64|riscv.lp64d|riscv.ilp32d)\.sla$/) {s+=$5; c++; print n}} END {print "unreachable", c, s}'
# trimmed-build check: S=<audit>; git worktree add --detach $S/wt/slim HEAD; cd $S/wt/slim/vendor/sleigh-config/ghidra/Ghidra/Processors && rm AARCH64/data/languages/AARCH64BE.slaspec ARM/data/languages/ARM{4,4t,5,5t,6,7}_{be,le}.slaspec ARM/data/languages/ARM8_be.slaspec ARM/data/languages/ARM8m_{be,le}.slaspec && cd $S/wt/slim && source ~/.cargo/env && export CARGO_TARGET_DIR=$S/targets/slim && cargo build --release -p r2s --features sleigh --timings && ls -l $CARGO_TARGET_DIR/release/r2s; cd <repo> && git worktree remove --force $S/wt/slim
```
**B5** — see D9.
**B6**
```
source ~/.cargo/env; S=<audit>; git -C <repo> worktree add --detach $S/wt/inc HEAD; cd $S/wt/inc; export CARGO_TARGET_DIR=$S/targets/inc; cargo build --release -p r2s --features sleigh; echo '// touch' >> crates/r2ssa/src/lib.rs; time cargo build --release -p r2s --features sleigh; git checkout crates/r2ssa/src/lib.rs; export CARGO_PROFILE_RELEASE_INCREMENTAL=true; cargo build --release -p r2s --features sleigh; sed -i '' '145s/$/ std::hint::black_box(0u8);/' crates/r2ssa/src/cfg.rs; time cargo build --release -p r2s --features sleigh; git checkout crates/r2ssa/src/cfg.rs; cd <repo>; git worktree remove --force $S/wt/inc
```
**B7**
```
source ~/.cargo/env; cd <repo>; export CARGO_TARGET_DIR=<audit>/targets/p-build-test; time cargo test --workspace --all-features --no-run --timings; cargo test --workspace --all-features --no-run --message-format=json 2>/dev/null | python3 -c "import json,sys,os\nfor l in sys.stdin:\n  m=json.loads(l)\n  if m.get('reason')=='compiler-artifact' and m.get('executable') and m['profile']['test']: print(os.path.getsize(m['executable']), m['target']['name'])" | sort -rn | head -30; ls crates/r2engine/tests/*.rs | wc -l
```
**B8**
```
source ~/.cargo/env; cd <repo>; export CARGO_TARGET_DIR=<audit>/targets/p-build-feat; cargo build -p r2s --features sleigh; cargo test --workspace --all-features --no-run --timings 2>&1 | grep -E 'Compiling (sleigh-config|r2ssa|r2engine)'; ls -d $CARGO_TARGET_DIR/debug/build/sleigh-config-*/out | wc -l
```
**B9**
```
source ~/.cargo/env; cd <repo>; export CARGO_TARGET_DIR=<audit>/targets/p-build; cargo build --release -p r2s --features sleigh; cargo build --profile dist -p r2s --features sleigh; ls -l $CARGO_TARGET_DIR/release/r2s $CARGO_TARGET_DIR/dist/r2s; cd ../radare2/test/bins/elf; for b in $CARGO_TARGET_DIR/release/r2s $CARGO_TARGET_DIR/dist/r2s; do /usr/bin/time -l $b -qc 'pdd @ 0x23fdf0' pumasim 2>&1 >/dev/null | grep 'instructions retired'; done
```
**B10** [p-build; c-architecture]
```
source ~/.cargo/env; cd <repo>; cargo tree -d -p r2s --features sleigh -e normal,build --offline | grep -E '^[a-z]' | sort -u; grep -rln petgraph crates/*/src; strings -n 4 target/release/r2s | grep -c '/Users/'
source ~/.cargo/env; cd <repo>; grep -rn serde_json crates/r2types crates/r2engine; grep -hE '^(authors|repository)' crates/*/Cargo.toml | wc -l; grep -hE '^(version|edition|license)\.workspace' crates/*/Cargo.toml | sort | uniq -c; sed -n 1,15p crates/r2s/src/allocator.rs; sed -n 28,36p crates/r2s/Cargo.toml; grep -n 'unused' <audit>/c-architecture/dylint.log
```

### Tests & CI (T)

**T1**
```
Copy tests/equiv to a scratch dir on an x86-64 Linux host with gcc. Append the cases in $A/probe_cases.py (A=<audit>/r2-equiv-ci) to the copy's selftest.py. Then run: python3 $A/only_cases.py <copy>/tests/equiv /tmp/out audit-wrong-global-then-residual-return audit-wrong-print-then-residual audit-wrong-global-control. Already run on contabo: /root/audit-equiv/repo-probe, output in $A/probe_masking.txt. Population counts: python3 -c "import json;r=[x for x in json.load(open('$A/ci/equivalence-38555101615-1/records.json'))['records'] if x['status']=='residual-trap'];print(len(r),sum(x['vectors']['equal']==0 for x in r))"
```
(verifier: the print case can grade `ub` because of x+1 overflow on INT_MAX; use an XOR variant.)
**T2**
```
cd <repo>; for k in kani mutants machete udeps strict-dylint quality-gate; do printf '%s ci=%s\n' $k $(grep -c $k .github/workflows/ci.yml); done; grep -rn 'kani::proof' crates/*/src | wc -l; bash scripts/quality-gate.sh --dry-run | tail -3; find . -type d -name fuzz -not -path './target*' -not -path './vendor/*'
# Running the proofs (all pass today):
source ~/.cargo/env; cargo install --locked kani-verifier && cargo kani setup; T=<audit>/targets/c-tests/kani; for m in r2il r2sleigh-lift r2ssa r2types; do CARGO_TARGET_DIR=$T cargo kani --manifest-path crates/$m/Cargo.toml --output-format terse 2>&1 | grep 'Complete -'; done
```
**T3** [c-architecture; c-tests]
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; CARGO_TARGET_DIR=<audit>/targets/c-architecture timeout 1200 cargo dylint --path tools/dylints/r2sleigh_lints --workspace -- --all-features --lib --bins 2>&1 | grep -A1 '^warning' | grep -- '-->'; grep -n 'cargo dylint' .github/workflows/ci.yml; grep -n 'STRICT_DYLINT:-' scripts/quality-gate.sh
```
```
cd <repo>; grep -c 'declare_lint!' tools/dylints/r2sleigh_lints/src/lib.rs; grep -A2 'pub R2DEC_RAW_CALL_TARGET_ADDRESS_PARSER' tools/dylints/r2sleigh_lints/src/lib.rs; grep -rhn 'dylint_lib = "r2sleigh_lints", deny' crates/*/src/lib.rs crates/*/src/main.rs | sed 's/.*deny(//' | sort | uniq -c; grep -n 'cargo dylint' .github/workflows/ci.yml
```
**T4** [c-tests; c-info]
```
cd <repo>; grep -n 'diff_r2' .github/workflows/ci.yml scripts/quality-gate.sh
```
```
source ~/.cargo/env; export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:$HOME/.local/bin:$PATH"; cd <repo>; python3 scripts/diff_r2.py --r2 ~/.local/bin/r2 --r2s target/release/r2s --bins ../radare2/test/bins/pe --limit 400 --only is --no-build | tail -25; python3 scripts/diff_r2.py --r2 ~/.local/bin/r2 --r2s target/release/r2s --bins ../radare2/test/bins/mach0 --limit 400 --only ie --verbose --no-build | head -4
```
**T5**
```
grep -n 'strip --strip-all' tests/equiv/README.md
target/release/r2s -qc 'aa; pdd @ sym.sext' tests/fixtures/rv_O0g | grep residual
target/release/r2s -qc 'aa; pdd @ 0x144c' tests/fixtures/rv_O0g_stripped | grep -c residual
```
**T6** [c-decompiler; r2-whole-program]
```
python3 scripts/certify_render.py --no-build --r2s target/release/r2s tests/fixtures/rv_O0g --functions 100 --verbose | grep -v '^  ok'; echo rc=$?
python3 scripts/certify_render.py --no-build --r2s target/release/r2s --bins ../radare2/test/bins/elf --limit 24 --functions 8 | tail -12
python3 scripts/certify_render.py --no-build --r2s target/release/r2s tests/fixtures/rv_O0g_stripped; echo rc=$?
python3 scripts/certify_render.py --no-build --r2s target/release/r2s tests/fixtures/syscalls_static_O2; echo rc=$?
```
```
for f in elf/ls elf/static-glibc-2.27 elf/r2pay-arm64.so elf/true32 mach0/ls-osx-x86_64; do python3 scripts/certify_render.py ../radare2/test/bins/$f --r2s target/release/r2s --no-build --functions 100000 --timeout 60 | tail -6; done
```
**T7**
```
P=<audit>/r2-aarch64; head -40 $P/diff1.txt; grep -c '^== ' $P/diff1.txt   # first pass without harness fallbacks: 27 cases STOP; every float case needed harness_ops
```
(verifier: diff1 already used the float fallbacks.)
**T8**
```
source ~/.cargo/env; cd <repo>; T=<audit>/targets/c-tests/cov; A=<audit>/c-tests; CARGO_TARGET_DIR=$T cargo llvm-cov nextest --workspace --all-features --no-fail-fast --no-report --config-file $A/nextest.toml && CARGO_TARGET_DIR=$T cargo llvm-cov report --json --output-path $A/cov.json --ignore-filename-regex '(vendor/|/tests/|\.cargo/registry|/rustc/)' && python3 $A/cov_rank.py $A/cov.json && python3 $A/cov_funcs.py $A/cov.json | head; grep -rn 'memory_mirrored_carriers\|register_identity_census' crates --include='*.rs'
```
**T9**
```
source ~/.cargo/env; cd <repo>; T=<audit>/targets/c-tests; CARGO_TARGET_DIR=$T/plain cargo test --workspace --all-features --no-run; nm $T/plain/debug/r2s | grep -c dhat; nm $T/plain/debug/r2s | grep -c mi_malloc; nm target/release/r2s | grep -ci dhat; CARGO_TARGET_DIR=$T/r2s-sleigh cargo build -p r2s --features sleigh && cp $T/r2s-sleigh/debug/r2s $T/r2s-sleigh/r2s-mimalloc && CARGO_TARGET_DIR=$T/r2s-sleigh cargo build -p r2s --features sleigh,dhat-heap,alloc-count && cp $T/r2s-sleigh/debug/r2s $T/r2s-sleigh/r2s-dhat; for b in r2s-mimalloc r2s-dhat; do /usr/bin/time -l $T/r2s-sleigh/$b -qc 'aa; pdd @ 0x01002ecc' tests/fixtures/shapes_zig_riscv64_O0 2>&1 >/dev/null | grep 'instructions retired'; done
```
**T10**
```
cd <repo>; sh -c 'ulimit -v 1000000; echo rc=$?'; timeout 60 sh -c 'ulimit -v 1000000; exec "$0" -q -c "$1" "$2"' target/release/r2s 'pdf @ sym.classify' tests/fixtures/rv_O0g 2>&1 | head -2; gcc --version | head -1; cc --version | head -1; grep -n -A7 '^fn gcc()' crates/r2s/tests/pddj.rs
```
**T11**
```
cd <repo>; grep -n '^class ' tests/equiv/test_equiv.py; grep -n -A4 'The harness.s contracts' .github/workflows/ci.yml; git log --oneline -S 'test_equiv.BatchTests' -- .github/workflows/ci.yml; cd tests/equiv && python3 -m unittest -v test_equiv.TargetTests 2>&1 | tail -3
```
**T12**
```
cd <repo>; grep -n 'parse_count(argument, 64)' crates/r2s/src/commands.rs; grep -n '"px' scripts/diff_r2.py; grep -rn '"px' crates/r2s/tests/; F=tests/fixtures/rv_O0g; timeout 60 target/release/r2s -qc 'px @ 0x120a' $F | wc -l; timeout 60 ~/.local/bin/r2 -e scr.color=0 -qc 'px @ 0x120a' $F 2>/dev/null | wc -l; timeout 60 ~/.local/bin/r2 -qc 'b' $F
```
**T13** — see M21 (second block).
**T14**
```
source ~/.cargo/env; cd <repo>; W=<audit>/wt/c-tests-doc; git worktree add -q --detach $W HEAD && cd $W && sed -i '' 's/```rust,ignore/```rust,no_run/' crates/r2sleigh-lift/src/lib.rs crates/r2sleigh-lift/src/disasm/mod.rs crates/r2sleigh-lift/src/sleigh.rs && CARGO_TARGET_DIR=<audit>/targets/c-tests/plain cargo test -p r2sleigh-lift --features x86 --doc 2>&1 | grep -E '^error|test result'; cd <repo> && git worktree remove --force $W
```
**T15**
```
source ~/.cargo/env; cd <repo>; A=<audit>; CARGO_TARGET_DIR=$A/targets/c-tests/plain cargo nextest run --workspace --all-features --no-fail-fast --config-file $A/c-tests/nextest.toml && python3 $A/c-tests/junit_times.py $A/targets/c-tests/nextest-store/default/junit.xml | head -40
```
**T16**
```
cd <repo>; ls .config/nextest.toml; grep -n 'nextest run\|timeout-minutes: 20' .github/workflows/ci.yml | head -3
```
**T17**
```
cd <repo>; git check-ignore -v tools/dylints/r2sleigh_lints/Cargo.lock; git ls-files | grep Cargo.lock; grep -n 'dylint' tools/dylints/r2sleigh_lints/Cargo.toml
```
**T18**
```
cd <repo>; grep -rn 'test_setup_corpus\|merge_audit' .github scripts/quality-gate.sh; python3 -m unittest tests/test_setup_corpus.py 2>&1 | tail -2
```
**T19**
```
sed -n 40,45p tests/coverage/run_coverage.sh
sed -e 's|^cargo build.*|:|' tests/coverage/run_coverage.sh > /tmp/rc.sh  # then run the copy from tests/coverage/ with artifact_root redirected (see artifacts/cov/run_coverage_nobuild.sh)
clang --version | head -1; python3 -c "import json;print(json.load(open('tests/coverage/coverage-baseline.json'))['clang'])"
```
**T20**
```
cd <repo>; python3 -c "import json;b=json.load(open('tests/equiv/baseline.json'))['records'];b.update(json.load(open('tests/equiv/baseline-aarch64.json'))['records']);[print(k,'::',b[k]['cause'][:160]) for k in ['tests/gold/review.c::gcc-O2::sext','tests/corpus/branchy.c::gcc-O1::gate_three','tests/corpus/shapes.c::aarch64-clang-O0::shape_recurse_mutual','tests/corpus/branchy.c::clang-O0::main']]"; objdump -d <audit>/r2-equiv-ci/ci/equiv-shard-gcc-O2-a/build/review/gcc-O2/shown/review --start-address=0x401550 --stop-address=0x401563
```
**T21** — see W46 (frame_agree line).
**T22** — see M22 (second block).
**T23**
```
VM: cd /root/r2s-stack && python3 scripts/census.py exponent --r2s /root/r2s-target-audit/r2s-release --out /tmp/exp.tsv /root/radare2/test/bins/elf/pumasim /root/radare2/test/bins/elf/0pack
```

## Appendix B — Finding counts

**Raw (as filed, finder severity), 228 findings from 19 probes.**

| Probe | Filed | Confirmed | Refuted | Critical | High | Medium | Low |
|---|---|---|---|---|---|---|---|
| c-info | 15 | 15 | 0 | 1 | 3 | 6 | 5 |
| c-listing | 11 | 11 | 0 | 1 | 1 | 3 | 6 |
| c-analysis | 14 | 14 | 0 | 0 | 3 | 8 | 3 |
| c-decompiler | 12 | 12 | 0 | 0 | 2 | 4 | 6 |
| c-robustness | 11 | 11 | 0 | 1 | 1 | 5 | 4 |
| c-missing | 14 | 14 | 0 | 0 | 3 | 7 | 4 |
| c-architecture | 8 | 7 | 1 | 0 | 1 | 3 | 4 |
| c-tests | 14 | 14 | 0 | 0 | 2 | 6 | 6 |
| p-cpu-mac | 12 | 12 | 0 | 0 | 2 | 3 | 7 |
| p-linux | 12 | 12 | 0 | 0 | 2 | 5 | 5 |
| p-memory | 14 | 13 | 1 | 0 | 1 | 7 | 6 |
| p-scaling | 10 | 10 | 0 | 0 | 2 | 5 | 3 |
| p-build | 11 | 11 | 0 | 0 | 4 | 4 | 3 |
| p-session | 11 | 11 | 0 | 0 | 2 | 5 | 4 |
| r2-equiv-ci | 9 | 8 | 1 | 0 | 2 | 3 | 4 |
| r2-aarch64 | 15 | 15 | 0 | 0 | 7 | 7 | 1 |
| r2-render-corpora | 14 | 14 | 0 | 0 | 4 | 7 | 3 |
| r2-whole-program | 10 | 10 | 0 | 0 | 3 | 5 | 2 |
| r2-tui | 11 | 10 | 1 | 0 | 2 | 7 | 2 |
| **Total** | **228** | **224** | **4** | **3** | **47** | **100** | **78** |

The severity columns above cover filed findings including the refuted ones. Among the 224 confirmed findings, the finder severities are critical 3, high 46, medium 99, low 76. Refuted: high 1, medium 1, low 2. No finding has DISPUTED status. In this report, 88 rows carry a `(corrected …)` tag, meaning a verifier changed the cause, scope, numbers or severity, so "224 confirmed" does not mean 224 unchanged; split votes (`partially-confirmed`) were resolved by applying the verifier's corrections.

**After deduplication (this report, verifier-corrected severity):** see the merged tally at the end of this appendix.

**Merged tally (rows of this report, verifier-corrected severity):**

| Section | Rows | High | Medium | Low |
|---|---|---|---|---|
| §2 Correctness (W) | 63 | 15 | 33 | 15 |
| §3 Missing (M) | 22 | 1 | 12 | 9 |
| §4 Design (D) | 16 | 0 | 9 | 7 |
| §5.2 Performance (P) | 32 | 2 | 12 | 18 |
| §5.3 Build (B) | 10 | 0 | 4 | 6 |
| §6 Tests & CI (T) | 23 | 0 | 8 | 15 |
| **Total** | **166** | **18** | **78** | **70** |

Critical after correction: 0. Four rows (D1, D2, D3, B5) restate the design root of rows elsewhere (W4; W45/W56/W59; W8; D9), so there are 162 distinct issues. The 224 confirmed findings collapse into these rows because 23 root causes were reported by 2–5 probes each. For example: the PE read gate ×4, callee preparation ×5, DWARF eager ×4, PE imports ×3, spans scan ×3, producers ×3, phantom functions ×4, invented arguments ×4.
