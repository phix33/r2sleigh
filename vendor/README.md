# Vendored crates

The Sleigh crates this engine is built on, owned and built from this tree.
Each is a copy of its 0verflowme fork's `main` (which carries every change
below as a merged pull request), keeping only the files its own `include`
list packages; a refresh copies the fork again and re-applies the trims.
`libsla-sys`'s Ghidra, the compiler `sleigh-compiler` builds against its
headers, and `sleigh-config`'s specifications sit on one Ghidra commit, master
`918acd744d` (2026-10-13): the engine resyncs whenever the specifications do
(ROADMAP D33).

| Crate | Fork `main` | Upstream | Carried by the fork | Vendoring trims |
|---|---|---|---|---|
| `libsla` 1.2.0 | 0verflowme/libsla `e97cd24d` | mnemonikr/libsla | user-operation names and the parser-cache reset (mnemonikr/libsla#18, #19); `GhidraSleigh` reads its address spaces once, a space's name is interned, and the p-code emit reads each varnode in place and its space from that list (ROADMAP PF1; #1); the specification's instruction alignment as `Sleigh::instruction_alignment` (audit W25; #3) | the fork's `[patch]` to the other forks; the workspace's `[patch.crates-io]` stands in |
| `libsla-sys` 0.1.5 | 0verflowme/libsla-sys `0919334f` (Ghidra 0verflowme/ghidra `6763e1ec`, `r2sleigh-sleigh-context` on 11.4's `aed1cf1c`); this tree vendors Ghidra 0verflowme/ghidra `ec9a9312`, `r2sleigh-sleigh-context-12`: PF0 and W2 on master `918acd744d` | mnemonikr/libsla-sys | the same two passthroughs (mnemonikr/libsla-sys#8, #9); `getVarnodeSpace` and `getVarnodeOffset`, which read a varnode where `getAddress` allocated an `Address` (#1); Ghidra's include directory stated as `DEP_SLA_INCLUDE` (#2); Ghidra: `SleighBase` keeps the context fields `buildXrefs` found, `Sleigh` records whether a decode committed context and can mark its cached parses stale, and `clearCache` rebuilds the context only after a commit (ROADMAP PF0; #3); `cc`'s `parallel` feature (audit B1; #4); `getAlignment` passed through as `getAlignmentProxy` (audit W25; #5) | Ghidra's decompiler C++ only, copied in place of the submodule, with `metatype.cc` built since `918acd744d` (`marshal.hh` includes it); built at `opt-level = 3` in dev and release by the root `Cargo.toml`, as the spec compiler's build dependency too (audit B2) |
| `sleigh-compiler` 2.0.2 | 0verflowme/sleigh-compiler `4e380af4` | mnemonikr/sleigh-compiler | compiles against `DEP_SLA_INCLUDE`, `libsla-sys`'s Ghidra headers, since it links that `libsla` and must see the same class layouts (#1); carried here, fork pull request owed: `slgh_compile.cc` re-ported onto `918acd744d`, the commit those headers are, and `largeTemporaryWarning` gone with GP-6316, which made a temporary over 256 bytes an error | no Ghidra copy of its own: `DEP_SLA_INCLUDE` is required; built at `opt-level = 3` as a build dependency (audit B2) |
| `sleigh-config` 1.0.1 | 0verflowme/sleigh-config `cd2c2111` | mnemonikr/sleigh-config | each processor's files by name with its `.ldefs` and `.dwarf` (#1); Ghidra's Go compiler specifications corrected to Go's `abi-internal.md` (ROADMAP LP1; #2); AArch64 `addv` zeroes the vector above its byte result (#3); resynced from Ghidra master (918acd744d): `ldpsw`, `ldapr Xt`, `ldar Wt`, `stlrb`/`stlrh`, scalar `fmadd`/`fmsub` and the reductions' zero-fill (#4), `eor3`/`bcax`/`rax1`/`xar` (GP-7313; #10); W-form sign-extending loads (#5, the shape of Ghidra #6471 and #6447); W/H/B atomics, CAS, `ldapr`, `ldlar` and `swp` write the whole register and min/max compare at the access size (#6, Ghidra #9893); `mrs`/`msr nzcv` and `crc32`'s polynomial (#7, Ghidra #9895, #9896); `stlxp` at +8 (#8, Ghidra #9894); scalar FP rounding (#9, Ghidra #9897); specifications and tables `static` (audit B3; #11); one `sla-<stem>` feature per `.slaspec` beside the processor features (audit B4; #12); AArch64 `casp` X form compares and stores Xs and Xt at `[Xn]` in either byte order (#13, Ghidra #9900); every AArch64 load-exclusive marks the monitor with `SetExclusiveMonitors` (audit M2; #14); every acquire and release stated on the side it orders (`LoadAcquire`, `LoadAcquirePC`, `StoreRelease`), where Ghidra marked only the LSE forms, with LDLAR's LORegion names and on the wrong side (#15) | only the x86, ARM, AARCH64, MIPS and RISCV processors, and only their `sla-<stem>` features (no processor feature), so the engine's 8 languages are the ones compiled (`ARM8_be` added for BE32 ARM, audit W26) |

Carried in this tree, not yet in the fork (sleigh-config #16 and #17): AArch64's unsigned scalar
`fcvt{a,m,n,p,z}u` into W and X and the scalar fixed-point `fcvtzu` into H, S
and D saturate as FPToFixed states (NaN and below 0 give 0, at or above 2^N all
ones), where #9's text wrapped (`fp_to_unsigned`, `fp_to_unsigned64`;
`AARCH64neon.sinc`). The scalar fixed-point `fcvtzu` into H and D reads its
fraction bits with `Imm_shr_imm16` and `Imm_shr_imm64`, as `fcvtzs` does, where
Ghidra read `Imm_shr_imm32`: `fcvtzu d0, d1, #8` decoded as `#-0x38` and
`fcvtzu h0, h1, #8` as `#0x28`.

Carried in this tree, its Ghidra half on 0verflowme/ghidra
`r2sleigh-sleigh-context-12` (`ec9a9312`) and not yet in the forks' mains (fork
pull requests owed to 0verflowme/libsla-sys and 0verflowme/libsla; audit W2):
Ghidra's `ParserContext::applyCommits` writes only a commit aimed at the
instruction's fall-through into the context database. One aimed elsewhere
(a Thumb or ARM `blx`'s `globalset` of `TMode` at its target, MIPS `jalx`'s
`ISA_MODE`) goes to `Sleigh::contextTargets()` with the bits the database holds
there, so a continued run no longer decodes everything above a backward
target in the target's set, and `contextCommitted` no longer counts it
(`context.hh`, `context.cc`, `sleigh.hh`, `sleigh.cc`). Java's
`DisassemblerContextImpl` already keeps such a value for that address alone,
and the decompiler never commits, so this is a fork change, not a Ghidra one.
libsla-sys passes the record through as `context_targets` (`bridge.hh`,
`bridge.cc`, `sys.rs`), and libsla as `PcodeDisassembly::context_targets`
(`ContextTarget`, with `differs`).

Carried in this tree, fork pull requests owed to 0verflowme/libsla-sys and
0verflowme/libsla: GP-2493 renamed `CPUI_EXTRACT` to `CPUI_ZPULL` and added
`CPUI_SPULL` (74); `sys.rs` states both, and libsla maps them to
`AnalysisOp::Extract` and `AnalysisOp::SignedExtract`.

A parse deeper than Ghidra's parser holds is Ghidra's own refusal since GP-6554
(`5328fa2c6d`, in `918acd744d`): `ParserContext` grows its constructor states,
and `allocateOperand` and `pushOperand` throw `LowlevelError` past a 32-entry
operand path or a state's 20 operands, which libsla-sys returns as a decode
error. The `BadDataError` check this tree carried for 11.4 is gone; libflutter's
`vldm` at `0x7cd6ea9f` (a count of 159) still decodes as invalid
(`crates/r2sleigh-lift/tests/parse_depth.rs`), and no Ghidra pull request is
owed.

Licences: Apache-2.0 (each crate's `LICENSE`), with Ghidra's `NOTICE`,
`DISCLAIMER.md` and `licenses/` kept beside its sources.
