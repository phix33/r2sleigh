# Vendored crates

The Sleigh crates this engine is built on, owned and built from this tree.
Each is a copy of its 0verflowme fork's `main` (which carries every change
below as a merged pull request), keeping only the files its own `include`
list packages; a refresh copies the fork again and re-applies the trims.

| Crate | Fork `main` | Upstream | Carried by the fork | Vendoring trims |
|---|---|---|---|---|
| `libsla` 1.2.0 | 0verflowme/libsla `e97cd24d` | mnemonikr/libsla | user-operation names and the parser-cache reset (mnemonikr/libsla#18, #19); `GhidraSleigh` reads its address spaces once, a space's name is interned, and the p-code emit reads each varnode in place and its space from that list (ROADMAP PF1; #1); the specification's instruction alignment as `Sleigh::instruction_alignment` (audit W25; #3) | the fork's `[patch]` to the other forks; the workspace's `[patch.crates-io]` stands in |
| `libsla-sys` 0.1.5 | 0verflowme/libsla-sys `0919334f` (Ghidra 0verflowme/ghidra `6763e1ec`, `r2sleigh-sleigh-context` on `aed1cf1c`) | mnemonikr/libsla-sys | the same two passthroughs (mnemonikr/libsla-sys#8, #9); `getVarnodeSpace` and `getVarnodeOffset`, which read a varnode where `getAddress` allocated an `Address` (#1); Ghidra's include directory stated as `DEP_SLA_INCLUDE` (#2); Ghidra: `SleighBase` keeps the context fields `buildXrefs` found, `Sleigh` records whether a decode committed context and can mark its cached parses stale, and `clearCache` rebuilds the context only after a commit (ROADMAP PF0; #3); `cc`'s `parallel` feature (audit B1; #4); `getAlignment` passed through as `getAlignmentProxy` (audit W25; #5) | Ghidra's decompiler C++ only, copied in place of the submodule; built at `opt-level = 3` in dev and release by the root `Cargo.toml`, as the spec compiler's build dependency too (audit B2) |
| `sleigh-compiler` 2.0.2 | 0verflowme/sleigh-compiler `4e380af4` | mnemonikr/sleigh-compiler | compiles against `DEP_SLA_INCLUDE`, `libsla-sys`'s Ghidra headers, since it links that `libsla` and must see the same class layouts (#1) | no Ghidra copy of its own: `DEP_SLA_INCLUDE` is required; built at `opt-level = 3` as a build dependency (audit B2) |
| `sleigh-config` 1.0.1 | 0verflowme/sleigh-config `4b6f11ea` | mnemonikr/sleigh-config | each processor's files by name with its `.ldefs` and `.dwarf` (#1); Ghidra's Go compiler specifications corrected to Go's `abi-internal.md` (ROADMAP LP1; #2); AArch64 `addv` zeroes the vector above its byte result (#3); resynced from Ghidra master (918acd744d): `ldpsw`, `ldapr Xt`, `ldar Wt`, `stlrb`/`stlrh`, scalar `fmadd`/`fmsub` and the reductions' zero-fill (#4), `eor3`/`bcax`/`rax1`/`xar` (GP-7313; #10); W-form sign-extending loads (#5, the shape of Ghidra #6471 and #6447); W/H/B atomics, CAS, `ldapr`, `ldlar` and `swp` write the whole register and min/max compare at the access size (#6, Ghidra #9893); `mrs`/`msr nzcv` and `crc32`'s polynomial (#7, Ghidra #9895, #9896); `stlxp` at +8 (#8, Ghidra #9894); scalar FP rounding (#9, Ghidra #9897); specifications and tables `static` (audit B3; #11); one `sla-<stem>` feature per `.slaspec` beside the processor features (audit B4; #12); AArch64 `casp` X form compares and stores Xs and Xt at `[Xn]` in either byte order (#13, Ghidra #9900); every AArch64 load-exclusive marks the monitor with `SetExclusiveMonitors` (audit M2; #14) | only the x86, ARM, AARCH64, MIPS and RISCV processors, and only their `sla-<stem>` features (no processor feature), so the engine's 7 languages are the ones compiled |

Carried in this tree, not yet in the fork: every AArch64 instruction the Arm
ARM gives acquire or release semantics states it with a user operation in the
shape of Ghidra's `LOAcquire()`, named by the Arm ARM's own terms (B2.3):
`LoadAcquire()` after the load of `ldar`, `ldaxr`, `ldaxp` and their B/H forms
(C6.2.145-151), `LoadAcquirePC()` after `ldapr` and `ldapur*` (C6.2.136-144),
`StoreRelease()` before the store of `stlr`, `stlur*`, `stlxr`, `stlxp` and
their B/H forms (C6.2.310-319), and both around the LSE `ld<op>`, `st<op>`,
`swp` and `cas`/`casp` A, L and AL forms (C6.2.42-45, C6.2.133-135,
C6.2.366-368; `ls_loa`/`ls_lor` and the new `cas_loa`/`cas_lor`). A release
opens the instruction and an acquire closes it, the side each orders, so the
lift states either as a fence there. Ghidra's own `ls_loa`/`ls_lor` spelled the
LSE forms with `LOAcquire`/`LORelease`, which are LDLAR's and STLLR's
LORegion-limited orderings (C6.2.160-162, C6.2.307-309), and put the acquire
before the load and the release after the store; `ldar`, `stlr`, the
exclusives and `cas` were unmarked. `ldlar`/`stllr` keep Ghidra's text and stay
unmodelled. A form with no mark is Relaxed: Ghidra's `""` forms of
`ls_loa`/`ls_lor` already said so, and with every ordered form marked it holds
for the whole file (audit M2's rest; `AARCH64base.sinc`,
`AARCH64instructions.sinc`).

Licences: Apache-2.0 (each crate's `LICENSE`), with Ghidra's `NOTICE`,
`DISCLAIMER.md` and `licenses/` kept beside its sources.
