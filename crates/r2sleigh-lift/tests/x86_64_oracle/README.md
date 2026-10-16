# x86-64 CPU oracle

`x86_64_oracle.rs` checks that the trusted x86-64 lift, run through `r2il::eval`,
computes what an x86-64 CPU computes (ROADMAP D35, VC). It is the AArch64 oracle's
format (`../aarch64_oracle/README.md`), drawn from the same stream
(`../oracle_common/stream.h`, `../oracle_common/mod.rs`).

- `cases.txt`: one instruction sequence per line, `name|flags|asm[|extra]`, the
  assembly in GNU as Intel syntax. Flags shape the input state: `P` points RSI and
  RDI into scratch memory, `E` puts RAX in `[rdi]` and RBX on half the runs (a
  `cmpxchg` that succeeds), `N` keeps BX nonzero (a `bsf`/`bsr` whose destination
  is defined), `D` and `S` keep an unsigned or signed division from faulting at
  every width, `F` draws float lanes. `extra` names a flag or register the SDM
  leaves undefined for every input the case draws (`bsf` of a zero source).
- `gen.py` derives what each case leaves undefined from its table of the Intel
  SDM Vol. 2 "Flags Affected" rows, instruction by instruction, a shift's or
  rotate's by its masked count. A mnemonic without a row stops the generator, so
  a new instruction comes with its citation.
- `record.sh` (x86-64 Linux) assembles the cases with `driver.c` and runs each
  on the CPU from 16 states, writing `recorded.txt`: per case its undefined set
  and encoding, and per run the input hash and what the run changed in the
  defined state. An undefined flag is printed as it was and an undefined
  register not at all, so the recording holds no vendor's choice: recorded on
  contabo's AMD EPYC (twice, byte for byte), another x86-64 host should
  reproduce it, though no Intel host has yet. CI replays the committed
  recording and does not re-record.
- The test draws the same states (checking each hash), lifts each instruction,
  runs the case, and compares RAX to R15, RSP (never loaded, so it must not
  move), CF PF AF ZF SF DF OF, XMM0 to XMM15 (a NaN matches any NaN in its lane),
  that YMM's upper halves are not written (legacy SSE keeps them), and every
  memory byte including an 8 KiB zero guard. MXCSR starts at 0x1f80 and is not
  compared.
- `expected.txt` lists the cases that stop or disagree, a ratchet: a case leaving
  it must be removed, one joining it fails. `R2S_BLESS=1` rewrites it.

Adding a case: append its line to `cases.txt` (appending keeps every earlier
run's inputs), run `sh record.sh` on an x86-64 Linux host, then
`R2S_BLESS=1 cargo test -p r2sleigh-lift --features x86 --test x86_64_oracle`
and read the change to `expected.txt`.
