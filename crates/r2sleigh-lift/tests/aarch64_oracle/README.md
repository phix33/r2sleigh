# AArch64 CPU oracle

`aarch64_oracle.rs` checks that the trusted lift, run through `r2il::eval`,
computes what an arm64 CPU computes (ROADMAP VC, LS0; audit T7).

- `cases.txt`: one instruction sequence per line, `name|flags|asm`. Flags shape
  the input state (`P` pointers into scratch memory in x9/x10, `I`/`J`/`U` small
  indexes in x11, `F` float lanes, `B` a branch to `TGT`, `E` a cas whose
  expected value matches memory, `A` addresses computed from the code).
- `record.sh` (arm64 host only) generates `cases.S` with `gen.py`, links it with
  `driver.c` and runs every case on the CPU from 16 states drawn by one xorshift
  stream, writing `recorded.txt`: per case its page offset, branch distance and
  encoding, and per run the input hash and only what the run changed. Appending
  cases keeps every earlier recorded run unchanged.
- The test draws the same states (checking each hash), lifts each case, runs it,
  and compares every register, flag, vector (a NaN matches any NaN in its lane:
  p-code leaves the payload open) and memory byte, including an 8 KiB zero guard
  after the random memory.
- `expected.txt` lists the cases that stop or disagree, a ratchet: a case leaving
  it must be removed, one joining it fails. `R2S_BLESS=1` rewrites it.
