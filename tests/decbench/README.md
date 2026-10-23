Getting measured on DecBench
============================

[DecBench](https://decbench.com) ranks decompilers by how often they recover
source *exactly*: control-flow structure by graph edit distance, variable and
signature types against DWARF, and assembly similarity after recompiling with
the original toolchain. Its Union score is the share of functions perfect on at
least one of the three.

**Valid numbers start at [RESULT-2026-10-17.md](RESULT-2026-10-17.md) and are
corrected by [RESULT-2026-10-23.md](RESULT-2026-10-23.md): the first scored no bash
row for any decompiler.** Everything this directory recorded before
2026-09-25 -- `baseline.json`, the tables that used to be here, and the figures
in the since-deleted planning documents -- was measured
through the deleted radare2 plugin with `decbench run`, which hands the
decompiler the unstripped `-g` binary. r2sleigh read that binary's DWARF (the
prototypes, parameter and local names and types that `type_match` is scored
against) and its symbols (every function boundary and name), and the
population included CRT functions the leaderboard excludes. `baseline.json`
carries an `invalid` field saying so, and `report_decbench.py` refuses to
compare against it or merge into it; the next accepted run starts a new record.

The official protocol
---------------------

Measurement goes through DecBench's own driver, `scripts/run_benchmark.py`,
and nothing else:

* the decompiler gets a `strip --strip-all` copy of each binary;
* it is told the DWARF `low_pc` of every source function, and nothing about
  names;
* its answers are relabelled to the DWARF names afterwards and scored against
  the unstripped build.

```
git clone https://github.com/noelo-lab/decbench ../decbench
python3.12 -m venv ../decbench-venv && ../decbench-venv/bin/pip install -e ../decbench
tests/decbench/run_decbench.sh --decbench ../decbench --python ../decbench-venv/bin/python \
    --compile --project bzip2 --opt-level O0 --opt-level O2
tests/decbench/run_decbench.sh --plan          # print the commands, run nothing
```

`run_decbench.sh` builds `target/release/r2s` (or takes `--r2s`), installs this
tree's backend into the DecBench checkout (`install_backend.py`), refuses to
measure unless the installed backend reports the sha256 of that r2s, runs
`scripts/run_benchmark.py` through `decbench_cli.py` (which registers `vj_ged`
when DecBench does not), checks every result names that sha256, and reports
against `baseline.json` (`--accept-baseline` to record the run).

The driver needs cgroup v2 and a user systemd manager (`systemd-run --user`)
for its per-binary limits, and GED needs Joern, which `pyjoern` downloads from
github.com release assets. `angr` is the reference column and needs Python 3.12.

The backend
-----------

`r2sleigh_raw.py` registers one backend, `r2sleigh_native`, which asks `r2s`
one `pddj` per function, one stdin line each to a single `r2s -q <binary>`,
through the streaming runner it shares with the equivalence gate
(`tests/equiv/r2s_batch.py`). A binary of any size is one process; opening it
has its own deadline (`R2SLEIGH_STARTUP_TIMEOUT`, default 600 s) and each
function its own from the moment r2s starts on it
(`R2SLEIGH_FUNCTION_TIMEOUT`, default 300 s). It guarantees:

* **Exactly the targets.** It renders the addresses the driver gave it, with no
  symbol lookup; with no targets it renders what `afl` finds, through
  DecBench's shared skip rule.
* **Addresses pass through.** r2s reports ELF link addresses, which are
  DecBench's file space for PIE and non-PIE alike.
* **The name is the definition.** `FunctionDecompilation.name` is the
  identifier the rendering defines (`pddj.definition`), so DecBench's relabel
  renames the code and the key together.
* **Every function is accounted for.** Each is rendered or declined with a
  typed cause -- `refused: ...` (r2s's own), `r2s: ...` (a failed statement),
  or `harness: r2s <ending> while rendering <addr>` (a crash or deadline, after
  which r2s restarts at the next function) -- and
  `rendered + declined == requested` is checked.
* **Checkpoints.** The partial result is pickled after every function, so the
  driver's hard kill keeps what was answered.
* **Fails closed.** A binary carrying `.symtab` or any debug section
  (`.debug_*`, `.zdebug_*`, `.gnu_debugdata`) is declined
  whole: nothing r2s says about it is admissible.
* **Structured facts.** `variables` and `line_mappings` come from `pddj`.
  `r2sleigh_native` is not on DecBench's `ADDRESS_CORRESPONDENCE_BACKENDS`
  allowlist, but a function whose `line_mappings` carry instruction addresses
  is scored by address correspondence anyway (`has_line_address_evidence`):
  argument position, then stack offset, then address overlap of the lines
  naming a variable. In the 2026-10-23 run that is every function with a
  `type_match` row (the legacy offset rule, fed by `pddj`'s stack offsets,
  scored 20 functions of zlib in the 2026-10-17 run and none now).

Declines and residual counts are written per binary to
`r2sleigh-refusals-*.json` (schema 4) beside the run, and
`census_decbench.py` ranks their causes.

Memory and coverage
-------------------

Evaluating r2s's `bash` (a 13 MB C file for 1,540 functions) takes 5.2 GB in one
`evaluate_project` worker. Four workers on the 8 GB benchmark host are killed by
the OOM killer, `evaluate_project` then returns `{}` for the binary, and the
scoreboard silently drops it: the 2026-10-17 run scored no bash row for any
decompiler (angr kept 692 rows of one build). Run `bash` with `--workers 1`, check
`evaluated/<binary>.toml` is not 16 bytes, and read the scoreboard only over rows
every compared decompiler has (`compare_runs.py --exclude-project bash`): the
scoreboard's denominator is every row *anyone* scored, so a row only one decompiler
has counts as a miss for the others. A re-run of one decompiler is
`DECBENCH_REDO_DECOMPILERS=r2sleigh_native` on a copy of the tree; DecBench's
`finalize_results.py --allow-drops` is needed when functions that used to be declined
(rows named by their address) are now rendered.

Analysis tools
--------------

All read a results tree (`checkpoints/*.pkl`, `function_results.json`) and need the
DecBench venv (`PYTHONPATH=<decbench checkout>`); only `evaluate_checkpointed.py` writes
into the tree (the scores it adds to a checkpoint).

* `compare_runs.py`: the four-decompiler table, the delta against an earlier tree
  (`--old`), the same over a row subset (`--exclude-project bash`), paired
  better/worse/newly-perfect counts (`--paired`), the goto/residual split.
* `type_causes.py`: one verdict per DWARF variable from DecBench's own matcher
  (asserted equal to the stored `type_match`), grouped by cause with the number of
  functions each cause alone keeps imperfect; `universe` says why a function has no row.
* `ged_causes.py`, `counterfactual_ged.py`: block-graph deltas of the not-GED-perfect
  functions, and a re-score after a respelling, to bound what a renderer change gains.
* `evaluate_checkpointed.py`: evaluates decompilers already in a checkpoint (the driver
  only evaluates what it has just run); `r2s_timing.py`: r2s alone, without the backend's
  checkpoint, with peak RSS; `show_function.py`: source, rendering, scores and DWARF of one function.

Local measurement
-----------------

Two censuses run on one binary, on this machine, without the driver. Both show
r2s a stripped copy and take the targets from the binary's own DWARF:

* `compile_census.py <binary>` compiles every rendering exactly as `pddj`
  printed it, at `-std=gnu11` (implicit declarations are errors, so a unit that
  calls a helper it does not define fails) and at
  `-std=c11 -O2 -Wall -Wextra -Werror`, and groups failures by first message;
* `byte_match_census.py <binary built with -g> --decbench ../decbench` scores
  every rendering with DecBench's own `byte_match` implementation.

Tests
-----

```
python3 -m unittest discover -s tests/decbench -p 'test_*.py'
../decbench-venv/bin/python -m unittest discover -s tests/decbench -p 'test_*.py'
```

The backend tests drive `tests/equiv/testdata/stub_r2s.py`, which answers
`pddj` per the contract and fails on request in every way r2s can (a failed
statement, an abort, a hang, garbage, a contract breach, death before the first
answer). They run against DecBench itself when it is importable and against
minimal stand-ins otherwise.
