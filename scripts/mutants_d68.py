#!/usr/bin/env python3
"""D68's mutation target: each mutant of the dominance checks is applied to the tree, the tests that should kill it run,
and the file is restored. A mutant that survives is expected to, and says why (doc/adr-decompiler-rewrite.md, "D2's
spelling order", the D68 section).

  mutants_d68.py [--check] [NAME...]    run (or only --check that every edit applies once) the named mutants, else all

Run from the repository root with the files below unmodified. Exit 1 where a mutant lives that should die, or dies that
should live."""

import os
import subprocess
import sys

LANES = "cargo test -p r2ssa --lib --features fact_mutants function::tests::lanes"
R2DEC = "cargo test -p r2dec --lib --all-features"
ENGINE = "cargo test -p r2engine --test engine structure::"
# The tests that accept a residual where the lane was: all but the one that wants r2ssa's own refusal.
RESIDUAL = "cargo test -p r2engine --test engine -- a_call_argument_is_never a_lane_the_facts_name_on_the_other_arm_is_read_as"

SHARED = "crates/r2ssa/src/semantic/shared.rs"
STAGE = "crates/r2ssa/src/function/stage.rs"
INTEGRITY = "crates/r2ssa/src/integrity.rs"
VALUES = "crates/r2dec/src/render/values.rs"
SPELLED = "crates/r2dec/src/render/spelled.rs"
ORDER = "crates/r2dec/src/structure/order.rs"

UNFILTERED = (SHARED, "crate::fact_mutants::unsound_lanes()\n                ||", "true\n                ||")
UNCHECKED = (STAGE, "if !crate::fact_mutants::facts_unchecked() {", "if false {")
UNGUARDED = (VALUES, "variable_or_residual(owed == Some(0), scope)", "variable_or_residual(owed == Some(0), || true)")


def drop_read(old):
    return (INTEGRITY, old, "Ok::<(), SsaIntegrityError>(())?;")


# (name, edits, tests that run in order, whether it must die, why it may live)
MUTANTS = [
    ("lane-unfiltered", [UNFILTERED], [LANES], True, ""),
    ("lane-unfiltered-facts-unchecked", [UNFILTERED, UNCHECKED], [LANES], True, ""),
    ("guard-alone-holds", [UNFILTERED, UNCHECKED], [RESIDUAL], False,
     "with r2ssa's pick and check both gone the renderer's guard still makes the read a residual, which the engine tests accept"),
    ("guard-unwired", [UNGUARDED], [R2DEC, ENGINE], True, ""),
    ("block-never-entered", [(SPELLED, "values.enter(addr);", "let _ = addr;")], [ENGINE], True, ""),
    ("guard-allows-nondominating", [(VALUES, "    } else if !scope() {", "    } else if false && !scope() {")], [R2DEC], True, ""),
    ("guard-cause-swapped", [(VALUES, "Err(UnassignedCause::NotDominated)\n    } else {", "Err(UnassignedCause::Unassigned)\n    } else {")], [R2DEC], True, ""),
    ("validator-unwired", [UNCHECKED], [LANES, ENGINE], True, ""),
    ("defined-before-same-block-inclusive", [(INTEGRITY, "is_none_or(|defined| defined < ordinal)", "is_none_or(|defined| defined <= ordinal)")], [LANES], True, ""),
    ("defined-before-phi-late", [(INTEGRITY, "is_none_or(|defined| defined < ordinal)", "is_some_and(|defined| defined < ordinal)")], [LANES], True, ""),
    ("defined-before-entry-undefined", [(INTEGRITY, "let Some(def) = graph.def_inst(value) else {\n        return true;", "let Some(def) = graph.def_inst(value) else {\n        return false;")], [LANES], True, ""),
    ("defined-before-always", [(INTEGRITY, "    function.domtree().strictly_dominates(def_block, block_addr)\n}", "    true\n}")], [LANES], True, ""),
    ("defined-before-dominates-not-strictly", [(INTEGRITY, "function.domtree().strictly_dominates(def_block, block_addr)\n}", "function.domtree().dominates(def_block, block_addr)\n}")], [LANES], False,
     "equivalent: the same block returned above, so the blocks differ and dominance is strict"),
    ("validator-call-argument", [drop_read('read("call argument", site, value)?;')], [LANES], True, ""),
    ("validator-carrier", [drop_read('read("call argument carrier", site, carrier)?;')], [LANES], True, ""),
    ("validator-call-target", [drop_read('read("call target", BoundarySite::Inst(call.at), call.target)?;')], [LANES], True, ""),
    ("validator-return-value", [drop_read('read("return value", site, value.value)?;')], [LANES], True, ""),
    ("validator-return-address", [drop_read('read("return address", site, address.value)?;')], [LANES], True, ""),
    ("validator-exit-stack-pointer", [drop_read('read("exit stack pointer", site, value)?;')], [LANES], True, ""),
    ("validator-branch-condition", [drop_read('read("branch condition", site, predicate.condition)?;')], [LANES], True, ""),
    ("validator-switch-selector", [drop_read('read(\n                "switch selector",\n                BoundarySite::BlockEnd(switch.block_addr),\n                selector,\n            )?;')], [LANES], True, ""),
    ("validator-block-end-is-start", [(INTEGRITY, "BoundarySite::BlockEnd(addr) => Some((addr, usize::MAX)),", "BoundarySite::BlockEnd(addr) => Some((addr, 0)),")], [LANES], False,
     "no fact the fixtures hold reads a value its own block defines; the block-end reads the SSA validator already orders"),
    ("order-inlines-exits-not", [(ORDER, "pub(crate) const fn inlines_exits(self) -> bool {\n            true", "pub(crate) const fn inlines_exits(self) -> bool {\n            false")], [R2DEC], True, ""),
    ("order-exits-reversed", [(ORDER, "pub(crate) fn exits(self, _: &mut [u64]) {}", "pub(crate) fn exits(self, list: &mut [u64]) {\n            list.reverse();\n        }")], [R2DEC], True, ""),
    ("order-merges-reversed", [(ORDER, "pub(crate) fn merges(self, _: &mut [u64]) {}", "pub(crate) fn merges(self, list: &mut [u64]) {\n            list.reverse();\n        }")], [R2DEC], True, ""),
]


def run(name, edits, tests, must_die, why, check):
    files = {path for path, _, _ in edits}
    originals = {path: open(path).read() for path in files}
    for path, old, new in edits:
        if originals[path].count(old) != 1:
            return f"{name}: the edit's old text occurs {originals[path].count(old)} times in {path}", False
    if check:
        return f"{name}: applies", True
    text = dict(originals)
    for path, old, new in edits:
        text[path] = text[path].replace(old, new, 1)
    try:
        for path in files:
            open(path, "w").write(text[path])
        killer = None
        for command in tests:
            done = subprocess.run(command, shell=True, capture_output=True, text=True)
            if done.returncode != 0:
                killer = command
                break
    finally:
        for path in files:
            open(path, "w").write(originals[path])
    died = killer is not None
    verdict = f"killed by `{killer}`" if died else f"survived {len(tests)} test commands" + (f" ({why})" if why else "")
    return f"{name}: {verdict}", died == must_die


def main():
    args = sys.argv[1:]
    check = "--check" in args
    names = [a for a in args if not a.startswith("--")]
    if not check and subprocess.run(["git", "diff", "--quiet", "--"] + sorted({p for _, e, *_ in MUTANTS for p, _, _ in e})).returncode:
        sys.exit("a file a mutant edits has changes: commit or restore them first")
    bad = 0
    for name, edits, tests, must_die, why in MUTANTS:
        if names and name not in names:
            continue
        line, ok = run(name, edits, tests, must_die, why, check)
        print(("ok   " if ok else "WRONG"), line, flush=True)
        bad += not ok
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    main()
