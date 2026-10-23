#!/usr/bin/env python3
"""Fail a DecBench run that lost rows, and refuse an evaluation that the host will kill.

    run_gate.py evaluated --tree <results tree> --decompilers a,b [--since EPOCH]
    run_gate.py workers   --tree <results tree> --workers N --decompilers a,b

On 2026-10-17 the host's OOM killer took the evaluation worker of every bash binary, `evaluate_project` returned `{}`,
and the driver went on: kuna, ghidra and r2s had no bash row, and the scoreboard dropped them without a word.

* `evaluated`: every binary a decompiler rendered functions for in this run (its `decompiled/<dec>_<binary>.toml` is
  newer than `--since` and says `function_count > 0`) needs an `evaluated/<binary>.toml` that carries a score key of that
  decompiler. A missing file, a file of just `binary = "bash"` (16 bytes) and a file that scores only other
  decompilers all stop the run with exit status 71.
* `workers`: one evaluation worker needs 5.2 GB for the 13 MB of C that r2s writes for bash, so more than one worker on
  a binary whose decompiled C exceeds 8 MB is refused (exit status 72). The same check runs inside the driver through
  `install_workers_guard`, before `evaluate_project`, where the C is known; it raises `SystemExit` because the driver
  catches `Exception` around the evaluation and carries on with `{}`.
"""

from __future__ import annotations

import argparse
import functools
import inspect
import os
import re
import sys
from pathlib import Path

LOST = 71
REFUSED = 72
MAX_PARALLEL_C_BYTES = 8 * 1024 * 1024
# Read without a TOML parser, so the shell can run this under any python3: DecBench writes
# `function_count = N` and quotes the dotted score keys, `"<decompiler>.<metric>.total" = 0.5`.
FUNCTION_COUNT = re.compile(r"^function_count\s*=\s*(\d+)", re.MULTILINE)
SCORE_KEY = re.compile(r'^"?([^".=\s]+)\.[^"=]*"?\s*=', re.MULTILINE)


def split_name(stem: str, decompilers: list[str]) -> tuple[str, str] | None:
    """`r2sleigh_native_bash` -> (`r2sleigh_native`, `bash`), the longest decompiler name that fits."""
    for decompiler in sorted(decompilers, key=len, reverse=True):
        if stem.startswith(decompiler + "_") and len(stem) > len(decompiler) + 1:
            return decompiler, stem[len(decompiler) + 1:]
    return None


def binaries_by_stem(directory: Path) -> dict[str, Path]:
    """`{stem: file}` of a run's `stripped/` directory: `libz.so.1.2.13` is the driver's binary `libz.so.1.2`."""
    return {path.stem: path for path in sorted(directory.glob("*")) if path.is_file()}


def rendered_binaries(tree: Path, decompilers: list[str], since: float | None = None) -> list[dict]:
    """The (opt, project, binary, decompiler) cells the driver decompiled into this tree, with function counts."""
    cells = []
    for toml in sorted(tree.glob("*/*/decompiled/*.toml")):
        named = split_name(toml.stem, decompilers)
        if named is None or (since is not None and int(toml.stat().st_mtime) < since):
            continue
        try:
            found = FUNCTION_COUNT.search(toml.read_text())
        except (OSError, ValueError):
            found = None
        count = int(found.group(1)) if found else 0
        if count > 0:
            opt, project = toml.parts[-4], toml.parts[-3]
            cells.append({"opt": opt, "project": project, "binary": named[1], "decompiler": named[0],
                          "functions": count, "dir": toml.parent.parent, "toml": toml})
    return cells


def lost_evaluations(tree: Path, decompilers: list[str], since: float | None = None) -> tuple[int, list[str]]:
    """How many cells were checked, and one message per cell whose scores are not in the evaluated file."""
    cells = rendered_binaries(tree, decompilers, since)
    lost = []
    for cell in cells:
        where = f"{cell['opt']}/{cell['project']}/evaluated/{cell['binary']}.toml"
        evaluated = cell["dir"] / "evaluated" / f"{cell['binary']}.toml"
        who = f"{cell['decompiler']} rendered {cell['functions']} functions of {cell['binary']}"
        if not evaluated.is_file():
            reason = f"{where} is missing"
        else:
            try:
                scored = sorted(set(SCORE_KEY.findall(evaluated.read_text())))
            except (OSError, ValueError):
                scored = None
            size = evaluated.stat().st_size
            if scored is None:
                reason = f"{where} cannot be read ({size} bytes)"
            elif cell["decompiler"] not in scored:
                reason = (f"{where} is {size} bytes and scores "
                          f"{', '.join(scored) if scored else 'no decompiler'}, not {cell['decompiler']}")
            else:
                continue
        c_file = cell["toml"].with_suffix(".c")
        if c_file.is_file() and c_file.stat().st_size > MAX_PARALLEL_C_BYTES:
            reason += (f"; its decompiled C is {c_file.stat().st_size / 2**20:.1f} MB, so the evaluation worker was "
                       "most likely OOM-killed (evaluate with --workers 1)")
        lost.append(f"{who}, but {reason}")
    return len(cells), lost


def c_bytes_of(decompilations: dict) -> dict[tuple[str, str], int]:
    """`{binary: {decompiler: DecompilationResult}}` -> the bytes of C each pair holds."""
    sizes = {}
    for binary, per_decompiler in decompilations.items():
        for decompiler, result in per_decompiler.items():
            functions = getattr(result, "functions", None) or {}
            sizes[(str(binary), str(decompiler))] = sum(
                len((getattr(function, "decompiled_code", "") or "").encode()) for function in functions.values())
    return sizes


def unsafe_workers(sizes: dict[tuple[str, str], int], workers: int | None) -> list[str]:
    """One line per binary whose decompiled C is over the limit when more than one worker would evaluate it."""
    if (workers if workers is not None else os.cpu_count() or 1) <= 1:
        return []
    return [f"{binary} ({decompiler}): {size / 2**20:.1f} MB of C"
            for (binary, decompiler), size in sorted(sizes.items()) if size > MAX_PARALLEL_C_BYTES]


def refuse_unsafe_workers(decompilations: dict, workers: int | None) -> None:
    over = unsafe_workers(c_bytes_of(decompilations), workers)
    if over:
        raise SystemExit(
            f"refusing to evaluate with {workers if workers is not None else 'all'} workers: "
            + "; ".join(over)
            + f" (limit {MAX_PARALLEL_C_BYTES // 2**20} MB). One evaluation worker for r2s's bash holds 5.2 GB, "
            "so parallel workers are OOM-killed and the binary loses every score. Run it with --workers 1.")


def install_workers_guard() -> None:
    """Put `refuse_unsafe_workers` in front of DecBench's `evaluate_project`, before the driver imports the name."""
    from decbench.pipeline import evaluate

    original = evaluate.evaluate_project
    if getattr(original, "_r2sleigh_guard", False):
        return
    signature = inspect.signature(original)

    @functools.wraps(original)
    def guarded(*args, **kwargs):
        given = signature.bind_partial(*args, **kwargs).arguments
        refuse_unsafe_workers(given.get("decompilations") or {}, given.get("workers"))
        return original(*args, **kwargs)

    guarded._r2sleigh_guard = True
    evaluate.evaluate_project = guarded


def tree_c_bytes(tree: Path, decompilers: list[str]) -> dict[tuple[str, str], int]:
    """The decompiled C files already in a tree: `(opt/project/binary, decompiler) -> bytes`."""
    sizes = {}
    for c_file in sorted(tree.glob("*/*/decompiled/*.c")):
        named = split_name(c_file.stem, decompilers)
        if named is not None:
            sizes[(f"{c_file.parts[-4]}/{c_file.parts[-3]}/{named[1]}", named[0])] = c_file.stat().st_size
    return sizes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("check", choices=("evaluated", "workers"))
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--decompilers", default="")
    parser.add_argument("--since", type=float)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args(argv)
    decompilers = [d for d in args.decompilers.split(",") if d]
    if not decompilers:
        parser.error("--decompilers is required")

    if args.check == "workers":
        over = unsafe_workers(tree_c_bytes(args.tree, decompilers), args.workers)
        if over:
            print(f"refusing --workers {args.workers}: " + "; ".join(over) + f" in {args.tree} "
                  f"(limit {MAX_PARALLEL_C_BYTES // 2**20} MB); one evaluation worker for r2s's bash holds 5.2 GB. "
                  "Use --workers 1.", file=sys.stderr)
            return REFUSED
        return 0

    checked, lost = lost_evaluations(args.tree, decompilers, args.since)
    if lost:
        print(f"ERROR: {len(lost)} of {checked} rendered binaries have no evaluation; their rows would be dropped "
              "from the scoreboard:", file=sys.stderr)
        for line in lost[:30]:
            print(f"  {line}", file=sys.stderr)
        if len(lost) > 30:
            print(f"  ... and {len(lost) - 30} more", file=sys.stderr)
        return LOST
    print(f"evaluations present for all {checked} binaries the run decompiled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
