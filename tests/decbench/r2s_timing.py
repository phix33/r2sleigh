#!/usr/bin/env python3
"""Time r2s alone on the functions a DecBench run asked it for, one binary at a time, without the harness.

    r2s_timing.py --r2s <r2s> --run <results tree> [--project NAME ...] > timing.tsv

The official driver's wall time for r2s includes the backend's progress checkpoint, a pickle of the whole partial
result (every 30 s since 2026-10-23; after every function before, which grew with the binary). This replays the same
`s <addr>; pddj` stream through the same runner (`tests/equiv/r2s_batch.py`) with no checkpoint, and prints per binary:
functions asked, rendered, declined, wall seconds (open, `aa`, every function) and the peak resident set of the r2s
process in kB.
Targets are the addresses the run's own tomls name (rendered plus failed), so the two measure the same set.
Each binary runs in its own Python process, serially, so the peak RSS is that binary's alone.
"""

from __future__ import annotations

import argparse
import json
import re
import resource
import subprocess
import sys
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "equiv"))
sys.path.insert(0, str(HERE))

from run_gate import binaries_by_stem  # noqa: E402


def targets(toml_path: Path) -> list[int]:
    data = tomllib.loads(toml_path.read_text())
    addresses = {int(v["address"], 16) if isinstance(v["address"], str) else int(v["address"])
                 for k, v in data.items() if k.startswith("functions.")}
    addresses |= {int(a, 16) for a in data.get("failed_functions", []) if re.fullmatch(r"0x[0-9a-fA-F]+", a)}
    return sorted(addresses)


def one(r2s: Path, binary: Path, addresses: list[int]) -> dict:
    import r2s_batch

    started = time.monotonic()
    report = r2s_batch.run_batch(r2s, binary, addresses, function_timeout=300.0, startup_timeout=600.0)
    wall = time.monotonic() - started
    ok = sum(1 for a in report.answers if a.ok)
    return {"asked": len(addresses), "rendered": ok, "declined": len(report.answers) - ok,
            "seconds": round(wall, 2), "processes": report.processes,
            "maxrss_kb": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}


def cells(run: Path, opts, projects) -> list[tuple[str, str, str, Path, Path | None]]:
    """`(opt, project, binary stem, toml, stripped file or None)` for every r2s toml of the run.

    The stripped file is found by stem: `libz.so.1.2.13` on disk is the driver's binary `libz.so.1.2`.
    """
    found = []
    for opt in opts:
        for toml_path in sorted(run.glob(f"{opt}/*/decompiled/r2sleigh_native_*.toml")):
            project = toml_path.parts[-3]
            if projects and project not in projects:
                continue
            binary = toml_path.name.removesuffix(".toml")[len("r2sleigh_native_"):]
            stripped = binaries_by_stem(toml_path.parent.parent / "stripped").get(binary)
            found.append((opt, project, binary, toml_path, stripped))
    return found


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--r2s", type=Path)
    p.add_argument("--run", type=Path)
    p.add_argument("--project", action="append")
    p.add_argument("--opt", action="append")
    p.add_argument("--one", nargs=2, metavar=("BINARY", "TOML"))
    args = p.parse_args(argv)
    if args.one:
        print(json.dumps(one(args.r2s, Path(args.one[0]), targets(Path(args.one[1])))))
        return 0
    print("project\topt\tbinary\tasked\trendered\tdeclined\tseconds\tmaxrss_kb")
    timed = unresolved = failed = 0
    for opt, project, binary, toml_path, stripped in cells(args.run, args.opt or ("O2", "O2-noinline"), args.project):
        if stripped is None:
            unresolved += 1
            print(f"{project}\t{opt}\t{binary}\tNO-STRIPPED-BINARY\t\t\t\t", flush=True)
            continue
        out = subprocess.run([sys.executable, __file__, "--r2s", str(args.r2s), "--one", str(stripped), str(toml_path)],
                             capture_output=True, text=True, check=False)
        try:
            r = json.loads(out.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            failed += 1
            print(f"{project}\t{opt}\t{binary}\tFAILED\t\t\t\t", flush=True)
            print(out.stderr[-300:], file=sys.stderr)
            continue
        timed += 1
        print(f"{project}\t{opt}\t{binary}\t{r['asked']}\t{r['rendered']}\t{r['declined']}\t{r['seconds']}\t{r['maxrss_kb']}",
              flush=True)
    print(f"timed {timed} binaries, {unresolved} without a stripped binary, {failed} failed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
