#!/usr/bin/env python3
"""Evaluate decompilers whose results already sit in a run's checkpoint, with the driver's own functions.

    PYTHONPATH=<decbench> <venv>/bin/python evaluate_checkpointed.py <tree> --project bash \
        --decompilers angr,kuna,ghidra [--workers 1]

`scripts/run_benchmark.py` evaluates only the decompilers it has just run, so a decompiler whose evaluation was lost
(the 2026-10-17 run lost every bash evaluation to the host's OOM killer: five GB per worker, four workers) cannot be
re-scored without decompiling it again. This takes the stored `DecompilationResult`s, calls the driver's
`project_source_functions`, `extract_source_cfgs` and DecBench's `evaluate_project` exactly as `main` does, writes the
scores into the checkpoint, and leaves `finalize_results.py` to rebuild `scoreboard.toml`. Nothing is decompiled, and
the per-binary `evaluated/*.toml` files are not touched (the output directory of `evaluate_project` is a scratch one).
`--workers` above 1 is refused when a binary's stored C is over 8 MB (`run_gate.py`).
"""

from __future__ import annotations

import argparse
import os
import pickle
import sys
import tempfile
from pathlib import Path

from run_gate import refuse_unsafe_workers


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("tree", type=Path)
    p.add_argument("--project", required=True)
    p.add_argument("--decompilers", required=True)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--opt-levels", default="O2,O2-noinline")
    p.add_argument("--metrics", default="byte_match,ged,vj_ged,type_match")
    args = p.parse_args()
    os.environ["DECBENCH_WORKERS"] = str(args.workers)
    os.environ["DECBENCH_METRICS"] = args.metrics
    os.environ["DECBENCH_OPT_LEVELS"] = args.opt_levels
    import decbench
    sys.path.insert(0, str(Path(decbench.__file__).resolve().parents[1] / "scripts"))
    import run_benchmark as rb  # the driver's module; importing it runs nothing

    from decbench.models.project import Project
    from decbench.pipeline.evaluate import evaluate_project
    from decbench.results_store import gather_project_tomls

    decs = args.decompilers.split(",")
    ckpt = args.tree / "checkpoints" / f"{args.project}.pkl"
    ck = pickle.loads(ckpt.read_bytes())
    for opt_decompiled in ck["decompile"].values():
        refuse_unsafe_workers({stem: {d: per[d] for d in decs if d in per}
                               for stem, per in opt_decompiled.items()}, args.workers)
    project = Project.from_toml(next(t for t in gather_project_tomls() if t.stem == args.project))
    rb.discover(project, args.tree)
    scratch = Path(tempfile.mkdtemp(prefix="evaluate_checkpointed_"))
    for opt in rb.OPT_LEVELS:
        source_stems = set(project.preprocessed_sources.get(opt, {}).keys())
        owners, kept = {}, []
        for b in project.compiled_binaries.get(opt, []):
            stems = {}
            fns = rb.project_source_functions(b, source_stems, stem_out=stems)
            if fns:
                owners[b.stem] = {a: (n, stems[a]) for a, n in fns.items() if a in stems}
                kept.append(b)
        project.compiled_binaries[opt] = kept
        src_cfgs = rb.extract_source_cfgs(project, opt)
        stored = ck["decompile"][opt]
        dec = {b.stem: {d: stored[b.stem][d] for d in decs if d in stored.get(b.stem, {})} for b in kept}
        print(f"[{args.project}/{opt.value}] evaluating {decs} on {len(kept)} binaries", flush=True)
        ev = evaluate_project(project, dec, scratch, opt, rb.METRICS, parallel=True, workers=args.workers,
                              precomputed_source_cfgs=src_cfgs, source_function_owners=owners)
        merged = ck["evaluate"].setdefault(opt, {})
        for stem, per_dec in ev.items():
            merged.setdefault(stem, {}).update({d: m for d, m in per_dec.items() if m})
        print(f"[{args.project}/{opt.value}] done: " + ", ".join(
            f"{stem}:{sorted(d for d, m in per.items() if m)}" for stem, per in ev.items()), flush=True)
    ckpt.write_bytes(pickle.dumps(ck))
    print(f"wrote {ckpt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
