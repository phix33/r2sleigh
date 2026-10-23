#!/usr/bin/env python3
"""Print one function of a DecBench run: the source body, the r2s rendering, GED and type_match, and DWARF variables.

    PYTHONPATH=<decbench> <venv>/bin/python show_function.py --run <tree> PROJECT OPT BINARY FUNCTION [--dec angr]
"""

from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ged_causes import function_body  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--run", required=True, type=Path)
    p.add_argument("--dec", default="r2sleigh_native")
    p.add_argument("--no-source", action="store_true")
    p.add_argument("--graphs", action="store_true", help="print the source's and the rendering's block graphs")
    p.add_argument("--short", action="store_true", help="omit the rendering's helper prelude and declarations")
    p.add_argument("project")
    p.add_argument("opt")
    p.add_argument("binary")
    p.add_argument("function")
    a = p.parse_args(argv)
    from decbench.models.project import OptimizationLevel, Project
    from decbench.pipeline.executor import PipelineConfig, PipelineExecutor
    from decbench.results_store import gather_project_tomls
    from decbench.metrics.type_match import extract_ground_truth_type_index

    ck = pickle.loads((a.run / "checkpoints" / f"{a.project}.pkl").read_bytes())
    opt = OptimizationLevel(a.opt)
    res = ck["decompile"][opt][a.binary][a.dec]
    fn = res.functions[a.function]
    ev = ck["evaluate"][opt][a.binary][a.dec]
    print(f"== {a.dec} {a.project}/{a.opt}/{a.binary} {a.function} @ {hex(fn.address)}  metadata gotos={fn.metadata.get('gotos')} "
          f"bools={fn.metadata.get('bools')} residual={fn.metadata.get('residual')}")
    for m in ("ged", "type_match", "byte_match"):
        if m in ev and a.function in ev[m].function_results:
            v = ev[m].function_results[a.function]
            print(f"{m}: {v.value}  {({k: v.metadata[k] for k in v.metadata if k in ('tp','fp','fn','gt_vars','source_nodes','source_edges','decompiled_nodes','decompiled_edges')})}")
    gt = extract_ground_truth_type_index(res.binary_path)
    for addr, names in gt.items():
        if a.function in names and (addr == fn.address or len(names) == 1):
            print("DWARF variables:")
            for v in names[a.function]:
                print("  ", v["name"], "arg" if v["is_arg"] else "loc", v["type"][:5], "stack" if v["rbp_offset"] else "")
    if not a.no_source or a.graphs:
        project = Project.from_toml(next(t for t in gather_project_tomls() if t.stem == a.project))
        PipelineExecutor(PipelineConfig(output_dir=a.run, optimization_levels=[opt]))._discover_existing_binaries([project], a.run)
    if not a.no_source:
        for stem, path in project.preprocessed_sources.get(opt, {}).items():
            body = function_body(Path(path).read_text(errors="replace"), a.function)
            if body:
                print(f"--- source ({stem}.i)")
                print(body)
                break
    if a.graphs:
        from decbench.utils.cfg import extract_cfgs_from_decompilation, extract_cfgs_from_source

        sub = res.model_copy(update={"functions": {a.function: fn}})
        dgraph = extract_cfgs_from_decompilation(sub).get(a.function)
        sgraph = None
        for stem, path in project.preprocessed_sources.get(opt, {}).items():
            sg = extract_cfgs_from_source(Path(path))
            if a.function in sg:
                sgraph = sg[a.function]
                break
        for label, g in (("source", sgraph), (a.dec, dgraph)):
            if g is None:
                continue
            print(f"--- {label} block graph: {g.number_of_nodes()} blocks, {g.number_of_edges()} edges")
            order = {n: i for i, n in enumerate(sorted(g.nodes, key=lambda n: n.addr if hasattr(n, "addr") else 0))}
            for n in sorted(g.nodes, key=lambda n: order[n]):
                role = ("E" if getattr(n, "is_entrypoint", False) else "") + ("X" if getattr(n, "is_exitpoint", False) else "")
                print(f"  b{order[n]}[{len(n.statements)}]{role} -> " + ", ".join(f"b{order[m]}" for m in g.successors(n)))
    print(f"--- {a.dec} rendering")
    code = fn.decompiled_code
    if a.short:
        code = code[code.index(a.function + "("):] if (a.function + "(") in code else code
        code = "\n".join(line for line in code.splitlines() if not line.strip().startswith(("/* r2dec proof",)))
    print(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
