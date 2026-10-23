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
    from decbench.metrics.type_match import _ground_truth_for_function, extract_ground_truth_type_index
    from decbench.utils.binfmt import detect, source_function_owners
    from decbench.utils.dwarf_policy import dwarf_follow_abstract_origin

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
    info = detect(res.binary_path)
    variables = _ground_truth_for_function(extract_ground_truth_type_index(res.binary_path), a.function,
                                           int(fn.address), info.arch if info is not None else "")
    if variables:
        print("DWARF variables:")
        for v in variables:
            print("  ", v["name"], "arg" if v["is_arg"] else "loc", v["type"][:5], "stack" if v["rbp_offset"] else "")
    # The unit that defines the function is the one the binary's DWARF names for its address, never a guess by name.
    units, owner = {}, None
    if not a.no_source or a.graphs:
        project = Project.from_toml(next(t for t in gather_project_tomls() if t.stem == a.project))
        PipelineExecutor(PipelineConfig(output_dir=a.run, optimization_levels=[opt]))._discover_existing_binaries([project], a.run)
        units = {stem: Path(path) for stem, path in project.preprocessed_sources.get(opt, {}).items()}
        owner = source_function_owners(
            res.binary_path, set(units), follow_abstract_origin=dwarf_follow_abstract_origin()).get(int(fn.address))
        if owner is None:
            print(f"--- source: no DWARF owner at {hex(fn.address)}")
    if owner is not None and not a.no_source:
        body = function_body(units[owner[1]].read_text(errors="replace"), owner[0])
        if body:
            print(f"--- source ({units[owner[1]].name})")
            print(body)
    if a.graphs:
        from decbench.utils.cfg import extract_cfgs_from_decompilation, extract_cfgs_from_source

        sub = res.model_copy(update={"functions": {a.function: fn}})
        dgraph = extract_cfgs_from_decompilation(sub).get(a.function)
        sgraph = extract_cfgs_from_source(units[owner[1]]).get(owner[0]) if owner is not None else None
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
