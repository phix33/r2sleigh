#!/usr/bin/env python3
"""What separates an r2s function from a GED-perfect one, by graph shape and text.

    PYTHONPATH=<decbench> <venv>/bin/python ged_causes.py collect --run <results tree> --out rows.jsonl [--project zlib]
    python3 ged_causes.py report rows.jsonl

`collect` reads a checkpointed DecBench run (`<run>/checkpoints/*.pkl`), takes each function's stored GED of every
decompiler, and re-extracts the two block graphs DecBench's `ged` compared (the source's and r2s's, through the same
`evaluate_project` path) only to count their blocks, edges, exits, branches, multiway nodes and back edges. It also
counts `&&`, `||`, `switch` and the loop keywords in the source function (from the preprocessed unit) and in the
rendering. GED itself is not recomputed.

`report` takes the goto-free functions that are not GED-perfect and assigns each one class by the first rule that
holds (see `classify`). The classes are a reading of the graph delta, not a proof of the cause; the ceiling of a
class is the number of its functions on which some other decompiler is GED-perfect (an achieved shape), the same
test the 2026-10-22 goto analysis used.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import os
import pickle
import re
import sys
from pathlib import Path


def graph_features(g) -> dict:
    nodes = list(g.nodes)
    entries = [n for n in nodes if getattr(n, "is_entrypoint", False)] or [n for n in nodes if g.in_degree(n) == 0]
    # back edges: edges to a node still on the DFS stack
    state: dict = {}
    back = 0
    for root in entries:
        if root in state:
            continue
        stack = [(root, iter(g.successors(root)))]
        state[root] = 1
        while stack:
            node, it = stack[-1]
            for nxt in it:
                s = state.get(nxt, 0)
                if s == 1:
                    back += 1
                elif s == 0:
                    state[nxt] = 1
                    stack.append((nxt, iter(g.successors(nxt))))
                    break
            else:
                state[node] = 2
                stack.pop()
    return {
        "V": len(nodes), "E": g.number_of_edges(),
        "X": sum(1 for n in nodes if getattr(n, "is_exitpoint", g.out_degree(n) == 0)),
        "B": sum(1 for n in nodes if g.out_degree(n) == 2),
        "M": sum(1 for n in nodes if g.out_degree(n) >= 3),
        "L": back,
    }


def strip_noncode(text: str) -> str:
    text = re.sub(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', '""', text)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def function_body(unit: str, name: str) -> str | None:
    """The text of `name`'s definition in a preprocessed unit (ANSI or K&R), or None."""
    for m in re.finditer(r"(?<![\w.])" + re.escape(name) + r"\s*\(", unit):
        depth, i = 0, m.end() - 1
        while i < len(unit):
            c = unit[i]
            depth += c == "("
            depth -= c == ")"
            i += 1
            if depth == 0:
                break
        rest = unit[i:i + 600]
        if rest.lstrip().startswith((";", ",", ")", "=")):
            continue
        brace = rest.find("{")
        if brace < 0 or "}" in rest[:brace]:
            continue
        start = i + brace
        depth, j = 0, start
        while j < len(unit):
            depth += unit[j] == "{"
            depth -= unit[j] == "}"
            j += 1
            if depth == 0:
                return unit[start:j]
    return None


def text_features(code: str) -> dict:
    code = strip_noncode(code)
    return {
        "and_or": len(re.findall(r"&&|\|\|", code)),
        "switch": len(re.findall(r"\bswitch\b", code)),
        "case": len(re.findall(r"\bcase\b", code)),
        "for": len(re.findall(r"\bfor\s*\(", code)),
        "for_full": len(re.findall(r"\bfor\s*\([^;()]*;[^;()]+;[^()]*[^;\s)][^()]*\)", code)),
        "while": len(re.findall(r"\bwhile\s*\(", code)),
        "do": len(re.findall(r"\bdo\b\s*\{", code)),
        "goto": len(re.findall(r"\bgoto\b", code)),
        "ret": len(re.findall(r"\breturn\b", code)),
        "ternary": len(re.findall(r"\?", code)),
        "residual": len(re.findall(r"r2sleigh_residual", code)),
    }


def collect(args) -> None:
    os.environ["DECBENCH_NO_CACHE"] = "1"
    import decbench.metrics  # noqa: F401
    from decbench.metrics import ged as gedmod
    from decbench.models.metrics import MetricValue
    from decbench.models.project import OptimizationLevel, Project
    from decbench.pipeline.evaluate import evaluate_project
    from decbench.pipeline.executor import PipelineConfig, PipelineExecutor
    from decbench.results_store import gather_project_tomls
    from decbench.utils import binfmt
    from decbench.utils.cfg import extract_cfgs_from_source
    from decbench.utils.dwarf_policy import dwarf_follow_abstract_origin

    run = Path(args.run)
    scratch = Path(args.scratch)
    opts = [OptimizationLevel(v) for v in args.opt_levels.split(",")]
    captured: dict[str, dict] = {}

    def capture(self, decompiled, source_cfg=None, decompiled_cfg=None, **kw):
        if source_cfg is not None and decompiled_cfg is not None:
            captured[decompiled.name] = {"S": graph_features(source_cfg), "D": graph_features(decompiled_cfg)}
        return MetricValue(value=0.0)

    gedmod.GEDMetric.compute_for_function = capture
    out = open(args.out, "w")
    for toml in gather_project_tomls():
        if args.project and toml.stem not in args.project:
            continue
        ck_path = run / "checkpoints" / f"{toml.stem}.pkl"
        if not ck_path.exists():
            continue
        ck = pickle.loads(ck_path.read_bytes())
        project = Project.from_toml(toml)
        PipelineExecutor(PipelineConfig(output_dir=run, optimization_levels=opts))._discover_existing_binaries(
            [project], run)
        for opt in opts:
            units = project.preprocessed_sources.get(opt, {})
            stems = set(units)
            src_cfgs = {stem: extract_cfgs_from_source(path) or {} for stem, path in units.items()}
            unit_text = {}
            for b in project.compiled_binaries.get(opt, []):
                per_dec = (ck["decompile"].get(opt) or {}).get(b.stem) or {}
                stored = (ck["evaluate"].get(opt) or {}).get(b.stem) or {}
                r2s = per_dec.get("r2sleigh_native")
                if r2s is None:
                    continue
                owners = binfmt.source_function_owners(
                    b, stems, follow_abstract_origin=dwarf_follow_abstract_origin())
                captured.clear()
                evaluate_project(project, {b.stem: {"r2sleigh_native": r2s}}, scratch, opt, ["ged"],
                                 parallel=False, precomputed_source_cfgs=src_cfgs,
                                 source_function_owners={b.stem: owners})
                by_addr = {a: v for a, v in owners.items()}
                for name, fn in r2s.functions.items():
                    owner = by_addr.get(int(fn.address))
                    row = {"project": project.name, "opt": opt.value, "binary": b.stem, "function": name,
                           "address": int(fn.address), "gotos": fn.metadata.get("gotos", 0) if fn.metadata else 0,
                           "bools": fn.metadata.get("bools", 0) if fn.metadata else 0,
                           "residual": fn.metadata.get("residual", 0) if fn.metadata else 0,
                           "lines": fn.line_count,
                           "ged": {}, "tu": owner[1] if owner else None}
                    for dec in ("r2sleigh_native", "angr", "kuna", "ghidra"):
                        sv = stored.get(dec, {}).get("ged")
                        v = sv.function_results.get(name) if sv is not None else None
                        row["ged"][dec] = None if v is None or not math.isfinite(v.value) else v.value
                    row.update(captured.get(name, {}))
                    row["D_text"] = text_features(fn.decompiled_code or "")
                    if owner and owner[1] in units:
                        if owner[1] not in unit_text:
                            unit_text[owner[1]] = Path(units[owner[1]]).read_text(errors="replace")
                        body = function_body(unit_text[owner[1]], owner[0])
                        row["S_text"] = text_features(body) if body else None
                    out.write(json.dumps(row) + "\n")
                out.flush()
                print(project.name, opt.value, b.stem, len(r2s.functions), file=sys.stderr, flush=True)
    out.close()


def classify(r: dict) -> str:
    S, D, St, Dt = r["S"], r["D"], r["S_text"], r["D_text"]
    if St is None:
        return "no_source_text"
    if S["M"] != D["M"] or (St["switch"] and not Dt["switch"]):
        return "switch"
    if St["and_or"] > Dt["and_or"] and D["B"] < S["B"]:
        return "missing_and_or"
    if S["L"] != D["L"]:
        return "loop_count"
    if S["V"] == D["V"] and S["E"] == D["E"] and S["X"] == D["X"] and S["B"] == D["B"]:
        return "wiring_only"
    if S["X"] != D["X"]:
        return "exit_blocks"
    loops_s = St["for_full"] > 0
    loops_d = Dt["for_full"] > 0
    if (St["for"] or St["while"] or St["do"]) and loops_s != loops_d and S["V"] != D["V"]:
        return "loop_form"
    if D["V"] > S["V"]:
        return "extra_blocks"
    if D["V"] < S["V"]:
        return "missing_blocks"
    return "other"


def report(args) -> None:
    rows = [json.loads(line) for line in open(args.rows)]
    decs = ("r2sleigh_native", "angr", "kuna", "ghidra")
    scored = [r for r in rows if r["ged"]["r2sleigh_native"] is not None]
    perfect = [r for r in scored if r["ged"]["r2sleigh_native"] == 0]
    print(f"r2s functions with a rendering {len(rows)}, GED scored {len(scored)}, GED-perfect {len(perfect)}")
    gf = [r for r in scored if r["gotos"] == 0]
    gb = [r for r in scored if r["gotos"] > 0]
    print(f"goto-free {len(gf)} (perfect {sum(r['ged']['r2sleigh_native'] == 0 for r in gf)}), "
          f"with goto {len(gb)} (perfect {sum(r['ged']['r2sleigh_native'] == 0 for r in gb)})")
    pool = [r for r in gf if r["ged"]["r2sleigh_native"] > 0]
    print(f"goto-free, not perfect: {len(pool)}")

    def other_perfect(r):
        return {d: r["ged"][d] == 0 for d in decs[1:]}

    classes = collections.defaultdict(list)
    for r in pool:
        classes[classify(r) if "S" in r and "D" in r else "no_graph"].append(r)
    print(f"{'class':18s} {'n':>5s} {'resid>0':>8s} {'meanGED':>8s} {'GED<=3':>7s} {'any other perfect':>18s} "
          f"{'angr':>5s} {'kuna':>5s} {'ghidra':>6s}")
    for cls, items in sorted(classes.items(), key=lambda kv: -len(kv[1])):
        op = [other_perfect(r) for r in items]
        print(f"{cls:18s} {len(items):5d} {sum(r['residual'] > 0 for r in items):8d} "
              f"{sum(r['ged']['r2sleigh_native'] for r in items) / len(items):8.1f} "
              f"{sum(r['ged']['r2sleigh_native'] <= 3 for r in items):7d} "
              f"{sum(any(o.values()) for o in op):18d} "
              f"{sum(o['angr'] for o in op):5d} {sum(o['kuna'] for o in op):5d} {sum(o['ghidra'] for o in op):6d}")
    print("-- residual stratified by source size (goto-free scored functions)")
    for lo, hi in ((0, 5), (5, 10), (10, 20), (20, 40), (40, 10_000)):
        for name, cond in (("resid=0", lambda r: r["residual"] == 0), ("resid 1-2", lambda r: 1 <= r["residual"] <= 2),
                           ("resid>=3", lambda r: r["residual"] >= 3)):
            sel = [r for r in gf if "S" in r and lo <= r["S"]["V"] < hi and cond(r)]
            if sel:
                p = sum(r["ged"]["r2sleigh_native"] == 0 for r in sel)
                print(f"  source blocks [{lo},{hi}) {name:10s} n={len(sel):5d} perfect={p:5d} ({100 * p / len(sel):4.1f}%)")


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--run", required=True)
    c.add_argument("--scratch", required=True)
    c.add_argument("--opt-levels", default="O2,O2-noinline")
    c.add_argument("--project", action="append")
    c.add_argument("--out", required=True)
    r = sub.add_parser("report")
    r.add_argument("rows")
    args = p.parse_args()
    collect(args) if args.cmd == "collect" else report(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
