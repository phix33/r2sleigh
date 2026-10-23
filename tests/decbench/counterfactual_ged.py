#!/usr/bin/env python3
"""Re-score r2s renderings after one textual respelling, to bound what a renderer change could gain.

    PYTHONPATH=<decbench> <venv>/bin/python counterfactual_ged.py --run <tree> --transform empty_else \
        --scratch <dir> [--project NAME ...] > out.tsv

Each transform is a respelling that keeps the program's meaning (an empty `else { }` arm says nothing). It is
applied to the stored rendering, the result goes through DecBench's own `evaluate_project` with the `ged` metric,
and the tsv says per function: GED stored, GED after. The transform is a measuring device for a ceiling; the
change itself belongs in the renderer (r2dec), where the structure that proves it is.
"""

from __future__ import annotations

import argparse
import os
import pickle
import re
import sys
from pathlib import Path

def split_ternary(rhs: str):
    """`cond ? a : b` at nesting depth zero, or None (also None when a nested ternary sits at depth zero)."""
    depth, q, colon = 0, None, None
    pending = 0
    for i, c in enumerate(rhs):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == "?":
            if q is None:
                q = i
            else:
                pending += 1
        elif depth == 0 and c == ":" and q is not None:
            if pending:
                pending -= 1
            else:
                colon = i
                break
    if q is None or colon is None or pending:
        return None
    return rhs[:q].strip(), rhs[q + 1:colon].strip(), rhs[colon + 1:].strip()


def select_as_if(code: str) -> str:
    """`x = c ? a : b;` as `x = b; if (c) { x = a; }` when x is not read by c, a or b."""
    out = []
    for line in code.splitlines():
        m = re.match(r"^(\s*)(\w+) = (.*);$", line)
        parts = split_ternary(m.group(3)) if m and "?" in m.group(3) else None
        if parts and not any(re.search(r"\b" + re.escape(m.group(2)) + r"\b", part) for part in parts):
            indent, lhs = m.group(1), m.group(2)
            cond, a, b = parts
            out += [f"{indent}{lhs} = {b};", f"{indent}if ({cond}) {{", f"{indent}    {lhs} = {a};", f"{indent}}}"]
        else:
            out.append(line)
    return "\n".join(out)


_SELECT_RETURN = re.compile(
    r"(?P<ind>[ \t]*)(?P<lhs>\w+) = (?P<rhs>[^;\n]*\?[^;\n]*);\n(?P<mid>(?:[ \t]*\{[ \t]*\n)*)"
    r"[ \t]*return (?P<cast>\([^()]*\))? ?(?P=lhs);\n")


def select_return_arms(code: str) -> str:
    """`x = c ? a : b; return x;` as `if (c) { return a; } else { return b; }`, bare braces between kept."""
    def arms(m):
        parts = split_ternary(m.group("rhs"))
        if not parts or re.search(r"\b" + re.escape(m.group("lhs")) + r"\b", " ".join(parts)):
            return m.group(0)
        cond, a, b = parts
        cast, ind = m.group("cast") or "", m.group("ind")
        return (m.group("mid") + f"{ind}if ({cond}) {{\n{ind}    return {cast}({a});\n{ind}}} else {{\n"
                f"{ind}    return {cast}({b});\n{ind}}}\n")

    return _SELECT_RETURN.sub(arms, code)


def noreturn_guard(code: str, returns: bool = False) -> str:
    """`if (c) { f(); } else { rest }` as `if (c) { f(); } rest` when f is declared noreturn in the rendering.

    With `returns`, an arm ending in `return ...;`, `break;` or `continue;` is a guard too.
    """
    names = set(re.findall(r"__attribute__\(\(noreturn\)\)[\w\s\*]*?\b(\w+)\(", code))
    if not names and not returns:
        return code
    lines = code.splitlines()
    out = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)\} else \{$", lines[i])
        arm_ok = False
        if m and out:
            # the arm just closed ends in a call to a noreturn function and nothing after it
            j = len(out) - 1
            while j >= 0 and not out[j].strip():
                j -= 1
            call = re.match(r"^\s*(\w+)\(.*\);$", out[j]) if j >= 0 else None
            arm_ok = bool(call and call.group(1) in names)
            if returns and j >= 0 and re.match(r"^\s*(return\b.*|break|continue);$", out[j]):
                arm_ok = True
        if m and arm_ok:
            depth, k = 1, i + 1
            while k < len(lines) and depth:
                depth += lines[k].count("{") - lines[k].count("}")
                k += 1
            body = lines[i + 1:k - 1]
            out.append(f"{m.group(1)}}}")
            out.extend(body)
            i = k
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


TRANSFORMS = {
    "guard_after_exit": lambda code: noreturn_guard(code, returns=True),
    "all_respellings_guard": lambda code: noreturn_guard(select_as_if(select_return_arms(code)), returns=True),
    "noreturn_guard": noreturn_guard,
    "all_respellings": lambda code: noreturn_guard(select_as_if(select_return_arms(code))),
    "select_return_arms": select_return_arms,
    "select_both": lambda code: select_as_if(select_return_arms(code)),
    "select_as_if": select_as_if,
    # `if (c) { ... } else { }`: the empty arm adds a block the source does not have.
    "empty_else": lambda code: re.sub(r"\s*\belse\s*\{\s*\}", "", code),
}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--run", required=True, type=Path)
    p.add_argument("--scratch", required=True, type=Path)
    p.add_argument("--transform", required=True, choices=sorted(TRANSFORMS))
    p.add_argument("--project", action="append")
    p.add_argument("--opt-levels", default="O2,O2-noinline")
    args = p.parse_args()
    os.environ["DECBENCH_NO_CACHE"] = "1"
    import decbench.metrics  # noqa: F401
    from decbench.models.project import OptimizationLevel, Project
    from decbench.pipeline.evaluate import evaluate_project
    from decbench.pipeline.executor import PipelineConfig, PipelineExecutor
    from decbench.results_store import gather_project_tomls
    from decbench.utils import binfmt
    from decbench.utils.cfg import extract_cfgs_from_source
    from decbench.utils.dwarf_policy import dwarf_follow_abstract_origin

    transform = TRANSFORMS[args.transform]
    opts = [OptimizationLevel(v) for v in args.opt_levels.split(",")]
    print("project\topt\tbinary\tfunction\tbefore\tafter\tchanged")
    for toml in gather_project_tomls():
        if args.project and toml.stem not in args.project:
            continue
        ck_path = args.run / "checkpoints" / f"{toml.stem}.pkl"
        if not ck_path.exists():
            continue
        ck = pickle.loads(ck_path.read_bytes())
        project = Project.from_toml(toml)
        PipelineExecutor(PipelineConfig(output_dir=args.run, optimization_levels=opts))._discover_existing_binaries(
            [project], args.run)
        for opt in opts:
            units = project.preprocessed_sources.get(opt, {})
            src_cfgs = {stem: extract_cfgs_from_source(path) or {} for stem, path in units.items()}
            for b in project.compiled_binaries.get(opt, []):
                per_dec = (ck["decompile"].get(opt) or {}).get(b.stem) or {}
                r2s = per_dec.get("r2sleigh_native")
                if r2s is None:
                    continue
                stored = ((ck["evaluate"].get(opt) or {}).get(b.stem) or {}).get("r2sleigh_native", {}).get("ged")
                changed = {}
                functions = {}
                for name, fn in r2s.functions.items():
                    new_code = transform(fn.decompiled_code)
                    changed[name] = new_code != fn.decompiled_code
                    functions[name] = fn.model_copy(update={"decompiled_code": new_code})
                modified = r2s.model_copy(update={"functions": functions})
                owners = binfmt.source_function_owners(
                    b, set(units), follow_abstract_origin=dwarf_follow_abstract_origin())
                res = evaluate_project(project, {b.stem: {"r2sleigh_native": modified}}, args.scratch, opt, ["ged"],
                                       parallel=False, precomputed_source_cfgs=src_cfgs,
                                       source_function_owners={b.stem: owners})
                after = res[b.stem]["r2sleigh_native"]["ged"].function_results
                for name, v in after.items():
                    before = stored.function_results.get(name) if stored is not None else None
                    print(f"{project.name}\t{opt.value}\t{b.stem}\t{name}\t{before.value if before else ''}\t{v.value}\t{int(changed[name])}",
                          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
