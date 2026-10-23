#!/usr/bin/env python3
"""Tables for a DecBench result note: the scoreboard, a delta against an earlier run, and the per-function split.

    compare_runs.py --new <results tree> [--old <results tree>] [--old-decompiled <tree with the old r2s tomls>]

A results tree holds `scoreboard.toml`, `function_results.json` and `<opt>/<project>/decompiled/<dec>_<binary>.toml`.
GED per function comes from `function_results.json`, gotos and residual counts from the decompiled tomls. When a
tree was re-run for one decompiler only (`DECBENCH_REDO_DECOMPILERS`), the tomls of the others are the same files
as in the tree it was copied from.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
from pathlib import Path

DECS = ("angr", "kuna", "ghidra", "r2sleigh_native")
METRICS = ("byte_match", "ged", "type_match")


def scoreboard(tree: Path) -> dict:
    import tomllib

    return tomllib.loads((tree / "scoreboard.toml").read_text())


def table(sb: dict) -> list[str]:
    lines = ["| Decompiler | Union-perfect | byte_match perfect | GED perfect (mean) | type_match perfect (mean) |",
             "|---|---|---|---|---|"]
    for dec in sorted(DECS, key=lambda d: sb["decompiler_scores"][d]["overall_rank"]):
        s = sb["decompiler_scores"][dec]
        m = s["metric_scores"]
        lines.append(
            f"| {dec} | {s['overall_perfect_count']} of {s['overall_total_count']} "
            f"({s['overall_perfect_percentage']:.1f}%), rank {s['overall_rank']} "
            f"| {m['byte_match']['perfect_count']} ({m['byte_match']['perfect_percentage']:.1f}%), rank {m['byte_match']['rank']} "
            f"| {m['ged']['perfect_count']} of {m['ged']['total_count']} ({m['ged']['perfect_percentage']:.1f}%), "
            f"{m['ged']['mean']:.1f}, rank {m['ged']['rank']} "
            f"| {m['type_match']['perfect_count']} of {m['type_match']['total_count']} "
            f"({m['type_match']['perfect_percentage']:.1f}%), {m['type_match']['mean']:.3f}, rank {m['type_match']['rank']} |")
    return lines


def delta(old: dict, new: dict, dec: str = "r2sleigh_native") -> list[str]:
    lines = ["| Metric (r2s) | 2026-10-17 | now | change |", "|---|---|---|---|"]
    o, n = old["decompiler_scores"][dec], new["decompiler_scores"][dec]
    rows = [("union-perfect", o["overall_perfect_count"], n["overall_perfect_count"], "d"),
            ("union-perfect %", o["overall_perfect_percentage"], n["overall_perfect_percentage"], "f")]
    for m in METRICS:
        rows.append((f"{m} perfect", o["metric_scores"][m]["perfect_count"], n["metric_scores"][m]["perfect_count"], "d"))
        rows.append((f"{m} mean", o["metric_scores"][m]["mean"], n["metric_scores"][m]["mean"], "f"))
    for name, a, b, kind in rows:
        fmt = "{:d}" if kind == "d" else "{:.3f}"
        lines.append(f"| {name} | {fmt.format(a)} | {fmt.format(b)} | {b - a:+.3f} |" if kind == "f"
                     else f"| {name} | {a} | {b} | {b - a:+d} |")
    return lines


def recompute(tree: Path, include) -> dict:
    """The scoreboard's own arithmetic (shared universe: rows measurable for anyone) on the rows `include(group)` keeps."""
    data = json.loads((tree / "function_results.json").read_text())
    decs = data["decompilers"]
    tot = {d: {m: 0 for m in METRICS} for d in decs}
    perf = {d: {m: 0 for m in METRICS} for d in decs}
    vals = {d: {m: [] for m in METRICS} for d in decs}
    opf = {d: 0 for d in decs}
    opt = {d: 0 for d in decs}
    rows = 0
    for g in data["groups"]:
        if not include(g):
            continue
        for f in g["functions"]:
            meas = {m: any(m in (f["values"].get(d) or {}) and math.isfinite(f["values"][d][m]) for d in decs)
                    for m in METRICS}
            if not any(meas.values()):
                continue
            rows += 1
            for d in decs:
                fv, fp = f["values"].get(d) or {}, f["perfects"].get(d) or {}
                for m in METRICS:
                    if not meas[m]:
                        continue
                    tot[d][m] += 1
                    if m in fv and math.isfinite(fv[m]):
                        vals[d][m].append(fv[m])
                    perf[d][m] += bool(fp.get(m))
                opt[d] += 1
                opf[d] += any(fp.get(m) for m in METRICS if meas[m])
    out = {"decompiler_scores": {}, "generated_at": "recomputed", "total_functions": rows, "total_binaries": 0}
    for d in decs:
        out["decompiler_scores"][d] = {
            "overall_perfect_count": opf[d], "overall_total_count": opt[d],
            "overall_perfect_percentage": 100 * opf[d] / opt[d] if opt[d] else 0.0,
            "metric_scores": {m: {
                "perfect_count": perf[d][m], "total_count": tot[d][m],
                "perfect_percentage": 100 * perf[d][m] / tot[d][m] if tot[d][m] else 0.0,
                "mean": sum(vals[d][m]) / len(vals[d][m]) if vals[d][m] else 0.0} for m in METRICS}}
    ranked = sorted(decs, key=lambda d: -out["decompiler_scores"][d]["overall_perfect_percentage"])
    for i, d in enumerate(ranked, 1):
        out["decompiler_scores"][d]["overall_rank"] = i
    for m in METRICS:
        ranked = sorted(decs, key=lambda d: -out["decompiler_scores"][d]["metric_scores"][m]["perfect_percentage"])
        for i, d in enumerate(ranked, 1):
            out["decompiler_scores"][d]["metric_scores"][m]["rank"] = i
    return out


def load_function_rows(tree: Path) -> dict:
    data = json.loads((tree / "function_results.json").read_text())
    rows = {}
    for g in data["groups"]:
        for f in g["functions"]:
            rows[(g["project"], g["opt_level"], g["binary"], f["function"])] = f
    return rows, data


def load_tomls(decompiled_root: Path, dec: str) -> dict:
    """(project, opt, binary, function) -> (gotos, residual) from `<opt>/<project>/decompiled/<dec>_<bin>.toml`."""
    import tomllib

    out = {}
    for path in decompiled_root.glob(f"*/*/decompiled/{dec}_*.toml"):
        opt, project = path.parts[-4], path.parts[-3]
        binary = path.name.removesuffix(".toml")[len(dec) + 1:]
        for key, meta in tomllib.loads(path.read_text()).items():
            if key.startswith("functions."):
                out[(project, opt, binary, key[len("functions."):])] = (meta.get("gotos", 0), meta.get("residual", 0))
    return out


def split(tree: Path, decompiled_root: Path | None = None) -> list[str]:
    rows, _ = load_function_rows(tree)
    decompiled_root = decompiled_root or tree
    lines = ["| Decompiler | Functions scored (GED) | With a goto | GED-perfect with no goto | GED-perfect with a goto |",
             "|---|---|---|---|---|"]
    detail = {}
    for dec in DECS:
        meta = load_tomls(decompiled_root, dec)
        scored = [(k, r["values"][dec]["ged"]) for k, r in rows.items()
                  if dec in r["values"] and "ged" in r["values"][dec] and math.isfinite(r["values"][dec]["ged"])]
        goto = [(k, v) for k, v in scored if meta.get(k, (0, 0))[0] > 0]
        nogoto = [(k, v) for k, v in scored if meta.get(k, (0, 0))[0] == 0]
        pg = sum(v == 0 for _, v in goto)
        pn = sum(v == 0 for _, v in nogoto)
        lines.append(f"| {dec} | {len(scored):,} | {100 * len(goto) / len(scored):.1f}% "
                     f"| {100 * pn / max(1, len(nogoto)):.1f}% | {100 * pg / max(1, len(goto)):.1f}% ({pg} of {len(goto):,}) |")
        if dec == "r2sleigh_native":
            buckets = collections.OrderedDict((("none", (0, 0)), ("one or two", (1, 2)), ("three or more", (3, 10**9))))
            res = []
            for name, (lo, hi) in buckets.items():
                sel = [(k, v) for k, v in scored if lo <= meta.get(k, (0, 0))[1] <= hi]
                res.append(f"{name} {100 * sum(v == 0 for _, v in sel) / max(1, len(sel)):.1f}% ({len(sel):,})")
            detail["residual"] = "r2s GED-perfect rate by residual count: " + ", ".join(res)
            detail["no_output"] = sum(1 for r in rows.values() if not r["decompiled"].get(dec))
        else:
            detail[dec] = sum(1 for r in rows.values() if not r["decompiled"].get(dec))
    lines.append("")
    lines.append(detail["residual"])
    lines.append(f"Functions with no output ({len(rows):,} rows): r2s {detail['no_output']}, "
                 + ", ".join(f"{d} {detail[d]}" for d in ("ghidra", "kuna", "angr")))
    return lines


def paired(old: Path, new: Path, dec: str = "r2sleigh_native", exclude=("bash",)) -> list[str]:
    """Per-function change of one decompiler between two trees: better, worse, equal, newly and no longer perfect."""
    orows, _ = load_function_rows(old)
    nrows, _ = load_function_rows(new)
    ometa, nmeta = load_tomls(old, dec), load_tomls(new, dec)
    lines = ["| Metric (r2s, same functions) | scored in both | better | worse | equal | newly perfect | no longer perfect |",
             "|---|---|---|---|---|---|---|"]
    for m, lower in (("ged", True), ("type_match", False), ("byte_match", False)):
        better = worse = equal = newly = lost = both = 0
        for key, o in orows.items():
            if key[0] in exclude or key not in nrows:
                continue
            a = (o["values"].get(dec) or {}).get(m)
            b = (nrows[key]["values"].get(dec) or {}).get(m)
            if a is None or b is None or not (math.isfinite(a) and math.isfinite(b)):
                continue
            both += 1
            if a == b:
                equal += 1
            elif (b < a) == lower:
                better += 1
            else:
                worse += 1
            pa = bool((o["perfects"].get(dec) or {}).get(m))
            pb = bool((nrows[key]["perfects"].get(dec) or {}).get(m))
            newly += pb and not pa
            lost += pa and not pb
        lines.append(f"| {m} | {both} | {better} | {worse} | {equal} | {newly} | {lost} |")
    keys = [k for k in nmeta if k[0] not in exclude]
    g_old = sum(ometa.get(k, (0, 0))[0] for k in keys if k in ometa)
    g_new = sum(nmeta[k][0] for k in keys if k in ometa)
    f_old = sum(1 for k in keys if k in ometa and ometa[k][0] > 0)
    f_new = sum(1 for k in keys if k in ometa and nmeta[k][0] > 0)
    r_old = sum(ometa[k][1] for k in keys if k in ometa)
    r_new = sum(nmeta[k][1] for k in keys if k in ometa)
    lines.append("")
    lines.append(f"Functions rendered in both runs {sum(1 for k in keys if k in ometa)} (new only {sum(1 for k in keys if k not in ometa)}): "
                 f"gotos {g_old} to {g_new}, functions with a goto {f_old} to {f_new}, residual sites {r_old} to {r_new}.")
    return lines


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--new", required=True, type=Path)
    p.add_argument("--old", type=Path)
    p.add_argument("--decompiled-old", type=Path)
    p.add_argument("--decompiled-new", type=Path)
    p.add_argument("--paired", action="store_true")
    p.add_argument("--exclude-project", action="append", default=[])
    p.add_argument("--only-project", action="append", default=[])
    args = p.parse_args()
    if args.old and args.paired:
        print("\n".join(paired(args.old, args.new)))
        return 0
    if args.exclude_project or args.only_project:
        keep = (lambda g: g["project"] not in args.exclude_project and (not args.only_project or g["project"] in args.only_project))
        new = recompute(args.new, keep)
        print(f"restricted population: {new['total_functions']} rows "
              f"(exclude {args.exclude_project}, only {args.only_project})")
        print("\n".join(table(new)))
        if args.old:
            print()
            print("\n".join(delta(recompute(args.old, keep), new)))
        return 0
    new = scoreboard(args.new)
    print(f"generated_at {new['generated_at']}, {new['total_functions']} function rows, {new['total_binaries']} binaries")
    print("\n".join(table(new)))
    if args.old:
        print()
        print("\n".join(delta(scoreboard(args.old), new)))
    print()
    print("\n".join(split(args.new, args.decompiled_new)))
    if args.old:
        print()
        print("old run:")
        print("\n".join(split(args.old, args.decompiled_old)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
