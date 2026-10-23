#!/usr/bin/env python3
"""The mined-set comparison: what a structurer change does to GED, on the functions it was mined from.

A change to the structurer (or to anything that moves a rendering) is graded on every function of one
pinned set of DecBench projects, with the build before it and the build after it:

    mined_set.py dump  --tree <run> --r2s <base r2s> --out base/ --set mining
    mined_set.py dump  --tree <run> --r2s <new r2s>  --out new/  --set mining
    mined_set.py score --tree <run> --dump base/ --out base.json --decbench ../decbench
    mined_set.py score --tree <run> --dump new/  --out new.json  --decbench ../decbench
    mined_set.py pair  base.json new.json

* `dump` asks r2s for `pddj` of every function of every binary of the set, at O2 and O2-noinline, through
  the runner the backend uses (`tests/equiv/r2s_batch.py`, on the stripped binary). The functions are the
  addresses the run's own `decompiled/*.toml` name, the union over its decompilers, so the targets are the
  driver's: the DWARF functions of the project's own sources.
* `score` computes DecBench's GED for each rendering against the source CFG of the `.i` that defines the
  function (`<tree>/<opt>/<project>/compiled/*.i`), by the flow of DecBench's `metrics/ged.py` (isomorphism,
  the size bound above `GED_MAX_NODES`, else VJ). It needs DecBench importable (`--decbench` or the venv) and
  Joern; it is not run by the unit tests.
* `pair` reports two scored runs over the functions both scored: perfect count (newly, lost), mean and total
  GED (better, worse, same), gotos, functions with a goto, functions whose text changed and functions newly
  refused.

The pinned lists split what may be mined from what may only be reported: MINING (bzip2, zlib, grep) is run
on every change; HELD_OUT is the rest of the sailr set, run nightly and at an item's exit only, and a
regression there opens an investigation. A structurer rule is chosen by reading MINING; reading HELD_OUT to
choose one defeats it. `pair` refuses to compare a mining run with a held-out run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import re
import statistics
import sys
import tempfile
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from run_gate import split_name  # noqa: E402

MINING = ("bzip2", "zlib", "grep")
HELD_OUT = ("bash", "diffutils", "findutils", "gzip", "libexpat")
SETS = {"mining": MINING, "heldout": HELD_OUT}
OPT_LEVELS = ("O2", "O2-noinline")
DECOMPILERS = ("r2sleigh_native", "angr", "ghidra", "kuna")
SCHEMA = 1
GED_SECONDS = 120


# --- targets and dump -------------------------------------------------------------------------


def function_targets(project_dir: Path, decompilers=DECOMPILERS) -> dict[str, dict[int, str]]:
    """`{binary stem: {address: DWARF name}}` from the tomls the run's decompilers wrote for a project."""
    found: dict[str, dict[int, str]] = {}
    for toml in sorted((project_dir / "decompiled").glob("*.toml")):
        named = split_name(toml.stem, list(decompilers))
        if named is None:
            continue
        data = tomllib.loads(toml.read_text())
        for key, value in data.items():
            if key.startswith("functions.") and isinstance(value, dict) and "address" in value:
                address = value["address"]
                address = int(address, 16) if isinstance(address, str) else int(address)
                found.setdefault(named[1], {}).setdefault(address, key[len("functions."):])
    return found


def row_keys(opt: str, project: str, binary: str, targets: dict[int, str]) -> dict[int, str]:
    """`opt|project|binary|name` per address; a name already taken by a lower address gets `@0x<address>`."""
    keys: dict[int, str] = {}
    taken: set[str] = set()
    for address in sorted(targets):
        key = f"{opt}|{project}|{binary}|{targets[address]}"
        if key in taken:
            key += f"@0x{address:x}"
        taken.add(key)
        keys[address] = key
    return keys


def record_of(answer, name: str) -> dict:
    """One dumped function: what r2s said, with the definition renamed to the DWARF name."""
    row = {"name": name, "addr": f"0x{answer.address:x}", "status": answer.kind,
           "refused": bool(answer.refusal)}
    if answer.ok and answer.record is not None:
        code = str(answer.record.get("code") or "")
        definition = str(answer.record.get("definition") or "")
        if definition and definition != name:
            code = re.sub(rf"\b{re.escape(definition)}\b", name, code)
        row["code"] = code
    else:
        row["cause"] = (answer.cause or "")[:300]
    return row


def dump(tree: Path, r2s: Path, out: Path, projects, opt_levels=OPT_LEVELS, decompilers=DECOMPILERS,
         function_timeout: float = 300.0, startup_timeout: float = 600.0, set_name: str = "adhoc") -> int:
    sys.path.append(str(HERE.parent / "equiv"))
    import r2s_batch

    out.mkdir(parents=True, exist_ok=True)
    total = 0
    for opt in opt_levels:
        for project in projects:
            project_dir = tree / opt / project
            stripped = {p.stem: p for p in sorted((project_dir / "stripped").glob("*")) if p.is_file()}
            for binary, targets in sorted(function_targets(project_dir, decompilers).items()):
                if binary not in stripped:
                    print(f"skip {opt}/{project}/{binary}: no stripped binary", file=sys.stderr)
                    continue
                keys = row_keys(opt, project, binary, targets)
                report = r2s_batch.run_batch(r2s, stripped[binary], sorted(targets),
                                             function_timeout=function_timeout,
                                             startup_timeout=startup_timeout)
                rows = {keys[a.address]: record_of(a, targets[a.address]) for a in report.answers}
                (out / f"{opt}.{project}.{binary}.json").write_text(json.dumps(rows, sort_keys=True))
                total += len(rows)
                print(f"{opt} {project} {binary}: {len(rows)} functions", flush=True)
    manifest = {"schema": SCHEMA, "set": set_name, "projects": list(projects), "opt_levels": list(opt_levels),
                "r2s_sha256": hashlib.sha256(Path(r2s).read_bytes()).hexdigest(), "functions": total}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return total


# --- scoring (DecBench) ------------------------------------------------------------------------


class Timeout(Exception):
    pass


def decbench_scorer(decbench: Path | None):
    """DecBench's GED flow as `(source_cfgs, ged, dec_cfg_of)`; imports DecBench, so it needs the venv."""
    if decbench is not None:
        sys.path.insert(0, str(decbench))
    from decbench.metrics.ged import GED_MAX_NODES, _is_isomorphic
    from decbench.metrics.vj_ged import vj_ged
    from decbench.utils.cfg import (
        _parse_cfgs,
        canonicalize_infinite_loops,
        extract_cfgs_from_source,
        is_degenerate_source_cfg,
        preprocess_decompiled_c,
        sanitize_decompiled_c,
    )

    def ged(source_cfg, decompiled_cfg):
        if is_degenerate_source_cfg(source_cfg):
            return None
        if _is_isomorphic(source_cfg, decompiled_cfg):
            return 0.0
        s, d = source_cfg.number_of_nodes(), decompiled_cfg.number_of_nodes()
        if s > GED_MAX_NODES or d > GED_MAX_NODES:
            return max(1.0, float(abs(s - d) + abs(source_cfg.number_of_edges() - decompiled_cfg.number_of_edges())))
        return max(1.0, float(vj_ged(source_cfg, decompiled_cfg)))

    scratch = "/dev/shm" if os.path.isdir("/dev/shm") else None

    def dec_cfg_of(text: str, name: str):
        marked = f"// Function: {name}\n{sanitize_decompiled_c(text)}"
        marked = canonicalize_infinite_loops(preprocess_decompiled_c(marked))
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            path = Path(directory) / "rendering.c"
            path.write_text(marked)
            return _parse_cfgs(path).get(name)

    return (lambda path: extract_cfgs_from_source(Path(path))), ged, dec_cfg_of


def source_cfgs_by_name(tree: Path, opt: str, project: str, cache: Path, extract) -> dict[str, list]:
    """`{function: [(translation unit stem, cfg)]}` over the project's `.i` files; cached per (opt, project).

    The cache is keyed by name alone: delete it when the sources are recompiled.
    """
    pickled = cache / f"{opt}.{project}.pkl"
    if pickled.exists():
        return pickle.loads(pickled.read_bytes())
    by_name: dict[str, list] = {}
    for source in sorted((tree / opt / project / "compiled").glob("*.i")):
        try:
            cfgs = extract(source)
        except Exception as error:  # noqa: BLE001
            print(f"no source CFGs from {source.name}: {error}", file=sys.stderr)
            continue
        for name, graph in cfgs.items():
            by_name.setdefault(name, []).append((source.stem, graph))
    cache.mkdir(parents=True, exist_ok=True)
    pickled.write_bytes(pickle.dumps(by_name))
    return by_name


def pick_source(candidates: list, binary: str):
    """The only definition, else the one in the translation unit named like the binary, else the first."""
    if len(candidates) == 1:
        return candidates[0][1]
    wanted = {binary, binary.split(".so")[0]}
    for stem, graph in candidates:
        if stem in wanted:
            return graph
    return candidates[0][1]


def score(tree: Path, dump_dir: Path, out: Path, decbench: Path | None, cache: Path | None) -> int:
    import signal

    extract, ged, dec_cfg_of = decbench_scorer(decbench)
    cache = cache or out.parent / "srccache"
    manifest = json.loads((dump_dir / "manifest.json").read_text())

    def alarm(signum, frame):
        raise Timeout

    signal.signal(signal.SIGALRM, alarm)
    rows: dict[str, dict] = {}
    for dumped in sorted(dump_dir.glob("*.json")):
        if dumped.name == "manifest.json":
            continue
        opt, project, binary = dumped.name[:-len(".json")].split(".", 2)
        cfgs = source_cfgs_by_name(tree, opt, project, cache, extract)
        for key, record in json.loads(dumped.read_text()).items():
            code = record.get("code") or ""
            row = {"gotos": len(re.findall(r"\bgoto\b", code)), "lines": code.count("\n"),
                   "refused": bool(record.get("refused")), "status": record["status"],
                   "loops": len(re.findall(r"for \(; ; \)", code)), "whiles": len(re.findall(r"\bwhile \(", code)),
                   "text": hashlib.sha256(code.encode()).hexdigest()[:16], "ged": None}
            if record["status"] == "output" and not row["refused"] and record["name"] in cfgs:
                signal.alarm(GED_SECONDS)
                try:
                    cfg = dec_cfg_of(code, record["name"])
                    row["ged"] = ged(pick_source(cfgs[record["name"]], binary), cfg) if cfg is not None else None
                except Timeout:
                    row["ged"] = "err:timeout"
                except Exception as error:  # noqa: BLE001
                    row["ged"] = "err:" + type(error).__name__
                finally:
                    signal.alarm(0)
            rows[key] = row
        print(f"{opt} {project} {binary}: {len(rows)} scored so far", flush=True)
    meta = {k: manifest[k] for k in ("set", "r2s_sha256", "projects", "opt_levels") if k in manifest}
    out.write_text(json.dumps({"schema": SCHEMA, **meta, "rows": rows}))
    return len(rows)


# --- pairing (pure) ------------------------------------------------------------------------------


def load_scores(path: Path) -> tuple[dict, dict]:
    """`(rows, meta)` of a scored run; a bare `{key: row}` file (the scratch format) has no meta."""
    data = json.loads(Path(path).read_text())
    if isinstance(data.get("rows"), dict) and "schema" in data:
        return data["rows"], {k: v for k, v in data.items() if k != "rows"}
    return data, {}


def has_ged(row: dict) -> bool:
    return isinstance(row.get("ged"), float)


def one_per_function(keys) -> set[str]:
    """One key per (opt, project, function): the first binary that holds it, libz before its static copies."""
    seen, kept = set(), set()
    for key in sorted(keys, key=lambda k: (0 if "libz" in k else 1, k)):
        opt, project, _binary, function = key.split("|", 3)
        if (opt, project, function) not in seen:
            seen.add((opt, project, function))
            kept.add(key)
    return kept


def pair(base: dict, new: dict, unique: bool = False) -> dict:
    """The comparison of two scored runs over the functions both scored."""
    if unique:
        kept = one_per_function(base)
        base = {k: v for k, v in base.items() if k in kept}
        new = {k: v for k, v in new.items() if k in kept}
    both = [k for k in sorted(base) if k in new and has_ged(base[k]) and has_ged(new[k])]
    only_base = [k for k in base if has_ged(base[k]) and not (k in new and has_ged(new[k]))]
    only_new = [k for k in new if has_ged(new[k]) and not (k in base and has_ged(base[k]))]
    old = {k: base[k]["ged"] for k in both}
    now = {k: new[k]["ged"] for k in both}
    shared = [k for k in sorted(base) if k in new]
    with_text = [k for k in shared if base[k].get("text") and new[k].get("text")]
    return {
        "scored": len(both),
        "lost_scoring": len(only_base),
        "gained_scoring": len(only_new),
        "perfect": [sum(1 for k in both if old[k] == 0), sum(1 for k in both if now[k] == 0)],
        "newly_perfect": sorted(k for k in both if old[k] > 0 and now[k] == 0),
        "lost_perfect": sorted(k for k in both if old[k] == 0 and now[k] > 0),
        "mean_ged": [statistics.mean(old.values()) if both else None, statistics.mean(now.values()) if both else None],
        "total_ged": [sum(old.values()), sum(now.values())],
        "better": sorted(k for k in both if now[k] < old[k]),
        "worse": sorted(k for k in both if now[k] > old[k]),
        "same": sum(1 for k in both if now[k] == old[k]),
        "gotos_all": [sum(r.get("gotos", 0) for r in base.values()), sum(r.get("gotos", 0) for r in new.values())],
        "gotos_scored": [sum(base[k].get("gotos", 0) for k in both), sum(new[k].get("gotos", 0) for k in both)],
        "functions_with_goto": [sum(1 for k in both if base[k].get("gotos", 0) > 0),
                                sum(1 for k in both if new[k].get("gotos", 0) > 0)],
        "functions": len(shared),
        "text_changed": sum(1 for k in with_text if base[k]["text"] != new[k]["text"]) if with_text else None,
        "text_compared": len(with_text),
        "refused": [sum(1 for r in base.values() if r.get("refused")), sum(1 for r in new.values() if r.get("refused"))],
        "newly_refused": sorted(k for k in shared if new[k].get("refused") and not base[k].get("refused")),
    }


def format_report(label: str, report: dict) -> str:
    mean = report["mean_ged"]
    lines = [
        f"{label}: scored {report['scored']} (lost scoring {report['lost_scoring']}, gained {report['gained_scoring']})",
        f"  perfect {report['perfect'][0]} -> {report['perfect'][1]}  newly {len(report['newly_perfect'])} "
        f"lost {len(report['lost_perfect'])}",
        f"  mean GED {'n/a' if mean[0] is None else f'{mean[0]:.2f}'} -> {'n/a' if mean[1] is None else f'{mean[1]:.2f}'}  "
        f"better {len(report['better'])} worse {len(report['worse'])} same {report['same']}",
        f"  gotos all {report['gotos_all'][0]} -> {report['gotos_all'][1]}; scored {report['gotos_scored'][0]} -> "
        f"{report['gotos_scored'][1]}; scored fns with a goto {report['functions_with_goto'][0]} -> "
        f"{report['functions_with_goto'][1]}",
        f"  total GED {report['total_ged'][0]:.0f} -> {report['total_ged'][1]:.0f}",
    ]
    if report["text_changed"] is None:
        lines.append(f"  text changed: n/a (these scores carry no text hash); refused {report['refused'][0]} -> "
                     f"{report['refused'][1]}")
    else:
        lines.append(f"  text changed {report['text_changed']} of {report['text_compared']} functions in both runs; "
                     f"refused {report['refused'][0]} -> {report['refused'][1]}, newly refused "
                     f"{len(report['newly_refused'])}")
    return "\n".join(lines)


# --- command line ----------------------------------------------------------------------------------


def projects_of(args) -> tuple[str, tuple[str, ...]]:
    if args.project:
        return "adhoc", tuple(args.project)
    if args.set is None:
        raise SystemExit("name a pinned set (--set mining|heldout) or the projects (--project)")
    if args.set == "heldout":
        print("held-out set: run it nightly and at an item's exit, and do not choose rules by it", file=sys.stderr)
    return args.set, SETS[args.set]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("dump", help="r2s pddj of every function of the set")
    d.add_argument("--tree", type=Path, required=True)
    d.add_argument("--r2s", type=Path, required=True)
    d.add_argument("--out", type=Path, required=True)
    d.add_argument("--set", choices=sorted(SETS))
    d.add_argument("--project", action="append")
    d.add_argument("--opt-level", action="append")
    d.add_argument("--decompilers", default=",".join(DECOMPILERS), help="whose tomls name the targets")
    s = sub.add_parser("score", help="DecBench GED of every dumped rendering")
    s.add_argument("--tree", type=Path, required=True)
    s.add_argument("--dump", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--decbench", type=Path)
    s.add_argument("--cache", type=Path)
    q = sub.add_parser("pair", help="compare two scored runs")
    q.add_argument("base", type=Path)
    q.add_argument("new", type=Path)
    q.add_argument("--label", default="")
    q.add_argument("-u", "--unique", action="store_true", help="one entry per function across binaries")
    q.add_argument("-v", "--verbose", action="store_true", help="name the worse, lost and newly refused")
    args = parser.parse_args(argv)

    if args.command == "dump":
        name, projects = projects_of(args)
        total = dump(args.tree, args.r2s, args.out, projects, tuple(args.opt_level or OPT_LEVELS),
                     tuple(d for d in args.decompilers.split(",") if d), set_name=name)
        print(f"dumped {total} functions of {name}: {', '.join(projects)}")
        return 0
    if args.command == "score":
        print(f"scored {score(args.tree, args.dump, args.out, args.decbench, args.cache)} functions")
        return 0

    base, base_meta = load_scores(args.base)
    new, new_meta = load_scores(args.new)
    sets = {base_meta.get("set"), new_meta.get("set")} - {None}
    if len(sets) > 1:
        print(f"refusing to pair a {base_meta.get('set')} run with a {new_meta.get('set')} run", file=sys.stderr)
        return 2
    report = pair(base, new, args.unique)
    print(format_report(args.label or (next(iter(sets)) if sets else "pair"), report))
    if args.verbose:
        for heading, keys in (("worse", report["worse"]), ("lost perfect", report["lost_perfect"]),
                              ("newly perfect", report["newly_perfect"]), ("newly refused", report["newly_refused"])):
            for key in keys:
                print(f"  {heading}: {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
