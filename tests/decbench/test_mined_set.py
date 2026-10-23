#!/usr/bin/env python3
"""The mined-set comparison pairs two runs and reports them; the DecBench scoring is not run here."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
STUB = HERE.parents[1] / "tests" / "equiv" / "testdata" / "stub_r2s.py"
sys.path.insert(0, str(HERE))

import mined_set  # noqa: E402


def row(ged, gotos=0, text="a", refused=False, status="output"):
    return {"ged": ged, "gotos": gotos, "text": text, "refused": refused, "status": status}


BASE = {
    "O2|zlib|libz|keeps": row(0.0, text="1"),
    "O2|zlib|libz|gains": row(5.0, gotos=2, text="2"),
    "O2|zlib|libz|loses": row(0.0, text="3"),
    "O2|zlib|libz|better": row(4.0, gotos=1, text="4"),
    "O2|zlib|libz|same": row(2.0, text="5"),
    "O2|zlib|libz|unscored": row(1.0, text="6"),
    "O2|zlib|libz|gets_scored": row(None, text="7"),
    "O2|zlib|libz|dropped": row(9.0, text="8"),
}
NEW = {
    "O2|zlib|libz|keeps": row(0.0, text="1"),
    "O2|zlib|libz|gains": row(0.0, gotos=0, text="2b"),
    "O2|zlib|libz|loses": row(3.0, gotos=1, text="3b"),
    "O2|zlib|libz|better": row(2.0, gotos=1, text="4"),
    "O2|zlib|libz|same": row(2.0, text="5"),
    "O2|zlib|libz|unscored": row(None, text="6b", refused=True, status="decline"),
    "O2|zlib|libz|gets_scored": row(7.0, text="7"),
}


class Pairing(unittest.TestCase):
    def test_two_runs_are_paired_over_the_functions_both_scored(self):
        report = mined_set.pair(BASE, NEW)
        self.assertEqual(report["scored"], 5)
        self.assertEqual((report["lost_scoring"], report["gained_scoring"]), (2, 1))
        self.assertEqual(report["perfect"], [2, 2])
        self.assertEqual(report["newly_perfect"], ["O2|zlib|libz|gains"])
        self.assertEqual(report["lost_perfect"], ["O2|zlib|libz|loses"])
        self.assertEqual(report["mean_ged"], [2.2, 1.4])
        self.assertEqual(report["total_ged"], [11.0, 7.0])
        self.assertEqual(report["better"], ["O2|zlib|libz|better", "O2|zlib|libz|gains"])
        self.assertEqual(report["worse"], ["O2|zlib|libz|loses"])
        self.assertEqual(report["same"], 2)
        self.assertEqual(report["gotos_all"], [3, 2])
        self.assertEqual(report["gotos_scored"], [3, 2])
        self.assertEqual(report["functions_with_goto"], [2, 2])
        # Seven functions are in both runs; text differs in gains, loses and unscored.
        self.assertEqual((report["text_changed"], report["text_compared"]), (3, 7))
        self.assertEqual(report["refused"], [0, 1])
        self.assertEqual(report["newly_refused"], ["O2|zlib|libz|unscored"])

    def test_the_report_names_each_figure_the_item_is_graded_by(self):
        text = mined_set.format_report("mining", mined_set.pair(BASE, NEW))
        self.assertEqual(text.splitlines(), [
            "mining: scored 5 (lost scoring 2, gained 1)",
            "  perfect 2 -> 2  newly 1 lost 1",
            "  mean GED 2.20 -> 1.40  better 2 worse 1 same 2",
            "  gotos all 3 -> 2; scored 3 -> 2; scored fns with a goto 2 -> 2",
            "  total GED 11 -> 7",
            "  text changed 3 of 7 functions in both runs; refused 0 -> 1, newly refused 1",
        ])

    def test_scores_without_a_text_hash_say_so_and_an_empty_pairing_does_not_divide(self):
        legacy = {"O2|a|b|f": {"ged": 3.0, "gotos": 1, "refused": False}}
        report = mined_set.pair(legacy, legacy)
        self.assertIsNone(report["text_changed"])
        self.assertIn("text changed: n/a", mined_set.format_report("x", report))
        empty = mined_set.pair({}, {})
        self.assertEqual(empty["mean_ged"], [None, None])
        self.assertIn("mean GED n/a -> n/a", mined_set.format_report("x", empty))

    def test_unique_keeps_one_entry_per_function_and_prefers_the_library(self):
        keys = ["O2|zlib|example|crc32", "O2|zlib|libz.so.1.2|crc32", "O2|zlib|example|main",
                "O2|zlib|minigzip|main", "O2-noinline|zlib|example|main"]
        self.assertEqual(sorted(mined_set.one_per_function(keys)), [
            "O2-noinline|zlib|example|main", "O2|zlib|example|main", "O2|zlib|libz.so.1.2|crc32"])
        rows = {k: row(1.0) for k in keys}
        self.assertEqual(mined_set.pair(rows, rows, unique=True)["scored"], 3)
        self.assertEqual(mined_set.pair(rows, rows)["scored"], 5)

    def test_a_mining_run_is_not_paired_with_a_held_out_run(self):
        with tempfile.TemporaryDirectory() as directory:
            def write(name, set_name):
                path = Path(directory) / name
                path.write_text(json.dumps({"schema": 1, "set": set_name, "rows": BASE}))
                return str(path)

            mining, held_out = write("a.json", "mining"), write("b.json", "heldout")
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mined_set.main(["pair", mining, held_out]), 2)
            self.assertIn("refusing to pair a mining run with a heldout run", err.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(mined_set.main(["pair", mining, mining]), 0)
            self.assertTrue(out.getvalue().startswith("mining: scored 7"))
            # The scratch format, a bare {key: row} file, still pairs.
            bare = Path(directory) / "bare.json"
            bare.write_text(json.dumps(BASE))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mined_set.main(["pair", str(bare), str(bare)]), 0)


class Sets(unittest.TestCase):
    def test_mining_and_held_out_split_the_sailr_set(self):
        self.assertEqual(mined_set.MINING, ("bzip2", "zlib", "grep"))
        self.assertFalse(set(mined_set.MINING) & set(mined_set.HELD_OUT))
        self.assertEqual(sorted(mined_set.MINING + mined_set.HELD_OUT), sorted(
            ["bash", "bzip2", "diffutils", "findutils", "grep", "gzip", "libexpat", "zlib"]))
        self.assertEqual(mined_set.OPT_LEVELS, ("O2", "O2-noinline"))


class Dump(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tree = Path(self.dir.name) / "run"
        project = self.tree / "O2" / "zlib"
        (project / "decompiled").mkdir(parents=True)
        (project / "stripped").mkdir()
        # The file is libz.so.1.2.13, the driver's name for it is the stem libz.so.1.2.
        (project / "stripped" / "libz.so.1.2.13").write_bytes(b"\x7fELF")
        (project / "decompiled" / "kuna_libz.so.1.2.toml").write_text(
            'binary = "libz.so.1.2"\n["functions.crc32"]\naddress = "0x401150"\n'
            '["functions.helper"]\naddress = "0x401160"\n')
        (project / "decompiled" / "angr_libz.so.1.2.toml").write_text(
            'binary = "libz.so.1.2"\n["functions.helper"]\naddress = "0x401160"\n'
            '["functions.helper_2"]\naddress = "0x4011f0"\n')
        self.out = Path(self.dir.name) / "dump"

    def tearDown(self):
        self.dir.cleanup()

    def dump(self, mode="minimal"):
        env = {"STUB_R2S_MODE": mode, "STUB_R2S_FAULTS": "", "STUB_R2S_STATE": self.dir.name}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
            return mined_set.dump(self.tree, STUB, self.out, ("zlib",), ("O2",), set_name="mining",
                                  function_timeout=30.0)

    def test_targets_are_the_union_of_the_decompilers_tomls(self):
        found = mined_set.function_targets(self.tree / "O2" / "zlib")
        self.assertEqual(found, {"libz.so.1.2": {0x401150: "crc32", 0x401160: "helper", 0x4011f0: "helper_2"}})

    def test_a_name_two_addresses_share_is_told_apart_by_address(self):
        keys = mined_set.row_keys("O2", "grep", "grep", {0x2000: "usage", 0x1000: "usage", 0x3000: "main"})
        self.assertEqual(keys, {0x1000: "O2|grep|grep|usage", 0x2000: "O2|grep|grep|usage@0x2000",
                                0x3000: "O2|grep|grep|main"})

    def test_every_function_is_dumped_under_its_dwarf_name(self):
        self.assertEqual(self.dump(), 3)
        rows = json.loads((self.out / "O2.zlib.libz.so.1.2.json").read_text())
        self.assertEqual(sorted(rows), ["O2|zlib|libz.so.1.2|crc32", "O2|zlib|libz.so.1.2|helper",
                                        "O2|zlib|libz.so.1.2|helper_2"])
        crc = rows["O2|zlib|libz.so.1.2|crc32"]
        self.assertEqual((crc["status"], crc["refused"], crc["addr"]), ("output", False, "0x401150"))
        self.assertIn("void crc32(void)", crc["code"])
        self.assertNotIn("fcn_", crc["code"])
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual((manifest["set"], manifest["projects"], manifest["functions"]), ("mining", ["zlib"], 3))
        self.assertEqual(len(manifest["r2s_sha256"]), 64)

    def test_a_refusal_is_dumped_as_a_refusal_with_no_code(self):
        self.dump(mode="refuse")
        rows = json.loads((self.out / "O2.zlib.libz.so.1.2.json").read_text())
        refused = rows["O2|zlib|libz.so.1.2|crc32"]
        self.assertEqual((refused["status"], refused["refused"]), ("decline", True))
        self.assertNotIn("code", refused)
        self.assertEqual(refused["cause"], "refused: stub refuses")


class Graph:
    """Stands in for a networkx CFG: a shape (`kind`) and a size."""

    def __init__(self, kind: str, nodes: int):
        self.kind, self.nodes = kind, nodes

    def number_of_nodes(self):
        return self.nodes

    def number_of_edges(self):
        return self.nodes


class Score(unittest.TestCase):
    """`score` walks a dump, finds each source CFG, and writes one row per function.

    DecBench is replaced by stand-ins that are isomorphic by `kind` and otherwise a distance of the node
    count, so this checks the walk, the pick of the source, the rows and their pairing; the GED itself is
    DecBench's.
    """

    def stand_ins(self):
        def module(name, **members):
            mod = types.ModuleType(name)
            mod.__dict__.update(members)
            return mod

        parsed = lambda path: {  # noqa: E731
            name: Graph("loop" if "while" in text else "line", text.count(";") + 1)
            for name, text in re.findall(r"// Function: (\w+)\n(.*?)(?=// Function:|\Z)", Path(path).read_text(), re.S)}
        cfg = module(
            "decbench.utils.cfg", _parse_cfgs=parsed, sanitize_decompiled_c=lambda t: t,
            preprocess_decompiled_c=lambda t: t, canonicalize_infinite_loops=lambda t: t,
            is_degenerate_source_cfg=lambda g: g.kind == "degenerate",
            extract_cfgs_from_source=lambda path: {"crc32": Graph("loop", 2), "tiny": Graph("degenerate", 1)}
            if path.stem == "crc32" else {"crc32": Graph("line", 99), "helper": Graph("line", 2)})
        return {
            "decbench": module("decbench"), "decbench.utils": module("decbench.utils"),
            "decbench.utils.cfg": cfg, "decbench.metrics": module("decbench.metrics"),
            "decbench.metrics.ged": module("decbench.metrics.ged", GED_MAX_NODES=200,
                                           _is_isomorphic=lambda a, b: a.kind == b.kind and a.nodes == b.nodes),
            "decbench.metrics.vj_ged": module("decbench.metrics.vj_ged",
                                              vj_ged=lambda a, b: abs(a.nodes - b.nodes) + (a.kind != b.kind)),
        }

    def test_each_dumped_function_gets_a_row_and_two_runs_pair(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(sys.modules, self.stand_ins()):
            root = Path(directory)
            compiled = root / "run" / "O2" / "zlib" / "compiled"
            compiled.mkdir(parents=True)
            for name in ("crc32", "other"):
                (compiled / f"{name}.i").write_text("")

            def dump(name, helper_code, refused=False):
                folder = root / name
                folder.mkdir()
                rows = {
                    "O2|zlib|libz.so.1.2|crc32": {"name": "crc32", "addr": "0x1", "status": "output",
                                                  "refused": False, "code": "while (1) { goto out; }\n"},
                    "O2|zlib|libz.so.1.2|helper": {"name": "helper", "addr": "0x2", "status": "output",
                                                   "refused": False, "code": helper_code},
                    "O2|zlib|libz.so.1.2|tiny": {"name": "tiny", "addr": "0x3", "status": "output",
                                                 "refused": False, "code": "x;\n"},
                    "O2|zlib|libz.so.1.2|nosource": {"name": "nosource", "addr": "0x4", "status": "output",
                                                     "refused": False, "code": "y;\n"},
                }
                if refused:
                    rows["O2|zlib|libz.so.1.2|helper"] = {"name": "helper", "addr": "0x2", "status": "decline",
                                                          "refused": True, "cause": "refused: no"}
                (folder / "O2.zlib.libz.so.1.2.json").write_text(json.dumps(rows))
                (folder / "manifest.json").write_text(json.dumps({"set": "mining", "r2s_sha256": name}))
                with contextlib.redirect_stdout(io.StringIO()):
                    mined_set.score(root / "run", folder, root / f"{name}.json", None, root / "cache")
                return mined_set.load_scores(root / f"{name}.json")

            base, meta = dump("base", "a; b;\n")
            self.assertEqual(meta["set"], "mining")
            crc = base["O2|zlib|libz.so.1.2|crc32"]
            # Two definitions: libz.so.1.2 has no translation unit of its name, so the first, crc32.i, is the one.
            self.assertEqual((crc["ged"], crc["gotos"], crc["loops"], crc["whiles"]), (0.0, 1, 0, 1))
            self.assertEqual(base["O2|zlib|libz.so.1.2|helper"]["ged"], 1.0)  # 3 nodes against 2: distance 1
            self.assertIsNone(base["O2|zlib|libz.so.1.2|tiny"]["ged"])  # a degenerate source scores nothing
            self.assertIsNone(base["O2|zlib|libz.so.1.2|nosource"]["ged"])
            new, _ = dump("new", "a;\n")
            self.assertEqual(new["O2|zlib|libz.so.1.2|helper"]["ged"], 0.0)
            report = mined_set.pair(base, new)
            self.assertEqual((report["scored"], report["perfect"], report["text_changed"]), (2, [1, 2], 1))
            gone, _ = dump("gone", "", refused=True)
            report = mined_set.pair(base, gone)
            self.assertEqual((report["lost_scoring"], report["newly_refused"]),
                             (1, ["O2|zlib|libz.so.1.2|helper"]))
            self.assertTrue((root / "cache" / "O2.zlib.pkl").exists())


if __name__ == "__main__":
    unittest.main()
