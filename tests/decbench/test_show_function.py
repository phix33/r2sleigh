#!/usr/bin/env python3
"""`show_function.py` prints one function of a run; DecBench is replaced by stand-ins, the checkpoint by a dict."""

from __future__ import annotations

import contextlib
import io
import pickle
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import show_function  # noqa: E402


class Block:
    def __init__(self, addr):
        self.addr, self.statements = addr, ["s"]


class Graph:
    """The subset of a networkx CFG that `show_function` prints."""

    def __init__(self, blocks, edges):
        self.nodes, self.edges = blocks, edges

    def number_of_nodes(self):
        return len(self.nodes)

    def number_of_edges(self):
        return len(self.edges)

    def successors(self, node):
        return [b for a, b in self.edges if a is node]


def chain(length):
    blocks = [Block(i) for i in range(length)]
    return Graph(blocks, list(zip(blocks, blocks[1:])))


class Function:
    address, metadata, decompiled_code = 0x1000, {}, "int crc32(void) { return 0; }\n"


class Result:
    binary_path = Path("/unused/libz.so.1.2.13")

    def __init__(self):
        self.functions = {"crc32": Function()}

    def model_copy(self, update):
        return self


def module(name, **members):
    mod = types.ModuleType(name)
    mod.__dict__.update(members)
    return mod


class Shown(unittest.TestCase):
    """A run with one function, `crc32`, in a checkpoint, and the stand-ins DecBench would have supplied."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.run = Path(self.dir.name)
        (self.run / "checkpoints").mkdir()
        (self.run / "checkpoints" / "zlib.pkl").write_bytes(b"")
        self.loaded = []
        self.owner_calls, self.variable_calls = [], []
        # Two units define a crc32, `alpha` sorts first; the DWARF says the function at 0x1000 is zeta's.
        self.units = {}
        for stem, value in (("alpha", 1), ("zeta", 2)):
            (self.run / f"{stem}.i").write_text(f"int crc32(void) {{ return {value}; }}\n")
            self.units[stem] = self.run / f"{stem}.i"
        self.source_graphs = {"alpha": {"crc32": chain(7)}, "zeta": {"crc32": chain(3)}}
        self.owners = {0x1000: ("crc32", "zeta")}

        class Project:
            preprocessed_sources = {"O2": self.units}

            @staticmethod
            def from_toml(toml):
                self.loaded.append(toml)
                return Project

        class Executor:
            def __init__(self, config):
                pass

            def _discover_existing_binaries(self, projects, run):
                pass

        graphs = {"crc32": chain(2)}

        def source_function_owners(path, stems, follow_abstract_origin=False):
            self.owner_calls.append((path, set(stems), follow_abstract_origin))
            return self.owners

        def ground_truth_for_function(index, name, address, architecture):
            self.variable_calls.append((name, address, architecture))
            return [{"name": "strm", "is_arg": True, "type": ["z_stream*"], "rbp_offset": 0}]
        stand_ins = {
            "decbench": module("decbench"), "decbench.models": module("decbench.models"),
            "decbench.pipeline": module("decbench.pipeline"), "decbench.metrics": module("decbench.metrics"),
            "decbench.utils": module("decbench.utils"),
            "decbench.models.project": module("decbench.models.project", OptimizationLevel=str, Project=Project),
            "decbench.pipeline.executor": module(
                "decbench.pipeline.executor", PipelineConfig=lambda **kw: kw, PipelineExecutor=Executor),
            "decbench.results_store": module(
                "decbench.results_store", gather_project_tomls=lambda: [Path("tomls/zlib.toml")]),
            "decbench.metrics.type_match": module(
                "decbench.metrics.type_match", extract_ground_truth_type_index=lambda path: {},
                _ground_truth_for_function=ground_truth_for_function),
            "decbench.utils.cfg": module(
                "decbench.utils.cfg", extract_cfgs_from_decompilation=lambda result: graphs,
                extract_cfgs_from_source=lambda path: self.source_graphs[Path(path).stem]),
            "decbench.utils.binfmt": module(
                "decbench.utils.binfmt", source_function_owners=source_function_owners,
                detect=lambda path: types.SimpleNamespace(arch="x86")),
            "decbench.utils.dwarf_policy": module(
                "decbench.utils.dwarf_policy", dwarf_follow_abstract_origin=lambda: True),
        }
        checkpoint = {"decompile": {"O2": {"libz.so.1.2": {"r2sleigh_native": Result()}}},
                      "evaluate": {"O2": {"libz.so.1.2": {"r2sleigh_native": {}}}}}
        self.patches = [mock.patch.dict(sys.modules, stand_ins),
                        mock.patch.object(show_function.pickle, "loads", return_value=checkpoint)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.dir.cleanup()

    def show(self, *flags):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = show_function.main(["--run", str(self.run), *flags, "zlib", "O2", "libz.so.1.2", "crc32"])
        self.assertEqual(status, 0)
        return out.getvalue()

    def test_graphs_are_printed_with_the_source_left_out(self):
        text = self.show("--no-source", "--graphs")
        self.assertIn("--- source block graph: 3 blocks, 2 edges", text)
        self.assertIn("--- r2sleigh_native block graph: 2 blocks, 1 edges", text)
        self.assertNotIn("--- source (", text)

    def test_the_source_is_the_unit_the_dwarf_names_for_the_address_not_the_first_that_has_the_name(self):
        text = self.show("--graphs")
        self.assertIn("--- source (zeta.i)\n{ return 2; }", text)
        self.assertNotIn("return 1;", text)
        self.assertIn("--- source block graph: 3 blocks, 2 edges", text)  # zeta's chain(3), not alpha's chain(7)
        self.assertEqual(self.owner_calls, [(Path("/unused/libz.so.1.2.13"), {"alpha", "zeta"}, True)])

    def test_a_function_whose_address_has_no_owner_shows_no_source_and_says_so(self):
        self.owners = {}
        text = self.show("--graphs")
        self.assertIn("--- source: no DWARF owner at 0x1000", text)
        self.assertNotIn("--- source (", text)
        self.assertNotIn("--- source block graph", text)
        self.assertIn("--- r2sleigh_native block graph: 2 blocks, 1 edges", text)

    def test_the_dwarf_variables_are_the_ones_the_type_metric_joins_by_address(self):
        text = self.show("--no-source")
        self.assertEqual(self.variable_calls, [("crc32", 0x1000, "x86")])
        self.assertIn("DWARF variables:\n   strm arg ['z_stream*'] ", text)

    def test_the_project_is_not_loaded_when_neither_source_nor_graphs_are_asked_for(self):
        text = self.show("--no-source")
        self.assertEqual(self.loaded, [])
        self.assertIn("--- r2sleigh_native rendering", text)


if __name__ == "__main__":
    unittest.main()
