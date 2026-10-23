#!/usr/bin/env python3
"""The pure parts of the DecBench run-analysis tools: type kinds, graph features, the scoreboard arithmetic."""

import json
import tempfile
import unittest
from pathlib import Path

import compare_runs
import ged_causes
import type_causes


class Node:
    def __init__(self, entry=False, exit_=False):
        self.is_entrypoint, self.is_exitpoint = entry, exit_


class Graph:
    """The subset of networkx.DiGraph the feature counter reads."""

    def __init__(self, nodes, edges):
        self.nodes = list(nodes)
        self.out = {n: [] for n in nodes}
        self.inn = {n: [] for n in nodes}
        for a, b in edges:
            self.out[a].append(b)
            self.inn[b].append(a)

    def successors(self, n):
        return iter(self.out[n])

    def out_degree(self, n):
        return len(self.out[n])

    def in_degree(self, n):
        return len(self.inn[n])

    def number_of_edges(self):
        return sum(len(v) for v in self.out.values())


class TypeKinds(unittest.TestCase):
    def test_decompiler_spellings(self):
        kind = type_causes.dec_kind
        self.assertEqual(kind("uint64_t", None), "int8")
        self.assertEqual(kind("const char *", None), "ptr_char")
        self.assertEqual(kind("uint8_t*", None), "ptr_char")
        self.assertEqual(kind("void*", None), "ptr_void")
        self.assertEqual(kind("uint64_t**", None), "ptr_ptr")
        self.assertEqual(kind("struct fcn_4330_arg0*", None), "ptr_struct")
        self.assertEqual(kind("unsigned long long", None), "int8")
        self.assertEqual(kind("_Bool", None), "bool")

    def test_a_named_type_cannot_be_spelled_from_a_stripped_binary(self):
        self.assertFalse(type_causes.expressible(["z_stream_s*", "z_streamp"]))
        self.assertTrue(type_causes.expressible(["z_stream_s*", "char*"]))
        self.assertTrue(type_causes.expressible(["uInt", "unsigned int", "int"]))
        self.assertTrue(type_causes.expressible(["char", "char[10]"]))

    def test_mismatch_causes(self):
        fp = type_causes.fp_class
        self.assertEqual(fp("ptr_char", "int8"), "fp:pointer_as_integer")
        self.assertEqual(fp("ptr_ptr", "ptr_int"), "fp:wrong_pointee")
        self.assertEqual(fp("int4", "int8"), "fp:integer_width")
        self.assertEqual(fp("bool", "int1"), "fp:bool")

    def test_greedy_order_fixes_the_class_that_frees_most_functions(self):
        def row(*classes):
            return {"value": 0.5, "vars": [{"verdict": c} for c in classes]}

        rows = [row("fp:a"), row("fp:a"), row("fp:a", "fp:b"), row("fp:b", "fn:unobservable"), row("fp:c", "fp:b")]
        steps = type_causes.greedy(rows)
        self.assertEqual(steps, [("fp:a", 2), ("fp:b", 1), ("fp:c", 1)])


class GraphShape(unittest.TestCase):
    def test_features_count_exits_branches_and_back_edges(self):
        a, b, c, d = Node(entry=True), Node(), Node(), Node(exit_=True)
        g = Graph([a, b, c, d], [(a, b), (b, c), (c, b), (b, d)])
        f = ged_causes.graph_features(g)
        self.assertEqual((f["V"], f["E"], f["X"], f["B"], f["M"], f["L"]), (4, 4, 1, 1, 0, 1))

    def test_function_body_reads_ansi_and_old_style_definitions(self):
        unit = "static int foo(int a);\nstatic int bar(s, f)\n    char *s;\n    int f;\n{ if (s && f) return 1; }\nint x = foo(3);\n"
        self.assertEqual(ged_causes.function_body(unit, "bar"), "{ if (s && f) return 1; }")
        self.assertIsNone(ged_causes.function_body(unit, "foo"))

    def test_text_features_ignore_strings_and_comments(self):
        t = ged_causes.text_features('{ if (a && b) { puts("x && y"); } /* || */ for (i = 0; i < n; i++) {} }')
        self.assertEqual((t["and_or"], t["for"], t["for_full"]), (1, 1, 1))

    def test_a_merged_return_is_an_exit_difference(self):
        s = {"V": 5, "E": 5, "X": 2, "B": 1, "M": 0, "L": 0}
        d = {"V": 5, "E": 5, "X": 1, "B": 1, "M": 0, "L": 0}
        zero = {"and_or": 0, "switch": 0, "case": 0, "for": 0, "for_full": 0, "while": 0, "do": 0,
                "goto": 0, "ret": 2, "ternary": 0, "residual": 0}
        row = {"S": s, "D": d, "S_text": zero, "D_text": zero}
        self.assertEqual(ged_causes.classify(row), "exit_blocks")


class Scoreboard(unittest.TestCase):
    def test_a_row_only_one_decompiler_scored_is_a_miss_for_the_others(self):
        def fn(name, values):
            return {"function": name, "values": values,
                    "perfects": {d: {m: v == (0.0 if m == "ged" else 1.0) for m, v in vs.items()} for d, vs in values.items()},
                    "decompiled": {}}

        data = {"decompilers": ["a", "b"], "groups": [
            {"project": "p", "opt_level": "O2", "binary": "x", "functions": [
                fn("f", {"a": {"ged": 0.0}, "b": {"ged": 3.0}})]},
            {"project": "q", "opt_level": "O2", "binary": "y", "functions": [
                fn("g", {"a": {"ged": 0.0}})]}]}
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "function_results.json").write_text(json.dumps(data))
            everything = compare_runs.recompute(Path(tmp), lambda g: True)
            only_p = compare_runs.recompute(Path(tmp), lambda g: g["project"] == "p")
        self.assertEqual(everything["decompiler_scores"]["b"]["metric_scores"]["ged"]["total_count"], 2)
        self.assertEqual(everything["decompiler_scores"]["b"]["overall_perfect_count"], 0)
        self.assertEqual(only_p["decompiler_scores"]["b"]["metric_scores"]["ged"]["total_count"], 1)
        self.assertEqual(only_p["decompiler_scores"]["a"]["overall_rank"], 1)


if __name__ == "__main__":
    unittest.main()
