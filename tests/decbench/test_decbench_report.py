#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


report = load("report_decbench")
merger = load("merge_decbench")


def payload(project: str, score: float | None, decompiled: bool = True) -> dict:
    values = {"r2sleigh_native": {"byte_match": score}} if score is not None else {}
    return {
        "schema_version": 2,
        "decompilers": ["r2sleigh_native"],
        "decompiler_versions": {"r2sleigh_native": "test"},
        "metrics": ["byte_match"],
        "groups": [
            {
                "project": project,
                "binary": "same-name",
                "opt_level": "O0",
                "functions": [
                    {
                        "function": "same_function",
                        "values": values,
                        "decompiled": {"r2sleigh_native": decompiled},
                    }
                ],
            }
        ],
    }


def results_of(projects: dict[str, list[dict]], **extra) -> dict:
    """Result set: per project, one function per entry; an entry maps a decompiler to its metrics, or None."""
    decompilers = sorted({d for rows in projects.values() for row in rows for d in row})
    return {
        "schema_version": 2,
        "decompilers": decompilers,
        "decompiler_versions": {d: "test" for d in decompilers},
        "metrics": ["byte_match", "ged"],
        "perfect_values": {"byte_match": 1.0, "ged": 0.0},
        "groups": [
            {
                "project": project,
                "binary": "b",
                "opt_level": "O2",
                "functions": [
                    {
                        "function": f"f{number}",
                        "values": {d: m for d, m in row.items() if m},
                        "decompiled": {d: m is not None for d, m in row.items()},
                    }
                    for number, row in enumerate(rows)
                ],
            }
            for project, rows in projects.items()
        ],
        **extra,
    }


def perfect() -> dict:
    return {"byte_match": 1.0, "ged": 0.0}


def worse() -> dict:
    return {"byte_match": 0.5, "ged": 3.0}


class CoverageTests(unittest.TestCase):
    def test_a_project_one_decompiler_lost_stops_the_report_before_any_number(self) -> None:
        # The 2026-10-17 bash: three decompilers lost every row, angr kept some.
        lost = {"angr": perfect(), "kuna": None, "r2sleigh_native": None}
        kept = {"angr": perfect(), "kuna": worse(), "r2sleigh_native": worse()}
        data = results_of({"bash": [lost, lost, lost], "zlib": [kept, kept]})
        cover = report.coverage(data, report.compared_decompilers(data))
        self.assertEqual(cover.failures, [
            "kuna scored 0 of 3 rows of bash",
            "r2sleigh_native scored 0 of 3 rows of bash",
        ])
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "function_results.json"
            results.write_text(json.dumps(data))
            baseline = Path(directory) / "baseline.json"
            argv = ["report_decbench.py", "--results", str(results), "--baseline", str(baseline),
                    "--accept-baseline"]
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                status = report.main()
            self.assertEqual(status, report.LOST_ROWS)
            self.assertIn("kuna scored 0 of 3 rows of bash", stderr.getvalue())
            self.assertFalse(baseline.exists())  # a lossy run is not accepted as the record

    def test_decompilers_are_compared_only_on_rows_every_one_scored(self) -> None:
        both = {"angr": perfect(), "r2sleigh_native": worse()}
        only_r2s = {"angr": None, "r2sleigh_native": perfect()}
        only_angr = {"angr": perfect(), "r2sleigh_native": None}
        data = results_of({"zlib": [both, both, only_r2s, only_r2s, only_r2s, only_angr]})
        cover = report.coverage(data, ["angr", "r2sleigh_native"])
        self.assertEqual(cover.failures, [])
        self.assertEqual(cover.rows, 6)
        self.assertEqual(len(cover.common), 2)
        self.assertEqual(cover.no_score, {"angr": 3, "r2sleigh_native": 1})
        self.assertEqual(cover.by_project["zlib"], {"angr": (3, 6), "r2sleigh_native": (5, 6)})
        table = report.common_rows_table(cover)
        # Over the two shared rows r2s is perfect on none, angr on both; the three rows only r2s
        # scored, all perfect, do not make it look better.
        self.assertEqual(table["ged"]["angr"], {"n": 2, "mean": 0.0, "perfect": 2})
        self.assertEqual(table["ged"]["r2sleigh_native"], {"n": 2, "mean": 3.0, "perfect": 0})

    def test_the_report_says_how_many_rows_it_left_out(self) -> None:
        row = {"angr": perfect(), "r2sleigh_native": None}
        data = results_of({"zlib": [row, row, row]})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            report.print_coverage(report.coverage(data, ["angr", "r2sleigh_native"]))
        text = out.getvalue()
        self.assertIn("rows: 3; scored by all 2: 0; left out of the comparison: 3", text)
        self.assertIn("rows with no score: angr 0, r2sleigh_native 3", text)

    def test_a_stated_fraction_fails_a_project_that_is_mostly_unscored(self) -> None:
        mostly_lost = [{"kuna": worse()}] + [{"kuna": None}] * 3
        data = results_of({"bash": mostly_lost})
        self.assertEqual(report.coverage(data, ["kuna"]).failures, [])
        failures = report.coverage(data, ["kuna"], min_fraction=0.5).failures
        self.assertEqual(failures, ["kuna scored 1 of 4 rows of bash"])

    def test_a_decompiler_is_owed_only_the_cells_it_ran_in(self) -> None:
        # A merge of shards: angr ran in `fresh` only, so `cached` is not a loss.
        data = results_of({"fresh": [{"angr": perfect(), "r2sleigh_native": worse()}],
                           "cached": [{"r2sleigh_native": worse()}]},
                          sweep={"decompiler_cells": {"angr": ["fresh/O2"],
                                                      "r2sleigh_native": ["cached/O2", "fresh/O2"]}})
        cover = report.coverage(data, ["angr", "r2sleigh_native"])
        self.assertEqual(cover.failures, [])
        self.assertEqual(sorted(cover.by_project), ["cached", "fresh"])
        self.assertNotIn("angr", cover.by_project["cached"])
        # Naming a decompiler that never scored is a failure, not a pass.
        self.assertEqual(report.coverage(data, ["ghidra"]).failures,
                         ["ghidra scored 0 of 1 rows of cached", "ghidra scored 0 of 1 rows of fresh"])

    def test_the_compared_set_is_what_the_results_name(self) -> None:
        data = results_of({"zlib": [{"angr": perfect(), "kuna": worse()}]})
        self.assertEqual(report.compared_decompilers(data), ["angr", "kuna"])
        del data["decompiler_versions"]
        data["decompilers"] = ["angr"]
        self.assertEqual(report.compared_decompilers(data), ["angr"])


class ReportTests(unittest.TestCase):
    def test_an_invalid_baseline_is_neither_compared_nor_merged(self) -> None:
        self.assertEqual(report.usable_baseline(None), (None, None))
        kept = {"functions": {}}
        self.assertEqual(report.usable_baseline(kept), (kept, None))
        self.assertEqual(
            report.usable_baseline({"functions": {"x": {}}, "invalid": {"reason": "plugin era"}}),
            (None, "plugin era"),
        )

    def test_the_plugin_era_record_may_not_grade_a_run(self) -> None:
        import json

        recorded = json.loads((HERE / "baseline.json").read_text())
        baseline, invalid = report.usable_baseline(recorded)
        self.assertIsNone(baseline)
        self.assertIn("unstripped", invalid)

    def test_project_is_part_of_function_key(self) -> None:
        merged = merger.merge([payload("one", 0.5), payload("two", 0.75)])
        collected = report.collect(merged)
        rows = collected.rows
        self.assertEqual(
            set(rows),
            {
                "one/same-name/O0::same_function",
                "two/same-name/O0::same_function",
            },
        )
        measured = report.measured_record(collected, rows)
        self.assertEqual(
            measured["summary"]["population"]["cells"]["one/O0"],
            {
                "binaries": 1,
                "functions": 1,
                "rendered": 1,
                "reference_rendered": 0,
                "reference": "none",
            },
        )

    def test_all_function_mean_scores_refusal_as_zero(self) -> None:
        rows = {
            "one/bin/O0::yes": {
                "decompiled": True,
                "scores": {"byte_match": 0.5, "ged": 3.0},
                "reference_decompiled": False,
                "reference": {},
            },
            "one/bin/O0::no": {
                "decompiled": False,
                "scores": {},
                "reference_decompiled": False,
                "reference": {},
            },
        }
        summary = report.summarise(rows)["metrics"]
        self.assertEqual(
            summary["byte_match"]["rendered"], {"n": 1, "mean": 0.5}
        )
        self.assertEqual(summary["byte_match"]["all_functions"]["mean"], 0.25)
        self.assertEqual(summary["ged"]["rendered"], {"n": 1, "mean": 3.0})
        self.assertEqual(summary["ged"]["all_functions"]["mean"], 0.125)

    def test_requested_metric_is_reported_when_every_function_refuses(self) -> None:
        rows = {
            "one/bin/O0::no": {
                "decompiled": False,
                "scores": {},
                "reference_decompiled": False,
                "reference": {},
            }
        }
        metric = report.summarise(rows, {"vj_ged"})["metrics"]["vj_ged"]
        self.assertEqual(metric["rendered"], {"n": 0, "mean": None})
        self.assertEqual(metric["all_functions"]["mean"], 0.0)

    def test_cached_reference_defines_refused_function_universe(self) -> None:
        current = report.collect(payload("one", 0.5))
        baseline = {
            "functions": {
                "one/same-name/O0::same_function": {
                    "decompiled": True,
                    "scores": {"byte_match": 0.4},
                    "reference_decompiled": True,
                    "reference": {"byte_match": 0.8},
                },
                "one/same-name/O0::refused": {
                    "decompiled": False,
                    "scores": {},
                    "reference_decompiled": True,
                    "reference": {"byte_match": 0.6},
                },
            }
        }
        rows, fill = report.reference_universe(current, baseline)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(fill["absent"]), 1)
        self.assertFalse(rows["one/same-name/O0::refused"]["decompiled"])
        self.assertEqual(
            report.summarise(rows)["metrics"]["byte_match"]["all_functions"][
                "mean"
            ],
            0.25,
        )

    def test_fresh_reference_does_not_import_old_only_functions(self) -> None:
        current = report.collect(payload("one", 0.5))
        current.reference_version = "new"
        current.reference_cells = {"one/O0"}
        baseline = {
            "functions": {
                "one/same-name/O0::old_only": {
                    "decompiled": False,
                    "scores": {},
                    "reference_decompiled": True,
                    "reference": {"byte_match": 0.9},
                }
            }
        }
        rows, fill = report.reference_universe(current, baseline)
        self.assertEqual(set(rows), {"one/same-name/O0::same_function"})
        self.assertEqual(fill["absent"], [])

    def test_partial_fresh_reference_only_fills_cached_cells(self) -> None:
        fresh = payload("fresh", 0.5)
        fresh["decompilers"].append("angr")
        fresh["decompiler_versions"] = {"angr": "9.3.3"}
        cached = payload("cached", 0.5)
        current = report.collect(merger.merge([fresh, cached]))
        baseline = {
            "functions": {
                "fresh/same-name/O0::old_only": {
                    "decompiled": False,
                    "scores": {},
                    "reference_decompiled": True,
                    "reference": {"byte_match": 0.9},
                },
                "cached/same-name/O0::old_only": {
                    "decompiled": False,
                    "scores": {},
                    "reference_decompiled": True,
                    "reference": {"byte_match": 0.8},
                },
            }
        }
        rows, fill = report.reference_universe(current, baseline)
        self.assertNotIn("fresh/same-name/O0::old_only", rows)
        self.assertIn("cached/same-name/O0::old_only", rows)
        self.assertEqual(
            current.reference_cells,
            {"fresh/O0"},
        )
        self.assertEqual(fill["absent"], ["cached/same-name/O0::old_only"])

    def test_reference_coverage_counts_only_cells_the_reference_ran_in(self) -> None:
        # The cached fill exists so a function we refuse still counts against
        # us. It must not also make the reference look like it ran.
        fresh = payload("fresh", 0.5)
        fresh["decompilers"].append("angr")
        fresh["decompiler_versions"] = {"angr": "9.3.3"}
        fresh["groups"][0]["functions"][0]["values"]["angr"] = {"byte_match": 0.4}
        fresh["groups"][0]["functions"][0]["decompiled"]["angr"] = True
        cached = payload("cached", 0.5)
        current = report.collect(merger.merge([fresh, cached]))
        baseline = {
            "functions": {
                "cached/same-name/O0::same_function": {
                    "decompiled": True,
                    "scores": {"byte_match": 0.5},
                    "reference_decompiled": True,
                    "reference": {"byte_match": 0.9},
                }
            }
        }
        rows, _ = report.reference_universe(current, baseline)
        measured = report.measured_record(current, rows)
        population = measured["summary"]["population"]
        self.assertEqual(population["functions"], 2)
        self.assertEqual(population["reference_functions"], 1)
        self.assertEqual(population["reference_rendered"], 1)
        self.assertEqual(population["reference_coverage"], 1.0)
        self.assertEqual(population["reference_cells"], ["fresh/O0"])
        self.assertEqual(
            population["cells"]["cached/O0"]["reference"], "cached"
        )
        self.assertEqual(population["cells"]["cached/O0"]["reference_rendered"], 1)
        self.assertEqual(
            population["cells"]["fresh/O0"]["reference"], "measured"
        )
        # The cached 0.9 must not enter the reference mean either.
        reference_mean = measured["summary"]["metrics"]["byte_match"][
            "reference_rendered"
        ]
        self.assertEqual(reference_mean["n"], 1)
        self.assertAlmostEqual(reference_mean["mean"], 0.4)

    def test_compare_limits_itself_to_cells_the_baseline_covers(self) -> None:
        current = report.collect(merger.merge([payload("shared", 0.5), payload("new", 0.5)]))
        measured = report.measured_record(current, current.rows)
        baseline = {
            "selection": {"cells": ["shared/O0", "absent/O0"]},
            "functions": {
                "shared/same-name/O0::same_function": {
                    "decompiled": True,
                    "scores": {"byte_match": 0.5},
                    "reference_decompiled": False,
                    "reference": {},
                },
                "absent/same-name/O0::same_function": {
                    "decompiled": True,
                    "scores": {"byte_match": 0.9},
                    "reference_decompiled": False,
                    "reference": {},
                },
            },
        }
        status = report.compare(measured, baseline)
        # `new/O0` has no baseline and `absent/O0` was not run; neither is a
        # regression, and the one shared function is unchanged.
        self.assertEqual(status, 0)

    def test_a_function_declining_while_the_population_rises_is_not_a_regression(
        self,
    ) -> None:
        current = report.collect(
            merger.merge(
                [
                    {
                        **payload("one", None),
                        "groups": [
                            {
                                "project": "one",
                                "binary": "same-name",
                                "opt_level": "O0",
                                "functions": [
                                    {
                                        "function": "down",
                                        "values": {"r2sleigh_native": {"byte_match": 0.40}},
                                        "decompiled": {"r2sleigh_native": True},
                                    },
                                    {
                                        "function": "up",
                                        "values": {"r2sleigh_native": {"byte_match": 0.90}},
                                        "decompiled": {"r2sleigh_native": True},
                                    },
                                ],
                            }
                        ],
                    }
                ]
            )
        )
        measured = report.measured_record(current, current.rows)
        baseline = {
            "selection": {"cells": ["one/O0"]},
            "functions": {
                "one/same-name/O0::down": {
                    "decompiled": True,
                    "scores": {"byte_match": 0.50},
                    "reference_decompiled": False,
                    "reference": {},
                },
                "one/same-name/O0::up": {
                    "decompiled": True,
                    "scores": {"byte_match": 0.50},
                    "reference_decompiled": False,
                    "reference": {},
                },
            },
        }
        # 0.50 -> 0.40 on one function, 0.50 -> 0.90 on the other: the paired
        # mean rose, so the tree did not regress.
        self.assertEqual(report.compare(measured, baseline), 0)

    def test_a_declining_paired_mean_is_a_regression(self) -> None:
        current = report.collect(merger.merge([payload("one", 0.40)]))
        measured = report.measured_record(current, current.rows)
        baseline = {
            "selection": {"cells": ["one/O0"]},
            "functions": {
                "one/same-name/O0::same_function": {
                    "decompiled": True,
                    "scores": {"byte_match": 0.50},
                    "reference_decompiled": False,
                    "reference": {},
                }
            },
        }
        self.assertEqual(report.compare(measured, baseline), 1)

    def test_merge_rejects_silent_missing_cell(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing project/opt cells: one/O1"):
            merger.merge([payload("one", 0.5)], {"one/O0", "one/O1"})

    def test_merge_rejects_duplicate_binary_group(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate binary group"):
            merger.merge([payload("one", 0.5), payload("one", 0.6)])

    def test_baseline_records_metric_completeness_per_reference_cell(self) -> None:
        old = {
            "reference": {"decompiler": "angr", "version": "9.3.3"},
            "selection": {"cells": ["cached/O0"]},
            "groups": [],
            "functions": {},
            "summary": {"metrics": {"byte_match": {}}},
        }
        fresh_payload = payload("fresh", 0.5)
        fresh_payload["decompilers"].append("angr")
        fresh_payload["decompiler_versions"] = {"angr": "9.3.3"}
        fresh_payload["metrics"] = ["byte_match", "vj_ged"]
        current = report.collect(merger.merge([fresh_payload]))
        measured = report.measured_record(current, current.rows)
        baseline = report.merge_baseline(old, measured)
        self.assertEqual(
            baseline["reference"]["metric_cells"],
            {
                "byte_match": ["cached/O0", "fresh/O0"],
                "vj_ged": ["fresh/O0"],
            },
        )
        self.assertEqual(
            baseline["selection"]["cells"],
            ["cached/O0", "fresh/O0"],
        )


if __name__ == "__main__":
    unittest.main()
