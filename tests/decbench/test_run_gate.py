#!/usr/bin/env python3
"""A run that loses rows stops, and an evaluation the host would kill is refused."""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_gate  # noqa: E402

SCORED = '''binary = "{binary}"
"{dec}.byte_match.total" = 0.8461538461538461
"{dec}.byte_match.functions.main" = 0.0
"{dec}.ged.total" = 4.0
'''


class Tree:
    """A results tree: `<opt>/<project>/{decompiled,evaluated}/`."""

    def __init__(self, root: str):
        self.root = Path(root)

    def decompiled(self, decompiler: str, binary: str, functions: int = 3, c_bytes: int = 0,
                   opt: str = "O2", project: str = "bash") -> Path:
        directory = self.root / opt / project / "decompiled"
        directory.mkdir(parents=True, exist_ok=True)
        toml = directory / f"{decompiler}_{binary}.toml"
        toml.write_text(f'binary = "{binary}"\ndecompiler = "{decompiler}"\nfunction_count = {functions}\n')
        if c_bytes:
            (directory / f"{decompiler}_{binary}.c").write_bytes(b"a" * c_bytes)
        return toml

    def evaluated(self, binary: str, text: str, opt: str = "O2", project: str = "bash") -> Path:
        directory = self.root / opt / project / "evaluated"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{binary}.toml"
        path.write_text(text)
        return path


def gate(*argv: str) -> tuple[int, str]:
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        status = run_gate.main(list(argv))
    return status, err.getvalue()


class EvaluatedFiles(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tree = Tree(self.dir.name)
        self.args = ("evaluated", "--tree", self.dir.name, "--decompilers", "r2sleigh_native,angr,kuna")

    def tearDown(self):
        self.dir.cleanup()

    def test_a_16_byte_evaluated_file_stops_the_run(self):
        # The 2026-10-17 bash: the evaluation worker was killed and the file kept its header only.
        self.tree.decompiled("r2sleigh_native", "bash", functions=1540)
        path = self.tree.evaluated("bash", 'binary = "bash"\n')
        self.assertEqual(path.stat().st_size, 16)
        status, err = gate(*self.args)
        self.assertEqual(status, run_gate.LOST)
        self.assertIn("r2sleigh_native rendered 1540 functions of bash", err)
        self.assertIn("O2/bash/evaluated/bash.toml is 16 bytes and scores no decompiler", err)

    def test_the_command_exits_nonzero_for_the_shell(self):
        import subprocess

        self.tree.decompiled("kuna", "bash")
        self.tree.evaluated("bash", 'binary = "bash"\n')
        done = subprocess.run([sys.executable, str(HERE / "run_gate.py"), *self.args],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 71)
        self.assertIn("1 of 1 rendered binaries have no evaluation", done.stderr)

    def test_a_missing_file_stops_the_run(self):
        self.tree.decompiled("angr", "bash")
        status, err = gate(*self.args)
        self.assertEqual(status, run_gate.LOST)
        self.assertIn("O2/bash/evaluated/bash.toml is missing", err)

    def test_a_large_file_that_scores_only_other_decompilers_stops_the_run(self):
        # O2-noinline bash of 2026-10-17: 108 KB, angr's 692 rows, nothing of kuna, ghidra or r2s.
        self.tree.decompiled("angr", "bash")
        self.tree.decompiled("kuna", "bash")
        self.tree.evaluated("bash", SCORED.format(binary="bash", dec="angr") * 2000)
        status, err = gate(*self.args)
        self.assertEqual(status, run_gate.LOST)
        self.assertIn("kuna rendered 3 functions of bash", err)
        self.assertIn("scores angr, not kuna", err)
        self.assertNotIn("angr rendered", err)

    def test_an_oversized_c_file_names_the_likely_cause(self):
        self.tree.decompiled("r2sleigh_native", "bash", c_bytes=9 * 2**20)
        self.tree.evaluated("bash", 'binary = "bash"\n')
        status, err = gate(*self.args)
        self.assertEqual(status, run_gate.LOST)
        self.assertIn("9.0 MB", err)
        self.assertIn("--workers 1", err)

    def test_scored_binaries_pass_including_dotted_names_and_small_files(self):
        self.tree.decompiled("r2sleigh_native", "libz.so.1.2", project="zlib")
        self.tree.evaluated("libz.so.1.2", SCORED.format(binary="libz.so.1.2", dec="r2sleigh_native"),
                            project="zlib")
        self.tree.decompiled("kuna", "psize")
        self.tree.evaluated("psize", SCORED.format(binary="psize", dec="kuna"))
        status, err = gate(*self.args)
        self.assertEqual((status, err), (0, ""))

    def test_only_what_this_run_decompiled_is_checked(self):
        # A resumed run: angr is older than the run's start and not evaluated again.
        old = self.tree.decompiled("angr", "bash")
        os.utime(old, (1_000, 1_000))
        self.tree.decompiled("r2sleigh_native", "bash")
        self.tree.evaluated("bash", SCORED.format(binary="bash", dec="r2sleigh_native"))
        self.assertEqual(gate(*self.args, "--since", "2000")[0], 0)
        self.assertEqual(gate(*self.args)[0], run_gate.LOST)

    def test_a_decompiler_that_rendered_nothing_owes_no_scores(self):
        self.tree.decompiled("angr", "bash", functions=0)
        self.assertEqual(gate(*self.args)[0], 0)


class OneWorkerForBigC(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tree = Tree(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def workers(self, n: int) -> tuple[int, str]:
        return gate("workers", "--tree", self.dir.name, "--workers", str(n),
                    "--decompilers", "r2sleigh_native,angr")

    def test_more_than_one_worker_is_refused_for_a_binary_over_8_mb(self):
        self.tree.decompiled("r2sleigh_native", "bash", c_bytes=13 * 2**20)
        self.tree.decompiled("angr", "bash", c_bytes=2**20)
        status, err = self.workers(4)
        self.assertEqual(status, run_gate.REFUSED)
        self.assertIn("O2/bash/bash (r2sleigh_native): 13.0 MB", err)
        self.assertNotIn("angr", err)
        self.assertEqual(self.workers(1), (0, ""))

    def test_a_binary_under_the_limit_may_use_every_worker(self):
        self.tree.decompiled("r2sleigh_native", "bzip2", c_bytes=7 * 2**20, project="bzip2")
        self.assertEqual(self.workers(8), (0, ""))


class FakeResult:
    def __init__(self, megabytes: float):
        code = "a" * int(megabytes * 2**20)
        self.functions = {"main": types.SimpleNamespace(decompiled_code=code)}


class DriverGuard(unittest.TestCase):
    """`install_workers_guard` in front of a stand-in `evaluate_project` with DecBench's signature."""

    def setUp(self):
        self.calls = []

        def evaluate_project(project, decompilations, output_dir, optimization=None, metrics=None,
                             parallel=True, workers=None, precomputed_source_cfgs=None,
                             source_function_owners=None):
            self.calls.append(workers)
            return {"bash": {"r2sleigh_native": {"ged": 1}}}

        self.module = types.ModuleType("decbench.pipeline.evaluate")
        self.module.evaluate_project = evaluate_project
        pipeline = types.ModuleType("decbench.pipeline")
        pipeline.evaluate = self.module
        patcher = mock.patch.dict(sys.modules, {
            "decbench": types.ModuleType("decbench"),
            "decbench.pipeline": pipeline,
            "decbench.pipeline.evaluate": self.module,
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        run_gate.install_workers_guard()
        run_gate.install_workers_guard()  # idempotent

    def test_parallel_workers_over_big_c_end_the_run_instead_of_returning_nothing(self):
        big = {"bash": {"r2sleigh_native": FakeResult(9), "angr": FakeResult(1)}}
        # The driver catches `Exception` around `evaluate_project` and carries on with `{}`.
        with self.assertRaises(SystemExit) as stop:
            self.module.evaluate_project("project", big, Path("out"), None, None, True, 2)
        self.assertNotIsInstance(stop.exception, Exception)
        self.assertIn("bash (r2sleigh_native): 9.0 MB", str(stop.exception))
        self.assertIn("--workers 1", str(stop.exception))
        with self.assertRaises(SystemExit):
            self.module.evaluate_project("project", big, Path("out"), workers=2)
        self.assertEqual(self.calls, [])

    def test_one_worker_or_small_c_passes_through(self):
        big = {"bash": {"r2sleigh_native": FakeResult(9)}}
        small = {"bzip2": {"r2sleigh_native": FakeResult(1)}}
        self.assertEqual(self.module.evaluate_project("p", big, Path("o"), workers=1),
                         {"bash": {"r2sleigh_native": {"ged": 1}}})
        self.module.evaluate_project("p", small, Path("o"), workers=8)
        self.assertEqual(self.calls, [1, 8])

    def test_no_worker_count_means_every_cpu(self):
        big = {"bash": {"r2sleigh_native": FakeResult(9)}}
        with mock.patch.object(run_gate.os, "cpu_count", return_value=4):
            with self.assertRaises(SystemExit):
                self.module.evaluate_project("p", big, Path("o"))
        with mock.patch.object(run_gate.os, "cpu_count", return_value=1):
            self.module.evaluate_project("p", big, Path("o"))


if __name__ == "__main__":
    unittest.main()
