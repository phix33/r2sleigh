#!/usr/bin/env python3
"""The DecBench backend asks for exactly its targets and files every one.

The backend runs inside DecBench, which is not a dependency of this
repository, so when it is not importable the few names the backend uses are
stood in for below. The stand-ins carry no behaviour the tests depend on
except ``dump_progress`` (it pickles, as DecBench's does) and the target
filter (it keeps integer addresses, as DecBench's does). With DecBench
installed the real modules are used.

r2s is replaced by ``tests/equiv/testdata/stub_r2s.py``, which answers
``pddj`` per the contract and fails on request in each way r2s can.
"""

from __future__ import annotations

import itertools
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
STUB = REPO / "tests" / "equiv" / "testdata" / "stub_r2s.py"
STRIPPED = REPO / "tests" / "fixtures" / "hashes_gcc_x64_O2_stripped"
sys.path.insert(0, str(HERE))

REGISTERED: list[str] = []


def _install_decbench_stand_ins() -> None:
    try:
        import decbench.decompilers.registry  # noqa: F401

        return
    except ImportError:
        pass

    def module(name: str) -> types.ModuleType:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        return mod

    class Model:
        def __init__(self, **values):
            self.__dict__.update(values)

    module("decbench")
    module("decbench.decompilers")
    base = module("decbench.decompilers.base")

    class Decompiler:
        def __init__(self, config=None):
            self.config = config

        @property
        def id(self):
            return self.name

    base.Decompiler = Decompiler
    base.DecompilerConfig = Model
    raw = module("decbench.decompilers.raw")
    common = module("decbench.decompilers.raw.common")
    raw.common = common
    common.addr_targets_of = lambda names: {
        int(x) for x in (names or ()) if isinstance(x, int) and not isinstance(x, bool)
    }
    common.elf_text_ranges = lambda path: None
    common.should_skip_function = lambda name, addr, text, targets: (
        not name or name in {"_start", "frame_dummy", "__libc_csu_init"}
    )
    common.extract_metrics = lambda code: {"gotos": code.count("goto "), "bools": 0}

    def dump_progress(path, result):
        if path is not None:
            Path(path).write_bytes(pickle.dumps(result))

    common.dump_progress = dump_progress
    registry = module("decbench.decompilers.registry")

    def register_decompiler(name):
        def wrap(cls):
            REGISTERED.append(name)
            return cls

        return wrap

    registry.register_decompiler = register_decompiler
    module("decbench.models")
    models = module("decbench.models.decompilation")
    for name in ("DecompilationResult", "DecompilerMetadata", "FunctionDecompilation",
                 "LineMapping", "VariableInfo"):
        # Named where they live, so a partial result pickles like DecBench's.
        setattr(models, name, type(name, (Model,), {"__module__": models.__name__}))


_install_decbench_stand_ins()

import r2sleigh_raw  # noqa: E402

TARGETS = [0x401150, 0x401160, 0x4011F0, 0x401210, 0x401230, 0x401290]


class Backend(unittest.TestCase):
    runs = itertools.count()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {
            "R2SLEIGH_R2S_BIN": str(STUB),
            "STUB_R2S_MODE": "minimal",
            "STUB_R2S_FAULTS": "",
            "STUB_R2S_STATE": self.tmp.name,
            "R2SLEIGH_REFUSAL_CENSUS_DIR": self.tmp.name,
            "R2SLEIGH_FUNCTION_TIMEOUT": "30",
        }
        self.saved = {key: os.environ.get(key) for key in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tmp.cleanup()

    def decompile(self, binary=STRIPPED, **kwargs):
        return r2sleigh_raw.R2sDecompiler().decompile_binary(Path(binary), **kwargs)

    def test_it_renders_exactly_its_targets_at_their_own_addresses(self):
        # D1, D2: a stripped binary has no symbol to find a function by; the
        # DWARF low_pc set is the contract, and r2s addresses are file space.
        result = self.decompile(function_names=set(TARGETS))
        rendered = sorted(f.address for f in result.functions.values())
        self.assertEqual(rendered, TARGETS)
        for function in result.functions.values():
            self.assertEqual(function.name, f"fcn_{function.address:08x}")
            self.assertIn(f"void {function.name}(void)", function.decompiled_code)
        extra = result.decompiler.extra
        self.assertEqual((extra["requested"], extra["rendered"], extra["declined"]), (6, 6, 0))
        self.assertEqual(extra["requested_from"], "targets")

    def test_a_failed_statement_is_a_typed_decline_in_a_completed_batch(self):
        # D3: stderr merged, `r2s: ...` inside the markers, exit 1 is no crash.
        os.environ["STUB_R2S_FAULTS"] = f"error@{TARGETS[1]:x}"
        result = self.decompile(function_names=set(TARGETS))
        causes = result.decompiler.extra["decline_causes"]
        self.assertEqual(causes, {f"0x{TARGETS[1]:x}": f"r2s: nothing mapped at 0x{TARGETS[1]:x}"})
        self.assertEqual(len(result.functions), 5)
        self.assertEqual(result.decompiler.extra["processes"], 1)
        self.assertEqual(result.decompiler.failed_functions, [f"0x{TARGETS[1]:x}"])

    def test_a_crash_costs_one_function_and_the_end_is_checkpointed(self):
        # D4: abort on the third of six; r2s restarts at the fourth, and the
        # pickle the driver would recover holds the five answers.
        os.environ["STUB_R2S_FAULTS"] = f"abort@{TARGETS[2]:x}"
        progress = Path(self.tmp.name) / "progress.pkl"
        result = self.decompile(function_names=set(TARGETS), progress_path=progress)
        causes = result.decompiler.extra["decline_causes"]
        self.assertEqual(list(causes), [f"0x{TARGETS[2]:x}"])
        self.assertIn("SIGABRT", causes[f"0x{TARGETS[2]:x}"])
        self.assertIn(f"0x{TARGETS[2]:x}", causes[f"0x{TARGETS[2]:x}"])
        self.assertEqual(sorted(f.address for f in result.functions.values()),
                         TARGETS[:2] + TARGETS[3:])
        saved = pickle.loads(progress.read_bytes())
        self.assertEqual(len(saved.functions), 5)
        self.assertEqual(result.decompiler.extra["processes"], 2)
        self.assertNotIn("resume", result.decompiler.extra)

    def checkpoint_rows(self, answer_times, interval="30"):
        """The rows held by each checkpoint of a run whose answers arrive at ``answer_times`` seconds."""
        clock = [0.0]
        rows: list[int] = []
        os.environ["R2SLEIGH_CHECKPOINT_SECONDS"] = interval
        real_batch = r2sleigh_raw.r2s_batch.run_batch
        real_dump = r2sleigh_raw.common.dump_progress

        def timed(*args, on_answer=None, **kwargs):
            moments = iter(answer_times)

            def arrive(answer):
                clock[0] = next(moments)
                on_answer(answer)

            return real_batch(*args, on_answer=arrive, **kwargs)

        def spy(path, result):
            rows.append(len(result.functions) + len(result.decompiler.extra["decline_causes"]))
            real_dump(path, result)

        try:
            r2sleigh_raw.r2s_batch.run_batch = timed
            r2sleigh_raw.common.dump_progress = spy
            r2sleigh_raw._clock = lambda: clock[0]
            # A path of its own: a checkpoint left by an earlier call would resume.
            self.decompile(function_names=set(TARGETS),
                           progress_path=Path(self.tmp.name) / f"cadence-{next(self.runs)}.pkl")
        finally:
            r2sleigh_raw.r2s_batch.run_batch = real_batch
            r2sleigh_raw.common.dump_progress = real_dump
            r2sleigh_raw._clock = time.monotonic
        return rows

    def test_a_checkpoint_is_written_by_elapsed_time_and_at_the_end(self):
        # Six answers in one second are one pickle, not six; a pause of 30 seconds is one more.
        self.assertEqual(self.checkpoint_rows([1, 2, 3, 4, 5, 6]), [6])
        self.assertEqual(self.checkpoint_rows([1, 2, 31, 32, 33, 70]), [3, 6, 6])
        self.assertEqual(self.checkpoint_rows([1, 2, 3, 4, 5, 6], interval="0"),
                         [1, 2, 3, 4, 5, 6, 6])

    def test_the_interval_is_thirty_seconds_unless_the_environment_says_otherwise(self):
        os.environ.pop("R2SLEIGH_CHECKPOINT_SECONDS", None)
        self.assertEqual(r2sleigh_raw.checkpoint_interval(), 30.0)
        for given, expected in (("5", 5.0), ("0", 0.0), ("-3", 0.0), ("soon", 30.0),
                                ("nan", 30.0), ("inf", 30.0)):
            os.environ["R2SLEIGH_CHECKPOINT_SECONDS"] = given
            self.assertEqual(r2sleigh_raw.checkpoint_interval(), expected, given)

    def asked_addresses(self):
        """Patch the runner to record the addresses it is asked about; returns the list and an undo."""
        asked: list[int] = []
        real_batch = r2sleigh_raw.r2s_batch.run_batch

        def spy(executable, binary, addresses, **kwargs):
            asked.extend(addresses)
            return real_batch(executable, binary, addresses, **kwargs)

        r2sleigh_raw.r2s_batch.run_batch = spy
        self.addCleanup(setattr, r2sleigh_raw.r2s_batch, "run_batch", real_batch)
        return asked

    @unittest.skipUnless(hasattr(os, "fork"), "needs fork to kill a run without cleanup")
    def test_a_killed_run_resumes_from_its_last_checkpoint_and_gives_the_same_rows(self):
        progress = Path(self.tmp.name) / "progress.pkl"
        os.environ["R2SLEIGH_CHECKPOINT_SECONDS"] = "30"
        clock = [0.0]
        real_batch = r2sleigh_raw.r2s_batch.run_batch

        def dying(*args, on_answer=None, **kwargs):
            given = []

            def arrive(answer):
                clock[0] += 10.0  # a checkpoint on every third answer
                on_answer(answer)
                given.append(answer)
                if len(given) == 5:
                    os._exit(9)  # SIGKILL's view of the run: no handler, no `finally`

            return real_batch(*args, on_answer=arrive, **kwargs)

        pid = os.fork()
        if pid == 0:
            code = 2
            try:
                r2sleigh_raw._clock = lambda: clock[0]
                r2sleigh_raw.r2s_batch.run_batch = dying
                self.decompile(function_names=set(TARGETS), progress_path=progress)
            except BaseException:  # noqa: BLE001
                code = 3
            finally:
                os._exit(code)  # never fall back into the test runner
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.WEXITSTATUS(status), 9)
        # Five answers were given; the third's checkpoint is the last, so two are lost, one interval at most.
        kept = pickle.loads(progress.read_bytes())
        self.assertEqual(sorted(f.address for f in kept.functions.values()), TARGETS[:3])

        asked = self.asked_addresses()
        resumed = self.decompile(function_names=set(TARGETS), progress_path=progress)
        self.assertEqual(asked, TARGETS[3:])
        self.assertEqual(resumed.decompiler.extra["resumed"], 3)
        fresh = self.decompile(function_names=set(TARGETS))

        def rows(result):
            return ({name: (f.address, f.decompiled_code, f.metadata)
                     for name, f in result.functions.items()},
                    result.decompiler.extra["decline_causes"],
                    result.decompiler.failed_functions,
                    (result.decompiler.extra["requested"], result.decompiler.extra["rendered"],
                     result.decompiler.extra["declined"]))

        self.assertEqual(rows(resumed), rows(fresh))

    def test_a_checkpoint_of_another_task_is_not_read(self):
        progress = Path(self.tmp.name) / "progress.pkl"
        self.decompile(function_names=set(TARGETS[:3]), progress_path=progress)
        asked = self.asked_addresses()
        # The checkpoint holds three targets, this run has six: nothing carries over.
        result = self.decompile(function_names=set(TARGETS), progress_path=progress)
        self.assertEqual(asked, TARGETS)
        self.assertNotIn("resumed", result.decompiler.extra)
        # The same six, another r2s build: nothing carries over either.
        other = Path(self.tmp.name) / "other-build.pkl"
        shutil.copyfile(progress, other)
        asked.clear()
        with mock.patch.object(r2sleigh_raw.R2sDecompiler, "get_version",
                               return_value="r2s sha256:another"):
            self.decompile(function_names=set(TARGETS), progress_path=other)
        self.assertEqual(asked, TARGETS)
        # The same task: the end-of-run checkpoint answers everything.
        asked.clear()
        again = self.decompile(function_names=set(TARGETS), progress_path=progress)
        self.assertEqual((asked, again.decompiler.extra["resumed"]), ([], 6))

    def test_thousands_of_targets_are_one_process_and_every_one_is_filed(self):
        # The sailr set's large binaries have thousands of functions. As one -c
        # script that many addresses passed Linux's 128 KiB argv cap, Popen
        # raised, and the whole binary was lost with nothing filed.
        targets = {0x400000 + 16 * n for n in range(2500)}
        result = self.decompile(function_names=targets)
        extra = result.decompiler.extra
        self.assertEqual((extra["requested"], extra["rendered"], extra["declined"]),
                         (2500, 2500, 0))
        self.assertEqual({f.address for f in result.functions.values()}, targets)
        self.assertEqual(extra["processes"], 1)

    def test_two_functions_of_one_name_are_two_declines(self):
        # Static functions of different compile units share a name; each is
        # its own decline, and the count still closes.
        os.environ["STUB_R2S_MODE"] = "refuse"
        result = self.decompile(functions=[("helper", TARGETS[0]), ("helper", TARGETS[1])])
        extra = result.decompiler.extra
        self.assertEqual((extra["requested"], extra["declined"]), (2, 2))
        self.assertEqual(extra["decline_causes"], {
            f"helper@0x{TARGETS[0]:x}": "refused: stub refuses",
            f"helper@0x{TARGETS[1]:x}": "refused: stub refuses",
        })
        self.assertEqual(result.decompiler.failed_functions, ["helper", "helper"])

    def test_a_malformed_answer_is_a_decline_not_a_lost_binary(self):
        os.environ["STUB_R2S_FAULTS"] = f"elsewhere@{TARGETS[1]:x}"
        result = self.decompile(function_names=set(TARGETS[:3]))
        causes = result.decompiler.extra["decline_causes"]
        self.assertEqual(list(causes), [f"0x{TARGETS[1]:x}"])
        self.assertIn("breaks its contract", causes[f"0x{TARGETS[1]:x}"])
        self.assertEqual(len(result.functions), 2)

    def test_a_refusal_is_declined_with_its_reason(self):
        os.environ["STUB_R2S_MODE"] = "refuse"
        result = self.decompile(function_names={TARGETS[0]})
        self.assertEqual(result.functions, {})
        self.assertEqual(result.decompiler.extra["decline_causes"],
                         {f"0x{TARGETS[0]:x}": "refused: stub refuses"})

    @unittest.skipUnless(shutil.which("gcc"), "needs gcc to build an unstripped binary")
    def test_a_binary_with_symbols_or_dwarf_is_refused_whole(self):
        # D5: the evaluated file's own DWARF must never reach a scored rendering.
        binary = Path(self.tmp.name) / "hashes"
        subprocess.run(["gcc", "-g", "-O1", str(REPO / "tests" / "corpus" / "hashes.c"),
                        "-o", str(binary)], check=True, capture_output=True)
        result = self.decompile(binary=binary, function_names=set(TARGETS[:2]))
        self.assertEqual(result.functions, {})
        causes = set(result.decompiler.extra["decline_causes"].values())
        self.assertEqual(len(causes), 1)
        cause = causes.pop()
        self.assertIn(".debug_info", cause)
        self.assertIn(".symtab", cause)
        leaked = result.decompiler.extra["fail_closed"]
        self.assertIn(".debug_info", leaked)
        self.assertIn(".symtab", leaked)

    @unittest.skipUnless(shutil.which("objcopy"), "needs objcopy to add a section")
    def test_debug_information_in_any_spelling_is_refused_whole(self):
        # Compressed DWARF and MiniDebugInfo carry the same facts as .debug_info.
        for section in (".zdebug_info", ".gnu_debugdata", ".debug_line"):
            binary = Path(self.tmp.name) / f"carries{section}"
            payload = Path(self.tmp.name) / "payload"
            payload.write_bytes(b"\0" * 16)
            subprocess.run(["objcopy", "--add-section", f"{section}={payload}", str(STRIPPED),
                            str(binary)], check=True, capture_output=True)
            result = self.decompile(binary=binary, function_names=set(TARGETS[:2]))
            self.assertEqual(result.functions, {}, section)
            self.assertEqual(result.decompiler.extra["fail_closed"], [section])

    def test_variables_and_lines_come_from_pddj(self):
        # D6: the structured answer, not a parse of the C.
        result = self.decompile(function_names={TARGETS[0]})
        function = next(iter(result.functions.values()))
        param, local = function.variables
        self.assertEqual((param.name, param.kind, param.arg_index), ("a0", "arg", 0))
        self.assertEqual((local.name, local.kind, local.stack_offset), ("i", "stack", -0x14))
        self.assertEqual(function.metadata["residual"], 0)

    def test_a_named_request_renames_the_definition(self):
        result = self.decompile(functions=[("usage", TARGETS[0])])
        self.assertEqual(list(result.functions), ["usage"])
        code = result.functions["usage"].decompiled_code
        self.assertIn("void usage(void)", code)
        self.assertNotIn("fcn_", code)

    def test_with_no_targets_it_renders_what_afl_finds(self):
        os.environ["STUB_R2S_AFL"] = "0x401150 main,0x401160 -,0x401170 _start"
        try:
            result = self.decompile()
        finally:
            os.environ.pop("STUB_R2S_AFL", None)
        self.assertEqual(sorted(f.address for f in result.functions.values()),
                         [0x401150, 0x401160])
        self.assertEqual(result.decompiler.extra["requested_from"], "afl")

    def test_only_the_native_backend_is_registered(self):
        if REGISTERED:
            self.assertEqual(REGISTERED, ["r2sleigh_native"])
        self.assertFalse(hasattr(r2sleigh_raw, "RawR2SleighDecompiler"))


class Helpers(unittest.TestCase):
    def test_stack_locations(self):
        self.assertEqual(r2sleigh_raw.stack_offset("stack-0x14"), -0x14)
        self.assertEqual(r2sleigh_raw.stack_offset("[rbp-20]"), -20)
        self.assertEqual(r2sleigh_raw.stack_offset("sp+8"), 8)
        self.assertIsNone(r2sleigh_raw.stack_offset("rdi"))

    def test_section_names_of_a_stripped_binary(self):
        names = r2sleigh_raw.elf_section_names(STRIPPED)
        self.assertIn(".text", names)
        self.assertEqual(r2sleigh_raw.leaked_sections(STRIPPED), [])


if __name__ == "__main__":
    unittest.main()
