#!/usr/bin/env python3
"""`r2s_timing.py` times r2s per binary of a run; the child process that does it is replaced by a stub."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import r2s_timing  # noqa: E402

TIMED = {"asked": 3, "rendered": 2, "declined": 1, "seconds": 1.5, "processes": 1, "maxrss_kb": 4096}


class Timing(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.run = Path(self.dir.name)
        decompiled = self.run / "O2" / "zlib" / "decompiled"
        decompiled.mkdir(parents=True)
        (self.run / "O2" / "zlib" / "stripped").mkdir()
        # The file is libz.so.1.2.13, the driver's name for it (and its tomls') is the stem libz.so.1.2.
        (self.run / "O2" / "zlib" / "stripped" / "libz.so.1.2.13").write_bytes(b"\x7fELF")
        (self.run / "O2" / "zlib" / "stripped" / "example").write_bytes(b"\x7fELF")
        for binary in ("libz.so.1.2", "example", "ghost"):
            (decompiled / f"r2sleigh_native_{binary}.toml").write_text('["functions.f"]\naddress = "0x1000"\n')

    def tearDown(self):
        self.dir.cleanup()

    def time(self):
        calls = []

        def child(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(TIMED) + "\n", stderr="")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(r2s_timing.subprocess, "run", child), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(r2s_timing.main(["--r2s", "r2s", "--run", str(self.run), "--opt", "O2"]), 0)
        rows = [line.split("\t") for line in out.getvalue().splitlines()[1:]]
        return calls, rows, err.getvalue()

    def test_a_binary_whose_file_has_a_version_suffix_is_timed(self):
        calls, rows, _ = self.time()
        asked = {Path(command[command.index("--one") + 1]).name for command in calls}
        self.assertEqual(asked, {"libz.so.1.2.13", "example"})
        self.assertIn(["zlib", "O2", "libz.so.1.2", "3", "2", "1", "1.5", "4096"], rows)

    def test_a_binary_with_no_stripped_file_is_a_counted_row_not_a_silent_omission(self):
        _, rows, summary = self.time()
        self.assertIn(["zlib", "O2", "ghost", "NO-STRIPPED-BINARY", "", "", "", ""], rows)
        self.assertEqual(len(rows), 3)
        self.assertIn("timed 2 binaries, 1 without a stripped binary, 0 failed", summary)


if __name__ == "__main__":
    unittest.main()
