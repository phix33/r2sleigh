#!/usr/bin/env python3
"""Unit tests for the gate that a vendored specification change carries lift evidence.

Pure Python and a scratch git repository; no binary runs.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import spec_evidence  # noqa: E402

SINC = "vendor/sleigh-config/ghidra/Ghidra/Processors/x86/data/languages/ia.sinc"
PSPEC = "vendor/sleigh-config/ghidra/Ghidra/Processors/x86/data/languages/x86-64.pspec"
SLASPEC = "vendor/sleigh-config/ghidra/Ghidra/Processors/ARM/data/languages/ARM8_le.slaspec"
CASES = "crates/r2sleigh-lift/tests/x86_64_oracle/cases.txt"


class Unevidenced(unittest.TestCase):
    def test_a_specification_change_alone_fails(self) -> None:
        self.assertEqual(spec_evidence.unevidenced([SINC]), [SINC])
        self.assertEqual(spec_evidence.unevidenced([PSPEC, "ROADMAP.md"]), [PSPEC])
        self.assertEqual(spec_evidence.unevidenced([SLASPEC]), [SLASPEC])

    def test_every_unevidenced_file_is_named_in_order(self) -> None:
        self.assertEqual(spec_evidence.unevidenced([SINC, PSPEC]), sorted([SINC, PSPEC]))

    def test_an_oracle_case_or_lift_test_beside_it_passes(self) -> None:
        self.assertEqual(spec_evidence.unevidenced([SINC, CASES]), [])
        self.assertEqual(
            spec_evidence.unevidenced([PSPEC, "crates/r2sleigh-lift/tests/cmpxchg.rs"]), []
        )
        self.assertEqual(
            spec_evidence.unevidenced([SINC, "crates/r2sleigh-lift/src/disasm/tests.rs"]), []
        )

    def test_a_test_elsewhere_is_not_lift_evidence(self) -> None:
        self.assertEqual(spec_evidence.unevidenced([SINC, "crates/r2il/tests/eval.rs"]), [SINC])
        self.assertEqual(
            spec_evidence.unevidenced([SINC, "crates/r2sleigh-lift/src/disasm/mod.rs"]), [SINC]
        )
        self.assertEqual(
            spec_evidence.unevidenced([SINC, "crates/r2sleigh-lift/src/contests.rs"]), [SINC]
        )

    def test_files_that_are_not_specifications_need_nothing(self) -> None:
        self.assertEqual(spec_evidence.unevidenced([]), [])
        self.assertEqual(
            spec_evidence.unevidenced(
                ["vendor/sleigh-config/README.md", "vendor/sleigh-config/x86.cspec", "ia.sinc"]
            ),
            [],
        )


class AgainstGit(unittest.TestCase):
    """The gate reads the paths `git diff base...HEAD` names, so only the branch's own commits count."""

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", self.root, *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def write(self, path: str, text: str) -> None:
        file = pathlib.Path(self.root, path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        self.git("add", path)

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = self.scratch.name
        self.git("init", "-q", "-b", "base")
        self.git("config", "user.email", "oracle@example.invalid")
        self.git("config", "user.name", "oracle")
        self.write(SINC, "old\n")
        self.git("commit", "-q", "-m", "base")
        self.git("checkout", "-q", "-b", "change")

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def gate(self) -> int:
        cwd = pathlib.Path.cwd()
        try:
            os.chdir(self.root)
            return spec_evidence.main(["--base", "base"])
        finally:
            os.chdir(cwd)

    def test_a_branch_changing_a_sinc_alone_fails(self) -> None:
        self.write(SINC, "new\n")
        self.git("commit", "-q", "-m", "spec")
        self.assertEqual(self.gate(), 1)

    def test_a_branch_adding_a_case_passes(self) -> None:
        self.write(SINC, "new\n")
        self.write(CASES, "lodsd|P|lodsd\n")
        self.git("commit", "-q", "-m", "spec and case")
        self.assertEqual(self.gate(), 0)

    def test_a_case_on_the_base_after_the_fork_is_not_the_branchs_evidence(self) -> None:
        self.write(SINC, "new\n")
        self.git("commit", "-q", "-m", "spec")
        self.git("checkout", "-q", "base")
        self.write(CASES, "lodsd|P|lodsd\n")
        self.git("commit", "-q", "-m", "a case landed on the base")
        self.git("checkout", "-q", "change")
        self.assertEqual(self.gate(), 1)


if __name__ == "__main__":
    unittest.main()
