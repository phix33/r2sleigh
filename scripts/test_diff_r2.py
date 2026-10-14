#!/usr/bin/env python3
"""Unit tests for the differential's judged disagreements.

Pure Python; no binary runs.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import diff_r2  # noqa: E402

TABLE = """
[[judged]]
command = "pd"
binaries = "arm*"
r2 = 'push \\{'
r2s = 'stmdb sp!'
verdict = "r2-right"
reason = "alias"

[[judged]]
command = "iS"
binaries = "*"
values = ["0x70000001"]
verdict = "unfilled"
reason = "processor-specific type"

[[judged]]
command = "ie"
binaries = "*"
columns = ["vhaddr"]
verdict = "r2s-right"
reason = "a column radare2 leaves empty"

[[judged]]
command = "px"
binaries = "gone"
verdict = "r2s-right"
reason = "nothing matches this"
"""


def judgments():
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "judged.toml"
        path.write_text(TABLE)
        return diff_r2.load_judgments(path)


class Judged(unittest.TestCase):
    def test_a_listing_pair_is_judged_by_both_lines_and_the_binary(self):
        table = judgments()
        pair = ("lines", ("0x10 push {fp, lr}", "0x10 stmdb sp!, {fp, lr}"))
        self.assertIsNotNone(diff_r2.judgment_for(table, "arm1.bin", "pd 8", pair))
        self.assertIsNone(diff_r2.judgment_for(table, "x86.bin", "pd 8", pair))
        other = ("lines", ("0x10 push {fp, lr}", "0x10 push {fp, lr}, extra"))
        self.assertIsNone(diff_r2.judgment_for(table, "arm1.bin", "pd 8", other))

    def test_a_value_is_judged_only_by_its_listed_values(self):
        table = judgments()
        self.assertIsNotNone(diff_r2.judgment_for(table, "any", "iS", ("value", (0x70000001, "type", "1 0x70000001"))))
        self.assertIsNone(diff_r2.judgment_for(table, "any", "iS", ("value", (0x70000002, "type", "1 0x70000002"))))

    def test_a_column_judgment_covers_only_values_in_its_columns(self):
        table = judgments()
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "ie", ("value", (0x468, "vhaddr", "0x10 0x468"))))
        self.assertIsNone(diff_r2.judgment_for(table, "a", "ie", ("value", (0x468, "paddr", "0x468 0x10"))))

    def test_a_value_takes_the_column_its_header_names(self):
        lines = ["paddr      vaddr      phaddr     vhaddr     type", "0x10 0x1000 0x18 0x100018 program"]
        self.assertEqual(diff_r2.columns(lines)[0x100018][0][0], "vhaddr")
        self.assertEqual(diff_r2.columns(lines)[0x10][0][0], "paddr")

    def test_each_occurrence_of_a_value_is_its_own_disagreement(self):
        ours = "paddr vaddr phaddr vhaddr type\n0x10 0x1000 0x18 0x10 program\n"
        found = diff_r2.differences("ie", "values", ours, "0x1000 0x18\n")
        self.assertEqual([item[1][1] for item in found], ["paddr", "vhaddr"])

    def test_a_value_in_another_column_than_radare2s_is_a_disagreement(self):
        header = "paddr      vaddr      phaddr     vhaddr     type\n"
        theirs = header + "0x10 0x1000 0x18 0x100018 program\n"
        swapped = header + "0x10 0x1000 0x100018 0x18 program\n"
        found = diff_r2.differences("ie", "values", swapped, theirs)
        self.assertEqual([(item[1][0], item[1][1]) for item in found], [(0x18, "vhaddr"), (0x100018, "phaddr")])
        self.assertEqual(diff_r2.differences("ie", "values", theirs, theirs), [])

    def test_a_column_radare2_does_not_name_is_compared_with_every_value(self):
        ours = "paddr vaddr extra\n0x10 0x1000 0x18\n"
        self.assertEqual(diff_r2.differences("ie", "values", ours, "paddr vaddr\n0x18 0x1000\n0x10 0x0\n"), [])

    def test_values_only_radare2_reports_are_counted_by_column(self):
        header = "nth paddr vaddr bind type size lib name\n"
        theirs = header + "1 0x3b0 0x4011b0 NONE FUNC 0 imp.ExitProcess\n2 0x3b4 0x4011b4 NONE FUNC 0 imp.printf\n"
        ours = header + "1 0x3b0 0x4011b0 NONE FUNC 0 imp.ExitProcess\n"
        missed = diff_r2.radare2_only(diff_r2.normalise(ours), diff_r2.normalise(theirs))
        self.assertEqual(missed, [("paddr", 0x3B4), ("vaddr", 0x4011B4)])
        self.assertEqual(diff_r2.radare2_only(diff_r2.normalise(theirs), diff_r2.normalise(theirs)), [])

    def test_the_ratchet_names_each_count_that_moved(self):
        baseline = {"pe": {"is": 243, "refused": 10}, "elf": {"is": 4}}
        measured = {"pe": {"is": 240, "refused": 10}, "elf": {"is": 5}, "mach0": {"is": 1}}
        self.assertEqual(
            diff_r2.ratchet(baseline, measured),
            [("elf", "is", 4, 5), ("mach0", "is", None, 1), ("pe", "is", 243, 240)],
        )

    def test_a_fill_judgment_covers_only_radare2s_fill_past_what_r2s_shows(self):
        fill = '[[judged]]\ncommand = "px"\nbinaries = "*"\nfill = "ff"\nverdict = "r2s-right"\nreason = "fill"\n'
        table = diff_r2.load_judgments(None, tomllib.loads(fill))
        line = "0x08000050  0300 0058 c003 5fd6 ffff ffff ffff ffff  ...X.._........."
        prefix = "0x08000050  0300 0058 c003 5fd6                      ...X.._."
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (line, prefix))))
        filler = "0x08000060  ffff ffff ffff ffff ffff ffff ffff ffff  ................"
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (filler, None))))
        other = "0x08000050  0300 0058 c003 5fd7                      ...X.._."
        self.assertIsNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (line, other))))
        real = "0x08000050  0300 0058 c003 5fd6 0000 ffff ffff ffff  ...X.._........."
        self.assertIsNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (real, prefix))))
        self.assertIsNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (line, line.replace("0x0800", "0x0900")))))

    def test_a_value_judgment_can_require_radare2s_row_holding_the_value(self):
        table = diff_r2.load_judgments(None, tomllib.loads(
            '[[judged]]\ncommand = "is"\nbinaries = "*"\ncolumns = ["vaddr"]\nr2 = \'^\\d+ 0x0+8 0x\'\n'
            'r2s = \'^\\d+ -+ 0x0+8 \'\nverdict = "r2s-right"\nreason = "tls offset"\n'
        ))
        header = "nth paddr vaddr bind type size lib name\n"
        theirs = header + "1 0x00000008 0x00400008 LOOS TLS 8 tid\n"
        ours = header + "1 ---------- 0x00000008 10 NOTYPE 8 tid\n"
        (found,) = diff_r2.differences("is", "values", ours, theirs)
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "is", found))
        moved = theirs.replace("0x00000008 0x00400008", "0x00000010 0x00400008")
        (found,) = diff_r2.differences("is", "values", ours, moved)
        self.assertIsNone(diff_r2.judgment_for(table, "a", "is", found))

    def test_a_rounded_judgment_covers_only_radare2s_value_rounded_up_in_the_same_row(self):
        table = diff_r2.load_judgments(None, tomllib.loads(
            '[[judged]]\ncommand = "iS"\nbinaries = "*"\ncorpus = "pe"\ncolumns = ["vsize"]\nkey = "vaddr"\n'
            'verdict = "r2s-right"\nreason = "aligned"\n'
        ))
        header = "nth paddr size vaddr vsize perm flags type name\n"
        theirs = header + "0 0x400 0x1000 0x401000 0x1000 -r-x 0x60000020 ---- .text\n"
        (found,) = diff_r2.differences("iS", "values", header + "1 0x400 0x1000 0x401000 0xe2d -r-x 0x60000020 .text\n", theirs)
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "iS", found, "pe"))
        self.assertIsNone(diff_r2.judgment_for(table, "a", "iS", found, "elf"))
        elsewhere = header + "1 0x400 0x1000 0x402000 0xe2d -r-x 0x60000020 .text\n"
        (found,) = [item for item in diff_r2.differences("iS", "values", elsewhere, theirs) if item[1][1] == "vsize"]
        self.assertIsNone(diff_r2.judgment_for(table, "a", "iS", found, "pe"))
        self.assertTrue(diff_r2.rounded(0x174, 0x200))
        self.assertFalse(diff_r2.rounded(0x174, 0x300))
        self.assertFalse(diff_r2.rounded(0x1000, 0x1000))

    def test_a_listing_line_shows_its_bytes(self):
        self.assertEqual(diff_r2.dumped("pd", "0x412c9      ff             invalid"), ("0x412c9", "ff"))
        self.assertEqual(diff_r2.dumped("px", "0x10  6162 6364                                abcd"), ("0x10", "61626364"))

    def test_two_different_invalid_bytes_stay_different(self):
        def out(byte):
            script = "import sys; sys.stdout.buffer.write(bytes([{}]))".format(byte)
            return diff_r2.run([sys.executable, "-c", script], 10)[0]

        self.assertNotEqual(out(0xFF), out(0xFE))

    def test_a_judgment_nothing_matched_is_left_unmatched(self):
        table = judgments()
        diff_r2.judgment_for(table, "arm1.bin", "pd 8", ("lines", ("push {r4}", "stmdb sp!, {r4}")))
        self.assertEqual([j["reason"] for j in table if j["matched"] == 0][-1], "nothing matches this")

    def test_the_table_names_the_radare2_it_was_judged_against(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "judged.toml"
            path.write_text('radare2 = "6.2.4"\n' + TABLE)
            pinned, table = diff_r2.load_table(path)
        self.assertEqual(pinned, "6.2.4")
        self.assertEqual(len(table), 4)
        self.assertEqual(diff_r2.release("radare2 6.2.4 +38388 abi:152 @ linux-x86-64\n"), "6.2.4")
        self.assertIsNone(diff_r2.release(""))

    def test_an_unknown_verdict_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "judged.toml"
            path.write_text(TABLE.replace('"unfilled"', '"maybe"'))
            with self.assertRaises(ValueError):
                diff_r2.load_judgments(path)

    def test_every_listing_line_that_differs_is_one_disagreement(self):
        found = diff_r2.differences("pd 8", "exact", "0x1 nop\n0x2 ret\n", "0x1 nop\n0x2 leave\n0x3 ret\n")
        self.assertEqual(
            found, [("lines", ("0x2 leave", "0x2 ret")), ("lines", ("0x3 ret", None))]
        )


if __name__ == "__main__":
    unittest.main()
