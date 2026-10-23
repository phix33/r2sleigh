#!/usr/bin/env python3
"""Unit tests for the census's residual-site check on renderings the staged pipeline printed.

Pure Python; no binary runs.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import census  # noqa: E402

# RISC-V `shape_call_chain` before the frame-setup fact: two prologue adds counted, no site.
HIDDEN = """
    /* r2dec proof: no individual construct is marked; 142 source obligations: 92 rendered, 33 elided, 0 refused, 15 assumed (frame extent unproven), 2 residual; 39 statements rendered */
    {
        return (uint64_t)a0_3;
    }
"""

SITED = """
    /* r2dec proof: 2 constructs are marked below; 26 source obligations: 10 rendered, 12 elided, 0 refused, 4 residual; 6 statements rendered */
    {
        if (c) {
            return r2sleigh_residual_u64(1);
        }
        r2sleigh_residual_void(2); /* r2dec gap: TailTransferNotRendered at 0x401070 (render::control) */
    }
"""

UNACCOUNTED = """
    /* r2dec proof: no individual construct is marked; 10 source obligations: 8 rendered, 0 elided, 0 refused, 2 unaccounted; 3 statements rendered */
"""

# rv_O0g `sum_array`: ten private reads r2ssa seeds though nothing observes them, named.
PENDING = """
    /* r2dec proof: no individual construct is marked; 53 source obligations: 28 rendered, 15 elided, 0 refused, 10 residual (10 without a site: pending obligation seeding); 13 statements rendered */
"""

REFUSED = """/* r2sleigh refused sum_array: native effect obligations refused: 0 refused, 10 unaccounted (live-value-producer at 0x11e0:op:24), 0 conflicts */
"""


class ResidualSites(unittest.TestCase):
    def test_a_counted_residual_without_a_site_is_a_mismatch(self) -> None:
        self.assertEqual(census.site_mismatches(HIDDEN), ["2 residual, no site"])

    def test_each_site_in_the_text_is_counted(self) -> None:
        self.assertEqual(census.residual_sites(SITED), (2, 4, 0, 2))
        self.assertEqual(census.site_mismatches(SITED), [])

    def test_an_unaccounted_obligation_is_a_mismatch(self) -> None:
        self.assertEqual(census.site_mismatches(UNACCOUNTED), ["2 unaccounted"])

    def test_a_residual_without_a_site_under_a_named_cause_is_listed_not_failed(self) -> None:
        self.assertEqual(census.unsited(PENDING), {"pending obligation seeding": 10})
        self.assertEqual(census.site_mismatches(PENDING), [])
        unnamed = PENDING.replace("10 residual (10 without", "11 residual (10 without")
        self.assertEqual(census.site_mismatches(unnamed), ["1 residual, no site"])

    def test_a_refusal_has_no_proof_line_and_is_listed_with_its_kind(self) -> None:
        self.assertEqual(census.site_mismatches(REFUSED), [])
        found = census.REFUSED_UNACCOUNTED.search(REFUSED)
        self.assertEqual((found[1], found[2], found[3]), ("sum_array", "10", "live-value-producer at 0x11e0:op:24"))


class ExponentFit(unittest.TestCase):
    def test_a_power_law_fits_its_exponent(self):
        slope, r2 = census.fit([(n, 3 * n**2) for n in (300, 600, 1200, 5000)])
        self.assertAlmostEqual(slope, 2.0)
        self.assertAlmostEqual(r2, 1.0)

    def test_a_sample_spans_every_size(self):
        rows = [(address, address // 10) for address in range(3000, 13000, 10)]
        picked = census.evenly(rows, 5)
        self.assertEqual(len(picked), 5)
        self.assertEqual(min(n for _, n in picked), 300)
        self.assertEqual(max(n for _, n in picked), 1299)



class HeapSites(unittest.TestCase):
    def test_a_site_is_its_first_two_project_frames_past_the_allocator(self):
        profile = {
            "ftbl": ["[root]", "0x1: alloc (alloc/src/alloc.rs:95:9)",
                     "0x2: push (r2ssa/src/graph.rs:485:23)", "0x3: seal (src/function/stage.rs:199:25)",
                     "0x4: main (r2s/src/main.rs:47:29)"],
            "pps": [{"gb": 300, "fs": [1, 2, 3, 4]}, {"gb": 0, "fs": [1, 4]}, {"gb": 20, "fs": [1, 2, 3]}],
        }
        sites = census.heap_sites(profile)
        site = "push (r2ssa/src/graph.rs:485:23) <- seal (src/function/stage.rs:199:25)"
        self.assertEqual(sites, {site: 320})


# F1 of crates/r2engine/tests/engine/structure.rs under two write orders: the loop's merge `rax_2` has a gap for
# its entry copy, and one order reads it as a variable in the exit after the loop.
EXIT_INLINED = """
    /* r2dec proof: 3 constructs are marked below; 36 source obligations: 20 rendered, 8 elided, 0 refused, 8 residual; 11 statements rendered; 1 never assigned, read as residuals (RAX_2) */
    {
        r2sleigh_residual_void(1); /* r2dec gap: ValuesNotRendered at 0x1009 (render::values) */
        rdi_1 = arg0;
        for (; ; ) {
            if (c) {
                return (uint64_t)r2sleigh_residual_u64(2);
            } else {
                rax_2 = (uint64_t)((uint64_t)r2sleigh_residual_u64(3) + (uint64_t)1U);
                continue;
            }
        }
        L1:
        {
            return (uint64_t)((uint64_t)rax_2 + (uint64_t)5U);
        }
    }
"""
EXIT_AFTER = EXIT_INLINED.replace("r2sleigh_residual_u64(2)", "rax_2").replace("20 rendered", "22 rendered")


def record(code, **parts):
    base = {"refused": None, "code": code, "proof": {"total": 36, "residual": 8}, "variables": [], "links": [],
            "lines": [{"line": 5, "addrs": [4096]}],
            "residuals": [{"site": 1, "type": "void", "cause": "gap", "gap": "ValuesNotRendered", "callee": None,
                           "reason": None, "line": 5}]}
    return {**base, **parts}


class WriteOrders(unittest.TestCase):
    def test_the_names_read_as_never_assigned_come_from_the_proof_line(self) -> None:
        self.assertEqual(census.never_assigned(EXIT_INLINED), ["RAX_2"])
        self.assertEqual(census.never_assigned(HIDDEN), [])

    def test_statements_are_leaves_without_control_or_site_numbers(self) -> None:
        leaves = census.leaf_statements(EXIT_INLINED)
        self.assertIn("rdi_1 = arg0;", leaves)
        self.assertIn("rax_2 = (uint64_t)((uint64_t)r2sleigh_residual_u64(N) + (uint64_t)1U);", leaves)
        self.assertIn("r2sleigh_residual_void(N); /* r2dec gap: ValuesNotRendered at 0x1009 (render::values) */", leaves)
        self.assertFalse([leaf for leaf in leaves if leaf.startswith(("for", "if", "continue", "L1"))])
        self.assertEqual(census.leaf_statements("L17: ;\nL4:\n    x = 1;\n"), ["x = 1;"])

    def test_a_layout_that_moves_only_control_moves_no_verdict(self) -> None:
        moved = EXIT_INLINED.replace("continue;", "goto L0;").replace("L1:", "L1: L2:")
        self.assertEqual(census.verdict_moves(census.fingerprint(record(EXIT_INLINED)),
                                              census.fingerprint(record(moved))), ([], None))

    def test_a_read_that_turns_from_a_residual_into_a_variable_is_a_moved_verdict(self) -> None:
        moves, refusal = census.verdict_moves(census.fingerprint(record(EXIT_INLINED)),
                                              census.fingerprint(record(EXIT_AFTER)))
        self.assertEqual((moves, refusal), (["statements"], None))

    def test_the_ledger_and_the_residual_sites_are_verdicts(self) -> None:
        natural = census.fingerprint(record(EXIT_INLINED))
        columns = census.fingerprint(record(EXIT_INLINED, proof={"total": 36, "residual": 6}))
        sites = census.fingerprint(record(EXIT_INLINED, lines=[{"line": 5, "addrs": [4100]}]))
        self.assertEqual(census.verdict_moves(natural, columns), (["proof"], None))
        self.assertEqual(census.verdict_moves(natural, sites), (["sites"], None))

    def test_a_selection_the_structurer_chose_differently_is_no_move(self) -> None:
        arms = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = 1;\n        x_1 = 2;")
        selected = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = c ? 1 : 2;")
        natural, mutant = census.fingerprint(record(arms)), census.fingerprint(record(selected))
        self.assertEqual(census.verdict_moves(natural, mutant), ([], None))
        self.assertNotEqual(natural["statements"], mutant["statements"])

    def test_a_statement_that_is_no_selection_is_a_move(self) -> None:
        other = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = 1;\n        y_1 = 2;")
        lone = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = c ? 1 : 2;")
        moves = census.verdict_moves(census.fingerprint(record(other)), census.fingerprint(record(lone)))
        self.assertEqual(moves, (["statements"], None))
        # A target assigned on one side only is no selection either.
        gone = census.fingerprint(record(EXIT_INLINED.replace("rdi_1 = arg0;", "")))
        self.assertEqual(census.verdict_moves(census.fingerprint(record(EXIT_INLINED)), gone)[0], ["statements"])

    def test_a_function_refused_under_one_side_only_is_reported_with_the_side(self) -> None:
        refused = census.fingerprint(record(REFUSED, refused={"kind": "rendering", "reason": "control certificate"}))
        natural = census.fingerprint(record(EXIT_INLINED))
        self.assertEqual(census.verdict_moves(natural, refused), ([], "refused only under the mutant"))
        self.assertEqual(census.verdict_moves(refused, natural), ([], "refused only at natural"))
        # No answer (a crash) is no fingerprint, and two of them agree.
        self.assertEqual(census.verdict_moves(natural, None), ([], "refused only under the mutant"))
        self.assertEqual(census.verdict_moves(None, natural), ([], "refused only at natural"))
        self.assertEqual(census.verdict_moves(None, None), ([], None))

    def test_a_verdict_that_moves_inside_a_refusal_is_a_moved_verdict(self) -> None:
        # ls-toybox 0x5323c: refused the same way, with 214 residual obligations on one side and 216 on the other.
        reason = {"kind": "rendering", "reason": "native effect obligations refused: 0 refused, 1 unaccounted"}
        was = census.fingerprint(record(REFUSED, refused=reason, proof={"total": 1252, "residual": 214}))
        now = census.fingerprint(record(REFUSED, refused=reason, proof={"total": 1252, "residual": 216}))
        self.assertEqual(census.verdict_moves(was, now), (["proof"], None))
        again = census.fingerprint(record(REFUSED, refused=reason, proof={"total": 1252, "residual": 214}))
        self.assertEqual(census.verdict_moves(was, again), ([], None))
        elsewhere = census.fingerprint(record(REFUSED, refused={**reason, "reason": reason["reason"] + " at 0x53748"},
                                              proof={"total": 1252, "residual": 214}))
        self.assertEqual(census.verdict_moves(was, elsewhere), (["refusal"], None))


if __name__ == "__main__":
    unittest.main()
