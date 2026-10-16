#!/usr/bin/env python3
"""Fails a change to a vendored Sleigh specification that brings no lift evidence (ROADMAP D35, D28).

A pull request that changes a `.sinc`, `.slaspec` or `.pspec` under `vendor/sleigh-config`
must also add or change a lift test: a CPU oracle's `cases.txt` or `expected.txt`, a Rust test
source directly under `crates/r2sleigh-lift/tests/`, or the lift's own test module
(`crates/r2sleigh-lift/src/**/tests.rs`). A deleted file is no evidence.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Collection

SPECIFICATION = re.compile(r"^vendor/sleigh-config/.*\.(sinc|slaspec|pspec)$")
EVIDENCE = re.compile(
    r"^crates/r2sleigh-lift/(tests/[^/]+\.rs|tests/[^/]+_oracle/(cases|expected)\.txt|src/(.+/)?tests\.rs)$"
)


def unevidenced(paths: list[str], deleted: Collection[str] = ()) -> list[str]:
    """The specification files changed without any lift test, other than a deleted one, beside them."""
    specifications = sorted(path for path in paths if SPECIFICATION.match(path))
    if any(EVIDENCE.match(path) and path not in deleted for path in paths):
        return []
    return specifications


def changed(base: str, head: str = "HEAD", only: str = "") -> list[str]:
    """Every path the change touches since it left `base` (of the `--diff-filter` kinds `only` names)."""
    out = subprocess.run(
        ["git", "diff", "--name-only", f"--diff-filter={only}", f"{base}...{head}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="the commit the change is graded against")
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args(argv)
    missing = unevidenced(changed(args.base, args.head), changed(args.base, args.head, "D"))
    if not missing:
        print("spec evidence: no vendored specification changed without a lift test")
        return 0
    print("A vendored Sleigh specification changed with no lift evidence (ROADMAP D35, D28):")
    for path in missing:
        print(f"  {path}")
    print("Add or change an oracle case or an r2il::eval test under crates/r2sleigh-lift/tests/")
    print("or in the lift's test module (crates/r2sleigh-lift/src/**/tests.rs).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
