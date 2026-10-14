#!/usr/bin/env python3
"""Differential harness: run the same commands through radare2 and r2s.

radare2 is the validation target for everything the engine reproduces natively,
so the cheapest way to grade discovery, mapping and decoding is to ask both
tools the same question and report where they disagree.

Two comparison modes, because the two tools do not yet fill the same columns:

  exact   normalised text must match line for line, with integer literals
          canonicalised because the two spell the same value differently.
          Used where r2s already claims radare2's layout, such as `px`, `pd`.
  values  compares the values each tool reports, column by column where both
          headers name the column. A value r2s reports and radare2 does not is
          a disagreement; a value radare2 reports and r2s does not is unfilled,
          counted per corpus and command and ratcheted (`diff_r2_baseline.json`):
          the count may fall, never rise. It is a floor, not a to-do list: it
          also counts values judged radare2's defect. Used for the listings.

Every disagreement is either judged in `diff_r2_judged.toml` (who is right,
and why) or fails the run; a judgment nothing matches any more is reported, so
the table cannot outlive what it judged (ROADMAP P11). The judgments were made
against one radare2 release, which the table names and the run refuses any other.

Usage:
  scripts/diff_r2.py                        # default corpus and commands
  scripts/diff_r2.py --bins DIR --limit 20
  scripts/diff_r2.py --bins ELF MACH0 PE --bless   # whole corpora; rewrite the baseline
  scripts/diff_r2.py --only pd --verbose
"""

import argparse
import concurrent.futures
import os
import fnmatch
import json
import pathlib
import re
import subprocess
import sys
import tomllib

VERDICTS = ("r2s-right", "r2-right", "unfilled", "deliberate")

# Command, comparison mode. The seek is issued to both so the cursor agrees.
COMMANDS = [
    ("px 64", "exact"),
    ("pd 8", "exact"),
    ("ie", "values"),
    ("iS", "values"),
    ("is", "values"),
]

HEX = re.compile(r"0x[0-9a-fA-F]+")
NOISE = re.compile(r"^\s*(WARN|ERROR|INFO):")
# radare2 annotates the listing from analysis the engine does not have yet.
ANNOTATION = re.compile(r"^\s*;")
# A trailing annotation on a disassembly line. Only applied to the listing,
# where a semicolon never belongs to the instruction itself.
TRAILING = re.compile(r"\s+;.*$")


def instruction(line):
    """One listing line from its address on, or nothing when it has none.

    radare2 draws the control flow in a gutter left of the address -- `,=<`
    for a jump, `:` for the column it passes through -- and a line that is
    only gutter carries no instruction at all. The drawing is analysis made
    visible, not disassembly, so it is dropped for the same reason the
    trailing annotations are.
    """
    start = line.find("0x")
    return line[start:] if start >= 0 else ""


def normalise(text, strip_trailing=False):
    lines = []
    for line in text.splitlines():
        if NOISE.match(line) or ANNOTATION.match(line):
            continue
        if strip_trailing:
            line = canonical_numbers(TRAILING.sub("", instruction(line)))
        line = line.rstrip()
        if line:
            lines.append(line)
    return lines


def values(lines):
    found = set()
    for line in lines:
        found.update(int(token, 16) for token in HEX.findall(line))
    return found


def header_of(lines):
    """The column names of a listing's header, or None when it prints none."""
    return next((line.split() for line in lines if "vaddr" in line.split()), None)


def columns(lines):
    """Each value with every (column, row) it appears at; the column is the header's name for it."""
    header = header_of(lines)
    found = {}
    for line in lines:
        for index, token in enumerate(line.split()):
            if not HEX.fullmatch(token):
                continue
            column = header[index] if header and index < len(header) else None
            found.setdefault(int(token, 16), []).append((column, line))
    return found


def by_column(lines):
    """Each column a header names, with the values printed in it."""
    found = {}
    for value, places in columns(lines).items():
        for column, _ in places:
            if column is not None:
                found.setdefault(column, set()).add(value)
    return found


def absent(value, column, named, everywhere):
    """Whether the other tool lacks this value: in the same column when it names one, else anywhere."""
    if column in named:
        return value not in named[column]
    return value not in everywhere


def cells(header, row):
    """A row's values by the column its header names."""
    found = {}
    for index, token in enumerate(row.split()):
        if header and index < len(header) and HEX.fullmatch(token):
            found.setdefault(header[index], int(token, 16))
    return found


class Listing:
    """radare2's rows of one values listing, found by a value they hold or by a column's value."""

    def __init__(self, lines):
        self.header, self.lines = header_of(lines), lines
        self.held, self.keys = None, {}

    def holding(self, value):
        if self.held is None:
            self.held = {}
            for found, places in columns(self.lines).items():
                self.held[found] = sorted({" ".join(row.split()) for _, row in places})
        return self.held.get(value, [])

    def keyed(self, column, value):
        if column not in self.keys:
            self.keys[column] = {}
            for line in self.lines:
                row = cells(self.header, line)
                if column in row:
                    self.keys[column].setdefault(row[column], []).append(row)
        return self.keys[column].get(value, [])


def rounded(value, other):
    """Whether `other` is `value` rounded up to a power-of-two alignment from 0x200 to 0x10000."""
    return other > value and any(other == -(-value // align) * align for align in (1 << n for n in range(9, 17)))


def radare2_only(left_lines, right_lines):
    """Each (column, value) radare2 reports and r2s does not: what r2s leaves unfilled."""
    ours, theirs = values(left_lines), columns(right_lines)
    named = by_column(left_lines) if header_of(left_lines) else {}
    return sorted(
        {
            (column or "", value)
            for value, places in theirs.items()
            for column, _ in places
            if absent(value, column, named, ours)
        }
    )


# `\b` never matches before a minus, so a negative decimal used to lose its
# sign: radare2's `[sp, -4]` normalised to `-0x4` while Sleigh's `[sp, -0x4]`
# normalised to the unsigned word, and the same displacement read as two.
NUMBER = re.compile(r"-?0x[0-9a-fA-F]+|(?<![0-9A-Za-z_])-?[0-9]+\b")


def canonical_numbers(line):
    """Rewrite every integer literal to unsigned 64-bit hex.

    radare2 prints `0xfffffffffffffff0` and a bare `8` where Sleigh prints
    `-0x10` and `0x8`. Both spell the same value, so a diff that reported them
    as a disagreement would bury the defects worth seeing.
    """

    def rewrite(match):
        token = match.group(0)
        try:
            value = int(token, 16) if "0x" in token.lower() else int(token, 10)
        except ValueError:
            return token
        return "0x{:x}".format(value & 0xFFFFFFFFFFFFFFFF)

    return NUMBER.sub(rewrite, line)


def run(argv, timeout):
    """Return (stdout, stderr, code); code is None when the tool never ran."""
    try:
        # A listing of a non-text byte is not UTF-8: each invalid byte keeps its value, so two
        # different ones still compare different.
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="surrogateescape",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "", "timeout", None
    except OSError as error:
        return "", str(error), None
    return done.stdout, done.stderr, done.returncode


def differences(command, mode, left, right):
    """Every disagreement of one command on one binary.

    A listing pairs its lines by position, each pair one disagreement, with
    `None` for a line one tool did not print; a values listing gives each
    value r2s reports and radare2 does not.
    """
    # Only the listing carries trailing annotations; a hex dump's ASCII column
    # can hold a semicolon that must not be mistaken for one.
    strip = command.startswith("pd")
    left_lines, right_lines = normalise(left, strip), normalise(right, strip)
    if mode == "values":
        theirs, ours = values(right_lines), columns(left_lines)
        named = by_column(right_lines) if header_of(right_lines) else {}
        # One disagreement per occurrence: a judgment of one column must not hide another, and a
        # value in a column both name is compared with that column alone, so a swap is seen.
        # A value inside a word (no column of its own) is compared with every value radare2 prints.
        inside = {value: [(None, "")] for value in values(left_lines) if value not in ours}
        listing, header = Listing(right_lines), header_of(left_lines)
        return [
            ("value", (value, column, " ".join(row.split()), {"ours": cells(header, row), "theirs": listing}))
            for value, places in sorted({**ours, **inside}.items())
            for column, row in places
            if absent(value, column, named, theirs)
        ]
    found = []
    for index in range(max(len(left_lines), len(right_lines))):
        ours = left_lines[index] if index < len(left_lines) else None
        theirs = right_lines[index] if index < len(right_lines) else None
        if ours != theirs:
            found.append(("lines", (theirs, ours)))
    return found


def load_table(path):
    """The radare2 release the table was judged against, and its judged disagreements."""
    if not path.exists():
        return None, []
    table = tomllib.loads(path.read_text())
    return table.get("radare2"), load_judgments(path, table)


def load_judgments(path, table=None):
    """The judged disagreements: each a class of them, with its verdict and reason."""
    if table is None:
        if not path.exists():
            return []
        table = tomllib.loads(path.read_text())
    judged = table["judged"]
    for judgment in judged:
        if judgment["verdict"] not in VERDICTS:
            raise ValueError("unknown verdict {!r}".format(judgment["verdict"]))
        judgment["values"] = {int(value, 16) for value in judgment.get("values", [])}
        judgment["columns"] = set(judgment.get("columns", []))
        judgment["matched"] = 0
    return judged


def release(banner):
    """The release `radare2 -v` names on its first line, or None."""
    words = banner.split()
    return words[1] if len(words) > 1 and words[0] == "radare2" else None


def dumped(verb, line):
    """The address and hex bytes a `px` or `pd` line shows, or None."""
    if line is None or not line.startswith("0x"):
        return None
    address, _, rest = line.partition(" ")
    if verb == "px":
        # Eight groups of four digits after two spaces; the ASCII column after them may look hex.
        return address, rest[1:40].replace(" ", "").lower()
    # radare2 marks a line that starts inside the previous instruction with `~`.
    words = [word for word in rest.split() if word != "~"]
    return (address, words[0].lower()) if words and re.fullmatch("[0-9a-fA-F]+", words[0]) else None


def filled(verb, theirs, ours, byte):
    """Whether radare2's line is r2s's (or nothing) followed only by `byte`: a fill past the mapping."""
    shown, prefix = dumped(verb, theirs), dumped(verb, ours) if ours is not None else None
    if shown is None or (ours is not None and (prefix is None or prefix[0] != shown[0])):
        return False
    head = prefix[1] if prefix else ""
    tail = shown[1][len(head) :]
    return shown[1].startswith(head) and tail != "" and tail == byte * (len(tail) // len(byte))


def aligned(key, column, value, context):
    """Whether radare2's row with r2s's `key` holds, in this column, r2s's value rounded up."""
    ours = context["ours"].get(key)
    return any(
        column in row and rounded(value, row[column]) for row in context["theirs"].keyed(key, ours)
    )


def judgment_for(judgments, binary, command, difference, corpus=None):
    """The first judgment that covers this disagreement, or None."""
    verb = command.split()[0]
    kind, detail = difference
    for judgment in judgments:
        patterns = judgment["binaries"]
        patterns = [patterns] if isinstance(patterns, str) else patterns
        verbs = judgment["command"]
        verbs = [verbs] if isinstance(verbs, str) else verbs
        if verb not in verbs or not any(fnmatch.fnmatchcase(binary, p) for p in patterns):
            continue
        if judgment.get("corpus", corpus) != corpus:
            continue
        if kind == "value":
            # No values listed covers every value of those binaries; columns listed cover only values
            # r2s prints in them; `r2s` matches r2s's row and `r2` a radare2 row holding the value.
            value, column, row, context = (detail + (None,))[:4]
            theirs = context["theirs"].holding(value) if context else []
            covered = (
                (not judgment["values"] or value in judgment["values"])
                and (not judgment["columns"] or column in judgment["columns"])
                and re.search(judgment.get("r2s", ""), row) is not None
                and ("r2" not in judgment or any(re.search(judgment["r2"], line) for line in theirs or ["<missing>"]))
                and ("key" not in judgment or (context is not None and aligned(judgment["key"], column, value, context)))
            )
        else:
            theirs, ours = detail
            covered = not judgment["values"] and all(
                re.search(judgment[side], line if line is not None else "<missing>")
                for side, line in (("r2", theirs), ("r2s", ours))
                if side in judgment
            )
            if "fill" in judgment:
                covered = covered and filled(verb, theirs, ours, judgment["fill"])
        if covered:
            judgment["matched"] += 1
            return judgment
    return None


def spelled(difference):
    """One disagreement as the report prints it, indented under its command."""
    kind, detail = difference
    if kind == "value":
        value, column, row = detail[:3]
        return "      {:#x}{}  {}".format(value, " ({})".format(column) if column else "", row)
    theirs, ours = detail
    return "      r2  {}\n      r2s {}".format(
        theirs if theirs is not None else "<missing>", ours if ours is not None else "<missing>"
    )


def answers(binary, commands, r2, r2s, timeout):
    """Both tools' output for each command on one binary, or r2s's refusal to open it."""
    # A refusal to open is a capability gap, not a disagreement about a
    # binary both tools read, so it is counted and reported separately.
    _, opened_error, opened_code = run([str(r2s), "-q", "-c", "i", str(binary)], timeout)
    if opened_code != 0:
        reason = opened_error.strip().splitlines()[-1] if opened_error.strip() else "failed"
        return reason.replace("r2s: ", ""), {}
    said = {}
    for command, _ in commands:
        # Every command seeks first, so a seek that timed out once times out each time.
        if None in said.values():
            said[command] = None
            continue
        script = "s entry0;{}".format(command)
        right, _, right_code = run(
            [str(r2), "-N", "-q", "-e", "scr.color=0", "-c", script, str(binary)], timeout
        )
        left, _, left_code = run([str(r2s), "-q", "-c", script, str(binary)], timeout)
        said[command] = None if right_code is None or left_code is None else (left, right)
    return None, said


def compare(name, command, mode, left, right, judgments, corpus=None):
    """Every disagreement, those no judgment covers, and the values only radare2 reports."""
    found = differences(command, mode, left, right)
    unjudged = [item for item in found if judgment_for(judgments, name, command, item, corpus) is None]
    missed = radare2_only(normalise(left), normalise(right)) if mode == "values" else []
    return found, unjudged, missed


def grade(corpus, binaries, commands, r2, r2s, judgments, args):
    """One corpus: per command, binaries agreeing, judged, unjudged, and radare2-only values."""
    tally = {command: {"agree": 0, "judged": 0, "unjudged": 0, "r2-only": 0} for command, _ in commands}
    unsupported, skipped = {}, []
    # The tools run in parallel; judging stays in name order, so the report and the matches do not move.
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        ran = pool.map(lambda binary: answers(binary, commands, r2, r2s, args.timeout), binaries)
        for binary, (refused, said) in zip(binaries, ran):
            if refused is not None:
                unsupported[refused] = unsupported.get(refused, 0) + 1
                continue
            reported = False
            for command, mode in commands:
                if said[command] is None:
                    skipped.append("{} {}".format(binary.name, command))
                    continue
                left, right = said[command]
                # A binary neither tool has anything to say about is not a difference.
                if not normalise(right) and not normalise(left):
                    continue

                found, unjudged, missed = compare(binary.name, command, mode, left, right, judgments, corpus)
                tally[command]["r2-only"] += len(missed)
                if not found:
                    tally[command]["agree"] += 1
                elif not unjudged:
                    tally[command]["judged"] += 1
                else:
                    tally[command]["unjudged"] += 1
                if not unjudged and not (missed and args.verbose):
                    continue
                if not reported:
                    print(binary.name)
                    reported = True
                if unjudged:
                    print("    {} differs: {} unjudged of {}".format(command, len(unjudged), len(found)))
                    for difference in unjudged if args.verbose else unjudged[:1]:
                        print(spelled(difference))
                if missed and args.verbose:
                    print("    {} radare2 only: {}".format(command, len(missed)))
                    shown = ["{}={:#x}".format(c, v) if c else "{:#x}".format(v) for c, v in missed[:8]]
                    print("      " + " ".join(shown + (["..."] if len(missed) > 8 else [])))
    return tally, unsupported, skipped


def ratchet(baseline, measured):
    """Each (corpus, count, before, now) that moved: radare2-only values per command, refusals."""
    moved = []
    for corpus, counts in sorted(measured.items()):
        for command, count in sorted(counts.items()):
            before = baseline.get(corpus, {}).get(command)
            if before != count:
                moved.append((corpus, command, before, count))
    return moved


def main():
    # A line holding an invalid byte prints as its escape.
    sys.stdout.reconfigure(errors="backslashreplace")
    here = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--r2", default=str(here.parent / "radare2/binr/radare2/radare2"))
    parser.add_argument("--r2s", default=str(here / "target/debug/r2s"))
    parser.add_argument(
        "--bins",
        nargs="+",
        default=[str(here.parent / "radare2/test/bins/elf")],
        help="corpus directories, each graded and ratcheted by its name",
    )
    parser.add_argument("--limit", type=int, help="the first N binaries of each corpus; no ratchet")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--jobs", type=int, default=os.cpu_count(), help="binaries run at once")
    parser.add_argument("--only", help="run just the commands whose verb matches this")
    parser.add_argument("--verbose", action="store_true", help="show each unjudged disagreement")
    parser.add_argument(
        "--judged",
        default=str(here / "scripts/diff_r2_judged.toml"),
        help="the judged disagreements",
    )
    parser.add_argument(
        "--baseline",
        default=str(here / "scripts/diff_r2_baseline.json"),
        help="radare2-only values per corpus and command, which may not rise",
    )
    parser.add_argument("--bless", action="store_true", help="write this run's counts as the baseline")
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="measure whatever binary is already there",
    )
    args = parser.parse_args()
    if args.bless and args.limit is not None:
        print("--bless needs whole corpora: drop --limit", file=sys.stderr)
        return 2

    # Build before measuring. The default binary is the debug one, which a
    # plain `cargo build --release` does not touch, so a run taken after one
    # reported the tree as it was several changes ago.
    if not args.no_build and args.r2s == str(here / "target/debug/r2s"):
        subprocess.run(
            ["cargo", "build", "-p", "r2s", "--features", "sleigh"],
            cwd=here,
            check=True,
        )

    r2, r2s = pathlib.Path(args.r2), pathlib.Path(args.r2s)
    for tool in (r2, r2s):
        if not tool.exists():
            print("missing {}".format(tool), file=sys.stderr)
            return 2

    commands = [
        (command, mode)
        for command, mode in COMMANDS
        if not args.only or command.split()[0] == args.only
    ]
    if not commands:
        print("no command matches --only {}".format(args.only), file=sys.stderr)
        return 2

    corpora = {}
    for directory in map(pathlib.Path, args.bins):
        binaries = sorted(p for p in directory.iterdir() if p.is_file())[: args.limit]
        if not binaries:
            print("no binaries under {}".format(directory), file=sys.stderr)
            return 2
        corpora[directory.name] = binaries

    pinned, judgments = load_table(pathlib.Path(args.judged))
    banner, _, _ = run([str(r2), "-v"], args.timeout)
    if pinned and release(banner) != pinned:
        print(
            "{} is radare2 {}; the judgments are against {} (build its tag, or CI's .deb)".format(
                r2, release(banner), pinned
            ),
            file=sys.stderr,
        )
        return 2

    unjudged, measured = 0, {}
    for corpus, binaries in corpora.items():
        print("== {} ({} binaries)".format(corpus, len(binaries)))
        tally, unsupported, skipped = grade(corpus, binaries, commands, r2, r2s, judgments, args)
        print("\n{:<8} {:>8} {:>8} {:>8} {:>8}".format("command", "agree", "judged", "unjudged", "r2-only"))
        print("-" * 44)
        for command, _ in commands:
            row = tally[command]
            print(
                "{:<8} {:>8} {:>8} {:>8} {:>8}".format(
                    command, row["agree"], row["judged"], row["unjudged"], row["r2-only"]
                )
            )
            unjudged += row["unjudged"]
        # A binary r2s stops opening, or a run that times out, hides its values: both are ratcheted.
        measured[corpus] = {
            command.split()[0]: tally[command]["r2-only"] for command, mode in commands if mode == "values"
        }
        measured[corpus]["refused"] = sum(unsupported.values())
        measured[corpus]["skipped"] = len(skipped)
        if skipped:
            print("\n{} runs skipped (timeout or launch failure): {}".format(len(skipped), ", ".join(skipped)))
        if unsupported:
            print("\nnot opened by r2s:")
            for reason, count in sorted(unsupported.items(), key=lambda item: -item[1]):
                print("  {:>4}  {}".format(count, reason))
        print()

    stale = [judgment for judgment in judgments if judgment["matched"] == 0]
    if stale:
        print("judgments nothing matched (stale, or outside these corpora):")
        for judgment in stale:
            print("  {} {}: {}".format(judgment["command"], judgment["binaries"], judgment["reason"]))
        print()

    # A partial corpus says nothing about the whole one's count.
    risen = []
    if args.limit is None:
        path = pathlib.Path(args.baseline)
        baseline = json.loads(path.read_text()) if path.exists() else {}
        if args.bless:
            for corpus, counts in measured.items():
                baseline.setdefault(corpus, {}).update(counts)
            path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")
            print("blessed {}".format(path))
        else:
            for corpus, command, before, now in ratchet(baseline, measured):
                if before is None:
                    risen.append((corpus, command))
                    print("{} {}: {} with no baseline; --bless to start one".format(corpus, command, now))
                elif now > before:
                    risen.append((corpus, command))
                    # Opening a refused binary adds its misses: that rise is blessed with the fall.
                    refused = baseline.get(corpus, {}).get("refused"), measured[corpus]["refused"]
                    print("{} {}: {} rose to {} (refused {} to {})".format(corpus, command, before, now, *refused))
                else:
                    print("{} {}: {} fell to {}; --bless to keep it".format(corpus, command, before, now))
    return 1 if unjudged or risen else 0


if __name__ == "__main__":
    sys.exit(main())
