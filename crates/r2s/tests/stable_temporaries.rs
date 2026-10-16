//! ROADMAP D36's gate: each instruction's raw temporaries shifted or reversed before the lift's
//! passes (`R2S_MOVE_TEMPORARIES`) change nothing `pdd`, `pdil` or `ao` print on a census function.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use libtest_mimic::{Arguments, Failed, Trial};

const MOVES: [&str; 2] = ["shift", "reverse"];

fn main() {
    let args = Arguments::from_args();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut trials = vec![Trial::test("an unknown move is refused", {
        let root = root.clone();
        move || unknown_move_is_refused(&root)
    })];
    for (binary, functions) in census(&root) {
        let name = format!("census::{binary}");
        let root = root.clone();
        trials.push(Trial::test(name, move || {
            unmoved(&root, &binary, &functions)
        }));
    }
    libtest_mimic::run(&args, trials).exit();
}

/// Each census binary with the functions its tests decompile, in file order.
fn census(root: &Path) -> BTreeMap<String, Vec<String>> {
    let mut functions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut files = std::fs::read_dir(root.join("tests/db/census"))
        .expect("the census")
        .map(|entry| entry.expect("a census file").path())
        .collect::<Vec<_>>();
    files.sort();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a census file");
        let mut binary = None;
        for line in text.lines() {
            if let Some(path) = line.strip_prefix("FILE=") {
                binary = Some(path.to_owned());
            }
            if let (Some(at), Some(binary)) = (line.strip_prefix("CMDS=aa; pdd @ "), &binary) {
                functions
                    .entry(binary.clone())
                    .or_default()
                    .push(at.to_owned());
            }
        }
    }
    functions
}

/// One script per binary: each function's C, its low IL and its first instructions' lifts.
fn unmoved(root: &Path, binary: &str, functions: &[String]) -> Result<(), Failed> {
    let mut script = String::from("aa");
    for at in functions {
        script.push_str(&format!(
            "; ?e == {at}; pdd @ {at}; pdil @ {at}; s {at}; ao 64"
        ));
    }
    let base = run(root, binary, &script, None)?;
    for how in MOVES {
        let moved = run(root, binary, &script, Some(how))?;
        if let Some((line, (want, got))) = base
            .lines()
            .zip(moved.lines())
            .enumerate()
            .find(|(_, (want, got))| want != got)
        {
            let function = base
                .lines()
                .take(line)
                .filter(|l| l.starts_with("== "))
                .last();
            return Err(
                format!("{how} moved line {line} of {function:?}:\n- {want}\n+ {got}").into(),
            );
        }
        if base.lines().count() != moved.lines().count() {
            return Err(format!("{how} moved the line count").into());
        }
    }
    Ok(())
}

fn run(root: &Path, binary: &str, script: &str, how: Option<&str>) -> Result<String, Failed> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_r2s"));
    command.current_dir(root).args(["-q", "-c", script, binary]);
    if let Some(how) = how {
        command.env("R2S_MOVE_TEMPORARIES", how);
    }
    let done = command.output().map_err(|error| error.to_string())?;
    if !done.status.success() {
        return Err(format!("{how:?}: {}", String::from_utf8_lossy(&done.stderr)).into());
    }
    Ok(String::from_utf8_lossy(&done.stdout).into_owned())
}

/// The gate cannot pass by ignoring its knob: a move the lift does not know stops it.
fn unknown_move_is_refused(root: &Path) -> Result<(), Failed> {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .current_dir(root)
        .args([
            "-q",
            "-c",
            "pdil @ 0x401330",
            "tests/coverage/pinned/hashes_gcc_x64_O2",
        ])
        .env("R2S_MOVE_TEMPORARIES", "sideways")
        .output()
        .map_err(|error| error.to_string())?;
    match done.status.success() {
        true => Err("an unknown move lifted".into()),
        false => Ok(()),
    }
}
