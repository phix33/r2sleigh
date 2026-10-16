//! ARM states the instruction set per function, in the low bit of the symbol
//! that names it. The same SLA decodes both, so the mode is a processor
//! context and Thumb is the specification Ghidra ships with `TMode` set.
#![cfg(feature = "arm")]

fn decoded(name: &str, bytes: &[u8], at: u64) -> (u32, usize) {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let mut window = bytes.to_vec();
    window.resize(16, 0);
    let block = machine.disasm.lift(&window, at).expect("lift");
    (block.size, block.ops.len())
}

#[test]
fn thumb_reads_a_two_byte_push_where_arm_reads_four() {
    // push {r7, lr}; sub sp, 8   at 0x10548 of test/bins/elf/thumb-movpcadd
    let prologue = [0x80u8, 0xb5, 0x82, 0xb0];
    assert_eq!(decoded("arm-thumb", &prologue, 0x10548).0, 2);
    assert_eq!(decoded("arm", &prologue, 0x10548).0, 4);
}

#[test]
fn arm_and_thumb_are_the_same_instruction_set() {
    let arm = r2sleigh_lift::embedded_machine("arm").expect("arm machine");
    let thumb = r2sleigh_lift::embedded_machine("arm-thumb").expect("thumb machine");
    assert_eq!(arm.arch.name, thumb.arch.name);
}

/// The same move under `it eq` and under `it ne`: `cmp r0, #0; it <cond>; mov<cond> r0, #1`.
const EQ: [u8; 6] = [0x00, 0x28, 0x08, 0xbf, 0x01, 0x20];
const NE: [u8; 6] = [0x00, 0x28, 0x18, 0xbf, 0x01, 0x20];
const BASE: u64 = 0x1000;

fn window(code: &[u8], at: u64) -> Vec<u8> {
    let mut fetch = code[usize::try_from(at - BASE).expect("inside")..].to_vec();
    fetch.resize(16, 0);
    fetch
}

#[test]
fn a_decode_keeps_only_the_context_its_own_run_left() {
    use r2sleigh_lift::{Disassembler, TrustedSleighProfile};
    let profile = TrustedSleighProfile::ArmThumbLe;
    let ours = Disassembler::shared_profile_for_analysis(profile).expect("Thumb");
    let theirs = Disassembler::shared_profile_for_analysis(profile).expect("Thumb");
    assert!(ours.shares_loaded_specification(&theirs));
    let moved = BASE + 4;
    let spelled = |after| {
        ours.decode(&window(&EQ, moved), moved, after)
            .expect("decodes")
            .syntax
            .text()
    };
    let fresh = spelled(None);
    // The `it` of a run, and where it leaves the decoder for the move.
    let run = |disasm: &Disassembler, code: &[u8]| {
        [BASE, BASE + 2].into_iter().fold(None, |after, at| {
            let one = disasm.decode(&window(code, at), at, after);
            one.expect("decodes").continuation
        })
    };
    let own = spelled(run(&ours, &EQ));
    assert_ne!(own, fresh, "the `it` changed nothing");
    assert!(own.contains("eq"), "{own} runs under no `eq`");
    // Another run on the specification in between leaves its `it ne` there, which ours must not read.
    let after = run(&ours, &EQ);
    run(&theirs, &NE);
    assert_eq!(spelled(after), fresh, "continued under {own}");
}

/// Decode `code` at `base` as one run, each instruction continuing the last; the spelling of each.
fn spelled_run(
    profile: r2sleigh_lift::TrustedSleighProfile,
    code: &[u8],
    base: u64,
) -> Vec<String> {
    let disasm = r2sleigh_lift::Disassembler::shared_profile_for_analysis(profile).expect("ARM");
    let (mut at, mut after, mut spelled) = (base, None, Vec::new());
    while at < base + code.len() as u64 {
        let mut fetch = code[usize::try_from(at - base).expect("inside")..].to_vec();
        fetch.resize(16, 0);
        let one = disasm.decode(&fetch, at, after).expect("decodes");
        at += one.syntax.size as u64;
        after = one.continuation;
        spelled.push(one.syntax.text());
    }
    spelled
}

#[test]
fn a_backward_blx_leaves_the_thumb_run_in_thumb() {
    // special-sym-with-dot.bin 0x472: `blx sym.imp.printf` back into ARM, then `mov.w lr, 0; str r0, [sp, 4]`.
    let code = [0xff, 0xf7, 0xa6, 0xef, 0x4f, 0xf0, 0x00, 0x0e, 0x01, 0x90];
    let spelled = spelled_run(
        r2sleigh_lift::TrustedSleighProfile::ArmThumbLe,
        &code,
        0x472,
    );
    assert_eq!(spelled.len(), 3, "{spelled:?}");
    assert!(spelled[1].starts_with("mov.w lr"), "{spelled:?}");
    // The target's instruction set is the decode's statement about that address alone.
    let thumb = r2sleigh_lift::embedded_machine("arm-thumb").expect("Thumb");
    let mut fetch = code.to_vec();
    fetch.resize(16, 0);
    let blx = thumb.disasm.decode(&fetch, 0x472, None).expect("decodes");
    let target = r2sleigh_lift::TargetContext {
        address: 0x3c0,
        foreign: true,
    };
    assert_eq!(blx.targets, [target]);
    fetch.rotate_left(4);
    let mov = thumb.disasm.decode(&fetch, 0x476, None).expect("decodes");
    assert!(mov.targets.is_empty(), "{:?}", mov.targets);
}

#[test]
fn a_backward_blx_leaves_the_arm_run_in_arm() {
    // `blx 0x1000` from 0x2000 into Thumb, then `mov r0, r1`.
    let code = [0xfe, 0xfb, 0xff, 0xfa, 0x01, 0x00, 0xa0, 0xe1];
    let spelled = spelled_run(
        r2sleigh_lift::TrustedSleighProfile::ArmCortexLe,
        &code,
        0x2000,
    );
    assert_eq!(spelled.len(), 2, "{spelled:?}");
    assert_eq!(spelled[1], "mov r0, r1", "{spelled:?}");
}
