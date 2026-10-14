//! ARM's exclusive-access pair, lifted to the operations it performs.

#![cfg(all(feature = "arm", feature = "sleigh-config"))]

use r2il::R2ILOp;

/// `ldrex r2, [r1, 0]` then `adds r2, 1` then `strex r3, r2, [r1, 0]`, which
/// is what an atomic increment compiles to on ARM.
const EXCLUSIVE_INCREMENT: &[u8] = &[
    0x51, 0xe8, 0x00, 0x2f, // ldrex r2, [r1, 0]
    0x01, 0x32, // adds r2, 1
    0x41, 0xe8, 0x00, 0x23, // strex r3, r2, [r1, 0]
];

#[test]
fn an_exclusive_pair_lifts_to_a_linked_load_and_a_conditional_store() {
    // Sleigh writes each half as a user operation with no semantics beside
    // the ordinary load or store it guards, and the store is skipped by a
    // branch inside the instruction. Left alone the branch became
    // `Unimplemented` and the whole function refused.
    let machine = r2sleigh_lift::embedded_machine("thumb").expect("thumb machine");
    let ops = |at: u64, len: usize| {
        let mut bytes = EXCLUSIVE_INCREMENT[at as usize..].to_vec();
        bytes.resize(16, 0);
        let block = machine
            .disasm
            .lift(&bytes, 0x1000 + at)
            .expect("the instruction lifts");
        assert_eq!(block.size as usize, len, "{:?}", block.ops);
        block.ops
    };

    let linked = ops(0, 4);
    assert!(
        linked
            .iter()
            .any(|op| matches!(op, R2ILOp::LoadLinked { .. })),
        "{linked:?}"
    );
    assert!(
        !linked
            .iter()
            .any(|op| matches!(op, R2ILOp::CallOther { .. } | R2ILOp::Load { .. })),
        "the marking and the load are one operation: {linked:?}"
    );

    let conditional = ops(6, 4);
    assert!(
        conditional
            .iter()
            .any(|op| matches!(op, R2ILOp::StoreConditional { .. })),
        "{conditional:?}"
    );
    assert!(
        !conditional
            .iter()
            .any(|op| matches!(op, R2ILOp::Unimplemented | R2ILOp::Store { .. })),
        "the store happens only where the monitor held: {conditional:?}"
    );
}

/// The lift of one AArch64 instruction word.
fn aarch64(word: u32) -> Vec<R2ILOp> {
    let disassembler = r2sleigh_lift::Disassembler::from_trusted_profile(
        r2sleigh_lift::TrustedSleighProfile::Aarch64Le,
    )
    .expect("trusted AArch64 specification");
    let mut bytes = word.to_le_bytes().to_vec();
    bytes.resize(16, 0);
    disassembler
        .lift_genuine_block(&bytes, 0x1000, 4)
        .expect("the instruction lifts")
        .block()
        .ops
        .clone()
}

/// Each AArch64 load-exclusive is one linked load of its access width at `[Xn]`, the monitor
/// mark folded in; a pair's second register is a plain load beside it.
#[test]
fn an_aarch64_load_exclusive_is_one_linked_load() {
    for (name, word, width, plain) in [
        ("ldxr w8, [x0]", 0x885f_7c08, 4, 0),
        ("ldaxr x0, [x8]", 0xc85f_fd00, 8, 0),
        ("ldxrb w0, [x8]", 0x085f_7d00, 1, 0),
        ("ldxp x0, x1, [x8]", 0xc87f_0500, 8, 1),
    ] {
        let ops = aarch64(word);
        let linked: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                R2ILOp::LoadLinked { dst, addr, .. } => Some((dst.size, addr.space)),
                _ => None,
            })
            .collect();
        assert_eq!(
            linked,
            vec![(width, r2il::SpaceId::Register)],
            "{name}: {ops:?}"
        );
        let loads = ops
            .iter()
            .filter(|op| matches!(op, R2ILOp::Load { .. }))
            .count();
        assert_eq!(loads, plain, "{name}: {ops:?}");
        assert!(
            !ops.iter()
                .any(|op| matches!(op, R2ILOp::CallOther { .. } | R2ILOp::Unimplemented)),
            "{name}: {ops:?}"
        );
    }
}

/// Each AArch64 store-exclusive is one conditional store of its access width at `[Xn]`, a pair's
/// second register stored under its success, and the status register the negation of that
/// success: no branch, no user operation, no store that happens either way.
#[test]
fn an_aarch64_store_exclusive_is_one_conditional_store() {
    for (name, word, width, guarded) in [
        ("stxr w10, w9, [x0]", 0x880a_7c09, 4, 0),
        ("stlxr w10, x9, [x8]", 0xc80a_fd09, 8, 0),
        ("stxrb w9, w1, [x8]", 0x0809_7d01, 1, 0),
        ("stxp w9, x0, x1, [x8]", 0xc829_0500, 8, 1),
    ] {
        let ops = aarch64(word);
        let conditional: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                R2ILOp::StoreConditional {
                    result: Some(ok),
                    val,
                    addr,
                    ..
                } => Some((ok.clone(), val.size, addr.space)),
                _ => None,
            })
            .collect();
        let [(ok, size, space)] = conditional.as_slice() else {
            panic!("{name}: one conditional store with a result: {ops:?}");
        };
        assert_eq!(
            (*size, *space),
            (width, r2il::SpaceId::Register),
            "{name}: {ops:?}"
        );
        let under_success = ops
            .iter()
            .filter(|op| matches!(op, R2ILOp::StoreGuarded { guard, .. } if guard == ok))
            .count();
        assert_eq!(under_success, guarded, "{name}: {ops:?}");
        assert!(
            ops.iter()
                .any(|op| matches!(op, R2ILOp::BoolNot { src, .. } if src == ok)),
            "{name}: the status is the negated success: {ops:?}"
        );
        assert!(
            !ops.iter().any(|op| matches!(
                op,
                R2ILOp::Store { .. }
                    | R2ILOp::CallOther { .. }
                    | R2ILOp::CBranch { .. }
                    | R2ILOp::Unimplemented
            )),
            "{name}: {ops:?}"
        );
    }
}
