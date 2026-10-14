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

/// AArch64 `clrex`, with or without its ignored immediate, is the one clear of the monitor.
#[test]
fn an_aarch64_clrex_clears_the_monitor() {
    for word in [0xd503_3f5f, 0xd503_305f] {
        assert_eq!(aarch64(word), vec![R2ILOp::ClearExclusive], "{word:#x}");
    }
}

/// Each AArch64 store-exclusive is one conditional store at `[Xn]`, a pair's second under its
/// success, and the status its negation: no branch, user operation or unconditional store.
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

/// An instruction's accesses and orderings in program order: an exclusive's ordering is its own,
/// any other's is a fence on the side it orders (`vendor/README.md`).
fn ordered_accesses(word: u32) -> Vec<String> {
    aarch64(word)
        .iter()
        .filter_map(|op| match op {
            R2ILOp::Load { .. } => Some("load".to_string()),
            R2ILOp::Store { .. } => Some("store".to_string()),
            R2ILOp::StoreGuarded { ordering, .. } => Some(format!("guarded {ordering:?}")),
            R2ILOp::LoadLinked { ordering, .. } => Some(format!("linked {ordering:?}")),
            R2ILOp::StoreConditional { ordering, .. } => Some(format!("conditional {ordering:?}")),
            R2ILOp::Fence { ordering } => Some(format!("fence {ordering:?}")),
            R2ILOp::CallOther { .. } | R2ILOp::Unimplemented => Some("unmodelled".to_string()),
            _ => None,
        })
        .collect()
}

/// Each AArch64 acquire is stated after its access and each release before it (Arm ARM B2.3);
/// a relaxed form states neither, and only LDLAR's and STLLR's LORegion orderings stay unmodelled.
#[test]
fn every_aarch64_acquire_and_release_is_stated_on_the_side_it_orders() {
    for (name, word, expected) in [
        ("ldxr w8, [x0]", 0x885f_7c08, &["linked Relaxed"][..]),
        ("ldaxr x0, [x8]", 0xc85f_fd00, &["linked Acquire"]),
        ("ldaxr w0, [x8]", 0x885f_fd00, &["linked Acquire"]),
        ("ldaxrb w0, [x8]", 0x085f_fd00, &["linked Acquire"]),
        ("ldaxrh w0, [x8]", 0x485f_fd00, &["linked Acquire"]),
        (
            "ldxp x0, x1, [x8]",
            0xc87f_0500,
            &["linked Relaxed", "load"],
        ),
        // The pair's second load has no ordering of its own, so the fence after both stays.
        (
            "ldaxp x0, x1, [x8]",
            0xc87f_8500,
            &["linked Relaxed", "load", "fence Acquire"],
        ),
        ("stxr w10, w9, [x0]", 0x880a_7c09, &["conditional Relaxed"]),
        ("stlxr w10, x9, [x8]", 0xc80a_fd09, &["conditional Release"]),
        ("stlxrb w9, w1, [x8]", 0x0809_fd01, &["conditional Release"]),
        ("stlxrh w9, w1, [x8]", 0x4809_fd01, &["conditional Release"]),
        (
            "stxp w9, x0, x1, [x8]",
            0xc829_0500,
            &["conditional Relaxed", "guarded Relaxed"],
        ),
        (
            "stlxp w9, x0, x1, [x8]",
            0xc829_8500,
            &["conditional Release", "guarded Release"],
        ),
        ("ldar x0, [x8]", 0xc8df_fd00, &["load", "fence Acquire"]),
        ("ldarb w0, [x8]", 0x08df_fd00, &["load", "fence Acquire"]),
        ("stlr x0, [x8]", 0xc89f_fd00, &["fence Release", "store"]),
        ("stlrh w0, [x8]", 0x489f_fd00, &["fence Release", "store"]),
        ("ldapr x0, [x8]", 0xf8bf_c100, &["load", "fence Acquire"]),
        (
            "ldapurb w0, [x8, #3]",
            0x1940_3100,
            &["load", "fence Acquire"],
        ),
        (
            "stlur w0, [x8, #-4]",
            0x991f_c100,
            &["fence Release", "store"],
        ),
        // A limited-ordering acquire orders only within its LORegion, so no ordering is stated.
        ("ldlar x0, [x8]", 0xc8df_7d00, &["unmodelled", "load"]),
        ("stllr w0, [x8]", 0x889f_7d00, &["store", "unmodelled"]),
        ("ldadd w1, w0, [x8]", 0xb821_0100, &["load", "store"]),
        (
            "ldadda w1, w0, [x8]",
            0xb8a1_0100,
            &["load", "store", "fence Acquire"],
        ),
        (
            "ldaddl x1, x0, [x8]",
            0xf861_0100,
            &["fence Release", "load", "store"],
        ),
        (
            "ldaddal w1, w0, [x8]",
            0xb8e1_0100,
            &["fence Release", "load", "store", "fence Acquire"],
        ),
        (
            "staddl w1, [x8]",
            0xb861_011f,
            &["fence Release", "load", "store"],
        ),
        (
            "swpal x1, x0, [x8]",
            0xf8e1_8100,
            &["fence Release", "load", "store", "fence Acquire"],
        ),
        (
            "ldsmaxal w1, w0, [x8]",
            0xb8e1_4100,
            &["fence Release", "load", "store", "fence Acquire"],
        ),
        (
            "cas x0, x1, [x8]",
            0xc8a0_7d01,
            &["load", "guarded Relaxed"],
        ),
        (
            "casa w0, w1, [x8]",
            0x88e0_7d01,
            &["load", "guarded Relaxed", "fence Acquire"],
        ),
        (
            "casl w0, w1, [x8]",
            0x88a0_fd01,
            &["fence Release", "load", "guarded Relaxed"],
        ),
        (
            "casalb w0, w1, [x8]",
            0x08e0_fd01,
            &["fence Release", "load", "guarded Relaxed", "fence Acquire"],
        ),
        (
            "caspal x0, x1, x2, x3, [x8]",
            0x4860_fd02,
            &[
                "fence Release",
                "load",
                "load",
                "guarded Relaxed",
                "guarded Relaxed",
                "fence Acquire",
            ],
        ),
    ] {
        assert_eq!(ordered_accesses(word), expected, "{name}");
    }
}
