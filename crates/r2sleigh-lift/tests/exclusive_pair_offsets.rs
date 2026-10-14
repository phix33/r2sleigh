//! A 64-bit AArch64 store-exclusive pair writes Rt2 at [Xn + 8] (Arm ARM: `el1:el2`, one 16-byte
//! access); eval does not run the exclusive monitor, so the store offsets are read off the lift.
#![cfg(feature = "arm")]

use r2il::{R2ILOp, Varnode};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

/// `stlxp w0, x1, x2, [x3]` and `stxp w0, x1, x2, [x3]`.
const PAIRS: [(&str, u32); 2] = [("stlxp", 0xc820_8861), ("stxp", 0xc820_0861)];

/// The constant each store adds to its address, in program order.
fn store_offsets(word: u32) -> Vec<u64> {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted arm64 specification");
    let mut bytes = word.to_le_bytes().to_vec();
    bytes.resize(16, 0);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, 4)
        .expect("lift");
    let ops = &lifted.block().ops;
    let added = |address: &Varnode| {
        ops.iter().find_map(|op| match op {
            R2ILOp::IntAdd { dst, b, .. } if dst == address => b.const_value(),
            _ => None,
        })
    };
    ops.iter()
        .filter_map(|op| match op {
            R2ILOp::Store { addr, .. } => Some(added(addr).unwrap_or(0)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_store_exclusive_pair_writes_its_second_register_eight_bytes_up() {
    for (name, word) in PAIRS {
        assert_eq!(store_offsets(word), vec![0, 8], "{name}");
    }
}
