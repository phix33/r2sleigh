//! Every x86 compare-and-exchange lifts to what the Intel SDM states (Vol. 2A, CMPXCHG and
//! CMPXCHG8B/CMPXCHG16B), run through `r2il::eval`: the destination takes the source where it
//! equals the accumulator, which otherwise takes the destination; ZF says which (audit M13).
#![cfg(feature = "x86")]

mod x86_machine;

use r2il::R2ILOp;
use x86_machine::{CELL, HELD, Machine, low};

fn machine() -> Machine {
    Machine::x86_64()
}

#[test]
fn cmpxchg_with_memory_stores_the_source_where_it_matched_and_reads_the_cell_where_not() {
    let machine = machine();
    // `cmpxchg [rsi], rcx` and `cmpxchg [rsi], ecx`.
    for (bytes, accumulator, width) in [
        (&[0x48, 0x0f, 0xb1, 0x0e][..], "RAX", 8),
        (&[0x0f, 0xb1, 0x0e][..], "EAX", 4),
    ] {
        let source = 0x0bad_cafe_u128;
        let state = &mut machine.run(bytes, &[("RAX", low(width)), ("RCX", source)]);
        assert_eq!(machine.read(state, "ZF"), 1, "{accumulator} equal");
        assert_eq!(state.load(CELL, width), Ok(source), "{accumulator} equal");
        assert_eq!(machine.read(state, accumulator), low(width));

        let state = &mut machine.run(bytes, &[("RAX", 7), ("RCX", source)]);
        assert_eq!(machine.read(state, "ZF"), 0, "{accumulator} unequal");
        assert_eq!(
            state.load(CELL, width),
            Ok(low(width)),
            "{accumulator} unequal"
        );
        // A 32-bit write in 64-bit mode clears the register above it.
        assert_eq!(
            machine.read(state, "RAX"),
            low(width),
            "{accumulator} unequal"
        );
    }
}

#[test]
fn cmpxchg_with_a_register_writes_it_or_the_accumulator() {
    let machine = machine();
    // `cmpxchg rsi, rcx`: the destination register is RSI, which `run` sets to the cell.
    let bytes = [0x48, 0x0f, 0xb1, 0xce];
    let state = &mut machine.run(&bytes, &[("RAX", u128::from(CELL)), ("RCX", 9)]);
    assert_eq!(
        (machine.read(state, "ZF"), machine.read(state, "RSI")),
        (1, 9)
    );
    assert_eq!(machine.read(state, "RAX"), u128::from(CELL));
    let state = &mut machine.run(&bytes, &[("RAX", 3), ("RCX", 9)]);
    assert_eq!(
        (machine.read(state, "ZF"), machine.read(state, "RSI")),
        (0, u128::from(CELL))
    );
    assert_eq!(machine.read(state, "RAX"), u128::from(CELL));
}

#[test]
fn cmpxchg8b_and_16b_exchange_the_pair() {
    let machine = machine();
    // `cmpxchg8b [rsi]` compares EDX:EAX and stores ECX:EBX; `cmpxchg16b [rsi]` the 64-bit pairs.
    for (bytes, half, width) in [
        (&[0x0f, 0xc7, 0x0e][..], 4u32, 8u32),
        (&[0x48, 0x0f, 0xc7, 0x0e][..], 8, 16),
    ] {
        let mask = u128::MAX >> (128 - 8 * half);
        let (held_low, held_high) = (HELD & mask, (HELD >> (8 * half)) & mask);
        let (new_low, new_high) = (0x0123_4567 & mask, 0x89ab_cdef & mask);
        let state = &mut machine.run(
            bytes,
            &[
                ("RAX", held_low),
                ("RDX", held_high),
                ("RBX", new_low),
                ("RCX", new_high),
            ],
        );
        assert_eq!(machine.read(state, "ZF"), 1, "{width} equal");
        assert_eq!(
            state.load(CELL, width),
            Ok(new_low | (new_high << (8 * half))),
            "{width} equal"
        );

        let state = &mut machine.run(
            bytes,
            &[("RAX", 1), ("RDX", 2), ("RBX", new_low), ("RCX", new_high)],
        );
        assert_eq!(machine.read(state, "ZF"), 0, "{width} unequal");
        assert_eq!(state.load(CELL, width), Ok(low(width)), "{width} unequal");
        assert_eq!(
            (machine.read(state, "RAX"), machine.read(state, "RDX")),
            (held_low, held_high),
            "{width} unequal"
        );
    }
}

/// The locked forms lift alike, between the specification's `LOCK` and `UNLOCK`, with no refusal.
#[test]
fn a_locked_compare_and_exchange_lifts_with_its_store_guarded() {
    let machine = machine();
    for bytes in [
        &[0xf0, 0x48, 0x0f, 0xb1, 0x0e][..],
        &[0xf0, 0x48, 0x0f, 0xc7, 0x0e][..],
    ] {
        let ops = &machine.lift(bytes);
        assert!(
            ops.iter()
                .any(|op| matches!(op, R2ILOp::StoreGuarded { .. })),
            "{ops:?}"
        );
        assert!(
            !ops.iter().any(|op| matches!(op, R2ILOp::Store { .. })),
            "{ops:?}"
        );
    }
}
