//! Every x86 compare-and-exchange lifts to what the Intel SDM states (Vol. 2A, CMPXCHG and
//! CMPXCHG8B/CMPXCHG16B), run through `r2il::eval`: the destination takes the source where it
//! equals the accumulator, which otherwise takes the destination; ZF says which (audit M13).
#![cfg(feature = "x86")]

use r2il::eval::{Flow, State, step};
use r2il::{Endianness, R2ILOp};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

/// Where `[rsi]` points.
const CELL: u64 = 0x5000;
/// What the cell holds before every run, for the forms that compare with memory.
const HELD: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;

struct Machine {
    disassembler: Disassembler,
}

impl Machine {
    fn register(&self, name: &str) -> (u64, u32) {
        let register = self
            .disassembler
            .arch_spec()
            .registers
            .iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("x86-64 declares {name}"));
        (register.offset, register.size)
    }

    /// Runs `bytes` from `registers` with the cell holding [`HELD`]; the state it leaves.
    fn run(
        &self,
        bytes: &[u8],
        registers: &[(&str, u128)],
    ) -> State<impl r2il::eval::Mapped + use<>> {
        let mut padded = bytes.to_vec();
        padded.resize(16, 0);
        let lifted = self
            .disassembler
            .lift_genuine_block(&padded, 0x1000, bytes.len())
            .expect("lift");
        let ops = &lifted.block().ops;
        assert!(
            !ops.contains(&R2ILOp::Unimplemented),
            "{bytes:02x?}: {ops:?}"
        );
        let held = HELD.to_le_bytes();
        let memory = move |address: u64| {
            let at = usize::try_from(address.checked_sub(CELL)?).ok()?;
            held.get(at).copied()
        };
        let mut state = State::new(Endianness::Little, memory, 1 << 12).expect("state");
        for (name, value) in registers {
            let (offset, size) = self.register(name);
            state.set_register(offset, size, *value).expect(name);
        }
        let (rsi, _) = self.register("RSI");
        state.set_register(rsi, 8, u128::from(CELL)).expect("rsi");
        for op in ops {
            assert_eq!(step(op, &mut state), Flow::Next, "{bytes:02x?}: {op:?}");
        }
        state
    }

    fn read(&self, state: &State<impl r2il::eval::Mapped>, name: &str) -> u128 {
        let (offset, size) = self.register(name);
        state.register(offset, size).expect(name)
    }
}

fn machine() -> Machine {
    Machine {
        disassembler: Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
            .expect("trusted x86-64 specification"),
    }
}

fn low(bytes: u32) -> u128 {
    HELD & (u128::MAX >> (128 - 8 * bytes))
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
        let mut padded = bytes.to_vec();
        padded.resize(16, 0);
        let lifted = machine
            .disassembler
            .lift_genuine_block(&padded, 0x1000, bytes.len())
            .expect("lift");
        let ops = &lifted.block().ops;
        assert!(!ops.contains(&R2ILOp::Unimplemented), "{ops:?}");
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
