//! One x86-64 instruction lifted by the trusted specification and run through `r2il::eval`,
//! with `[rsi]` pointing at a cell that holds [`HELD`]; each test target uses part of it.
#![allow(dead_code)]

use r2il::eval::{Flow, Mapped, State, step};
use r2il::{Endianness, R2ILOp};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

/// Where `[rsi]` points.
pub const CELL: u64 = 0x5000;
/// What the cell holds before every run.
pub const HELD: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;

pub struct Machine {
    pub disassembler: Disassembler,
}

impl Machine {
    pub fn x86_64() -> Self {
        Self {
            disassembler: Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
                .expect("trusted x86-64 specification"),
        }
    }

    pub fn register(&self, name: &str) -> (u64, u32) {
        let register = self
            .disassembler
            .arch_spec()
            .registers
            .iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("x86-64 declares {name}"));
        (register.offset, register.size)
    }

    /// The operations `bytes`, one instruction, lift to; none `Unimplemented`.
    pub fn lift(&self, bytes: &[u8]) -> Vec<R2ILOp> {
        let mut padded = bytes.to_vec();
        padded.resize(16, 0);
        let lifted = self
            .disassembler
            .lift_genuine_block(&padded, 0x1000, bytes.len())
            .expect("lift");
        let ops = lifted.block().ops.clone();
        assert!(
            !ops.contains(&R2ILOp::Unimplemented),
            "{bytes:02x?}: {ops:?}"
        );
        ops
    }

    /// Runs `bytes` from `registers`, RSI at [`CELL`]; the state it leaves.
    pub fn run(&self, bytes: &[u8], registers: &[(&str, u128)]) -> State<impl Mapped + use<>> {
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
        for op in &self.lift(bytes) {
            assert_eq!(step(op, &mut state), Flow::Next, "{bytes:02x?}: {op:?}");
        }
        state
    }

    pub fn read(&self, state: &State<impl Mapped>, name: &str) -> u128 {
        let (offset, size) = self.register(name);
        state.register(offset, size).expect(name)
    }
}

/// The cell's low `bytes` bytes.
pub fn low(bytes: u32) -> u128 {
    HELD & (u128::MAX >> (128 - 8 * bytes))
}
