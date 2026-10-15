//! AArch64's LSE and `cas` (Arm ARM `MemAtomic`) and x86's locked operations as one typed `Atomic`,
//! or `IndivisibleAccess` beside accesses that are not one cell's fetch or compare-and-exchange.

use r2il::{AtomicFetchOp as Op, AtomicUpdate, MemoryOrdering, R2ILOp};

/// What an instruction's lift states of its atomic access: the fetch op (`None` for a
/// compare-and-exchange), its width and its ordering.
type Typed = (Option<Op>, u32, MemoryOrdering);

/// The one typed access, with nothing beside it that reads or writes memory or stays unmodelled.
fn typed(name: &str, ops: &[R2ILOp]) -> Typed {
    let atomics: Vec<_> = ops
        .iter()
        .filter_map(|op| match op {
            R2ILOp::Atomic(access) => Some(access),
            _ => None,
        })
        .collect();
    let [access] = &atomics[..] else {
        panic!("{name}: {ops:?}");
    };
    let beside = ops.iter().filter(|op| !matches!(op, R2ILOp::Atomic(_)));
    for op in beside {
        let (reads, writes) = (op.is_memory_read(), op.is_memory_write());
        let unmodelled = matches!(
            op,
            R2ILOp::CallOther { .. }
                | R2ILOp::Unimplemented
                | R2ILOp::Fence { .. }
                | R2ILOp::IndivisibleAccess
        );
        assert!(
            !(reads || writes || unmodelled),
            "{name}: {op:?} beside {ops:?}"
        );
    }
    let fetch = match &access.update {
        AtomicUpdate::Fetch { op, operand } => {
            assert_eq!(operand.size, access.dst.size, "{name}: {access:?}");
            Some(*op)
        }
        AtomicUpdate::CompareExchange {
            expected,
            replacement,
        } => {
            assert_eq!(
                (expected.size, replacement.size),
                (access.dst.size, access.dst.size),
                "{name}: {access:?}"
            );
            None
        }
    };
    (fetch, access.dst.size, access.ordering)
}

#[cfg(feature = "arm")]
mod aarch64 {
    use super::*;

    fn lift(word: u32) -> Vec<R2ILOp> {
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

    use MemoryOrdering::{AcqRel, Relaxed, Release};

    /// Every LSE operation at every size, the `st` aliases (Rt is the zero register), `swp`, and
    /// `cas` at each size; the pair `casp` of W registers is one compare-and-exchange of 8 bytes.
    const FORMS: [(&str, u32, Typed); 18] = [
        (
            "ldaddb w1, w0, [x8]",
            0x3821_0100,
            (Some(Op::Add), 1, Relaxed),
        ),
        (
            "ldclrh w1, w0, [x8]",
            0x7821_1100,
            (Some(Op::And), 2, Relaxed),
        ),
        (
            "ldeor w1, w0, [x8]",
            0xb821_2100,
            (Some(Op::Xor), 4, Relaxed),
        ),
        (
            "ldset x1, x0, [x8]",
            0xf821_3100,
            (Some(Op::Or), 8, Relaxed),
        ),
        (
            "ldsmaxb w1, w0, [x8]",
            0x3821_4100,
            (Some(Op::SignedMax), 1, Relaxed),
        ),
        (
            "ldsminh w1, w0, [x8]",
            0x7821_5100,
            (Some(Op::SignedMin), 2, Relaxed),
        ),
        (
            "ldumax w1, w0, [x8]",
            0xb821_6100,
            (Some(Op::UnsignedMax), 4, Relaxed),
        ),
        (
            "ldumin x1, x0, [x8]",
            0xf821_7100,
            (Some(Op::UnsignedMin), 8, Relaxed),
        ),
        (
            "ldsminal x1, x0, [x8]",
            0xf8e1_5100,
            (Some(Op::SignedMin), 8, AcqRel),
        ),
        (
            "swph w1, w0, [x8]",
            0x7821_8100,
            (Some(Op::Swap), 2, Relaxed),
        ),
        ("stclr x1, [x8]", 0xf821_111f, (Some(Op::And), 8, Relaxed)),
        ("steorb w1, [x8]", 0x3821_211f, (Some(Op::Xor), 1, Relaxed)),
        (
            "stsmaxh w1, [x8]",
            0x7821_411f,
            (Some(Op::SignedMax), 2, Relaxed),
        ),
        (
            "stumin w1, [x8]",
            0xb821_711f,
            (Some(Op::UnsignedMin), 4, Relaxed),
        ),
        ("staddl w1, [x8]", 0xb861_011f, (Some(Op::Add), 4, Release)),
        ("casb w0, w1, [x8]", 0x08a0_7d01, (None, 1, Relaxed)),
        ("cash w0, w1, [x8]", 0x48a0_7d01, (None, 2, Relaxed)),
        ("casp w0, w1, w2, w3, [x8]", 0x0820_7d02, (None, 8, Relaxed)),
    ];

    #[test]
    fn every_lse_form_and_cas_is_one_typed_atomic_access() {
        for (name, word, expected) in FORMS {
            assert_eq!(typed(name, &lift(word)), expected, "{name}");
        }
    }

    /// `casp` of X registers compares and writes two cells, which no one typed access states: the
    /// bracket stays an `IndivisibleAccess` beside its plain accesses, which eval still runs.
    #[test]
    fn casp_of_x_registers_is_an_indivisible_access_with_no_typed_statement() {
        let ops = lift(0x4820_7d02);
        assert!(
            ops.contains(&R2ILOp::IndivisibleAccess)
                && !ops.iter().any(|op| matches!(
                    op,
                    R2ILOp::Atomic(_) | R2ILOp::CallOther { .. } | R2ILOp::Unimplemented
                )),
            "{ops:?}"
        );
    }
}

#[cfg(feature = "x86")]
mod x86 {
    use super::*;
    use r2il::Endianness;
    use r2il::eval::{Flow, State, step};
    use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

    /// Where `[rdi]` points, and what it holds before each run.
    const CELL: u64 = 0x5000;
    const HELD: u64 = 0x8000_0000_0000_0001;

    fn disassembler() -> Disassembler {
        Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
            .expect("trusted x86-64 specification")
    }

    fn lift(disassembler: &Disassembler, bytes: &[u8]) -> Vec<R2ILOp> {
        let mut padded = bytes.to_vec();
        padded.resize(16, 0);
        disassembler
            .lift_genuine_block(&padded, 0x1000, bytes.len())
            .expect("lift")
            .block()
            .ops
            .clone()
    }

    use MemoryOrdering::SeqCst;

    /// The locked arithmetic, `xadd`, `xchg` (locked with or without the prefix), `cmpxchg`
    /// at a computed address, and `bts`, which the specification writes as an OR of one byte.
    const FORMS: [(&str, &[u8], Typed); 11] = [
        (
            "lock inc dword [rdi]",
            &[0xf0, 0xff, 0x07],
            (Some(Op::Add), 4, SeqCst),
        ),
        (
            "lock dec qword [rdi+8]",
            &[0xf0, 0x48, 0xff, 0x4f, 0x08],
            (Some(Op::Sub), 8, SeqCst),
        ),
        (
            "lock sub [rdi], esi",
            &[0xf0, 0x29, 0x37],
            (Some(Op::Sub), 4, SeqCst),
        ),
        (
            "lock and [rdi], si",
            &[0x66, 0xf0, 0x21, 0x37],
            (Some(Op::And), 2, SeqCst),
        ),
        (
            "lock or byte [rdi], 4",
            &[0xf0, 0x80, 0x0f, 0x04],
            (Some(Op::Or), 1, SeqCst),
        ),
        (
            "lock xor [rdi], rsi",
            &[0xf0, 0x48, 0x31, 0x37],
            (Some(Op::Xor), 8, SeqCst),
        ),
        (
            "lock bts [rdi], esi",
            &[0xf0, 0x0f, 0xab, 0x37],
            (Some(Op::Or), 1, SeqCst),
        ),
        (
            "xchg [rdi], rax",
            &[0x48, 0x87, 0x07],
            (Some(Op::Swap), 8, SeqCst),
        ),
        (
            "lock xadd [rdi], al",
            &[0xf0, 0x0f, 0xc0, 0x07],
            (Some(Op::Add), 1, SeqCst),
        ),
        (
            "lock xadd [rdi], esi",
            &[0xf0, 0x0f, 0xc1, 0x37],
            (Some(Op::Add), 4, SeqCst),
        ),
        (
            "lock cmpxchg [rdi+rcx*2+4], si",
            &[0x66, 0xf0, 0x0f, 0xb1, 0x74, 0x4f, 0x04],
            (None, 2, SeqCst),
        ),
    ];

    #[test]
    fn every_locked_form_is_one_sequentially_consistent_atomic_access() {
        let disassembler = disassembler();
        for (name, bytes, expected) in FORMS {
            assert_eq!(typed(name, &lift(&disassembler, bytes)), expected, "{name}");
        }
    }

    /// A locked form that is no fetch of one operand (`adc` adds the carry, `not` and `neg`
    /// take none) is an `IndivisibleAccess`, and an unlocked one stays plain.
    #[test]
    fn a_locked_form_with_no_fetch_is_indivisible_and_an_unlocked_one_is_plain() {
        let disassembler = disassembler();
        for (name, bytes) in [
            ("lock adc [rdi], esi", &[0xf0, 0x11, 0x37][..]),
            ("lock not dword [rdi]", &[0xf0, 0xf7, 0x17][..]),
            ("lock neg dword [rdi]", &[0xf0, 0xf7, 0x1f][..]),
        ] {
            let ops = lift(&disassembler, bytes);
            assert!(
                ops.contains(&R2ILOp::IndivisibleAccess)
                    && !ops
                        .iter()
                        .any(|op| matches!(op, R2ILOp::Atomic(_) | R2ILOp::CallOther { .. })),
                "{name}: {ops:?}"
            );
        }
        let plain = lift(&disassembler, &[0x01, 0x37]);
        assert!(
            !plain
                .iter()
                .any(|op| matches!(op, R2ILOp::Atomic(_) | R2ILOp::IndivisibleAccess)),
            "add [rdi], esi: {plain:?}"
        );
    }

    struct Run<'d> {
        disassembler: &'d Disassembler,
    }

    impl Run<'_> {
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

        /// Runs `bytes` through eval from `registers`, the cell holding [`HELD`].
        fn run(
            &self,
            bytes: &[u8],
            registers: &[(&str, u128)],
        ) -> State<impl r2il::eval::Mapped + use<>> {
            let held = HELD.to_le_bytes();
            let memory = move |address: u64| {
                let at = usize::try_from(address.checked_sub(CELL)?).ok()?;
                held.get(at).copied()
            };
            let mut state = State::new(Endianness::Little, memory, 1 << 12).expect("state");
            for (name, value) in registers.iter().chain(&[("RDI", u128::from(CELL))]) {
                let (offset, size) = self.register(name);
                state.set_register(offset, size, *value).expect(name);
            }
            for op in &lift(self.disassembler, bytes) {
                assert_eq!(step(op, &mut state), Flow::Next, "{bytes:02x?}: {op:?}");
            }
            state
        }

        fn read(&self, state: &State<impl r2il::eval::Mapped>, name: &str) -> u128 {
            let (offset, size) = self.register(name);
            state.register(offset, size).expect(name)
        }
    }

    /// Eval runs past `LOCK`: `xadd` answers the old value and leaves the sum, with the flags of
    /// the sum; `lock add` leaves the sum and its flags; `lock cmpxchg` writes only on a match.
    #[test]
    fn eval_runs_a_locked_operation_as_the_sdm_states() {
        let disassembler = disassembler();
        let run = Run {
            disassembler: &disassembler,
        };
        // lock xadd [rdi], rsi with rsi = -1: the cell 0x8000_0000_0000_0000, rsi the old value.
        let mut state = run.run(
            &[0xf0, 0x48, 0x0f, 0xc1, 0x37],
            &[("RSI", u128::from(u64::MAX))],
        );
        assert_eq!(state.load(CELL, 8), Ok(0x8000_0000_0000_0000));
        assert_eq!(run.read(&state, "RSI"), u128::from(HELD));
        assert_eq!(
            (
                run.read(&state, "CF"),
                run.read(&state, "SF"),
                run.read(&state, "ZF")
            ),
            (1, 1, 0)
        );
        // lock add dword [rdi], 0xffffffff: the low dword 1 + 0xffffffff wraps to zero.
        let mut state = run.run(&[0xf0, 0x83, 0x07, 0xff], &[]);
        assert_eq!(state.load(CELL, 8), Ok(0x8000_0000_0000_0000));
        assert_eq!((run.read(&state, "CF"), run.read(&state, "ZF")), (1, 1));
        // lock cmpxchg [rdi], rsi: rax equal stores rsi, rax unequal loads the cell into rax.
        let cmpxchg = [0xf0, 0x48, 0x0f, 0xb1, 0x37];
        let mut state = run.run(&cmpxchg, &[("RAX", u128::from(HELD)), ("RSI", 7)]);
        assert_eq!((state.load(CELL, 8), run.read(&state, "ZF")), (Ok(7), 1));
        let mut state = run.run(&cmpxchg, &[("RAX", 3), ("RSI", 7)]);
        assert_eq!(state.load(CELL, 8), Ok(u128::from(HELD)));
        assert_eq!(
            (run.read(&state, "RAX"), run.read(&state, "ZF")),
            (u128::from(HELD), 0)
        );
    }
}
