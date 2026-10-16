//! An Apple arm64 program: its compiler specification is Apple's, and a call to a libSystem import
//! it cannot declare is a typed gap naming the callee (ROADMAP B2).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `code` at `BASE`, an import stub at `STUB` and its slot after it, little-endian words.
fn arm64_with_stub(words: &[(u64, u32)]) -> &'static [u8] {
    let mut code = vec![0u8; 0xb0];
    for (at, word) in words {
        let at = (*at - BASE) as usize;
        code[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    // ldr x16, [slot]; br x16
    code[0x90..0x94].copy_from_slice(&0x5800_0050u32.to_le_bytes());
    code[0x94..0x98].copy_from_slice(&0xd61f_0200u32.to_le_bytes());
    Box::leak(code.into_boxed_slice())
}

fn rendered(literal: Literal, at: u64) -> String {
    OpenProgram::of(literal)
        .rendered(at)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// `tail`: `if (++*arg0 != 0) fts_close()` as a bare `b` to the import's stub; `call`: `bl` to it.
fn program() -> Literal {
    let code = arm64_with_stub(&[
        (BASE, 0xb940_0008),        // ldr w8, [x0]
        (BASE + 4, 0x1100_0508),    // add w8, w8, #1
        (BASE + 8, 0xb900_0008),    // str w8, [x0]
        (BASE + 12, 0x3500_0048),   // cbnz w8, 0x1014
        (BASE + 16, 0xd65f_03c0),   // ret
        (BASE + 20, 0x1400_001f),   // b stub
        (BASE + 0x30, 0xa9bf_7bfd), // stp x29, x30, [sp, #-16]!
        (BASE + 0x34, 0x5280_00a0), // mov w0, #5
        (BASE + 0x38, 0x9400_0016), // bl stub
        (BASE + 0x3c, 0xa8c1_7bfd), // ldp x29, x30, [sp], #16
        (BASE + 0x40, 0xd65f_03c0), // ret
    ]);
    Literal::of_code(code, &[("tail", BASE, 0x18), ("call", BASE + 0x30, 0x14)])
        .in_aarch64()
        .mach_o()
        .importing("fts_close")
}

/// A call and a tail jump to an import nothing declares are both gaps naming it and the refusal,
/// never `UnsupportedInstruction` with no cause (audit M3).
#[test]
fn an_undeclared_import_is_a_typed_gap_for_a_call_and_a_tail_jump() {
    for at in [BASE, BASE + 0x30] {
        let text = rendered(program(), at);
        assert!(
            text.contains(
                "call to fts_close: the import has no declaration to state its arguments"
            ),
            "{text}"
        );
        assert!(!text.contains("UnsupportedInstruction"), "{text}");
    }
}
