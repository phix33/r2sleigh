//! A call hands its callee exactly the arguments the callee's body states it takes, or shows what
//! it cannot prove (ROADMAP P7, audit W7): never the registers the caller happened to write.

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `f` writes both result registers and reads no argument (`xor eax, eax; pxor xmm0, xmm0`): its
/// result is unproven and its arity exact. `caller` sets `edi` and `esi` for nothing, then calls it.
const EXACT_WITH_AN_UNPROVEN_RESULT: &[u8] = &[
    0x31, 0xc0, // 1000 xor eax, eax
    0x66, 0x0f, 0xef, 0xc0, // 1002 pxor xmm0, xmm0
    0xc3, // 1006 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1007 padding
    0x53, // 1010 push rbx
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1011 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1016 mov esi, 7
    0xe8, 0xe0, 0xff, 0xff, 0xff, // 101b call 0x1000
    0x5b, // 1020 pop rbx
    0x31, 0xc0, // 1021 xor eax, eax
    0xc3, // 1023 ret
];

/// `crc32_init(0x402060, 61)` was the registers gcc set for a later call: a callee whose arity is
/// exact keeps it when its result is unproven, so the call passes none (audit W7).
#[test]
fn an_exact_callee_with_an_unproven_result_is_called_with_exactly_its_arguments() {
    let text = OpenProgram::of(Literal::of_code(
        EXACT_WITH_AN_UNPROVEN_RESULT,
        &[("f", BASE, 0x07), ("caller", BASE + 0x10, 0x14)],
    ))
    .rendered(BASE + 0x10)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert!(text.contains("f();"), "{text}");
    assert!(!text.contains("f(5"), "{text}");
}
