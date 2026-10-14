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

/// `f`: `call g; add eax, 1; ret`, handing on the `rdi` it arrived with; `g`: `mov eax, [rdi]; ret`;
/// `caller`: `mov edi, 5; mov esi, 7; call f; ret`, `esi` set for nothing.
const HANDED_ON_ONE: &[u8] = &[
    0xe8, 0x0b, 0x00, 0x00, 0x00, // 1000 call 0x1010
    0x83, 0xc0, 0x01, // 1005 add eax, 1
    0xc3, // 1008 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1009 padding
    0x8b, 0x07, // 1010 mov eax, [rdi]
    0xc3, // 1012 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1013 padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1025 mov esi, 7
    0xe8, 0xd1, 0xff, 0xff, 0xff, // 102a call 0x1000
    0xc3, // 102f ret
];

/// Resolved alone, `f`'s call to `g` may be handed any slot, so `f` takes at least none; under `aa`
/// `f` is resolved again against `g`, which takes exactly one, so `f` does too: `f(5)`, not the
/// `f(5, 7)` the caller's registers said (audit W7, `shape_bool_caller`).
#[test]
fn under_aa_a_floor_its_callee_owns_is_resolved_bottom_up() {
    let mut open = OpenProgram::of(Literal::of_code(
        HANDED_ON_ONE,
        &[
            ("f", BASE, 0x09),
            ("g", BASE + 0x10, 0x03),
            ("caller", BASE + 0x20, 0x10),
        ],
    ));
    open.analyse_program().expect("it surveys");
    let text = open
        .rendered(BASE + 0x20)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(
        text.contains("f(5)") || text.contains("f((uint64_t)5U)"),
        "{text}"
    );
    assert!(!text.contains(", 7)"), "{text}");
}

/// Without `aa`, `f`'s arity is a floor of none and `caller` writes two slots: the call is a gap
/// that names `f` and its floor, never `f(5, 7)` and never an unsupported instruction (audit M3).
#[test]
fn a_call_past_a_floor_is_a_gap_naming_its_callee_and_floor() {
    let text = OpenProgram::of(Literal::of_code(
        HANDED_ON_ONE,
        &[
            ("f", BASE, 0x09),
            ("g", BASE + 0x10, 0x03),
            ("caller", BASE + 0x20, 0x10),
        ],
    ))
    .rendered(BASE + 0x20)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert!(
        text.contains(
            "(render::values): call to f: its arity is only at least 0 (a floor), and this call writes 2 */"
        ),
        "{text}"
    );
    assert!(!text.contains("UnsupportedInstruction"), "{text}");
    assert!(!text.contains("f(5"), "{text}");
}

/// `caller`: `mov edi, 5; mov esi, 7; call [rip + 0x10]; ret`, the slot at 0x1020 the loader binds
/// to `puts`, in a segment the program may write.
const CALL_THROUGH_A_SLOT: &[u8] = &[
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1000 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1005 mov esi, 7
    0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // 100a call [rip + 0x10]
    0xc3, // 1010 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1011 padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1020 the slot
];

/// `caller` over the slot bound to `import`, sealed after load or not.
fn slot_caller(import: &str, sealed: bool) -> String {
    let slot = BASE + 0x20;
    let mut literal = Literal::of_code(CALL_THROUGH_A_SLOT, &[("caller", BASE, 0x11)])
        .writable_data_after(slot)
        .loader_written(common::import_write(slot, 8, import))
        .relocated(common::import_slot(slot, import));
    if sealed {
        literal = literal.sealed(slot..slot + 8);
    }
    OpenProgram::of(literal)
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// A call through a slot the loader binds to an import and seals is a call to that import, with
/// its declaration's arity: `puts(5)`, not a pointer call handed every register written (audit
/// W8). A slot the program may rebind stays a call through memory.
#[test]
fn a_call_through_a_sealed_import_slot_calls_the_import() {
    let text = slot_caller("puts", true);
    assert!(text.contains("puts((const char*)(uint64_t)5U)"), "{text}");
    assert!(!text.contains(", 7)"), "{text}");
    let text = slot_caller("puts", false);
    assert!(!text.contains("puts("), "{text}");
}

/// A send to `objc_msgSend`, variadic as objc4 declares it, states no argument count: the call is
/// a gap naming the import and why, never an unsupported instruction (audit M3, RF's W10 case).
#[test]
fn a_variadic_call_with_no_count_is_a_gap_naming_its_callee() {
    let text = slot_caller("objc_msgSend", true);
    assert!(
        text.contains(
            "call to objc_msgSend: variadic, its argument count unproven (missing_format_parameter) */"
        ),
        "{text}"
    );
    assert!(!text.contains("UnsupportedInstruction"), "{text}");
}
