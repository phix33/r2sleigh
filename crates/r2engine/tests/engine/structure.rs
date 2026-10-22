//! What the structurer writes for a function, from its bytes and an address.

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

fn c_of(code: &'static [u8]) -> String {
    let size = code.len() as u64;
    let mut program = OpenProgram::of(Literal::of_code(code, &[("f", BASE, size)]));
    program
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// The `if` lines of a rendering.
fn tests_of(c: &str) -> Vec<&str> {
    c.lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("if "))
        .collect()
}

/// `test edi, edi; jne no; test esi, esi; jne no; mov eax, 1; ret; no: xor eax, eax; ret`
const BOTH_ZERO: &[u8] = &[
    0x85, 0xff, 0x75, 0x0a, 0x85, 0xf6, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0,
    0xc3,
];

/// `test edi, edi; jne yes; test esi, esi; je no; yes: mov eax, 1; ret; no: xor eax, eax; ret`
const EITHER_NOT_ZERO: &[u8] = &[
    0x85, 0xff, 0x75, 0x04, 0x85, 0xf6, 0x74, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0,
    0xc3,
];

/// `test edi, edi; jne no; cmp dword [rsi], 0; jne no; mov eax, 1; ret; no: xor eax, eax; ret`
const SECOND_TEST_LOADS: &[u8] = &[
    0x85, 0xff, 0x75, 0x0b, 0x83, 0x3e, 0x00, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31,
    0xc0, 0xc3,
];

#[test]
fn two_tests_that_fail_to_one_exit_are_one_conjunction() {
    let c = c_of(BOTH_ZERO);
    let tests = tests_of(&c);
    assert_eq!(tests.len(), 1, "{c}");
    // The text is the machine's: both zero, which is what the source says.
    assert_eq!(tests[0].matches("== (uint32_t)0U").count(), 2, "{c}");
    assert!(tests[0].contains(" && ") && !tests[0].contains('!'), "{c}");
    assert!(!c.contains("goto"), "{c}");
}

#[test]
fn the_exit_only_the_chain_reaches_is_the_if_s_body() {
    // Either input non-zero returns 1, which both tests reach; zero for both returns 0, which only
    // the second test does, so that block is the body and the first block is the jump.
    let c = c_of(EITHER_NOT_ZERO);
    let tests = tests_of(&c);
    assert_eq!(tests.len(), 1, "{c}");
    assert_eq!(tests[0].matches("== (uint32_t)0U").count(), 2, "{c}");
    assert!(tests[0].contains(" && "), "{c}");
    assert!(c.contains("return 0;"), "{c}");
}

#[test]
fn a_second_test_that_reads_memory_is_a_test_of_its_own() {
    // The load is a statement between the two tests, so the second block is no part of the first's.
    let c = c_of(SECOND_TEST_LOADS);
    assert_eq!(tests_of(&c).len(), 2, "{c}");
    assert!(!c.contains(" && ") && !c.contains(" || "), "{c}");
}

/// `test edi, edi; jne no; sub esi, 5; jne no; mov eax, esi; ret; no: xor eax, eax; ret`: the second
/// test's block also computes the value the function returns.
const SECOND_TEST_KEEPS_ITS_VALUE: &[u8] = &[
    0x85, 0xff, 0x75, 0x08, 0x83, 0xee, 0x05, 0x75, 0x03, 0x89, 0xf0, 0xc3, 0x31, 0xc0, 0xc3,
];

/// The same, but the function returns 1: the subtraction is only its flags.
const SECOND_TEST_ONLY_COMPARES: &[u8] = &[
    0x85, 0xff, 0x75, 0x0b, 0x83, 0xee, 0x05, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31,
    0xc0, 0xc3,
];

#[test]
fn a_second_test_joins_the_chain_only_if_it_computes_nothing_the_function_keeps() {
    // r2ssa says both blocks owe nothing but their branch and what they carry; only the text
    // knows whether the subtraction is a statement of its own, which no `&&` may drop.
    let kept = c_of(SECOND_TEST_KEEPS_ITS_VALUE);
    assert_eq!(tests_of(&kept).len(), 2, "{kept}");
    assert!(!kept.contains(" && "), "{kept}");
    assert!(kept.contains("arg1 - (uint32_t)5U"), "{kept}");
    let flags = c_of(SECOND_TEST_ONLY_COMPARES);
    assert_eq!(tests_of(&flags).len(), 1, "{flags}");
    assert!(flags.contains(" && "), "{flags}");
}

/// `xor eax, eax; jmp test; body: inc eax; test: cmp eax, edi; jl body; ret`
const COUNT_UP: &[u8] = &[
    0x31, 0xc0, 0xeb, 0x02, 0xff, 0xc0, 0x39, 0xf8, 0x7c, 0xfa, 0xc3,
];

#[test]
fn a_loop_that_tests_before_its_body_is_a_while() {
    let c = c_of(COUNT_UP);
    assert_eq!(c.matches("while (").count(), 1, "{c}");
    assert!(!c.contains("for (; ; )") && !c.contains("break"), "{c}");
    // The test is the machine's: stay while the counter is below the bound.
    let test = c
        .lines()
        .find(|line| line.contains("while ("))
        .expect("a loop");
    assert!(test.contains('<'), "{c}");
}

/// `test edi, edi; je skip; xor eax, eax; body: inc eax; cmp eax, edi; jne body; ret; skip: xor eax, eax; ret`
const COUNT_TO: &[u8] = &[
    0x85, 0xff, 0x74, 0x09, 0x31, 0xc0, 0xff, 0xc0, 0x39, 0xf8, 0x75, 0xfa, 0xc3, 0x31, 0xc0, 0xc3,
];

#[test]
fn a_loop_that_tests_after_its_body_is_a_do_while_with_its_merge_copies_before_the_test() {
    let c = c_of(COUNT_TO);
    assert_eq!(c.matches("do {").count(), 1, "{c}");
    assert!(!c.contains("for (; ; )") && !c.contains("break"), "{c}");
    // The copy that carries the counter round the loop is written before the test reads the next value.
    let lines: Vec<&str> = c.lines().map(str::trim).collect();
    let end = lines
        .iter()
        .position(|line| line.starts_with("} while ("))
        .expect("a do-while");
    assert!(
        lines[end - 1].contains(" = ") && !lines[end - 1].contains("if"),
        "{c}"
    );
}

/// `test edi, edi; je skip; xor eax, eax; body: mov edx, eax; inc eax; cmp eax, edi; jne body;
/// mov eax, edx; ret; skip: xor eax, eax; ret`: the code after the loop wants the counter as the
/// last iteration began it.
const LAST_BEGUN: &[u8] = &[
    0x85, 0xff, 0x74, 0x0d, 0x31, 0xc0, 0x89, 0xc2, 0xff, 0xc0, 0x39, 0xf8, 0x75, 0xf8, 0x89, 0xd0,
    0xc3, 0x31, 0xc0, 0xc3,
];

#[test]
fn what_the_code_after_a_loop_reads_is_not_what_the_hoisted_copy_writes() {
    // The result is the counter as the last iteration began it, which the text keeps in a variable
    // of its own, so the copy of the next value may still be written before the test.
    let c = c_of(LAST_BEGUN);
    let lines: Vec<&str> = c.lines().map(str::trim).collect();
    let end = lines
        .iter()
        .position(|line| line.starts_with("} while ("))
        .expect("a do-while");
    let copied = lines[end - 1].split(" = ").next().expect("a copy");
    let returned = lines
        .iter()
        .find(|line| line.starts_with("return (uint32_t)"))
        .expect("a return of the loop's value");
    assert!(!returned.contains(copied), "{c}");
}
