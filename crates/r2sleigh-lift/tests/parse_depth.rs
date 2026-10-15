//! Ghidra's parser holds a fixed operand path and a fixed number of operands a state
//! (GP-6554); a parse deeper than either is refused, not written past them.
#![cfg(feature = "arm")]

fn lifted(word: u32) -> Option<u32> {
    let machine = r2sleigh_lift::embedded_machine("arm").expect("arm machine");
    let mut window = word.to_le_bytes().to_vec();
    window.resize(16, 0);
    machine
        .disasm
        .lift(&window, 0x1000)
        .ok()
        .map(|block| block.size)
}

#[test]
fn a_register_list_deeper_than_the_parser_holds_is_refused() {
    // vldmiavc r6, {s29, ...} with a count of 0x9f words, at libflutter.so's 0x13416a
    assert_eq!(lifted(0x7cd6_ea9f), None);
}

#[test]
fn the_longest_architectural_register_lists_still_decode() {
    // vldmia r0, {s0-s31}; vldmia r0, {d0-d15}; ldm r0, {r0-pc}
    for word in [0xec90_0a20, 0xec90_0b20, 0xe890_ffff] {
        assert_eq!(lifted(word), Some(4), "{word:#010x}");
    }
}
