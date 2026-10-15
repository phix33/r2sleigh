//! Big-endian ARM: BE32 reads its instructions in the data's order, BE8 little-endian (audit W26).
#![cfg(feature = "arm")]

use r2il::Endianness;
use r2sleigh_lift::ByteOrder;
use r2sleigh_lift::flow::Flow;

/// Each instruction of `code` at `at` and on, decoded alone: its spelling and where control goes.
fn decoded(machine: &r2sleigh_lift::EmbeddedMachine, code: &[u8], at: u64) -> Vec<(String, Flow)> {
    let mut spelled = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        let mut fetch = code[offset..].to_vec();
        fetch.resize(16, 0);
        let one = machine
            .disasm
            .decode(&fetch, at + offset as u64, None)
            .expect("decodes");
        offset += one.syntax.size;
        spelled.push((one.syntax.text(), one.flow.expect("it lifts")));
    }
    spelled
}

#[test]
fn a_be32_arm_word_reads_most_significant_byte_first() {
    let arm = r2sleigh_lift::embedded_machine("arm-be").expect("ARM:BE:32:v8");
    let returned = decoded(&arm, &[0xe1, 0x2f, 0xff, 0x1e], 0x1000);
    assert_eq!(returned, [("bx lr".to_owned(), Flow::Return)]);
}

#[test]
fn a_be32_thumb_halfword_reads_most_significant_byte_first() {
    // arm-thumb-movw-be.o's `back` and `f`: `bx lr; movw r0, 0xfffc; movt r0, 0xfffc`.
    let thumb = r2sleigh_lift::embedded_machine("arm-thumb-be").expect("Thumb BE");
    let code = [0x47, 0x70, 0xf6, 0x4f, 0x70, 0xfc, 0xf6, 0xcf, 0x70, 0xfc];
    let spelled = decoded(&thumb, &code, 0x34);
    let texts: Vec<_> = spelled.iter().map(|(text, _)| text.as_str()).collect();
    assert_eq!(texts, ["bx lr", "movw r0, 0xfffc", "movt r0, 0xfffc"]);
    assert_eq!(spelled[0].1, Flow::Return);
}

#[test]
fn be8_reads_little_endian_instructions_under_big_endian_data() {
    let be8 = ByteOrder {
        data: Endianness::Big,
        instructions: Some(Endianness::Little),
    };
    let arm = r2sleigh_lift::embedded_program_machine("ARM", be8, false).expect("BE8");
    assert_eq!(
        decoded(&arm, &[0x1e, 0xff, 0x2f, 0xe1], 0x1000),
        [("bx lr".to_owned(), Flow::Return)]
    );
    let thumb = r2sleigh_lift::embedded_thumb_machine("ARM", be8)
        .expect("ARM has Thumb")
        .expect("BE8 Thumb");
    assert_eq!(decoded(&thumb, &[0x70, 0x47], 0x1000)[0].0, "bx lr");
}
