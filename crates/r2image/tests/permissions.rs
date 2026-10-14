//! A segment the loader maps with any access holds the program's bytes; one with none is a
//! reservation (Mach-O `__PAGEZERO`). Audit W1: execute-only PE sections read as unmapped.

/// The fixture with its executable `PT_LOAD`'s `p_flags` replaced, and where that segment starts.
fn with_code_flags(p_flags: u32) -> (r2image::Image, u64) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/dwarf_graph.elf");
    let mut bytes = std::fs::read(path).expect("the fixture reads");
    let field = |at: usize, len: usize| {
        let mut word = [0u8; 8];
        word[..len].copy_from_slice(&bytes[at..at + len]);
        u64::from_le_bytes(word)
    };
    let (phoff, phentsize, phnum) = (
        field(0x20, 8) as usize,
        field(0x36, 2) as usize,
        field(0x38, 2),
    );
    let header = (0..phnum as usize)
        .map(|index| phoff + index * phentsize)
        .find(|at| field(*at, 4) == 1 && field(at + 4, 4) & 1 == 1)
        .expect("an executable PT_LOAD");
    let vaddr = field(header + 0x10, 8);
    bytes[header + 4..header + 8].copy_from_slice(&p_flags.to_le_bytes());
    (
        r2image::Image::parse(bytes).expect("the fixture parses"),
        vaddr,
    )
}

#[test]
fn an_execute_only_segment_is_mapped_and_reads_its_bytes() {
    let (readable, vaddr) = with_code_flags(0b101);
    let (execute_only, _) = with_code_flags(0b001);
    let expected = readable.read(vaddr, 16).expect("a readable segment reads");
    assert_eq!(execute_only.read(vaddr, 16), Some(expected));
    assert!(execute_only.read_upto(vaddr, 16).is_some());
}

#[test]
fn a_segment_with_no_access_is_a_reservation() {
    let (reserved, vaddr) = with_code_flags(0);
    assert_eq!(reserved.read(vaddr, 16), None);
}
