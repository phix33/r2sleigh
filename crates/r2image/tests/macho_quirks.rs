//! What a Mach-O image states, read as dyld and the linker read it. The fixtures are written by `data/macho_quirks.py`.

fn image(bytes: &[u8]) -> r2image::Image {
    r2image::Image::parse(bytes.to_vec()).expect("a Mach-O fixture")
}

#[test]
fn an_indirect_symbol_states_no_address() {
    let image = image(include_bytes!("data/macho_indirect"));
    let named = |name: &str| image.symbols().iter().any(|symbol| &*symbol.name == name);
    assert!(named("_start"));
    assert!(
        !named("_alias"),
        "N_INDR's n_value is the index of the name it stands for"
    );
}

#[test]
fn lc_main_is_an_offset_from_the_mapped_header_and_names_main_in_its_mode() {
    use r2image::EntryKind;
    let image = image(include_bytes!("data/macho_thumb_main"));
    let entry = |kind: EntryKind| {
        (image.entry_points().iter())
            .find(|entry| entry.kind == kind)
            .map(|entry| (entry.vaddr, entry.thumb))
    };
    // __TEXT maps file offset 0 at 0x1000, so entryoff 0x1801 is Thumb code at 0x2800, not 0x1800.
    assert_eq!(entry(EntryKind::Main), Some((0x2800, true)));
    assert_eq!(entry(EntryKind::CMain), Some((0x2800, true)));
}
