//! What a PE image states, read as the Windows loader reads it. The fixtures are written by `data/pe_quirks.py`.

fn image(bytes: &[u8]) -> r2image::Image {
    r2image::Image::parse(bytes.to_vec()).expect("a PE fixture")
}

fn symbol<'i>(image: &'i r2image::Image, name: &str) -> &'i r2image::Symbol {
    (image.symbols().iter())
        .find(|symbol| &*symbol.name == name)
        .expect("the fixture states it")
}

#[test]
fn an_absolute_coff_record_states_its_value_unplaced() {
    let image = image(include_bytes!("data/pe_absolute.exe"));
    let stack = symbol(&image, "__stack");
    assert_eq!(stack.vaddr, 0x1000);
    assert!(!stack.defined, "an absolute value is no address");
    assert_eq!(symbol(&image, "_start").vaddr, 0x401000);
}
