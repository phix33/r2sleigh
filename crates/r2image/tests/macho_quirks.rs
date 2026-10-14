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
