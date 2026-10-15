//! A PE image states its imports by address table slot and DLL, and its exports by name (audit M1).

fn fixture() -> r2image::Image {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/pe_imports_x64.dll"
    );
    r2image::Image::open(path).expect("the fixture opens")
}

#[test]
fn each_import_is_its_slot_by_dll_and_the_loader_writes_it() {
    let image = fixture();
    let imports: Vec<_> = image
        .symbols()
        .iter()
        .filter(|symbol| symbol.import)
        .collect();
    let stated: Vec<_> = imports
        .iter()
        .map(|symbol| (symbol.vaddr, &*symbol.name, symbol.library.as_deref()))
        .collect();
    assert_eq!(
        stated,
        [
            (0x1_4000_2060, "ExitProcess", Some("KERNEL32.dll")),
            // The container states only an ordinal; a name would be a guess.
            (0x1_4000_2068, "Ordinal_7", Some("KERNEL32.dll")),
        ]
    );
    let write = image
        .container()
        .loader_write_at(0x1_4000_2060)
        .expect("the slot is written");
    assert_eq!(
        write.kind,
        r2image::WriteKind::Import {
            symbol: "ExitProcess".to_owned(),
            library: Some("KERNEL32.dll".to_owned()),
        }
    );
}

/// The directory states the export's address and name, not its type: whether it begins a function
/// is discovery's to say.
#[test]
fn an_export_is_a_defined_symbol_of_this_image_with_no_stated_type() {
    let image = fixture();
    let export = image
        .symbols()
        .iter()
        .find(|symbol| &*symbol.name == "start_here")
        .expect("the export is stated");
    assert_eq!(export.vaddr, 0x1_4000_1000);
    assert!(export.defined && !export.import);
    assert_eq!(export.kind, r2image::SymbolKind::Other);
    assert_eq!(export.library.as_deref(), Some("fixture.dll"));
}
