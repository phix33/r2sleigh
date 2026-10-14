//! A symbol's type and binding as its table states them. The fixture is written by `data/symbol_kinds.py`.

use r2image::{Binding, SymbolKind};

fn symbol(name: &str) -> r2image::Symbol {
    let image = r2image::Image::parse(include_bytes!("data/symbol_kinds.elf").to_vec())
        .expect("the symbol-kinds fixture");
    image
        .symbols()
        .iter()
        .find(|symbol| &*symbol.name == name)
        .cloned()
        .expect("the fixture states it")
}

#[test]
fn a_thread_local_symbol_is_tls_and_names_no_address() {
    let counter = symbol("counter");
    assert_eq!(counter.kind, SymbolKind::Tls);
    assert!(
        !counter.defined,
        "a TLS value is an offset into the thread's block"
    );
}

#[test]
fn gnu_unique_is_its_own_binding_under_the_gnu_abi() {
    assert_eq!(symbol("unique").binding, Binding::Unique);
}
