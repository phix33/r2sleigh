//! Which of several symbols at one address names it.

use crate::common;

use common::{Literal, ONE, TEXT};
use r2engine::program::{Binding, OpenProgram, Symbol, SymbolKind};

fn symbol(name: &str, binding: Binding) -> Symbol {
    Symbol {
        name: name.into(),
        vaddr: ONE,
        size: 6,
        kind: SymbolKind::Function,
        defined: true,
        binding,
        ..Symbol::default()
    }
}

/// The strongest binding names the address, whichever the table lists first.
#[test]
fn a_global_names_its_address_before_a_weak_alias_or_a_local_one() {
    let named = |symbols: [Symbol; 2]| {
        let program = symbols
            .into_iter()
            .fold(Literal::new().stripped_of("one"), Literal::declaring);
        let program = OpenProgram::of(program);
        program.names().of(ONE).map(|name| name.spelled())
    };
    let aliases = [
        symbol("_Exit", Binding::Weak),
        symbol("_exit", Binding::Global),
    ];
    assert_eq!(named(aliases).as_deref(), Some("sym._exit"));
    let internal = [
        symbol("__GI___libc_write", Binding::Local),
        symbol("write", Binding::Weak),
    ];
    assert_eq!(named(internal).as_deref(), Some("sym.write"));
}

/// A flag is radare2's filtered name; the table keeps the container's text, which a prototype is keyed by.
#[test]
fn a_symbol_radare2_filters_is_spelled_and_sought_as_its_flag() {
    let object = Symbol {
        name: "__OBJC_METACLASS_RO_$_Test".into(),
        vaddr: TEXT,
        size: 8,
        kind: SymbolKind::Data,
        defined: true,
        ..Symbol::default()
    };
    let program = OpenProgram::of(Literal::new().with_data().declaring(object));
    let names = program.names();
    let spelled = names.of(TEXT).map(|name| name.spelled());
    assert_eq!(spelled.as_deref(), Some("obj.__OBJC_METACLASS_RO___Test"));
    assert_eq!(
        names.address_of("obj.__OBJC_METACLASS_RO___Test"),
        Some(TEXT)
    );
    assert_eq!(names.address_of("obj.__OBJC_METACLASS_RO_$_Test"), None);
    assert_eq!(names.text_at(TEXT), Some("__OBJC_METACLASS_RO_$_Test"));
}
