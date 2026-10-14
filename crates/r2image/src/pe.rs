//! What a PE image's directories state: each import address table slot and the import the loader
//! writes there, by library, and each address the export directory publishes; and what a COFF
//! symbol record states that `object` does not give.

use std::sync::Arc;

use object::LittleEndian as LE;
use object::read::pe::{ExportTarget, ImageNtHeaders, Import, ImportThunkList, PeFile};
use object::{Object, ReadRef};

/// One import address table slot: the loader writes `name`, which `library` defines, there.
pub(crate) struct Imported {
    pub slot: u64,
    pub library: Arc<str>,
    /// The name it binds, or `Ordinal_N` (radare2's spelling) for an import by ordinal.
    pub name: Arc<str>,
    /// Its position in its library's table, from one.
    pub nth: usize,
}

/// One address the export directory publishes, by name or `Ordinal_N`.
pub(crate) struct Exported {
    pub vaddr: u64,
    pub name: Arc<str>,
    /// The module name the directory states for itself.
    pub library: Option<Arc<str>>,
    pub nth: usize,
}

pub(crate) fn imports(file: &object::File<'_>) -> Vec<Imported> {
    match file {
        object::File::Pe32(pe) => imports_of(pe),
        object::File::Pe64(pe) => imports_of(pe),
        _ => Vec::new(),
    }
}

pub(crate) fn exports(file: &object::File<'_>) -> Vec<Exported> {
    match file {
        object::File::Pe32(pe) => exports_of(pe),
        object::File::Pe64(pe) => exports_of(pe),
        _ => Vec::new(),
    }
}

fn text(bytes: &[u8]) -> Arc<str> {
    String::from_utf8_lossy(bytes).into()
}

/// The ordinary and the delay-load tables; a malformed descriptor ends its table, not the image.
///
/// Tables are walked in slot order and one stops at a slot already stated, so tables that overlap
/// (each starting inside the last, all ending at one null) cost their distinct slots once.
fn imports_of<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(
    pe: &PeFile<'data, Pe, R>,
) -> Vec<Imported> {
    // Each table: its slots, its DLL, its names, and which directory reads them.
    let mut tables: Vec<(u32, Arc<str>, ImportThunkList<'data>, bool)> = Vec::new();
    let ordinary = pe.import_table().ok().flatten();
    if let Some(table) = &ordinary
        && let Ok(mut descriptors) = table.descriptors()
    {
        while let Ok(Some(descriptor)) = descriptors.next() {
            let (slots, lookup) = (
                descriptor.first_thunk.get(LE),
                descriptor.original_first_thunk.get(LE),
            );
            // A bound image may keep no lookup table: the slots hold the names until bound.
            let names = if lookup != 0 { lookup } else { slots };
            if let (Ok(library), Ok(thunks)) =
                (table.name(descriptor.name.get(LE)), table.thunks(names))
            {
                tables.push((slots, text(library), thunks, false));
            }
        }
    }
    let delayed = (pe.data_directories())
        .delay_load_import_table(pe.data(), &pe.section_table())
        .ok()
        .flatten();
    if let Some(table) = &delayed
        && let Ok(mut descriptors) = table.descriptors()
    {
        while let Ok(Some(descriptor)) = descriptors.next() {
            let slots = descriptor.import_address_table_rva.get(LE);
            let names = descriptor.import_name_table_rva.get(LE);
            if let (Ok(library), Ok(thunks)) = (
                table.name(descriptor.dll_name_rva.get(LE)),
                table.thunks(names),
            ) {
                tables.push((slots, text(library), thunks, true));
            }
        }
    }
    // A descriptor naming no file names no DLL: Corkami's manyimports pads with thousands whose
    // "names" are the next descriptor's bytes.
    tables.retain(|(_, library, ..)| !library.is_empty() && !library.chars().any(char::is_control));
    tables.sort_by_key(|(slots, ..)| *slots);
    let spelled = |import: object::Result<Import<'data>>| match import.ok()? {
        Import::Name(_, name) => Some(text(name)),
        Import::Ordinal(ordinal) => Some(format!("Ordinal_{ordinal}").into()),
    };
    let base = pe.relative_address_base();
    let pointer = if pe.is_64() { 8 } else { 4 };
    let mut stated = std::collections::BTreeSet::new();
    let mut found = Vec::new();
    for (slots, library, mut names, delay) in tables {
        let mut nth = 0;
        while let Ok(Some(thunk)) = names.next::<Pe>() {
            let slot = (base.wrapping_add(u64::from(slots))).wrapping_add(nth as u64 * pointer);
            let name = match (delay, &ordinary, &delayed) {
                (false, Some(table), _) => spelled(table.import::<Pe>(thunk)),
                (true, _, Some(table)) => spelled(table.import::<Pe>(thunk)),
                _ => None,
            };
            let Some(name) = name.filter(|_| stated.insert(slot)) else {
                break;
            };
            nth += 1;
            // A name with no character a symbol holds binds nothing.
            if name.is_empty() || name.chars().any(char::is_control) {
                continue;
            }
            found.push(Imported {
                slot,
                library: Arc::clone(&library),
                name,
                nth,
            });
        }
    }
    found
}

/// Each export at an address of this image; a forwarder names another image's and is no place here.
fn exports_of<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(
    pe: &PeFile<'data, Pe, R>,
) -> Vec<Exported> {
    let Some(table) = pe
        .export_table()
        .ok()
        .flatten()
        .or_else(|| unsized_export_table(pe))
    else {
        return Vec::new();
    };
    let Ok(exports) = table.exports() else {
        return Vec::new();
    };
    let library = table
        .name_from_pointer(table.directory().name.get(LE))
        .ok()
        .map(text);
    let base = pe.relative_address_base();
    exports
        .iter()
        .filter_map(|export| match export.target {
            ExportTarget::Address(rva) => Some((export, rva)),
            _ => None,
        })
        .enumerate()
        .map(|(index, (export, rva))| Exported {
            vaddr: base.wrapping_add(u64::from(rva)),
            name: export
                .name
                .map_or_else(|| format!("Ordinal_{}", export.ordinal.0).into(), text),
            library: library.clone(),
            nth: index + 1,
        })
        .collect()
}

/// The export directory where its data directory states a place but no size: the loader reads it
/// from its address alone (only a forwarder's test reads the size), and so does this.
fn unsized_export_table<'data, Pe: ImageNtHeaders, R: ReadRef<'data>>(
    pe: &PeFile<'data, Pe, R>,
) -> Option<object::read::pe::ExportTable<'data>> {
    let directory = pe
        .data_directories()
        .get(object::pe::IMAGE_DIRECTORY_ENTRY_EXPORT)?;
    let address = directory.virtual_address.get(LE);
    if address == 0 || directory.size.get(LE) != 0 {
        return None;
    }
    let data = pe.section_table().pe_data_at(pe.data(), address)?;
    object::read::pe::ExportTable::parse(data, address).ok()
}

/// A COFF record's `Value`, which `object` gives as no address where the record names no section:
/// an absolute record's (`SectionNumber` -1) is a value, not an address. One record read, by index.
pub(crate) fn coff_value(file: &object::File<'_>, data: &[u8], index: usize) -> Option<u64> {
    use object::read::coff::Symbol as _;
    const RECORD: usize = 18;
    let at = object::SymbolIndex(index);
    let table = match file {
        object::File::Coff(coff) => {
            return coff
                .coff_symbol_table()
                .symbol(at)
                .ok()
                .map(|record| u64::from(record.value()));
        }
        object::File::CoffBig(coff) => {
            return coff
                .coff_symbol_table()
                .symbol(at)
                .ok()
                .map(|record| u64::from(record.value()));
        }
        object::File::Pe32(pe) => pe.nt_headers().file_header.pointer_to_symbol_table.get(LE),
        object::File::Pe64(pe) => pe.nt_headers().file_header.pointer_to_symbol_table.get(LE),
        _ => return None,
    };
    // `Value` follows the record's eight-byte name.
    let start = (table as usize)
        .checked_add(index.checked_mul(RECORD)?)?
        .checked_add(8)?;
    let bytes = data.get(start..start.checked_add(4)?)?;
    Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?)))
}
