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

fn main_entry(image: &r2image::Image) -> Option<u64> {
    (image.entry_points().iter())
        .find(|entry| entry.kind == r2image::EntryKind::Main)
        .map(|entry| entry.vaddr)
}

#[test]
fn raw_data_reads_from_0x200_to_file_alignment_and_stops_at_virtual_size() {
    let image = image(include_bytes!("data/pe_rounded.exe"));
    let byte = |vaddr: u64| image.read(vaddr, 1).map(|bytes| bytes[0]);
    assert_eq!(
        byte(0x401000),
        Some(0xaa),
        "PointerToRawData 0x205 reads from 0x200"
    );
    assert_eq!(
        byte(0x401100),
        Some(0xcc),
        "the raw data runs to FileAlignment"
    );
    assert_eq!(
        byte(0x401190),
        Some(0),
        "past VirtualSize the page holds zeros"
    );
    assert_eq!(
        byte(0x401fff),
        Some(0),
        "the section spans its SectionAlignment"
    );
}

#[test]
fn a_null_virtual_size_means_the_raw_size() {
    let image = image(include_bytes!("data/pe_nullvirt.exe"));
    assert_eq!(image.sections()[0].vsize, 0x200);
    assert_eq!(main_entry(&image), Some(0x401000));
    assert_eq!(image.read(0x401000, 1).as_deref(), Some(&[0xc3][..]));
}

#[test]
fn an_exe_starts_where_its_entry_says_even_in_its_headers_and_a_dll_s_zero_is_none() {
    let exe = image(include_bytes!("data/pe_header_entry.exe"));
    assert_eq!(main_entry(&exe), Some(0x400000));
    let dll = image(include_bytes!("data/pe_dll_noentry.dll"));
    assert_eq!(main_entry(&dll), None);
}

#[test]
fn below_a_page_of_section_alignment_the_file_is_mapped_as_it_lies() {
    let image = image(include_bytes!("data/pe_flat.exe"));
    assert_eq!(main_entry(&image), Some(0x400180));
    assert_eq!(image.read(0x400180, 1).as_deref(), Some(&[0xc3][..]));
    assert_eq!(image.read(0x400000, 2).as_deref(), Some(&b"MZ"[..]));
}

#[test]
fn a_pe32_export_wraps_at_32_bits() {
    let image = image(include_bytes!("data/pe_export_wrap.dll"));
    assert_eq!(symbol(&image, "w").vaddr, 0xffffff);
}

#[test]
fn a_vc6_delay_descriptor_states_addresses() {
    let image = image(include_bytes!("data/pe_delay_vc6.exe"));
    let later = symbol(&image, "later");
    assert!(later.import);
    assert_eq!(later.vaddr, 0x401080);
    assert_eq!(later.library.as_deref(), Some("late.dll"));
}
