//! A big-endian ARM ELF states its instructions' order: BE8 (`EF_ARM_BE8`)
//! keeps them little-endian, and BE32, the flag clear, reads them as its data.

fn opened(fixture: &str) -> r2image::Image {
    let path = format!(
        "{}/../../tests/fixtures/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    );
    r2image::Image::parse(std::fs::read(path).expect("the fixture")).expect("an ARM ELF")
}

#[test]
fn be8_states_little_endian_instructions_in_a_big_endian_program() {
    let arch = opened("arm_plt_lld_be8.so").arch().clone();
    assert_eq!(arch.endian, r2image::Endian::Big);
    assert_eq!(arch.instructions, Some(r2image::Endian::Little));
}

#[test]
fn be32_states_no_instruction_order_apart_from_its_data() {
    let arch = opened("arm_thumb_movw_be.o").arch().clone();
    assert_eq!(arch.endian, r2image::Endian::Big);
    assert_eq!(arch.instructions, None);
}
