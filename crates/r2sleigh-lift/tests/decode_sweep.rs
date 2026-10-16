//! Every embedded language lifts deterministic random bytes without taking the
//! process down: a decode may refuse, never fault (libflutter's `vldm`, #278).

const WORDS: usize = 50_000;

fn sweep(name: &str) {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ name.len() as u64;
    let mut window = [0u8; 16];
    for at in (0..WORDS as u64).map(|i| 0x10_0000 + 4 * i) {
        for chunk in window.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        let _ = machine.disasm.lift(&window, at);
    }
}

#[cfg(feature = "x86")]
#[test]
fn x86_lifts_random_bytes_without_faulting() {
    sweep("x86-64");
    sweep("x86");
}

#[cfg(feature = "arm")]
#[test]
fn arm_lifts_random_bytes_without_faulting() {
    sweep("aarch64");
    sweep("arm");
    sweep("arm-thumb");
    sweep("arm-be");
    sweep("arm-thumb-be");
}

#[cfg(feature = "riscv")]
#[test]
fn riscv_lifts_random_bytes_without_faulting() {
    sweep("riscv64");
}
