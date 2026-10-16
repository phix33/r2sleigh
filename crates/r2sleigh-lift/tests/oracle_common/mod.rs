//! What both CPU oracles share: the input stream their recorders draw (`stream.h`), the
//! hash of an input state, lane equality open to a produced NaN's payload and the `expected.txt` ratchet.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The recorders' input stream (`stream.h`), drawn in the same order.
pub struct Stream(pub u64);

impl Stream {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn pick(&mut self) -> u64 {
        match self.next() % 13 {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => 0x8000_0000_0000_0000,
            4 => 0x7fff_ffff_ffff_ffff,
            5 => 0x8000_0000,
            6 => 0x7fff_ffff,
            7 => 0xffff_ffff,
            8 => self.next() % 64,
            9 => self.next() << 32,
            10 => self.next() as u32 as i32 as i64 as u64,
            11 => 0xffff_ffff_8000_0000,
            _ => self.next(),
        }
    }

    pub fn frand(&mut self) -> f64 {
        self.next() as i64 as f64 / 9.2e12
    }

    pub fn fbits(&mut self) -> u64 {
        u64::from((self.frand() as f32).to_bits())
    }

    pub fn fplane(&mut self) -> u128 {
        let lo = match self.next() % 4 {
            0 => DOUBLES[(self.next() % DOUBLES.len() as u64) as usize],
            1 => self.frand().to_bits(),
            2 => {
                let a = u64::from(SINGLES[(self.next() % SINGLES.len() as u64) as usize]);
                let b = u64::from(SINGLES[(self.next() % SINGLES.len() as u64) as usize]);
                a | (b << 32)
            }
            _ => {
                let a = self.fbits();
                let b = self.fbits();
                a | (b << 32)
            }
        };
        let hi = match self.next() % 3 {
            0 => DOUBLES[(self.next() % DOUBLES.len() as u64) as usize],
            1 => {
                let a = u64::from(SINGLES[(self.next() % SINGLES.len() as u64) as usize]);
                let b = u64::from(SINGLES[(self.next() % SINGLES.len() as u64) as usize]);
                a | (b << 32)
            }
            _ => self.next(),
        };
        u128::from(lo) | (u128::from(hi) << 64)
    }
}

pub const DOUBLES: [u64; 26] = [
    0,
    0x8000_0000_0000_0000,
    0x3ff0_0000_0000_0000,
    0xbff8_0000_0000_0000,
    0x4004_0000_0000_0000,
    0x3fe0_0000_0000_0000,
    0x7ff0_0000_0000_0000,
    0xfff0_0000_0000_0000,
    0x7ff8_0000_0000_0000,
    0x7ff4_0000_0000_0001,
    0x7ff8_dead_0000_beef,
    0x1,
    0x7e37_e43c_8800_759c,
    0xc3e1_58e4_6091_3d00,
    0x43e0_0000_0000_0000,
    0x43f0_0000_0000_0000,
    0xc3e0_0000_0000_0000,
    0x41e0_0000_0000_0000,
    0xc1e0_0000_0020_0000,
    0x41f0_0000_0000_0000,
    0x3fdf_ffff_ffff_ffff,
    0xc004_0000_0000_0000,
    0x400c_0000_0000_0000,
    0x3ff8_0000_0000_0000,
    0xfff8_0000_0000_0001,
    0x000f_ffff_ffff_ffff,
];

pub const SINGLES: [u32; 22] = [
    0,
    0x8000_0000,
    0x3f80_0000,
    0xbfc0_0000,
    0x4020_0000,
    0x3f00_0000,
    0x7f80_0000,
    0xff80_0000,
    0x7fc0_0000,
    0x7fa0_0001,
    0x7fc0_beef,
    1,
    0x5f00_0000,
    0xdf00_0000,
    0x4f00_0000,
    0xcf00_0001,
    0x4f80_0000,
    0x3eff_ffff,
    0xc020_0000,
    0x4060_0000,
    0x7f7f_ffff,
    0x007f_ffff,
];

pub fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// A float result lane an instruction writes: its width in bits and its index in the register.
pub type Lane = (u32, u32);

fn nan(bits: u32, x: u128) -> bool {
    match bits {
        16 => (x >> 10) & 0x1f == 0x1f && x & 0x3ff != 0,
        32 => f32::from_bits(x as u32).is_nan(),
        64 => f64::from_bits(x as u64).is_nan(),
        _ => false,
    }
}

/// Bit-equal but where both are NaNs in a `produced` lane: p-code leaves a result NaN's payload open.
pub fn same_lanes(lifted: u128, cpu: u128, produced: &[Lane]) -> bool {
    let open = produced.iter().fold(0u128, |open, &(bits, lane)| {
        let at = lane * bits;
        let mask = (u128::MAX >> (128 - bits)) << at;
        match nan(bits, (lifted & mask) >> at) && nan(bits, (cpu & mask) >> at) {
            true => open | mask,
            false => open,
        }
    });
    (lifted ^ cpu) & !open == 0
}

/// Each case's assembly by name, from a `cases.txt` (`name|flags|asm|...`).
pub fn assembly(cases: &str) -> BTreeMap<String, String> {
    cases
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| {
            let mut fields = line.split('|');
            let name = fields.next()?;
            Some((name.to_string(), fields.nth(1)?.to_string()))
        })
        .collect()
}

#[test]
fn a_nan_payload_is_open_only_in_a_produced_lane() {
    let one = 0x3ff0_0000_0000_0000u128;
    let hi = |x: u64| u128::from(x) << 64;
    let scalar = [(64, 0)];
    // A preserved upper lane keeps its NaN's payload.
    let upper = (
        one | hi(0x7ff8_0000_0000_0001),
        one | hi(0x7ff8_0000_0000_0000),
    );
    assert!(!same_lanes(upper.0, upper.1, &scalar));
    // A double whose 32-bit halves are NaNs is no NaN at its own width.
    assert!(!same_lanes(
        0x7fc0_0000_7fc0_0001,
        0x7fc0_0000_7fc0_0000,
        &scalar
    ));
    // A register no instruction writes a float into is bit-equal.
    assert!(!same_lanes(
        0x7ff8_0000_0000_0001,
        0x7ff8_0000_0000_0000,
        &[]
    ));
    let produced = (hi(5) | 0x7ff8_0000_0000_0001, hi(5) | 0xfff8_dead_0000_0000);
    assert!(same_lanes(produced.0, produced.1, &scalar));
    assert!(!same_lanes(
        hi(6) | 0x7ff8_0000_0000_0001,
        produced.1,
        &scalar
    ));
    assert!(same_lanes(0x7e00, 0x7c01, &[(16, 0)]));
    assert!(same_lanes(
        0x7fc0_0001_0000_0000,
        0xffc0_0000_0000_0000,
        &[(32, 1)]
    ));
}

/// The cases that stop or disagree, in case order, held exactly: `R2S_BLESS=1` rewrites the list.
pub fn ratchet(order: &[String], outcomes: &BTreeMap<String, BTreeSet<String>>, path: &Path) {
    let listed: String = order
        .iter()
        .filter_map(|name| {
            let seen = outcomes.get(name)?;
            Some(format!(
                "{name}: {}\n",
                seen.iter().cloned().collect::<Vec<_>>().join("; ")
            ))
        })
        .collect();
    if std::env::var_os("R2S_BLESS").is_some() {
        std::fs::write(path, &listed).expect("expected.txt");
        return;
    }
    let expected = std::fs::read_to_string(path).unwrap_or_default();
    if expected != listed {
        let old: BTreeSet<&str> = expected.lines().collect();
        let new: BTreeSet<&str> = listed.lines().collect();
        let gone: Vec<_> = old.difference(&new).collect();
        let came: Vec<_> = new.difference(&old).collect();
        panic!(
            "the oracle moved (R2S_BLESS=1 to accept)\nno longer:\n  {gone:?}\nnow:\n  {came:?}"
        );
    }
}
