//! Each AArch64 instruction in `aarch64_oracle/cases.txt` computes, through the trusted lift and
//! `r2il::eval`, what an arm64 CPU computed from the same state.
//!
//! `aarch64_oracle/record.sh` ran every case on a CPU from states drawn by one xorshift stream and
//! recorded only what changed (`recorded.txt`); this test draws the same states, checks each
//! against the recorded hash, runs the lift and compares every register, flag, vector and memory
//! byte. Cases that stop or disagree are listed in `expected.txt`, a ratchet: a case leaving it
//! must be removed from it, and a case joining it fails. `R2S_BLESS=1` rewrites it.
#![cfg(feature = "arm")]

use r2il::eval::{Flow, State, Stop, TransferKind, step};
use r2il::{Endianness, R2ILOp, Varnode};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const MEMSZ: usize = 1024;
/// Zero bytes after the random ones (`driver.c`).
const GUARD: usize = 8192;
/// Where the scratch memory sits; far from every value the stream draws.
const MEMORY: u64 = 0x5a00_0000_0000;
/// The page the cases sit in; each keeps the page offset it had on the CPU.
const CODE_PAGE: u64 = 0x0040_0000_0000;

/// The recorder's input stream (`driver.c`), drawn in the same order.
struct Stream(u64);

impl Stream {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick(&mut self) -> u64 {
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

    fn frand(&mut self) -> f64 {
        self.next() as i64 as f64 / 9.2e12
    }

    fn fbits(&mut self) -> u64 {
        u64::from((self.frand() as f32).to_bits())
    }

    fn fplane(&mut self) -> u128 {
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

const DOUBLES: [u64; 26] = [
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

const SINGLES: [u32; 22] = [
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

#[derive(Clone)]
struct Machine {
    x: [u64; 31],
    nzcv: u64,
    v: [u128; 32],
    memory: Vec<u8>,
    taken: bool,
}

fn generate(stream: &mut Stream, flags: &str) -> Machine {
    let mut x = [0u64; 31];
    for slot in &mut x {
        *slot = stream.pick();
    }
    let mut v = [0u128; 32];
    for lane in &mut v {
        *lane = if flags.contains('F') {
            stream.fplane()
        } else {
            let a = stream.next();
            let b = stream.next();
            u128::from(a) | (u128::from(b) << 64)
        };
    }
    let nzcv = (stream.next() & 0xf) << 28;
    let mut memory: Vec<u8> = (0..MEMSZ).map(|_| stream.next() as u8).collect();
    memory.resize(MEMSZ + GUARD, 0);
    if flags.contains('P') {
        let a = stream.next() % 16;
        let b = stream.next() % 16;
        x[9] = MEMORY + 384 + 16 * a;
        x[10] = MEMORY + 384 + 16 * b;
    }
    let small = (stream.next() % 33) as i64 - 16;
    if flags.contains('I') {
        x[11] = small as u64;
    }
    if flags.contains('J') {
        x[11] = if stream.next() % 2 == 1 {
            small as u64
        } else {
            (stream.next() << 32) | (small as u64 & 0xffff_ffff)
        };
    }
    if flags.contains('U') {
        let hi = stream.next() << 32;
        x[11] = hi | (stream.next() % 17);
    }
    if flags.contains('E') && stream.next() % 2 == 1 {
        let at = (x[9] - MEMORY) as usize;
        memory[at..at + 8].copy_from_slice(&x[0].to_le_bytes());
        memory[at + 8..at + 16].copy_from_slice(&x[1].to_le_bytes());
    }
    x[18] = 0;
    Machine {
        x,
        nzcv,
        v,
        memory,
        taken: false,
    }
}

fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The recorder's `input_hash`: a pointer into the memory hashes as its offset.
fn input_hash(state: &Machine) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for x in state.x {
        let x = if (MEMORY..MEMORY + MEMSZ as u64).contains(&x) {
            x - MEMORY
        } else {
            x
        };
        hash = fnv(hash, &x.to_le_bytes());
    }
    hash = fnv(hash, &state.nzcv.to_le_bytes());
    for lane in state.v {
        hash = fnv(hash, &lane.to_le_bytes());
    }
    fnv(hash, &state.memory[..MEMSZ])
}

struct Case {
    name: String,
    flags: String,
    code: u64,
    target: u64,
    words: Vec<u32>,
    runs: Vec<(u64, String)>,
}

fn hex(text: &str) -> u64 {
    u64::from_str_radix(text, 16).unwrap_or_else(|_| panic!("hex {text}"))
}

fn cases(text: &str) -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    for line in text.lines() {
        let mut fields = line.split(' ');
        match fields.next() {
            Some("C") => {
                let name = fields.next().expect("name").to_string();
                let flags = fields.next().expect("flags").to_string();
                let code = CODE_PAGE + hex(fields.next().expect("page offset"));
                let target = code
                    .wrapping_add_signed(fields.next().expect("target").parse().expect("offset"));
                let words = fields.map(|word| hex(word) as u32).collect();
                cases.push(Case {
                    name,
                    flags,
                    code,
                    target,
                    words,
                    runs: Vec::new(),
                });
            }
            Some("R") => {
                let hash = hex(fields.next().expect("hash"));
                let changes = fields.collect::<Vec<_>>().join(" ");
                cases.last_mut().expect("a case").runs.push((hash, changes));
            }
            _ => panic!("unexpected recording line {line}"),
        }
    }
    cases
}

/// What the CPU left: the input with the recorded changes applied.
fn after(case: &Case, before: &Machine, changes: &str) -> Machine {
    let mut out = before.clone();
    for change in changes.split(' ').filter(|change| !change.is_empty()) {
        if change == "t" {
            out.taken = true;
            continue;
        }
        let (key, value) = change.split_once('=').expect("key=value");
        let (kind, index) = key.split_at(1);
        match kind {
            "x" => out.x[index.parse::<usize>().expect("x")] = hex(value),
            "p" => out.x[index.parse::<usize>().expect("p")] = MEMORY.wrapping_add(hex(value)),
            "c" => {
                out.x[index.parse::<usize>().expect("c")] = case
                    .code
                    .wrapping_add_signed(value.parse().expect("distance"));
            }
            "n" => out.nzcv = hex(value) << 28,
            "v" => {
                out.v[index.parse::<usize>().expect("v")] =
                    u128::from_str_radix(value, 16).expect("vector");
            }
            "m" => {
                let at: usize = index.parse().expect("offset");
                for (n, pair) in value.as_bytes().chunks(2).enumerate() {
                    out.memory[at + n] = hex(std::str::from_utf8(pair).expect("ascii")) as u8;
                }
            }
            _ => panic!("unknown change {change}"),
        }
    }
    out
}

struct Lift {
    disassembler: Disassembler,
}

impl Lift {
    fn register(&self, name: &str) -> (u64, u32) {
        // The specification spells the flags upper case and the general registers lower case.
        let register = self
            .disassembler
            .arch_spec()
            .registers
            .iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("AArch64 declares {name}"));
        (register.offset, register.size)
    }

    /// The smallest register holding `offset`.
    fn name_at(&self, offset: u64) -> String {
        self.disassembler
            .arch_spec()
            .registers
            .iter()
            .filter(|register| {
                (register.offset..register.offset + u64::from(register.size)).contains(&offset)
            })
            .min_by_key(|register| register.size)
            .map_or_else(|| format!("{offset:#x}"), |register| register.name.clone())
    }

    fn set<M: r2il::eval::Mapped>(&self, state: &mut State<M>, name: &str, value: u128) {
        let (offset, size) = self.register(name);
        state.set_register(offset, size, value).expect(name);
    }

    fn operation(&self, op: &R2ILOp) -> String {
        if let R2ILOp::CallOther { userop, .. } = op {
            let names = &self.disassembler.arch_spec().user_ops;
            return format!(
                "CALLOTHER {}",
                names.get(*userop as usize).cloned().unwrap_or_default()
            );
        }
        format!("{op:?}")
            .split([' ', '{', '('])
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// Every way this run of the case disagrees with the CPU, or why it stopped.
    fn run(
        &self,
        case: &Case,
        lifted: &[Vec<R2ILOp>],
        before: &Machine,
        cpu: &Machine,
    ) -> BTreeSet<String> {
        let image = before.memory.clone();
        let mapped = move |address: u64| {
            address
                .checked_sub(MEMORY)
                .and_then(|at| image.get(usize::try_from(at).ok()?))
                .copied()
        };
        let mut state = State::new(Endianness::Little, mapped, 1 << 16).expect("machine");
        // The specification's scratch flags (`tmpNG` and the rest) are no CPU state; they start zero.
        let scratch: Vec<String> = self
            .disassembler
            .arch_spec()
            .registers
            .iter()
            .filter(|register| register.name.to_ascii_lowercase().starts_with("tmp"))
            .map(|register| register.name.clone())
            .collect();
        for name in &scratch {
            self.set(&mut state, name, 0);
        }
        for (n, x) in before.x.iter().enumerate() {
            self.set(&mut state, &format!("x{n}"), u128::from(*x));
        }
        self.set(&mut state, "xzr", 0);
        self.set(&mut state, "sp", 0x7ff0_0000);
        self.set(&mut state, "pc", u128::from(case.code));
        self.set(&mut state, "fpcr", 0);
        self.set(&mut state, "fpsr", 0);
        for (bit, flag) in [(31, "ng"), (30, "zr"), (29, "cy"), (28, "ov")] {
            self.set(&mut state, flag, u128::from((before.nzcv >> bit) & 1));
        }
        for (n, lane) in before.v.iter().enumerate() {
            self.set(&mut state, &format!("z{n}"), *lane);
        }
        let end = case.code + 4 * case.words.len() as u64;
        let mut taken = false;
        let mut at = 0usize;
        'instructions: while at < lifted.len() {
            for op in &lifted[at] {
                match step(op, &mut state) {
                    Flow::Next => {}
                    Flow::Transfer(transfer) if transfer.kind == TransferKind::Jump => {
                        if transfer.to == case.target {
                            taken = true;
                            break 'instructions;
                        }
                        if transfer.to == end {
                            break 'instructions;
                        }
                        let within = transfer.to.wrapping_sub(case.code);
                        if within % 4 == 0 && within < 4 * lifted.len() as u64 {
                            at = (within / 4) as usize;
                            continue 'instructions;
                        }
                        return BTreeSet::from([format!("stop jump to {:#x}", transfer.to)]);
                    }
                    Flow::Transfer(transfer) => {
                        return BTreeSet::from([format!("stop {:?}", transfer.kind)]);
                    }
                    Flow::Stop(Stop::Unmodelled) => {
                        return BTreeSet::from([format!("stop unmodelled {}", self.operation(op))]);
                    }
                    Flow::Stop(Stop::Unmapped { .. }) => {
                        return BTreeSet::from(["stop unmapped".to_string()]);
                    }
                    Flow::Stop(Stop::Unwritten { offset, .. }) => {
                        return BTreeSet::from([format!(
                            "stop unwritten {}",
                            self.name_at(offset)
                        )]);
                    }
                    Flow::Stop(stop) => return BTreeSet::from([format!("stop {stop:?}")]),
                }
            }
            at += 1;
        }
        let mut wrong = BTreeSet::new();
        for n in (0..31).filter(|n| *n != 18) {
            let (offset, size) = self.register(&format!("x{n}"));
            if state.register(offset, size) != Some(u128::from(cpu.x[n])) {
                wrong.insert(format!("x{n}"));
            }
        }
        for (bit, flag) in [(31, "ng"), (30, "zr"), (29, "cy"), (28, "ov")] {
            let (offset, size) = self.register(flag);
            if state.register(offset, size) != Some(u128::from((cpu.nzcv >> bit) & 1)) {
                wrong.insert(flag.to_string());
            }
        }
        for (n, lane) in cpu.v.iter().enumerate() {
            let (offset, _) = self.register(&format!("q{n}"));
            if state.register(offset, 16) != Some(*lane) {
                wrong.insert(format!("v{n}"));
            }
            let (z, _) = self.register(&format!("z{n}"));
            if state
                .value(&Varnode::register(z + 16, 16))
                .is_ok_and(|upper| upper != 0)
            {
                wrong.insert(format!("z{n} upper"));
            }
        }
        let memory_agrees = (0..MEMSZ + GUARD)
            .all(|at| state.load(MEMORY + at as u64, 1).ok() == Some(u128::from(cpu.memory[at])));
        if !memory_agrees {
            wrong.insert("memory".to_string());
        }
        if taken != cpu.taken {
            wrong.insert("taken".to_string());
        }
        wrong
            .into_iter()
            .map(|field| format!("wrong {field}"))
            .collect()
    }
}

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/aarch64_oracle")
        .join(name)
}

#[test]
fn every_case_computes_what_the_cpu_computed_or_is_listed() {
    let recording = std::fs::read_to_string(data("recorded.txt")).expect("recorded.txt");
    let lift = Lift {
        disassembler: Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
            .expect("trusted arm64 specification"),
    };
    let mut stream = Stream(0x9e37_79b9_7f4a_7c15);
    let mut outcomes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut order = Vec::new();
    for case in cases(&recording) {
        let lifted: Result<Vec<Vec<R2ILOp>>, String> = case
            .words
            .iter()
            .enumerate()
            .map(|(n, word)| {
                let mut bytes = word.to_le_bytes().to_vec();
                bytes.resize(16, 0);
                lift.disassembler
                    .lift_genuine_block(&bytes, case.code + 4 * n as u64, 4)
                    .map(|block| block.block().ops.clone())
                    .map_err(|error| format!("stop lift {error}"))
            })
            .collect();
        let mut seen = BTreeSet::new();
        for (hash, changes) in &case.runs {
            let before = generate(&mut stream, &case.flags);
            assert_eq!(
                input_hash(&before),
                *hash,
                "{}: the input stream drifted from driver.c",
                case.name
            );
            match &lifted {
                Ok(lifted) => {
                    seen.extend(lift.run(&case, lifted, &before, &after(&case, &before, changes)))
                }
                Err(stop) => {
                    seen.insert(stop.clone());
                }
            }
        }
        if !seen.is_empty() {
            outcomes.insert(case.name.clone(), seen);
        }
        order.push(case.name);
    }
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
    let path = data("expected.txt");
    if std::env::var_os("R2S_BLESS").is_some() {
        std::fs::write(&path, &listed).expect("expected.txt");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
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
