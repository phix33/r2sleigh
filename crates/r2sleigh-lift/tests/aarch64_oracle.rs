//! Each AArch64 case in `aarch64_oracle/cases.txt` computes, through the trusted lift and
//! `r2il::eval`, what an arm64 CPU computed from the same state (`aarch64_oracle/README.md`).
#![cfg(feature = "arm")]

use r2il::eval::{Flow, Mapped, State, Stop, TransferKind, step};
use r2il::{Endianness, R2ILOp, Varnode};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

mod oracle_common;
use oracle_common::{Lane, Stream, assembly, fnv, ratchet, same_lanes};

const MEMSZ: usize = 1024;
/// Zero bytes after the random ones (`driver.c`).
const GUARD: usize = 8192;
/// Where the scratch memory sits; far from every value the stream draws.
const MEMORY: u64 = 0x5a00_0000_0000;
/// The page the cases sit in; each keeps the page offset it had on the CPU.
const CODE_PAGE: u64 = 0x0040_0000_0000;

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
    /// The float result lanes the case writes, by vector register.
    produced: BTreeMap<usize, Vec<Lane>>,
}

/// The float result lanes `asm` writes, by vector register: `h`, `s` or `d` lane 0, `vN.<k><t>`
/// every lane, `vN.<t>[i]` lane i. A move, select, compare or integer conversion produces no float.
fn produced(asm: &str) -> BTreeMap<usize, Vec<Lane>> {
    let mut out: BTreeMap<usize, Vec<Lane>> = BTreeMap::new();
    for inst in asm.split(';').map(str::trim) {
        let (mnemonic, operands) = inst.split_once(' ').unwrap_or((inst, ""));
        let integer = mnemonic.len() == 6
            && mnemonic.starts_with("fcvt")
            && mnemonic[4..5].contains(['a', 'm', 'n', 'p', 'z'])
            && mnemonic[5..].contains(['s', 'u']);
        let moves = ["fmov", "fcsel", "fcm", "fccmp"];
        if !mnemonic.starts_with('f') || integer || moves.iter().any(|m| mnemonic.starts_with(m)) {
            continue;
        }
        let destination = operands.split(',').next().unwrap_or("").trim();
        if let Some((n, lanes)) = float_lanes(destination) {
            out.entry(n).or_default().extend(lanes);
        }
    }
    out
}

/// A float destination operand's register and lanes: `d3`, `v0.4s` or `v1.d[1]`.
fn float_lanes(operand: &str) -> Option<(usize, Vec<Lane>)> {
    let width = |t: &str| match t {
        "h" => Some(16),
        "s" => Some(32),
        "d" => Some(64),
        _ => None,
    };
    let Some((register, arrangement)) = operand.split_once('.') else {
        let (t, n) = operand.split_at_checked(1)?;
        return Some((n.parse().ok()?, vec![(width(t)?, 0)]));
    };
    let n = register.strip_prefix('v')?.parse().ok()?;
    if let Some((t, lane)) = arrangement.split_once('[') {
        return Some((n, vec![(width(t)?, lane.strip_suffix(']')?.parse().ok()?)]));
    }
    let (count, t) = arrangement.split_at_checked(arrangement.len().checked_sub(1)?)?;
    let (bits, count) = (width(t)?, count.parse::<u32>().ok()?);
    Some((n, (0..count).map(|lane| (bits, lane)).collect()))
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
                    produced: BTreeMap::new(),
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

/// The flags and the NZCV bit each is.
const FLAGS: [(u32, &str); 4] = [(31, "ng"), (30, "zr"), (29, "cy"), (28, "ov")];

/// What follows an operation that did not fall through.
enum Next {
    Instruction(usize),
    Done { taken: bool },
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

    fn set<M: Mapped>(&self, state: &mut State<M>, name: &str, value: u128) {
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
        let mut state = self.start(case, before);
        match self.execute(case, lifted, &mut state) {
            Ok(taken) => self.compare(case, &mut state, cpu, taken),
            Err(stop) => BTreeSet::from([stop]),
        }
    }

    /// The machine as the CPU began: the drawn registers, flags, vectors and memory.
    fn start(&self, case: &Case, before: &Machine) -> State<impl Mapped> {
        let image = before.memory.clone();
        let mapped = move |address: u64| {
            address
                .checked_sub(MEMORY)
                .and_then(|at| image.get(usize::try_from(at).ok()?))
                .copied()
        };
        let mut state = State::new(Endianness::Little, mapped, 1 << 16).expect("machine");
        // The specification's scratch flags (`tmpNG` and the rest) are no CPU state; they start zero.
        let registers = &self.disassembler.arch_spec().registers;
        for register in registers
            .iter()
            .filter(|r| r.name.to_ascii_lowercase().starts_with("tmp"))
        {
            self.set(&mut state, &register.name, 0);
        }
        for (n, x) in before.x.iter().enumerate() {
            self.set(&mut state, &format!("x{n}"), u128::from(*x));
        }
        for (name, value) in [
            ("xzr", 0),
            ("sp", 0x7ff0_0000),
            ("pc", u128::from(case.code)),
            ("fpcr", 0),
            ("fpsr", 0),
        ] {
            self.set(&mut state, name, value);
        }
        for (bit, flag) in FLAGS {
            self.set(&mut state, flag, u128::from((before.nzcv >> bit) & 1));
        }
        for (n, lane) in before.v.iter().enumerate() {
            self.set(&mut state, &format!("z{n}"), *lane);
        }
        state
    }

    /// Runs the case's instructions; whether its branch was taken, or why the run stopped.
    fn execute<M: Mapped>(
        &self,
        case: &Case,
        lifted: &[Vec<R2ILOp>],
        state: &mut State<M>,
    ) -> Result<bool, String> {
        let mut at = 0usize;
        while at < lifted.len() {
            let Some((op, flow)) = lifted[at].iter().find_map(|op| match step(op, state) {
                Flow::Next => None,
                flow => Some((op, flow)),
            }) else {
                state.end_instruction();
                at += 1;
                continue;
            };
            state.end_instruction();
            match self.after(case, lifted.len(), op, flow)? {
                Next::Instruction(next) => at = next,
                Next::Done { taken } => return Ok(taken),
            }
        }
        Ok(false)
    }

    /// Where control goes after an operation that did not fall through.
    fn after(&self, case: &Case, count: usize, op: &R2ILOp, flow: Flow) -> Result<Next, String> {
        let end = case.code + 4 * count as u64;
        match flow {
            Flow::Transfer(transfer) if transfer.kind == TransferKind::Jump => {
                let within = transfer.to.wrapping_sub(case.code);
                if transfer.to == case.target || transfer.to == end {
                    Ok(Next::Done {
                        taken: transfer.to == case.target,
                    })
                } else if within % 4 == 0 && within < 4 * count as u64 {
                    Ok(Next::Instruction((within / 4) as usize))
                } else {
                    Err(format!("stop jump to {:#x}", transfer.to))
                }
            }
            Flow::Transfer(transfer) => Err(format!("stop {:?}", transfer.kind)),
            Flow::Stop(Stop::Unmodelled) => Err(format!("stop unmodelled {}", self.operation(op))),
            Flow::Stop(Stop::Unmapped { .. }) => Err("stop unmapped".to_string()),
            Flow::Stop(Stop::Unwritten { offset, .. }) => {
                Err(format!("stop unwritten {}", self.name_at(offset)))
            }
            Flow::Stop(stop) => Err(format!("stop {stop:?}")),
            Flow::Next => unreachable!("only an operation that did not fall through is asked"),
        }
    }

    /// Every register, flag, vector and memory byte that differs from what the CPU left.
    fn compare<M: Mapped>(
        &self,
        case: &Case,
        state: &mut State<M>,
        cpu: &Machine,
        taken: bool,
    ) -> BTreeSet<String> {
        let mut wrong = BTreeSet::new();
        for n in (0..31).filter(|n| *n != 18) {
            let (offset, size) = self.register(&format!("x{n}"));
            if state.register(offset, size) != Some(u128::from(cpu.x[n])) {
                wrong.insert(format!("x{n}"));
            }
        }
        for (bit, flag) in FLAGS {
            let (offset, size) = self.register(flag);
            if state.register(offset, size) != Some(u128::from((cpu.nzcv >> bit) & 1)) {
                wrong.insert(flag.to_string());
            }
        }
        for (n, lane) in cpu.v.iter().enumerate() {
            let (offset, _) = self.register(&format!("q{n}"));
            if !state.register(offset, 16).is_some_and(|lifted| {
                same_lanes(
                    lifted,
                    *lane,
                    case.produced.get(&n).map_or(&[], Vec::as_slice),
                )
            }) {
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
    let asm = assembly(&std::fs::read_to_string(data("cases.txt")).expect("cases.txt"));
    for mut case in cases(&recording) {
        case.produced = produced(&asm[&case.name]);
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
    ratchet(&order, &outcomes, &data("expected.txt"));
}
