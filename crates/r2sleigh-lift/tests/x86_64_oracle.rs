//! Each x86-64 case in `x86_64_oracle/cases.txt` computes, through the trusted lift and
//! `r2il::eval`, what an x86-64 CPU computed from the same state (`x86_64_oracle/README.md`).
#![cfg(feature = "x86")]

use r2il::eval::{Flow, Mapped, State, Stop, TransferKind, step};
use r2il::{Endianness, R2ILOp, Varnode};
use r2sleigh_lift::{Disassembler, TrustedSleighProfile};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

mod oracle_common;
use oracle_common::{Stream, fnv, ratchet, same_lanes};

const MEMSZ: usize = 1024;
/// Zero bytes after the random ones (`driver.c`).
const GUARD: usize = 8192;
/// Where the scratch memory sits; far from every value the stream draws.
const MEMORY: u64 = 0x5a00_0000_0000;
const CODE: u64 = 0x0040_0000;
/// The recorder never loads RSP; the lift starts it here and must leave it.
const STACK: u64 = 0x7ff0_0000;
const GPRS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
const RSP: usize = 4;
const RSI: usize = 6;
const RDI: usize = 7;
/// The RFLAGS bits drawn and compared, each a byte register in the specification.
const FLAGS: [(u32, &str); 7] = [
    (0, "cf"),
    (2, "pf"),
    (4, "af"),
    (6, "zf"),
    (7, "sf"),
    (10, "df"),
    (11, "of"),
];
const DRAWN: u64 = 0xcd5;

#[derive(Clone)]
struct Machine {
    r: [u64; 16],
    rflags: u64,
    xmm: [u128; 16],
    memory: Vec<u8>,
}

/// The recorder's `generate` (`driver.c`), drawn in the same order.
fn generate(stream: &mut Stream, flags: &str) -> Machine {
    let mut r = [0u64; 16];
    for slot in &mut r {
        *slot = stream.pick();
    }
    let mut xmm = [0u128; 16];
    for lane in &mut xmm {
        *lane = if flags.contains('F') {
            stream.fplane()
        } else {
            let a = stream.next();
            let b = stream.next();
            u128::from(a) | (u128::from(b) << 64)
        };
    }
    let rflags = 0x202 | (stream.next() & DRAWN);
    let mut memory: Vec<u8> = (0..MEMSZ).map(|_| stream.next() as u8).collect();
    memory.resize(MEMSZ + GUARD, 0);
    let mut machine = Machine {
        r,
        rflags,
        xmm,
        memory,
    };
    shape(stream, flags, &mut machine);
    machine.r[RSP] = 0;
    machine
}

/// The flag letters' constraints on the drawn state (`cases.txt`).
fn shape(stream: &mut Stream, flags: &str, m: &mut Machine) {
    let (rax, rdx, rbx) = (0, 2, 3);
    if flags.contains('P') {
        let a = stream.next() % 16;
        let b = stream.next() % 16;
        m.r[RSI] = MEMORY + 384 + 16 * a;
        m.r[RDI] = MEMORY + 384 + 16 * b;
    }
    if flags.contains('E') && stream.next() % 2 == 1 {
        let at = (m.r[RDI] - MEMORY) as usize;
        m.memory[at..at + 8].copy_from_slice(&m.r[rax].to_le_bytes());
        m.r[rbx] = m.r[rax];
    }
    if flags.contains('N') && m.r[rbx] as u16 == 0 {
        m.r[rbx] |= 1 << (stream.next() % 16);
    }
    if flags.contains('D') {
        m.r[rdx] = 0;
        m.r[rax] &= !0xff00;
    }
    if flags.contains('S') {
        let small = (stream.next() % 128) as i64 - 64;
        m.r[rax] = small as u64;
        m.r[rdx] = if small < 0 { u64::MAX } else { 0 };
    }
    if (flags.contains('D') || flags.contains('S')) && m.r[rbx] as u8 == 0 {
        m.r[rbx] |= 1;
    }
}

/// The recorder's `input_hash`: a pointer into the memory hashes as its offset.
fn input_hash(state: &Machine) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for r in state.r {
        let r = if (MEMORY..MEMORY + MEMSZ as u64).contains(&r) {
            r - MEMORY
        } else {
            r
        };
        hash = fnv(hash, &r.to_le_bytes());
    }
    hash = fnv(hash, &state.rflags.to_le_bytes());
    for lane in state.xmm {
        hash = fnv(hash, &lane.to_le_bytes());
    }
    fnv(hash, &state.memory[..MEMSZ])
}

struct Case {
    name: String,
    flags: String,
    /// The flags and registers the SDM leaves undefined for this case (`gen.py`).
    undefined: BTreeSet<String>,
    bytes: Vec<u8>,
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
                let undefined = match fields.next().expect("undefined") {
                    "-" => BTreeSet::new(),
                    listed => listed.split(',').map(str::to_string).collect(),
                };
                let encoded = fields.next().expect("bytes");
                let bytes = (0..encoded.len())
                    .step_by(2)
                    .map(|at| hex(&encoded[at..at + 2]) as u8)
                    .collect();
                cases.push(Case {
                    name,
                    flags,
                    undefined,
                    bytes,
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
fn after(before: &Machine, changes: &str) -> Machine {
    let mut out = before.clone();
    for change in changes.split(' ').filter(|change| !change.is_empty()) {
        let (key, value) = change.split_once('=').expect("key=value");
        let (kind, index) = key.split_at(1);
        match kind {
            "r" => out.r[index.parse::<usize>().expect("r")] = hex(value),
            "p" => out.r[index.parse::<usize>().expect("p")] = MEMORY.wrapping_add(hex(value)),
            "f" => out.rflags = (out.rflags & !DRAWN) | hex(value),
            "x" => {
                out.xmm[index.parse::<usize>().expect("x")] =
                    u128::from_str_radix(value, 16).expect("xmm");
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
        // The specification spells its registers upper case.
        let register = self
            .disassembler
            .arch_spec()
            .registers
            .iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("x86-64 declares {name}"));
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

    /// Each instruction of the case lifted on its own, with its address, or why it was not.
    fn lift(&self, bytes: &[u8]) -> Result<Vec<(u64, Vec<R2ILOp>)>, String> {
        let mut padded = bytes.to_vec();
        padded.resize(bytes.len() + 16, 0);
        let whole = self
            .disassembler
            .lift_genuine_block(&padded, CODE, bytes.len())
            .map_err(|error| format!("stop lift {error}"))?;
        whole
            .instruction_spans()
            .iter()
            .map(|span| {
                let at = (span.addr() - CODE) as usize;
                self.disassembler
                    .lift_genuine_block(&padded[at..], span.addr(), span.size() as usize)
                    .map(|block| (span.addr(), block.block().ops.clone()))
                    .map_err(|error| format!("stop lift {error}"))
            })
            .collect()
    }

    /// Every way this run of the case disagrees with the CPU, or why it stopped.
    fn run(
        &self,
        case: &Case,
        lifted: &[(u64, Vec<R2ILOp>)],
        before: &Machine,
        cpu: &Machine,
    ) -> BTreeSet<String> {
        let mut state = self.start(before);
        match self.execute(case, lifted, &mut state) {
            Ok(()) => self.compare(case, &mut state, cpu),
            Err(stop) => BTreeSet::from([stop]),
        }
    }

    /// The machine as the CPU began: the drawn registers, flags, vectors and memory.
    fn start(&self, before: &Machine) -> State<impl Mapped> {
        let image = before.memory.clone();
        let mapped = move |address: u64| {
            address
                .checked_sub(MEMORY)
                .and_then(|at| image.get(usize::try_from(at).ok()?))
                .copied()
        };
        let mut state = State::new(Endianness::Little, mapped, 1 << 16).expect("machine");
        for (n, r) in before.r.iter().enumerate() {
            self.set(&mut state, GPRS[n], u128::from(*r));
        }
        self.set(&mut state, "rsp", u128::from(STACK));
        self.set(&mut state, "rip", u128::from(CODE));
        // The recorder runs at the C runtime's MXCSR, 0x1f80: round to nearest, every exception masked.
        self.set(&mut state, "mxcsr", 0x1f80);
        for (bit, flag) in FLAGS {
            self.set(&mut state, flag, u128::from((before.rflags >> bit) & 1));
        }
        for (n, lane) in before.xmm.iter().enumerate() {
            self.set(&mut state, &format!("xmm{n}"), *lane);
        }
        state
    }

    /// Runs the case's instructions until control leaves its last.
    fn execute<M: Mapped>(
        &self,
        case: &Case,
        lifted: &[(u64, Vec<R2ILOp>)],
        state: &mut State<M>,
    ) -> Result<(), String> {
        let end = CODE + case.bytes.len() as u64;
        let mut at = 0usize;
        while at < lifted.len() {
            let Some((op, flow)) = lifted[at].1.iter().find_map(|op| match step(op, state) {
                Flow::Next => None,
                flow => Some((op, flow)),
            }) else {
                state.end_instruction();
                at += 1;
                continue;
            };
            state.end_instruction();
            let Flow::Transfer(transfer) = flow else {
                return Err(self.stopped(op, flow));
            };
            if transfer.kind != TransferKind::Jump {
                return Err(self.stopped(op, flow));
            }
            if transfer.to == end {
                return Ok(());
            }
            at = lifted
                .iter()
                .position(|(address, _)| *address == transfer.to)
                .ok_or_else(|| format!("stop jump to {:#x}", transfer.to))?;
        }
        Ok(())
    }

    fn stopped(&self, op: &R2ILOp, flow: Flow) -> String {
        match flow {
            Flow::Transfer(transfer) => format!("stop {:?}", transfer.kind),
            Flow::Stop(Stop::Unmodelled) => format!("stop unmodelled {}", self.operation(op)),
            Flow::Stop(Stop::Unmapped { .. }) => "stop unmapped".to_string(),
            Flow::Stop(Stop::Unwritten { offset, .. }) => {
                format!("stop unwritten {}", self.name_at(offset))
            }
            Flow::Stop(stop) => format!("stop {stop:?}"),
            Flow::Next => unreachable!("only an operation that did not fall through is asked"),
        }
    }

    /// Every defined register, flag, vector and memory byte that differs from what the CPU left.
    fn compare<M: Mapped>(
        &self,
        case: &Case,
        state: &mut State<M>,
        cpu: &Machine,
    ) -> BTreeSet<String> {
        let mut wrong = BTreeSet::new();
        for (n, name) in GPRS.iter().enumerate() {
            let expected = if n == RSP { STACK } else { cpu.r[n] };
            let (offset, size) = self.register(name);
            if !case.undefined.contains(*name)
                && state.register(offset, size) != Some(expected.into())
            {
                wrong.insert((*name).to_string());
            }
        }
        for (bit, flag) in FLAGS {
            let (offset, size) = self.register(flag);
            let expected = u128::from((cpu.rflags >> bit) & 1);
            if !case.undefined.contains(flag) && state.register(offset, size) != Some(expected) {
                wrong.insert(flag.to_string());
            }
        }
        for (n, lane) in cpu.xmm.iter().enumerate() {
            let (offset, _) = self.register(&format!("xmm{n}"));
            if !state
                .register(offset, 16)
                .is_some_and(|lifted| same_lanes(lifted, *lane))
            {
                wrong.insert(format!("xmm{n}"));
            }
            // Legacy SSE leaves YMM's upper half as it was; the lift may not write it.
            if state.value(&Varnode::register(offset + 16, 16)).is_ok() {
                wrong.insert(format!("ymm{n} upper"));
            }
        }
        let memory_agrees = (0..MEMSZ + GUARD)
            .all(|at| state.load(MEMORY + at as u64, 1).ok() == Some(u128::from(cpu.memory[at])));
        if !memory_agrees {
            wrong.insert("memory".to_string());
        }
        wrong
            .into_iter()
            .map(|field| format!("wrong {field}"))
            .collect()
    }
}

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/x86_64_oracle")
        .join(name)
}

#[test]
fn every_case_computes_what_the_cpu_computed_or_is_listed() {
    let recording = std::fs::read_to_string(data("recorded.txt")).expect("recorded.txt");
    let lift = Lift {
        disassembler: Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
            .expect("trusted x86-64 specification"),
    };
    let mut stream = Stream(0x9e37_79b9_7f4a_7c15);
    let mut outcomes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut order = Vec::new();
    for case in cases(&recording) {
        let lifted = lift.lift(&case.bytes);
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
                    seen.extend(lift.run(&case, lifted, &before, &after(&before, changes)))
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
