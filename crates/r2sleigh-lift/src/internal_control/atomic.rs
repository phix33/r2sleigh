//! A specification's atomic bracket (`AtomicBegin`/`AtomicEnd`, `LOCK`/`UNLOCK`) as one `Atomic`
//! access, else `IndivisibleAccess`; run after `skips`, each trace refusing past [`DEPTH`].

use std::collections::BTreeMap;

use r2il::{
    AtomicAccess, AtomicFetchOp, AtomicUpdate, MemoryOrdering, R2ILBlock, R2ILOp, SpaceId, Varnode,
};

use super::{InstructionTempAllocator, constant_value, last_writer, same};

/// Definitions a trace follows before it refuses.
const DEPTH: usize = 8;

/// Which specification's bracket opens the access, which fixes its ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Bracket {
    /// AArch64's `MemAtomic`, ordered by the acquire and release marks around it.
    Arm,
    /// x86's locked operation, ordered with every other (SDM Vol. 3A 9.2.2): sequentially consistent.
    Lock,
}

impl Bracket {
    pub(super) fn opening(name: &str) -> Option<Self> {
        match name {
            "AtomicBegin" => Some(Self::Arm),
            "LOCK" => Some(Self::Lock),
            _ => None,
        }
    }

    fn closing(self) -> &'static str {
        match self {
            Self::Arm => "AtomicEnd",
            Self::Lock => "UNLOCK",
        }
    }
}

/// How a value relates to the value read, at the access's width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Exact,
    ZeroExtended,
    SignExtended,
}

/// The bracket's operations and where the trace reads them.
struct Region<'a> {
    ops: &'a [R2ILOp],
    /// The first load, where the typed access goes; nothing written before it reads the cell.
    first: usize,
    addr: &'a Varnode,
    bytes: u32,
    /// The register space's byte order, which places a truncated register read.
    big_endian: bool,
}

impl Region<'_> {
    /// The operation that last wrote exactly `varnode` before `at`, at or after the first load.
    fn writer(&self, varnode: &Varnode, at: usize) -> Writer<'_> {
        match last_writer(self.ops, at, varnode) {
            Some(index) if index >= self.first => match self.ops[index].output() {
                Some(output) if output == varnode => Writer::Op(index, &self.ops[index]),
                Some(output) if self.truncates(output, varnode) => {
                    Writer::Low(index, &self.ops[index], output)
                }
                _ => Writer::Partial,
            },
            _ => Writer::Before,
        }
    }

    /// Whether `part` is the register `whole`'s low bytes, as Sleigh places a truncation.
    fn truncates(&self, whole: &Varnode, part: &Varnode) -> bool {
        let low = match self.big_endian {
            false => part.offset == whole.offset,
            true => part.offset + u64::from(part.size) == whole.offset + u64::from(whole.size),
        };
        whole.space == SpaceId::Register
            && part.space == SpaceId::Register
            && part.size < whole.size
            && low
    }

    fn reads_cell(&self, op: &R2ILOp) -> bool {
        matches!(op, R2ILOp::Load { addr, space: SpaceId::Ram, dst } if same(addr, self.addr) && dst.size == self.bytes)
    }

    /// How `varnode` at `at` holds the value read, where it does.
    fn view(&self, varnode: &Varnode, at: usize, depth: usize) -> Option<View> {
        let depth = depth.checked_sub(1)?;
        let (index, op) = match self.writer(varnode, at) {
            Writer::Op(index, op) => (index, op),
            Writer::Low(index, _, whole) if varnode.size == self.bytes => {
                return self.view(whole, index + 1, depth).map(|_| View::Exact);
            }
            _ => return None,
        };
        match op {
            op if self.reads_cell(op) => Some(View::Exact),
            R2ILOp::Copy { src, .. } => self.view(src, index, depth),
            R2ILOp::Subpiece {
                dst,
                src,
                offset: 0,
            } if dst.size == self.bytes => self.view(src, index, depth).map(|_| View::Exact),
            R2ILOp::IntZExt { src, .. } => {
                (self.view(src, index, depth)? == View::Exact).then_some(View::ZeroExtended)
            }
            R2ILOp::IntSExt { src, .. } => {
                (self.view(src, index, depth)? == View::Exact).then_some(View::SignExtended)
            }
            _ => None,
        }
    }

    /// Whether `varnode` at `at` may depend on the value read; past [`DEPTH`] it is taken to.
    fn reads_old(&self, varnode: &Varnode, at: usize, depth: usize) -> bool {
        match self.writer(varnode, at) {
            Writer::Before => false,
            Writer::Partial => true,
            Writer::Op(index, op) | Writer::Low(index, op, _) => {
                let Some(depth) = depth.checked_sub(1) else {
                    return true;
                };
                op.is_memory_read()
                    || op
                        .inputs()
                        .into_iter()
                        .any(|input| self.reads_old(input, index, depth))
            }
        }
    }

    /// `varnode`'s value at `at`, computed again before the first load where the bracket wrote it.
    fn materialize(
        &self,
        varnode: &Varnode,
        at: usize,
        depth: usize,
        out: &mut Recomputed,
    ) -> Option<Varnode> {
        let (index, op) = match self.writer(varnode, at) {
            Writer::Before => return Some(varnode.clone()),
            Writer::Partial => return None,
            Writer::Op(index, op) => (index, op),
            Writer::Low(index, _, whole) => {
                let whole = self.materialize(whole, index + 1, depth.checked_sub(1)?, out)?;
                let low = out.temps.allocate(varnode.size)?;
                out.prelude.push(R2ILOp::Subpiece {
                    dst: low.clone(),
                    src: whole,
                    offset: 0,
                });
                return Some(low);
            }
        };
        let depth = depth.checked_sub(1)?;
        if !op.is_speculatable_value() || self.reads_old(varnode, at, DEPTH) {
            return None;
        }
        let mut clone = op.clone();
        let inputs = op
            .inputs()
            .into_iter()
            .map(|input| self.materialize(input, index, depth, out))
            .collect::<Option<Vec<_>>>()?;
        for (slot, input) in clone.inputs_mut().into_iter().zip(inputs) {
            *slot = input;
        }
        let fresh = out.temps.allocate(varnode.size)?;
        *clone.output_mut()? = fresh.clone();
        out.prelude.push(clone);
        Some(fresh)
    }

    /// `varnode` at `at` as an operand of the access's width: itself, or the low part of a value
    /// no part of which reads the cell.
    fn operand(&self, varnode: &Varnode, at: usize, out: &mut Recomputed) -> Option<Varnode> {
        let value = self.materialize(varnode, at, DEPTH, out)?;
        if value.size == self.bytes {
            return Some(value);
        }
        if value.size < self.bytes {
            return None;
        }
        let low = out.temps.allocate(self.bytes)?;
        out.prelude.push(R2ILOp::Subpiece {
            dst: low.clone(),
            src: value,
            offset: 0,
        });
        Some(low)
    }

    /// The fetch that writes `stored` back, read at `at`: `old op operand` where the operand reads
    /// no part of the cell, or the operand alone.
    fn fetch(
        &self,
        stored: &Varnode,
        at: usize,
        out: &mut Recomputed,
    ) -> Option<(AtomicFetchOp, Varnode)> {
        if !self.reads_old(stored, at, DEPTH) {
            return Some((AtomicFetchOp::Swap, self.operand(stored, at, out)?));
        }
        let (mut index, mut op) = match self.writer(stored, at) {
            Writer::Op(index, op) | Writer::Low(index, op, _) => (index, op),
            _ => return None,
        };
        while let R2ILOp::Copy { src, .. } = op
            && let Writer::Op(from, copied) = self.writer(src, index)
        {
            (index, op) = (from, copied);
        }
        // The low bytes of a wider sum, difference or bitwise result are those of the old value's.
        if let R2ILOp::Subpiece { src, offset: 0, .. } = op
            && src.size > self.bytes
            && let Writer::Op(wide, wider) = self.writer(src, index)
        {
            (index, op) = (wide, wider);
        }
        if let Some(found) = self.min_max(op, index, out) {
            return Some(found);
        }
        let (fetch, a, b, commutes) = match op {
            R2ILOp::IntAdd { a, b, .. } => (AtomicFetchOp::Add, a, b, true),
            R2ILOp::IntSub { a, b, .. } => (AtomicFetchOp::Sub, a, b, false),
            R2ILOp::IntAnd { a, b, .. } => (AtomicFetchOp::And, a, b, true),
            R2ILOp::IntOr { a, b, .. } => (AtomicFetchOp::Or, a, b, true),
            R2ILOp::IntXor { a, b, .. } => (AtomicFetchOp::Xor, a, b, true),
            _ => return None,
        };
        let other = match (self.view(a, index, DEPTH), self.view(b, index, DEPTH)) {
            (Some(_), _) => b,
            (None, Some(_)) if commutes => a,
            _ => return None,
        };
        (!self.reads_old(other, index, DEPTH)).then_some(())?;
        Some((fetch, self.operand(other, index, out)?))
    }

    /// The specification's select-by-multiplication, `zext(c1) * x1 + zext(c2) * x2`, where `c1`
    /// and `c2` are complementary comparisons of the old value and an operand at one extension.
    fn min_max(
        &self,
        op: &R2ILOp,
        at: usize,
        out: &mut Recomputed,
    ) -> Option<(AtomicFetchOp, Varnode)> {
        let R2ILOp::IntAdd { a, b, .. } = op else {
            return None;
        };
        let (a, b) = (self.selected(a, at)?, self.selected(b, at)?);
        self.ordered_min_max(a, b, at, out)
            .or_else(|| self.ordered_min_max(b, a, at, out))
    }

    /// [`Self::min_max`] with `c1` the strict comparison.
    fn ordered_min_max(
        &self,
        (c1, x1): (&Varnode, &Varnode),
        (c2, x2): (&Varnode, &Varnode),
        at: usize,
        out: &mut Recomputed,
    ) -> Option<(AtomicFetchOp, Varnode)> {
        let (strict, data, value, signed) = self.comparison(c1, at)?;
        let (inclusive, low, high, signed_too) = self.comparison(c2, at)?;
        // `data > value` picks x1, `data <= value` picks x2.
        let picks_data_when_greater = match (same(x1, data), same(x1, value)) {
            (true, false) => true,
            (false, true) => false,
            _ => return None,
        };
        let other = if picks_data_when_greater { value } else { data };
        if !(strict
            && !inclusive
            && signed == signed_too
            && same(low, data)
            && same(high, value)
            && same(x2, other))
        {
            return None;
        }
        let (old, operand) = match (self.view(data, at, DEPTH), self.view(value, at, DEPTH)) {
            (Some(view), None) => (view, value),
            _ => return None,
        };
        let (core, extension, read_at) = self.extension(operand, at)?;
        if old != extension || self.reads_old(&core, read_at, DEPTH) {
            return None;
        }
        // A zero-extended pair compares as unsigned at the access's width, whichever comparison.
        let signed = signed && old != View::ZeroExtended;
        let fetch = match (picks_data_when_greater, signed) {
            (true, true) => AtomicFetchOp::SignedMax,
            (true, false) => AtomicFetchOp::UnsignedMax,
            (false, true) => AtomicFetchOp::SignedMin,
            (false, false) => AtomicFetchOp::UnsignedMin,
        };
        Some((fetch, self.operand(&core, read_at, out)?))
    }

    /// `zext(c) * x`, either way round.
    fn selected<'r>(&'r self, product: &Varnode, at: usize) -> Option<(&'r Varnode, &'r Varnode)> {
        let Writer::Op(index, R2ILOp::IntMult { a, b, .. }) = self.writer(product, at) else {
            return None;
        };
        let condition = |side: &Varnode| match self.writer(side, index) {
            Writer::Op(_, R2ILOp::IntZExt { src, .. }) if src.size == 1 => Some(src),
            _ => None,
        };
        match (condition(a), condition(b)) {
            (Some(c), None) => Some((c, b)),
            (None, Some(c)) => Some((c, a)),
            _ => None,
        }
    }

    /// `(strict, greater, lesser, signed)` for `lesser < greater`, or `(false, lesser, greater, signed)`
    /// for `lesser <= greater`.
    fn comparison<'r>(
        &'r self,
        condition: &Varnode,
        at: usize,
    ) -> Option<(bool, &'r Varnode, &'r Varnode, bool)> {
        let Writer::Op(_, op) = self.writer(condition, at) else {
            return None;
        };
        match op {
            R2ILOp::IntSLess { a, b, .. } => Some((true, b, a, true)),
            R2ILOp::IntLess { a, b, .. } => Some((true, b, a, false)),
            R2ILOp::IntSLessEqual { a, b, .. } => Some((false, a, b, true)),
            R2ILOp::IntLessEqual { a, b, .. } => Some((false, a, b, false)),
            _ => None,
        }
    }

    /// The access-width value `varnode` extends, or `varnode` itself at that width, and where
    /// that value is read.
    fn extension(&self, varnode: &Varnode, at: usize) -> Option<(Varnode, View, usize)> {
        if varnode.size == self.bytes {
            return Some((varnode.clone(), View::Exact, at));
        }
        let Writer::Op(index, op) = self.writer(varnode, at) else {
            return None;
        };
        let (src, view) = match op {
            R2ILOp::IntZExt { src, .. } => (src, View::ZeroExtended),
            R2ILOp::IntSExt { src, .. } => (src, View::SignExtended),
            _ => return None,
        };
        (src.size == self.bytes).then(|| (src.clone(), view, index))
    }

    /// The expected value of a compare-and-exchange whose store `guard` allows, and where it is
    /// read: `old == e`, `!(old != e)`, the difference of the two `== 0`, or a flag holding one.
    fn expected(&self, guard: &Varnode, at: usize) -> Option<(Varnode, usize)> {
        self.expected_within(guard, at, DEPTH)
    }

    fn expected_within(
        &self,
        guard: &Varnode,
        at: usize,
        depth: usize,
    ) -> Option<(Varnode, usize)> {
        let depth = depth.checked_sub(1)?;
        let Writer::Op(index, op) = self.writer(guard, at) else {
            return None;
        };
        match op {
            R2ILOp::Copy { src, .. } => return self.expected_within(src, index, depth),
            R2ILOp::IntEqual { a, b, .. } if a.size == 1 && constant_value(b) == Some(1) => {
                return self.expected_within(a, index, depth);
            }
            _ => {}
        }
        let pair = |a: &Varnode, b: &Varnode, at: usize| match (
            self.view(a, at, DEPTH),
            self.view(b, at, DEPTH),
        ) {
            (Some(View::Exact), None) => Some((b.clone(), at)),
            (None, Some(View::Exact)) => Some((a.clone(), at)),
            _ => None,
        };
        match op {
            R2ILOp::IntEqual { a, b, .. } if constant_value(b) == Some(0) => {
                match self.writer(a, index) {
                    Writer::Op(sub, R2ILOp::IntSub { a, b, .. }) => pair(a, b, sub),
                    _ => pair(a, b, index),
                }
            }
            R2ILOp::IntEqual { a, b, .. } => pair(a, b, index),
            R2ILOp::BoolNot { src, .. } => match self.writer(src, index) {
                Writer::Op(test, R2ILOp::IntNotEqual { a, b, .. }) => pair(a, b, test),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Who last wrote a varnode inside the bracket.
enum Writer<'a> {
    /// Nothing at or after the first load: its value is the one it held there.
    Before,
    /// An operation wrote part of it.
    Partial,
    Op(usize, &'a R2ILOp),
    /// It is the low bytes of what the operation wrote.
    Low(usize, &'a R2ILOp, &'a Varnode),
}

/// Type the instruction's one bracket, or mark it untyped; leaves a block with no whole bracket as it is.
pub(super) fn type_bracket(
    block: &mut R2ILBlock,
    bracket: Bracket,
    names: &dyn Fn(u32) -> Option<String>,
    big_endian: bool,
) {
    let named = |op: &R2ILOp, wanted: &str| matches!(op, R2ILOp::CallOther { userop, output: None, inputs } if inputs.is_empty() && names(*userop).as_deref() == Some(wanted));
    let opening = match bracket {
        Bracket::Arm => "AtomicBegin",
        Bracket::Lock => "LOCK",
    };
    let Some(open) = block.ops.iter().position(|op| named(op, opening)) else {
        return;
    };
    let Some(close) =
        (open + 1..block.ops.len()).find(|at| named(&block.ops[*at], bracket.closing()))
    else {
        return;
    };
    let typed = typed(&block.ops, (open, close), bracket, big_endian);
    block.ops = match typed {
        Some(ops) => ops,
        None => {
            let mut ops = block.ops.clone();
            ops.remove(close);
            ops[open] = R2ILOp::IndivisibleAccess;
            ops
        }
    };
    block.op_metadata = BTreeMap::new();
}

/// The bracket's accesses where they are one cell's: a first load, one store at the same address,
/// every other access a load of it, and nothing but values beside them.
struct Shape<'a> {
    region: Region<'a>,
    accesses: Vec<usize>,
    store: usize,
    /// A guarded store's value and guard.
    guarded: Option<(&'a Varnode, &'a Varnode)>,
}

fn shape(ops: &[R2ILOp], (open, close): (usize, usize), big_endian: bool) -> Option<Shape<'_>> {
    let accesses: Vec<usize> = (open + 1..close)
        .filter(|at| ops[*at].is_memory_read() || ops[*at].is_memory_write())
        .collect();
    let first = *accesses.first()?;
    let R2ILOp::Load {
        addr,
        space: SpaceId::Ram,
        ..
    } = &ops[first]
    else {
        return None;
    };
    let stores: Vec<usize> = accesses
        .iter()
        .copied()
        .filter(|at| ops[*at].is_memory_write())
        .collect();
    let [store] = stores[..] else {
        return None;
    };
    let (bytes, guarded) = match &ops[store] {
        R2ILOp::Store {
            addr: at,
            val,
            space: SpaceId::Ram,
        } if same(at, addr) => (val.size, None),
        R2ILOp::StoreGuarded {
            addr: at,
            val,
            guard,
            space: SpaceId::Ram,
            ..
        } if same(at, addr) => (val.size, Some((val, guard))),
        _ => return None,
    };
    let region = Region {
        ops,
        first,
        addr,
        bytes,
        big_endian,
    };
    // Nothing in the bracket moves the address after the first load.
    let reads_cell = accesses
        .iter()
        .filter(|at| **at != store)
        .all(|at| region.reads_cell(&ops[*at]));
    let address_moves = (first..close).any(|at| {
        ops[at]
            .output()
            .is_some_and(|output| super::overlaps(output, addr))
    });
    if !reads_cell || address_moves || (open + 1..close).any(|at| !allowed(&ops[at])) {
        return None;
    }
    Some(Shape {
        region,
        accesses,
        store,
        guarded,
    })
}

/// The instruction's operations with the bracket typed, where its accesses are one fetch or
/// compare-and-exchange of one cell.
fn typed(
    ops: &[R2ILOp],
    (open, close): (usize, usize),
    bracket: Bracket,
    big_endian: bool,
) -> Option<Vec<R2ILOp>> {
    let Shape {
        region,
        accesses,
        store,
        guarded,
    } = shape(ops, (open, close), big_endian)?;
    let (first, addr, bytes) = (region.first, region.addr, region.bytes);
    let mut out = Recomputed {
        temps: InstructionTempAllocator::for_ops(ops),
        prelude: Vec::new(),
    };
    let update = update(&region, store, guarded, &mut out)?;
    let (release, acquire, ordering) = ordering(ops, (open, close), bracket);
    let old = out.temps.allocate(bytes)?;
    let reread_after_store = accesses.iter().any(|at| *at > store);
    let new = match (&update, reread_after_store) {
        (_, false) => None,
        (AtomicUpdate::Fetch { op, operand }, true) => {
            Some(updated(*op, &old, operand, out.temps.allocate(bytes)?)?)
        }
        (AtomicUpdate::CompareExchange { .. }, true) => return None,
    };
    let access = R2ILOp::Atomic(Box::new(AtomicAccess {
        dst: old.clone(),
        space: SpaceId::Ram,
        addr: addr.clone(),
        update,
        ordering,
    }));
    let mut rewritten = Vec::with_capacity(ops.len() + out.prelude.len() + 2);
    for (at, op) in ops.iter().enumerate() {
        match at {
            _ if at == open || at == close || Some(at) == release || Some(at) == acquire => {}
            _ if at == store => {}
            _ if at == first => {
                rewritten.append(&mut out.prelude);
                rewritten.push(access.clone());
                rewritten.extend(new.iter().cloned());
                rewritten.push(copy_of(op, &old));
            }
            _ if at > open && at < close && accesses.contains(&at) => {
                let from = if at < store {
                    &old
                } else {
                    new.as_ref()?.output()?
                };
                rewritten.push(copy_of(op, from));
            }
            _ => rewritten.push(op.clone()),
        }
    }
    Some(rewritten)
}

/// The operands recomputed before the access, and the temporaries they and it take.
struct Recomputed {
    temps: InstructionTempAllocator,
    prelude: Vec<R2ILOp>,
}

/// What the bracket's one store writes back: a fetch, or a compare-and-exchange where it is guarded.
fn update(
    region: &Region<'_>,
    store: usize,
    guarded: Option<(&Varnode, &Varnode)>,
    out: &mut Recomputed,
) -> Option<AtomicUpdate> {
    let Some((replacement, guard)) = guarded else {
        let R2ILOp::Store { val, .. } = &region.ops[store] else {
            return None;
        };
        let (op, operand) = region.fetch(val, store, out)?;
        return Some(AtomicUpdate::Fetch { op, operand });
    };
    let (expected, read_at) = region.expected(guard, store)?;
    if region.reads_old(&expected, read_at, DEPTH) || region.reads_old(replacement, store, DEPTH) {
        return None;
    }
    Some(AtomicUpdate::CompareExchange {
        expected: region.operand(&expected, read_at, out)?,
        replacement: region.operand(replacement, store, out)?,
    })
}

/// The release fence before the bracket and the acquire fence after it, and the ordering they
/// make; x86's LOCK is sequentially consistent on its own.
fn ordering(
    ops: &[R2ILOp],
    (open, close): (usize, usize),
    bracket: Bracket,
) -> (Option<usize>, Option<usize>, MemoryOrdering) {
    if bracket == Bracket::Lock {
        return (None, None, MemoryOrdering::SeqCst);
    }
    let fence =
        |at: &usize, wanted| matches!(ops[*at], R2ILOp::Fence { ordering } if ordering == wanted);
    let release = (0..open).find(|at| fence(at, MemoryOrdering::Release));
    let acquire = (close + 1..ops.len()).find(|at| fence(at, MemoryOrdering::Acquire));
    let ordering = match (release.is_some(), acquire.is_some()) {
        (true, true) => MemoryOrdering::AcqRel,
        (true, false) => MemoryOrdering::Release,
        (false, true) => MemoryOrdering::Acquire,
        (false, false) => MemoryOrdering::Relaxed,
    };
    (release, acquire, ordering)
}

/// What the bracket may hold beside its accesses: values, which run whichever way it goes.
fn allowed(op: &R2ILOp) -> bool {
    op.is_memory_read() || op.is_memory_write() || op.is_speculatable_value()
}

/// `dst = old op operand`, the value the cell holds after the fetch.
fn updated(op: AtomicFetchOp, old: &Varnode, operand: &Varnode, dst: Varnode) -> Option<R2ILOp> {
    let (a, b) = (old.clone(), operand.clone());
    Some(match op {
        AtomicFetchOp::Add => R2ILOp::IntAdd { dst, a, b },
        AtomicFetchOp::Sub => R2ILOp::IntSub { dst, a, b },
        AtomicFetchOp::And => R2ILOp::IntAnd { dst, a, b },
        AtomicFetchOp::Or => R2ILOp::IntOr { dst, a, b },
        AtomicFetchOp::Xor => R2ILOp::IntXor { dst, a, b },
        AtomicFetchOp::Swap => R2ILOp::Copy { dst, src: b },
        _ => return None,
    })
}

/// A load of the cell, now a copy of what the access read or wrote.
fn copy_of(load: &R2ILOp, from: &Varnode) -> R2ILOp {
    let dst = load.output().cloned().unwrap_or_else(|| from.clone());
    R2ILOp::Copy {
        dst,
        src: from.clone(),
    }
}
