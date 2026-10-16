//! A variadic body whose `va_arg` loop is bounded by a fixed parameter consumes at most that many
//! tail arguments (doc/adr-resolved-bodies.md, "Count-driven tail").

use r2source::{SourceConventionSlots, SourceRegisterSaveArea, SourceTailCount, StackAddressBase};

use crate::dense::DenseId;
use crate::graph::{BlockId, InstId, InstPayload};
use crate::save_area::SaveArea;
use crate::semantic::CompareKind;
use crate::{SSAFunction, SSAOp, SsaGraph, ValueId};

/// The longest run of register copies a value is followed through.
const COPIES: usize = 8;

/// A stack cell at entry-stack-pointer offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    at: i64,
    size: u32,
}

impl Cell {
    fn overlaps(self, at: i64, size: u32) -> bool {
        at < self.at + i64::from(self.size) && self.at < at + i64::from(size)
    }

    fn holds(self, at: i64) -> bool {
        self.at <= at && at < self.at + i64::from(self.size)
    }
}

/// What a `va_arg` loop does, in the order a block runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// The counter is set to zero.
    CounterInit,
    /// The counter steps by one.
    CounterStep,
    /// A cursor steps by one slot.
    Advance,
    /// A load through a cursor.
    Fetch,
    /// A load of a cursor's own cell: it must see the value the trip started with.
    Read,
}

/// What a path has done since it entered the loop: the cursors' steps and loads against the
/// counter's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tally {
    counting: bool,
    advances: i32,
    fetches: i32,
    stepped: bool,
    /// A cursor has stepped since the trip began.
    moved: bool,
}

/// How a value relates to the `va_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// The loaded `reg_save_area` (or `__gr_top`): an address only once an offset is added.
    Base,
    /// An address in the tail: the loaded overflow pointer, or the base and a register offset.
    Address,
}

/// The `va_list` cells the convention names, from the bound `va_start` stored.
struct List {
    base: Cell,
    offset: Cell,
    overflow: Cell,
}

/// The counter and the count the loop's header compares.
struct Bound {
    counter: Cell,
    count: Cell,
    signed: bool,
}

/// What the stores to the tracked cells are.
struct Stores {
    events: Vec<Vec<(usize, Event)>>,
    counter_init: InstId,
    count_store: (InstId, ValueId),
    overflow_init: i64,
}

struct Prover<'a> {
    function: &'a SSAFunction,
    graph: &'a SsaGraph,
    prep: &'a crate::DecompilePrepFacts,
    area: &'a SaveArea,
    observations: &'a crate::deadphi::ProvenProgramObservations,
    slots: &'a SourceConventionSlots,
    row: SourceRegisterSaveArea,
    /// The slot width: what a cursor steps by.
    width: u32,
}

/// The fixed parameter the body's `va_arg` loop is bounded by, where its machine code proves one.
/// O(insts + uses): every access to the tail must be a counted `va_arg`, or nothing is stated.
pub(crate) fn tail_count(
    function: &SSAFunction,
    graph: &SsaGraph,
    prep: &crate::DecompilePrepFacts,
    slots: &SourceConventionSlots,
    (area, observations): (&SaveArea, &crate::deadphi::ProvenProgramObservations),
) -> Option<SourceTailCount> {
    let row = slots.register_save_area()?;
    let prover = Prover {
        function,
        graph,
        prep,
        area,
        observations,
        slots,
        row,
        width: slots.argument_slots().first()?.size,
    };
    match prover.prove() {
        Ok(count) => Some(count),
        Err(why) => {
            r2il::refusal_evidence!("tail-count", "no parameter bounds the tail: {why}");
            None
        }
    }
}

impl Prover<'_> {
    fn root(&self, value: ValueId) -> Option<i64> {
        self.prep
            .entry_stack_address_root_of(value)
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset)
    }

    /// The value `value` copies, through the copies that move it between registers.
    fn source(&self, mut value: ValueId) -> ValueId {
        for _ in 0..COPIES {
            match self
                .graph
                .def_inst(value)
                .and_then(|inst| self.graph.inst(inst))
            {
                Some(inst) => match &inst.payload {
                    InstPayload::Op(SSAOp::Copy { src, .. }) => value = *src,
                    _ => break,
                },
                None => break,
            }
        }
        value
    }

    /// The operation that computes `value`, through its copies.
    fn op(&self, value: ValueId) -> Option<&SSAOp<ValueId>> {
        let inst = self.graph.inst(self.graph.def_inst(self.source(value))?)?;
        match &inst.payload {
            InstPayload::Op(op) => Some(op),
            InstPayload::Phi { .. } => None,
        }
    }

    fn size(&self, value: ValueId) -> u32 {
        self.graph.value(value).map_or(0, |value| value.var.size)
    }

    fn constant(&self, value: ValueId) -> Option<u64> {
        let (bits, _) = self.prep.views.representative_constant(value)?;
        Some(bits)
    }

    /// The cell a value was loaded whole from.
    fn loaded_from(&self, value: ValueId) -> Option<Cell> {
        let SSAOp::Load { dst, addr, .. } = self.op(value)? else {
            return None;
        };
        Some(Cell {
            at: self.root(*addr)?,
            size: self.size(*dst),
        })
    }

    /// `value` is `x + step` for an `x` loaded from `cell`.
    fn steps(&self, value: ValueId, cell: Cell, step: u64) -> bool {
        let Some(SSAOp::IntAdd { a, b, .. }) = self.op(value) else {
            return false;
        };
        [(*a, *b), (*b, *a)].into_iter().any(|(loaded, by)| {
            self.constant(by) == Some(step) && self.loaded_from(loaded) == Some(cell)
        })
    }

    /// Whether `value` is a load from the offset cell, widened or copied.
    fn offset_index(&self, mut value: ValueId, offset: Cell) -> bool {
        for _ in 0..COPIES {
            if self.loaded_from(value) == Some(offset) {
                return true;
            }
            match self.op(value) {
                Some(SSAOp::IntZExt { src, .. } | SSAOp::IntSExt { src, .. }) => value = *src,
                _ => return false,
            }
        }
        false
    }

    fn prove(&self) -> Result<SourceTailCount, String> {
        let list = self.list()?;
        let advances = self.advances(&list)?;
        let header = self.counted_loop(&advances)?;
        let bound = self.bound(header)?;
        let mut stores = self.classify_stores(&list, &bound)?;
        self.contain_cursors(&list, &bound, stores.overflow_init)?;
        self.fetches(&list, stores.overflow_init, &mut stores.events)?;
        self.check_paths(header, &stores)?;
        self.dominating(header, &stores)?;
        let parameter = self.parameter(stores.count_store.1, bound.count)?;
        Ok(SourceTailCount {
            parameter_index: u32::try_from(parameter).map_err(|_| "a parameter index")?,
            width_bytes: bound.count.size,
            signed: bound.signed,
        })
    }

    fn list(&self) -> Result<List, String> {
        let bound = self.area.stored_at;
        let list = List {
            base: Cell {
                at: bound,
                size: self.width,
            },
            offset: Cell {
                at: bound + self.row.offset_field,
                size: self.row.offset_width,
            },
            overflow: Cell {
                at: bound + self.row.stack_field,
                size: self.width,
            },
        };
        let cells = [list.base, list.offset, list.overflow];
        for (index, one) in cells.iter().enumerate() {
            if cells[index + 1..]
                .iter()
                .any(|other| one.overlaps(other.at, other.size))
            {
                return Err("the va_list cells overlap".into());
            }
        }
        Ok(list)
    }

    /// The area `va_start` saved the registers to.
    fn saved(&self) -> Cell {
        let slots = u32::try_from(self.slots.argument_slots().len()).unwrap_or(u32::MAX);
        Cell {
            at: self.area.base,
            size: self.width.saturating_mul(slots),
        }
    }

    /// The blocks that step a cursor by one slot.
    fn advances(&self, list: &List) -> Result<Vec<BlockId>, String> {
        let mut blocks = Vec::new();
        for inst in &self.graph.insts {
            let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
                continue;
            };
            let Some(at) = self.root(*addr) else {
                continue;
            };
            let size = self.size(*val);
            for cursor in [list.offset, list.overflow] {
                if !cursor.overlaps(at, size) {
                    continue;
                }
                if self.steps(*val, cursor, self.width.into()) {
                    blocks.push(inst.block);
                } else if self.constant(*val).is_none() {
                    r2il::refusal_evidence!(
                        "tail-count",
                        "a store to {cursor:?} is no step: {:?} defined by {:?}",
                        val,
                        self.op(*val)
                    );
                }
            }
        }
        match blocks.is_empty() {
            true => Err("no cursor steps".into()),
            false => Ok(blocks),
        }
    }

    /// The header of the innermost loop holding every step, whose only exit leaves from the
    /// header and which no block returns from.
    fn counted_loop(&self, advances: &[BlockId]) -> Result<u64, String> {
        let addrs = advances
            .iter()
            .map(|block| self.graph.block(*block).map(|block| block.addr))
            .collect::<Option<Vec<_>>>()
            .ok_or("a step has no block")?;
        let natural = self
            .function
            .natural_loops()
            .iter()
            .filter(|natural| addrs.iter().all(|addr| natural.body.contains(addr)))
            .min_by_key(|natural| natural.body.len())
            .ok_or("no loop holds every step")?;
        let cfg = self.function.cfg();
        for block in &natural.body {
            let successors = cfg.successors(*block);
            if successors.is_empty() {
                return Err(format!("block {block:#x} of the loop ends the function"));
            }
            if *block != natural.header && successors.iter().any(|s| !natural.body.contains(s)) {
                return Err(format!(
                    "block {block:#x} leaves the loop beside its header"
                ));
            }
        }
        Ok(natural.header)
    }

    /// The counter and the count the header compares: the loop continues while the counter is
    /// below the count, or differs from it, so the counter never passes the count.
    fn bound(&self, header: u64) -> Result<Bound, String> {
        let predicates =
            crate::semantic::collect_predicate_facts(self.function, Some(self.prep), self.graph);
        let fact = (predicates.predicates.values())
            .find(|fact| fact.block_addr == header)
            .ok_or("the header branches on nothing")?;
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        let continues = match (
            natural.body.contains(&fact.true_target),
            natural.body.contains(&fact.false_target),
        ) {
            (true, false) => true,
            (false, true) => false,
            _ => return Err("the header's branch does not leave the loop".into()),
        };
        let header_block =
            (self.graph.block_id_for_addr(header)).ok_or("the header has no block")?;
        let in_header = |value: ValueId| {
            (self.graph.def_inst(value))
                .and_then(|inst| self.graph.inst(inst))
                .is_some_and(|inst| inst.block == header_block)
        };
        for compare in [&fact.comparison, &fact.evaluated_comparison]
            .into_iter()
            .flatten()
        {
            let (below, above, equality) = match (compare.kind, continues) {
                (CompareKind::Less | CompareKind::SignedLess, true) => {
                    (compare.lhs, compare.rhs, false)
                }
                (CompareKind::LessEqual | CompareKind::SignedLessEqual, false) => {
                    (compare.rhs, compare.lhs, false)
                }
                (CompareKind::NotEqual, true) | (CompareKind::Equal, false) => {
                    (compare.lhs, compare.rhs, true)
                }
                _ => continue,
            };
            if !in_header(below) || !in_header(above) {
                continue;
            }
            let (Some(first), Some(second)) = (self.loaded_from(below), self.loaded_from(above))
            else {
                continue;
            };
            // An equality names no order, so the counter is the cell the body steps by one.
            let swap = equality && !self.stepped(first) && self.stepped(second);
            let (counter, count) = if swap {
                (second, first)
            } else {
                (first, second)
            };
            if counter.size != count.size || counter.overlaps(count.at, count.size) {
                continue;
            }
            return Ok(Bound {
                counter,
                count,
                signed: matches!(
                    compare.kind,
                    CompareKind::SignedLess | CompareKind::SignedLessEqual
                ),
            });
        }
        Err("the header compares no counter below a count".into())
    }

    /// Whether the body stores `cell + 1` back to `cell`.
    fn stepped(&self, cell: Cell) -> bool {
        self.graph.insts.iter().any(|inst| {
            let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
                return false;
            };
            self.root(*addr) == Some(cell.at) && self.steps(*val, cell, 1)
        })
    }

    /// Every store to a tracked cell is `va_start`'s, a cursor's step, the counter's, or the one
    /// that keeps the count; anything else refuses.
    fn classify_stores(&self, list: &List, bound: &Bound) -> Result<Stores, String> {
        let mut events = vec![Vec::new(); self.graph.blocks.len()];
        let saved = self.saved();
        let next = self.area.base
            + i64::from(self.width) * i64::try_from(self.area.named).unwrap_or(0)
            - self.area.bound;
        let mut counter_inits = Vec::new();
        let mut count_stores = Vec::new();
        let mut overflow_inits = Vec::new();
        let (mut base_inits, mut offset_inits) = (0, 0);
        for cell in [bound.counter, bound.count] {
            for tracked in [list.base, list.offset, list.overflow, saved] {
                if tracked.overlaps(cell.at, cell.size) {
                    return Err("the counter or the count sits in the va_list or its area".into());
                }
            }
        }
        for inst in &self.graph.insts {
            let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
                continue;
            };
            let Some(at) = self.root(*addr) else {
                continue;
            };
            let size = self.size(*val);
            let mut note = |event| events[inst.block.index()].push((inst.ordinal, event));
            let exact = |cell: Cell| cell.at == at && cell.size == size;
            if saved.overlaps(at, size) {
                if !self.area.saved.contains(self.prep.views.copy_root(*val)) {
                    return Err(format!(
                        "the area is written at {at:#x} beside the entry saves"
                    ));
                }
            } else if list.base.overlaps(at, size) {
                if !exact(list.base) || self.root(*val) != Some(self.area.bound) {
                    return Err("the area's bound is written other than by va_start".into());
                }
                base_inits += 1;
            } else if list.overflow.overlaps(at, size) {
                if !exact(list.overflow) {
                    return Err("the overflow pointer is written in part".into());
                }
                match (
                    self.steps(*val, list.overflow, self.width.into()),
                    self.root(*val),
                ) {
                    (true, _) => note(Event::Advance),
                    (false, Some(first)) => overflow_inits.push(first),
                    _ => return Err("the overflow pointer is set to something else".into()),
                }
            } else if list.offset.overlaps(at, size) {
                let wide = at == list.offset.at && size > list.offset.size;
                if exact(list.offset) && self.steps(*val, list.offset, self.width.into()) {
                    note(Event::Advance);
                } else if (exact(list.offset) || wide) && self.sets_offset(*val, list.offset, next)
                {
                    offset_inits += 1;
                } else {
                    return Err("the offset is written other than by va_start or a step".into());
                }
            } else if bound.counter.overlaps(at, size) {
                if !exact(bound.counter) {
                    return Err("the counter is written in part".into());
                }
                if self.constant(*val) == Some(0) {
                    note(Event::CounterInit);
                    counter_inits.push(inst.id);
                } else if self.steps(*val, bound.counter, 1) {
                    note(Event::CounterStep);
                } else {
                    return Err("the counter is set to something but zero or a step".into());
                }
            } else if bound.count.overlaps(at, size) {
                if !exact(bound.count) {
                    return Err("the count is written in part".into());
                }
                count_stores.push((inst.id, *val));
            }
        }
        let (&[counter_init], &[count_store], &[overflow_init]) =
            (&counter_inits[..], &count_stores[..], &overflow_inits[..])
        else {
            return Err(
                "the counter, the count or the overflow pointer is not set exactly once".into(),
            );
        };
        if base_inits != 1 || offset_inits != 1 {
            return Err("the va_list's base or offset is not set exactly once".into());
        }
        Ok(Stores {
            events,
            counter_init,
            count_store,
            overflow_init,
        })
    }

    /// Whether a constant store holds `next` in the offset field, alone or as the low bytes of a
    /// wider word.
    fn sets_offset(&self, value: ValueId, offset: Cell, next: i64) -> bool {
        let Some((bits, size)) = self.prep.views.representative_constant(value) else {
            return false;
        };
        let mask = u64::MAX >> (64 - 8 * offset.size.clamp(1, 8));
        size >= offset.size && bits & mask == next.cast_unsigned() & mask
    }

    /// No address into the cells or the area is used beyond loading and storing at it, bar the two
    /// stores `va_start` makes of the area's base and of the first stack argument's address, so
    /// nothing else writes a cell and nothing reads the tail without a cursor.
    fn contain_cursors(
        &self,
        list: &List,
        bound: &Bound,
        overflow_init: i64,
    ) -> Result<(), String> {
        let spans = [
            list.base,
            list.offset,
            list.overflow,
            bound.counter,
            bound.count,
            self.saved(),
        ];
        for value in &self.graph.values {
            let Some(at) = self.root(value.id) else {
                continue;
            };
            if !spans.iter().any(|span| span.holds(at)) && at < overflow_init {
                continue;
            }
            for site in self.graph.use_sites(value.id) {
                let inst = self
                    .graph
                    .inst(site.inst)
                    .ok_or("a use has no instruction")?;
                let allowed = match &inst.payload {
                    InstPayload::Op(SSAOp::Load { addr, .. }) => *addr == value.id,
                    InstPayload::Op(SSAOp::Store { addr, val, .. }) => {
                        *addr == value.id
                            || (*val == value.id
                                && self
                                    .root(*addr)
                                    .is_some_and(|to| to == list.base.at || to == list.overflow.at))
                    }
                    InstPayload::Op(
                        SSAOp::Copy { .. } | SSAOp::IntAdd { .. } | SSAOp::IntSub { .. },
                    ) => inst.output.is_some_and(|out| self.root(out).is_some()),
                    _ => false,
                };
                if !allowed {
                    return Err(format!(
                        "an address into the va_list or its area at {at:#x} is used by {:?}",
                        inst.payload
                    ));
                }
            }
        }
        Ok(())
    }

    /// Every load through a cursor reads the next slot: the base indexed by the register offset, or
    /// the overflow pointer itself, and nothing else holds a cursor's value. The loads are events.
    fn fetches(
        &self,
        list: &List,
        overflow_init: i64,
        events: &mut [Vec<(usize, Event)>],
    ) -> Result<(), String> {
        let saved = self.saved();
        let unnamed = i64::from(self.width) * i64::try_from(self.area.named).unwrap_or(0);
        let mut tail = vec![None; self.graph.values.len()];
        let mut pending = Vec::new();
        for inst in &self.graph.insts {
            let InstPayload::Op(SSAOp::Load { addr, .. }) = &inst.payload else {
                continue;
            };
            let (Some(at), Some(out)) = (self.root(*addr), inst.output) else {
                continue;
            };
            let size = self.size(out);
            let cell = Cell { at, size };
            if saved.overlaps(at, size) && at >= self.area.base + unnamed || at >= overflow_init {
                return Err(format!("the tail is read at {at:#x} without a cursor"));
            }
            if cell == list.base {
                tail[out.index()] = Some(Tail::Base);
                pending.push(out);
            } else if cell == list.overflow {
                events[inst.block.index()].push((inst.ordinal, Event::Read));
                tail[out.index()] = Some(Tail::Address);
                pending.push(out);
            } else if list.offset.overlaps(at, size) {
                if cell != list.offset {
                    return Err("the offset is read in part".into());
                }
                events[inst.block.index()].push((inst.ordinal, Event::Read));
            } else if list.base.overlaps(at, size) || list.overflow.overlaps(at, size) {
                return Err("a cursor pointer is read in part".into());
            }
        }
        let mut fetched = crate::dense::IdSet::<InstId>::new(self.graph.insts.len());
        while let Some(value) = pending.pop() {
            let kind = tail[value.index()].ok_or("an untagged cursor value")?;
            for site in self.graph.use_sites(value) {
                let inst = self
                    .graph
                    .inst(site.inst)
                    .ok_or("a use has no instruction")?;
                // A use nothing observes (the flags an `add` sets) reads no slot.
                let unobserved = inst
                    .output
                    .is_some_and(|out| !self.observations.contains(out));
                if unobserved && !matches!(inst.payload, InstPayload::Op(SSAOp::Load { .. })) {
                    continue;
                }
                let mut tag = |out: ValueId, kind: Tail, pending: &mut Vec<ValueId>| {
                    if tail[out.index()].is_none() {
                        tail[out.index()] = Some(kind);
                        pending.push(out);
                    }
                };
                match &inst.payload {
                    InstPayload::Op(SSAOp::Load { addr, dst, .. }) if *addr == value => {
                        if kind == Tail::Base || self.size(*dst) > self.width {
                            return Err("a cursor is loaded through other than a slot".into());
                        }
                        if fetched.insert(inst.id) {
                            events[inst.block.index()].push((inst.ordinal, Event::Fetch));
                        }
                    }
                    InstPayload::Op(SSAOp::Copy { dst, src }) if *src == value => {
                        tag(*dst, kind, &mut pending);
                    }
                    InstPayload::Phi { .. } if kind == Tail::Address => {
                        let out = inst.output.ok_or("a phi without an output")?;
                        tag(out, Tail::Address, &mut pending);
                    }
                    InstPayload::Op(SSAOp::IntAdd { dst, a, b }) => {
                        let other = if *a == value { *b } else { *a };
                        match kind {
                            Tail::Base if self.offset_index(other, list.offset) => {
                                tag(*dst, Tail::Address, &mut pending);
                            }
                            Tail::Address
                                if self.constant(other) == Some(self.width.into())
                                    && self.only_stored_to(*dst, list.overflow) => {}
                            _ => {
                                return Err(format!(
                                    "a {kind:?} cursor is added {:?} defined by {:?}",
                                    other,
                                    self.op(other)
                                ));
                            }
                        }
                    }
                    other => {
                        return Err(format!("a cursor value is used by {other:?}"));
                    }
                }
            }
        }
        for inst in &self.graph.insts {
            if let (InstPayload::Phi { .. }, Some(out)) = (&inst.payload, inst.output)
                && tail[out.index()] == Some(Tail::Address)
                && self
                    .graph
                    .inputs(inst.id)
                    .iter()
                    .any(|input| tail[input.index()] != Some(Tail::Address))
            {
                return Err("an address merges with a value that is no cursor".into());
            }
        }
        Ok(())
    }

    /// Whether every use of `value`, through copies, stores it whole to `cell`.
    fn only_stored_to(&self, value: ValueId, cell: Cell) -> bool {
        let mut pending = vec![value];
        let mut seen = crate::dense::IdSet::<ValueId>::new(self.graph.values.len());
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            for site in self.graph.use_sites(value) {
                let Some(inst) = self.graph.inst(site.inst) else {
                    return false;
                };
                match &inst.payload {
                    InstPayload::Op(SSAOp::Copy { dst, .. }) => pending.push(*dst),
                    InstPayload::Op(SSAOp::Store { addr, val, .. })
                        if *val == value && self.root(*addr) == Some(cell.at) => {}
                    _ => return false,
                }
            }
        }
        true
    }

    /// Every path from the header back to it steps the counter once, and each cursor step and
    /// load through a cursor is one the counter paid for, so the loop reads no more slots than the
    /// counter passes: an invariant each block's recorded tally is checked against, once per edge.
    fn check_paths(&self, header: u64, stores: &Stores) -> Result<(), String> {
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        let header_block = self
            .graph
            .block_id_for_addr(header)
            .ok_or("no header block")?;
        let blocks = self.graph.blocks.len();
        let in_loop = (0..blocks)
            .map(|index| {
                (self.graph.block(BlockId::from_index(index)))
                    .is_some_and(|block| natural.body.contains(&block.addr))
            })
            .collect::<Vec<_>>();
        for (index, events) in stores.events.iter().enumerate() {
            for (_, event) in events {
                let ok = match event {
                    Event::CounterInit => !in_loop[index],
                    _ => in_loop[index] && index != header_block.index(),
                };
                if !ok {
                    return Err(format!("{event:?} sits outside its place in the loop"));
                }
            }
        }
        let mut seen: Vec<Option<Tally>> = vec![None; blocks];
        let entry = self.graph.entry;
        seen[entry.index()] = Some(Tally {
            counting: false,
            advances: 0,
            fetches: 0,
            stepped: false,
            moved: false,
        });
        // Each block is expanded once, on its first arrival; a later arrival must carry the same tally.
        let mut pending = vec![entry];
        while let Some(block) = pending.pop() {
            let mut tally = seen[block.index()].ok_or("a block without a tally")?;
            let mut events = stores.events[block.index()].clone();
            events.sort_by_key(|(ordinal, _)| *ordinal);
            for (_, event) in events {
                match event {
                    Event::CounterInit if !tally.counting => tally.counting = true,
                    Event::CounterStep if tally.counting && !tally.stepped => {
                        tally.advances -= 1;
                        tally.fetches -= 1;
                        tally.stepped = true;
                    }
                    Event::Advance if tally.counting => {
                        tally.advances += 1;
                        tally.moved = true;
                    }
                    Event::Fetch if tally.counting => tally.fetches += 1,
                    Event::Read if tally.counting && !tally.moved => {}
                    _ => return Err(format!("{event:?} runs out of order")),
                }
            }
            let successors = &self.graph.block(block).ok_or("no block")?.successors;
            for next in successors {
                let mut onward = tally;
                if *next == header_block {
                    if in_loop[block.index()] {
                        if !tally.stepped {
                            return Err("a trip does not step the counter".into());
                        }
                        onward.stepped = false;
                        onward.moved = false;
                    } else if !tally.counting {
                        return Err("the loop is entered before its counter is set".into());
                    }
                }
                match seen[next.index()] {
                    None => {
                        seen[next.index()] = Some(onward);
                        pending.push(*next);
                    }
                    Some(before) if before == onward => {}
                    Some(_) => return Err("paths reach a block with different tallies".into()),
                }
            }
        }
        Ok(())
    }

    /// The counter is zeroed and the count kept before the loop runs.
    fn dominating(&self, header: u64, stores: &Stores) -> Result<(), String> {
        let natural =
            (self.function.natural_loops().get(header)).ok_or("the header has no loop")?;
        for store in [stores.counter_init, stores.count_store.0] {
            let addr = (self.graph.inst(store))
                .and_then(|inst| self.graph.block(inst.block))
                .map(|block| block.addr)
                .ok_or("a store has no block")?;
            if natural.body.contains(&addr) || !self.function.dominates(addr, header) {
                return Err("the counter or the count is not set before the loop".into());
            }
        }
        Ok(())
    }

    /// The register slot the count was stored from.
    fn parameter(&self, stored: ValueId, count: Cell) -> Result<usize, String> {
        let mut value = self.source(self.prep.views.copy_root(stored));
        for _ in 0..COPIES {
            if self.graph.caller_supplied(value) {
                let storage = self
                    .graph
                    .formal_projection_storage(value)
                    .or_else(|| self.graph.value(value).and_then(|v| v.canonical_storage))
                    .ok_or("the count is no register")?;
                let slot = self
                    .slots
                    .argument_slots()
                    .iter()
                    .position(|slot| {
                        slot.space == storage.space
                            && slot.offset == storage.offset
                            && storage.size >= count.size
                    })
                    .ok_or("the count is no argument register")?;
                return match slot < self.area.named {
                    true => Ok(slot),
                    false => Err("the count is a tail register".into()),
                };
            }
            match self.op(value) {
                Some(SSAOp::Subpiece { src, offset: 0, .. }) => value = self.source(*src),
                _ => break,
            }
        }
        Err("the count is not a named parameter's entry value".into())
    }
}
