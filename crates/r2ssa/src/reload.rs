//! Loads that reread an exact frame slot no write has touched since an earlier load, so are its bits.
//! Along single-predecessor chains, `O(ops log slots)` (doc/adr-frame-model.md, "Reloads").

use std::collections::BTreeMap;

use crate::SSAOp;
use crate::StackAddressBase;
use crate::dense::IdMap;
use crate::function::{DecompilePrepFacts, StackAddressRoot};
use crate::graph::{BlockId, SsaGraph, ValueId};
use crate::semantic::resolve_entry_stack_root;

/// Widest access the held slots are searched for overlap at.
const WIDEST: u32 = 64;

/// Where a frame slot is within its origin, and how wide: the key a held load is found by.
type Slot = (i64, u32);

/// How many origins a frame is addressed from.
const ORIGINS: usize = 3;

const fn origin(base: StackAddressBase) -> usize {
    match base {
        StackAddressBase::FramePointer => 0,
        StackAddressBase::StackPointer => 1,
        StackAddressBase::Realigned => 2,
    }
}

/// What walking a block did to the held loads, to be undone on leaving it.
enum Undo {
    Added(usize, Slot),
    Removed(usize, Slot, ValueId),
    Dropped(usize, BTreeMap<Slot, ValueId>),
}

/// The first load of each exact frame slot on the path being walked. Not `Clone`: a branch is entered by
/// noting the trail's length and left by rewinding it (doc/adr-frame-model.md, "Reloads").
#[derive(Default)]
struct Held {
    by_origin: [BTreeMap<Slot, ValueId>; ORIGINS],
    trail: Vec<Undo>,
}

impl Held {
    fn get(&self, root: StackAddressRoot, size: u32) -> Option<ValueId> {
        self.by_origin[origin(root.base)]
            .get(&(root.offset, size))
            .copied()
    }

    fn add(&mut self, root: StackAddressRoot, size: u32, value: ValueId) {
        let (origin, slot) = (origin(root.base), (root.offset, size));
        self.by_origin[origin].insert(slot, value);
        self.trail.push(Undo::Added(origin, slot));
    }

    /// Whatever the operation may have written, or left unstated: nothing is held.
    fn clear(&mut self) {
        (0..ORIGINS).for_each(|origin| self.drop_origin(origin));
    }

    fn drop_origin(&mut self, origin: usize) {
        if !self.by_origin[origin].is_empty() {
            let table = std::mem::take(&mut self.by_origin[origin]);
            self.trail.push(Undo::Dropped(origin, table));
        }
    }

    /// What a store leaves held: an exact frame slot keeps the slots of its origin it misses and drops the
    /// other origins', any other store keeps none.
    fn store(&mut self, stored: Option<(StackAddressRoot, u32)>) {
        let Some((root, size)) = stored else {
            return self.clear();
        };
        let mine = origin(root.base);
        (0..ORIGINS)
            .filter(|origin| *origin != mine)
            .for_each(|origin| self.drop_origin(origin));
        // An older slot reaches `WIDEST` bytes past its offset, so nothing before that overlaps.
        let low = root.offset.saturating_sub(i64::from(WIDEST));
        let high = root.offset.saturating_add(i64::from(size));
        let overlapped = (self.by_origin[mine].range((low, 0)..(high, 0)))
            .filter(|((offset, width), _)| {
                let end = |at: i64, size: u32| at.saturating_add(i64::from(size));
                *offset < end(root.offset, size) && root.offset < end(*offset, *width)
            })
            .map(|(slot, value)| (*slot, *value))
            .collect::<Vec<_>>();
        for (slot, value) in overlapped {
            self.by_origin[mine].remove(&slot);
            self.trail.push(Undo::Removed(mine, slot, value));
        }
    }

    /// Undo everything done since the trail was `mark` long.
    fn rewind(&mut self, mark: usize) {
        while self.trail.len() > mark {
            match self.trail.pop() {
                Some(Undo::Added(origin, slot)) => _ = self.by_origin[origin].remove(&slot),
                Some(Undo::Removed(origin, slot, value)) => {
                    self.by_origin[origin].insert(slot, value);
                }
                Some(Undo::Dropped(origin, table)) => self.by_origin[origin] = table,
                None => return,
            }
        }
    }
}

/// A block to walk, or the point to rewind to when its subtree is done.
enum Visit {
    Enter(BlockId),
    Leave(usize),
}

/// The graph walked, and the rereads found so far.
struct Rereads<'a> {
    graph: &'a SsaGraph,
    prep: Option<&'a DecompilePrepFacts>,
    found: IdMap<ValueId, ValueId>,
}

/// For each load that rereads a slot unchanged, the value of the load it rereads.
pub(crate) fn reloads(
    graph: &SsaGraph,
    prep: Option<&DecompilePrepFacts>,
) -> IdMap<ValueId, ValueId> {
    let mut rereads = Rereads {
        graph,
        prep,
        found: IdMap::new(graph.values.len()),
    };
    if prep.is_none() {
        return rereads.found;
    }
    let sole_predecessor = |block: BlockId| match graph.blocks[block.0 as usize].predecessors[..] {
        [only] if only != block => Some(only),
        _ => None,
    };
    // A sole-predecessor block continues its parent's slots, the rest start empty: each block is entered
    // once, and the table is empty again when its tree is left.
    let mut held = Held::default();
    let mut pending: Vec<Visit> = (graph.blocks.iter())
        .filter(|block| sole_predecessor(block.id).is_none())
        .map(|block| Visit::Enter(block.id))
        .collect();
    while let Some(visit) = pending.pop() {
        let block = match visit {
            Visit::Enter(block) => block,
            Visit::Leave(mark) => {
                held.rewind(mark);
                continue;
            }
        };
        pending.push(Visit::Leave(held.trail.len()));
        for &inst in graph.op_insts(block) {
            let (Some(op), Some(node)) = (graph.op(inst), graph.inst(inst)) else {
                continue;
            };
            rereads.step(op, node.output, &mut held);
        }
        let mut children = (graph.blocks[block.0 as usize].successors.iter())
            .copied()
            .filter(|child| sole_predecessor(*child) == Some(block))
            .collect::<Vec<_>>();
        children.sort_unstable();
        children.dedup();
        pending.extend(children.into_iter().map(Visit::Enter));
    }
    rereads.found
}

impl Rereads<'_> {
    fn step(&mut self, op: &SSAOp<ValueId>, output: Option<ValueId>, held: &mut Held) {
        let (graph, prep) = (self.graph, self.prep);
        let slot = |addr: ValueId, space: r2il::SpaceId| {
            (space == r2il::SpaceId::Ram)
                .then(|| resolve_entry_stack_root(prep, addr))
                .flatten()
        };
        match op {
            SSAOp::Load { space, addr, .. } => {
                let (Some(root), Some(out)) = (slot(*addr, *space), output) else {
                    return;
                };
                let size = graph.value(out).map_or(0, |value| value.var.size);
                if size == 0 || size > WIDEST {
                    return;
                }
                match held.get(root, size) {
                    Some(first) => {
                        self.found.insert(out, first);
                    }
                    None => held.add(root, size, out),
                }
            }
            SSAOp::Store { space, addr, val } => {
                let size = graph.value(*val).map_or(0, |value| value.var.size);
                let wide = size > 0 && size <= WIDEST;
                held.store(
                    slot(*addr, *space)
                        .filter(|_| wide)
                        .map(|root| (root, size)),
                );
            }
            op if clobbers(op) => held.clear(),
            _ => {}
        }
    }
}

/// Whether the operation may write memory the frame holds, or leave what a load reads unstated.
fn clobbers(op: &SSAOp<ValueId>) -> bool {
    op.is_memory_write()
        || op.is_call()
        || matches!(
            op,
            SSAOp::CallOther { .. }
                | SSAOp::Fence { .. }
                | SSAOp::ClearExclusive
                | SSAOp::IndivisibleAccess
                | SSAOp::BlockTransfer(_)
                | SSAOp::Unimplemented
                | SSAOp::LoadLinked { .. }
                | SSAOp::LoadGuarded { .. }
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(base: StackAddressBase, offset: i64) -> StackAddressRoot {
        StackAddressRoot { base, offset }
    }

    fn sp(offset: i64) -> StackAddressRoot {
        root(StackAddressBase::StackPointer, offset)
    }

    #[test]
    fn leaving_a_branch_restores_what_it_cleared_stored_over_and_added() {
        let mut held = Held::default();
        held.add(sp(0x10), 4, ValueId(1));
        held.add(sp(0x20), 4, ValueId(2));
        let mark = held.trail.len();
        held.store(Some((sp(0x12), 4)));
        assert_eq!(held.get(sp(0x10), 4), None);
        assert_eq!(held.get(sp(0x20), 4), Some(ValueId(2)));
        held.clear();
        held.add(sp(0x30), 4, ValueId(3));
        held.rewind(mark);
        assert_eq!(held.get(sp(0x10), 4), Some(ValueId(1)));
        assert_eq!(held.get(sp(0x20), 4), Some(ValueId(2)));
        assert_eq!(held.get(sp(0x30), 4), None);
    }

    #[test]
    fn a_store_drops_exactly_the_slots_it_overlaps_and_the_other_origins() {
        let mut held = Held::default();
        let frame = |offset| root(StackAddressBase::FramePointer, offset);
        held.add(sp(0x0c), 4, ValueId(1));
        held.add(sp(0x08), 8, ValueId(2));
        held.add(sp(0x14), 4, ValueId(3));
        held.add(sp(0x00), 64, ValueId(4));
        held.add(frame(0x10), 4, ValueId(5));
        held.store(Some((sp(0x10), 4)));
        let kept = [(0x0c, 4), (0x14, 4), (0x08, 8), (0x00, 64)]
            .map(|(offset, size)| held.get(sp(offset), size));
        // The first is clear of the store; the second and third are adjacent to it or end at it; only the last reaches in.
        assert_eq!(
            kept,
            [Some(ValueId(1)), Some(ValueId(3)), Some(ValueId(2)), None]
        );
        assert_eq!(held.get(frame(0x10), 4), None);
    }
}
