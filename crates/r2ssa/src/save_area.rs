//! A variadic prologue's register save area, proven from the machine (doc/adr-resolved-bodies.md,
//! "Variadic tail").

use std::collections::BTreeSet;

use r2source::{CanonicalStorageId, SourceConventionSlots, SourceSaveAreaAnchor, StackAddressBase};

use crate::graph::{InstId, InstPayload};
use crate::{SSAOp, SsaGraph, ValueId};

/// The argument registers a body saves to its convention's register save area: the slots below
/// `named` are its fixed parameters, and the entry values it saves are no parameter reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SaveArea {
    pub(crate) named: usize,
    pub(crate) saved: crate::dense::IdSet<ValueId>,
}

/// The register save area the body fills, where its rules prove one (doc/adr-resolved-bodies.md,
/// "Variadic tail"). Positions are entry-stack-pointer offsets. O(insts + uses of the saved values).
pub(crate) fn register_save_area(
    graph: &SsaGraph,
    prep: &crate::DecompilePrepFacts,
    slots: &SourceConventionSlots,
    observations: &crate::deadphi::ProvenProgramObservations,
) -> Option<SaveArea> {
    let anchor = slots.register_save_area()?;
    let arguments = slots.argument_slots();
    let width = i64::from(arguments.first()?.size);
    if arguments.iter().any(|slot| i64::from(slot.size) != width) {
        return None;
    }
    let at_entry = |value: ValueId| {
        prep.entry_stack_address_root_of(value)
            .filter(|root| root.base == StackAddressBase::StackPointer)
            .map(|root| root.offset)
    };
    // Each slot's entry value stored at a stack position, and every address stored to memory.
    let mut saves = vec![Vec::new(); arguments.len()];
    let mut stored_addresses = BTreeSet::new();
    for inst in &graph.insts {
        let InstPayload::Op(SSAOp::Store { addr, val, .. }) = &inst.payload else {
            continue;
        };
        if let Some(offset) = at_entry(*val) {
            stored_addresses.insert(offset);
        }
        let value = prep.views.copy_root(*val);
        if let (Some(at), Some(slot)) = (at_entry(*addr), entry_slot(graph, value, arguments)) {
            saves[slot].push((at, value, inst.id));
        }
    }
    let last = arguments.len() - 1;
    let position = |slot: usize| i64::try_from(slot).ok().map(|slot| slot * width);
    for &(top, ..) in &saves[last] {
        let base = top - position(last)?;
        let saved_at = |slot: usize| {
            let at = base + position(slot).unwrap_or(i64::MAX);
            saves[slot].iter().filter(move |(offset, ..)| *offset == at)
        };
        let mut named = last;
        while named > 0 && saved_at(named - 1).next().is_some() {
            named -= 1;
        }
        // A run from slot 0 is every argument spilled in order, an aggregate of them as readily.
        if named == 0 {
            continue;
        }
        let bound = match anchor {
            SourceSaveAreaAnchor::Base => base,
            SourceSaveAreaAnchor::End => base + position(arguments.len())?,
        };
        if !stored_addresses.contains(&bound) {
            continue;
        }
        let mut saved = crate::dense::IdSet::new(graph.values.len());
        let mut stores = BTreeSet::new();
        for (_, value, store) in (named..=last).flat_map(saved_at) {
            saved.insert(*value);
            stores.insert(*store);
        }
        if saved
            .iter()
            .all(|value| read_only_by(graph, value, &stores, observations))
        {
            return Some(SaveArea { named, saved });
        }
    }
    r2il::refusal_evidence!(
        "register-save-area",
        "no save area: saves by slot {:?}, addresses stored {stored_addresses:?}",
        saves
            .iter()
            .map(|slot| slot.iter().map(|(at, ..)| *at).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    None
}

/// The argument slot `value` is the whole entry value of.
fn entry_slot(graph: &SsaGraph, value: ValueId, arguments: &[CanonicalStorageId]) -> Option<usize> {
    let entry = graph.value(value)?;
    if entry.var.version != 0 || !graph.caller_supplied(value) {
        return None;
    }
    let storage = entry.canonical_storage?;
    arguments.iter().position(|slot| *slot == storage)
}

/// Whether only `stores` read `value`, through merges and copies; a use nothing observes (`xor ecx,
/// ecx`) or a call's implicit use reads nothing (ADR "Variadic tail"). Each value is taken once.
fn read_only_by(
    graph: &SsaGraph,
    value: ValueId,
    stores: &BTreeSet<InstId>,
    observations: &crate::deadphi::ProvenProgramObservations,
) -> bool {
    let mut seen = crate::dense::IdSet::new(graph.values.len());
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                return false;
            };
            match (&inst.payload, inst.output) {
                (InstPayload::Phi { .. } | InstPayload::Op(SSAOp::Copy { .. }), output) => {
                    pending.extend(output);
                }
                (InstPayload::Op(SSAOp::CallUse { .. }), _) => {}
                (_, Some(output)) if !observations.contains(output) => {}
                _ if stores.contains(&site.inst) => {}
                _ => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};
    use r2source::{
        CanonicalStorageSpace, SourceAbiParameterSpec, SourceFunctionInterface,
        SourceFunctionReturn,
    };

    use super::*;

    const SP: u64 = 0x100;

    fn register(offset: u64) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        }
    }

    /// Three argument slots `x0`..`x2`, a `va_list` holding the byte past the area.
    fn slots() -> SourceConventionSlots {
        SourceConventionSlots::new("test", [register(0), register(8), register(16)], None)
            .expect("slots")
            .with_register_save_area(Some(SourceSaveAreaAnchor::End))
    }

    /// `sp -= 0x20`, then each `(register, sp offset)` stored, then `sp + anchor` stored to a global,
    /// and each of `read` stored to another.
    fn area(saves: &[(u64, u64)], anchor: u64, read: &[u64]) -> Option<SaveArea> {
        let mut arch = ArchSpec::new("save-area");
        arch.addr_size = 8;
        for (name, offset) in [("x0", 0), ("x1", 8), ("x2", 16), ("sp", SP), ("lr", 0x108)] {
            arch.add_register(RegisterDef::new(name, offset, 8));
        }
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntSub {
            dst: Varnode::register(SP, 8),
            a: Varnode::register(SP, 8),
            b: Varnode::constant(0x20, 8),
        });
        let mut temp = 0;
        let mut at = |block: &mut R2ILBlock, offset: u64| {
            temp += 8;
            block.push(R2ILOp::IntAdd {
                dst: Varnode::unique(temp, 8),
                a: Varnode::register(SP, 8),
                b: Varnode::constant(offset, 8),
            });
            Varnode::unique(temp, 8)
        };
        for &(saved, offset) in saves {
            let addr = at(&mut block, offset);
            block.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr,
                val: Varnode::register(saved, 8),
            });
        }
        let bound = at(&mut block, anchor);
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x9000, 8),
            val: bound,
        });
        for &register in read {
            block.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::constant(0x9008, 8),
                val: Varnode::register(register, 8),
            });
        }
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(SP, 8),
            a: Varnode::register(SP, 8),
            b: Varnode::constant(0x20, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(0x108, 8),
        });
        let interface = SourceFunctionInterface::new_exact(
            b"save-area".to_vec(),
            "test",
            [SourceAbiParameterSpec::new(0, register(0))],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("interface")
        .with_return_address_storage(register(0x108))
        .expect("return address")
        .with_stack_pointer_storage(register(SP))
        .expect("stack pointer");
        let artifact = crate::testing::prepared(
            &[block],
            &crate::Arch::from(arch),
            Some(interface),
            Vec::new(),
            [register(SP)],
        )
        .expect("prepared");
        let graph = artifact.graph();
        let live_out = crate::liveout::FunctionLiveOut::default();
        let observations =
            crate::deadphi::ProvenProgramObservations::find(graph, &live_out, artifact.facts())
                .expect("observations");
        register_save_area(
            graph,
            artifact.decompile_prep_facts(),
            &slots(),
            &observations,
        )
    }

    #[test]
    fn the_registers_past_the_named_ones_saved_in_order_below_a_stored_bound_are_a_tail() {
        let found = area(&[(8, 8), (16, 16)], 24, &[]).expect("a save area");
        assert_eq!(found.named, 1);
        assert_eq!(found.saved.len(), 2);
    }

    #[test]
    fn a_save_area_needs_its_bound_stored_a_named_slot_below_it_its_stride_and_no_other_read() {
        let saves = [(8, 8), (16, 16)];
        assert_eq!(area(&saves, 16, &[]), None, "no bound stored");
        assert_eq!(
            area(&[(0, 0), (8, 8), (16, 16)], 24, &[]),
            None,
            "every slot saved"
        );
        assert_eq!(area(&[(8, 16), (16, 8)], 24, &[]), None, "out of order");
        assert_eq!(area(&saves, 24, &[16]), None, "a saved register read again");
    }
}
