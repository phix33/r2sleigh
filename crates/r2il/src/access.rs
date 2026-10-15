//! Which registers one instruction's operations read and write.
//!
//! A read is a register whose value on entry the instruction's effects use:
//! bytes an earlier operation wrote are its own result (`EDX = ZEXT(..);
//! RDX = ZEXT(EDX)` reads no `edx`), and a value computed into a temporary
//! nothing uses is no effect (`nop dword [rax + rax]` reads no `rax`).
//! Overlapping accesses are one register, the widest range they cover.
//! Cost: O(n · r) over the operations and the distinct ranges they touch.

use crate::opcode::R2ILOp;
use crate::space::SpaceId;
use crate::varnode::Varnode;

/// The registers an instruction reads on entry and the registers it writes,
/// each a register-space range in the order the operations first touch it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisterAccesses {
    pub reads: Vec<Varnode>,
    pub writes: Vec<Varnode>,
}

/// What `ops`, one instruction's operations in order, read and write in the register space;
/// `None` where one is `Unimplemented`, whose accesses nothing states.
///
/// A local branch can skip a write or repeat a use, so past one nothing is killed and nothing dropped.
pub fn register_accesses(ops: &[R2ILOp]) -> Option<RegisterAccesses> {
    if ops.iter().any(|op| matches!(op, R2ILOp::Unimplemented)) {
        return None;
    }
    let straight_line = !ops.iter().any(local_branch);
    let used = match straight_line {
        true => effective(ops),
        false => vec![true; ops.len()],
    };
    let mut accesses = RegisterAccesses::default();
    let mut killed: Vec<(u64, u64)> = Vec::new();
    for op in ops
        .iter()
        .zip(used)
        .filter_map(|(op, used)| used.then_some(op))
    {
        for input in op.inputs() {
            if input.space == SpaceId::Register && !covered(&killed, range(input)) {
                merge(&mut accesses.reads, input);
            }
        }
        if let Some(output) = op.output().filter(|vn| vn.space == SpaceId::Register) {
            merge(&mut accesses.writes, output);
            if straight_line {
                killed.push(range(output));
            }
        }
    }
    Some(accesses)
}

/// Whether each operation reaches an effect: one backward pass, a value into a
/// temporary dropped where nothing after it reads that temporary.
fn effective(ops: &[R2ILOp]) -> Vec<bool> {
    let mut needed: Vec<(u64, u64)> = Vec::new();
    let mut used = vec![true; ops.len()];
    for (index, op) in ops.iter().enumerate().rev() {
        let dead = op.is_speculatable_value()
            && op.output().is_some_and(|out| {
                out.space == SpaceId::Unique && !overlaps_any(&needed, range(out))
            });
        if dead {
            used[index] = false;
            continue;
        }
        let temporaries = op
            .inputs()
            .into_iter()
            .filter(|vn| vn.space == SpaceId::Unique);
        needed.extend(temporaries.map(range));
    }
    used
}

fn overlaps_any(ranges: &[(u64, u64)], (start, end): (u64, u64)) -> bool {
    ranges.iter().any(|&(from, to)| from < end && start < to)
}

/// `ranges`, disjoint, with each maximal run of adjacent ones that exactly fills
/// a register `declared` names joined into it, at its first member's place:
/// `movups` writing four lanes of `xmm6` writes `xmm6`. O(r log r).
pub fn join_tiles(ranges: Vec<Varnode>, declared: impl Fn(&Varnode) -> bool) -> Vec<Varnode> {
    let mut order: Vec<usize> = (0..ranges.len()).collect();
    order.sort_by_key(|&index| ranges[index].offset);
    let mut joined: Vec<Option<Varnode>> = ranges.into_iter().map(Some).collect();
    let mut start = 0;
    while start < order.len() {
        let mut end = start + 1;
        let mut reach = joined[order[start]].as_ref().map_or(0, |vn| range(vn).1);
        while let Some(next) = order.get(end).and_then(|&index| joined[index].as_ref()) {
            if next.offset != reach {
                break;
            }
            reach = range(next).1;
            end += 1;
        }
        let run = &order[start..end];
        let first = run.iter().copied().min().unwrap_or(order[start]);
        let offset = joined[order[start]].as_ref().map_or(0, |vn| vn.offset);
        let size = u32::try_from(reach - offset).unwrap_or(u32::MAX);
        let whole = Varnode::new(SpaceId::Register, offset, size);
        if run.len() > 1 && declared(&whole) {
            for &index in run {
                joined[index] = None;
            }
            joined[first] = Some(whole);
        }
        start = end;
    }
    joined.into_iter().flatten().collect()
}

/// A branch to an operation of the same instruction: Sleigh states its target in the constant space.
fn local_branch(op: &R2ILOp) -> bool {
    matches!(
        op,
        R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } if target.space == SpaceId::Const
    )
}

fn range(vn: &Varnode) -> (u64, u64) {
    (vn.offset, vn.offset.saturating_add(u64::from(vn.size)))
}

/// Whether the written ranges cover every byte of `wanted`.
fn covered(written: &[(u64, u64)], wanted: (u64, u64)) -> bool {
    let (mut from, end) = wanted;
    // Each pass moves `from` past one range, so at most `written.len()` passes.
    while from < end {
        match written
            .iter()
            .find(|(start, stop)| *start <= from && from < *stop)
        {
            Some((_, stop)) => from = *stop,
            None => return false,
        }
    }
    true
}

/// Add `vn` to `found`, joined with every entry it overlaps at the first one's place.
///
/// The entries are disjoint, so the ranges `vn` overlaps and `vn` itself cover one interval.
fn merge(found: &mut Vec<Varnode>, vn: &Varnode) {
    let (mut start, mut end) = range(vn);
    let overlapping: Vec<usize> = (0..found.len())
        .filter(|&index| {
            let (from, to) = range(&found[index]);
            from < end && start < to
        })
        .collect();
    let Some(&first) = overlapping.first() else {
        found.push(vn.clone());
        return;
    };
    for &index in &overlapping {
        let (from, to) = range(&found[index]);
        (start, end) = (start.min(from), end.max(to));
    }
    let size = u32::try_from(end - start).unwrap_or(u32::MAX);
    found[first] = Varnode::new(SpaceId::Register, start, size);
    for &index in overlapping[1..].iter().rev() {
        found.remove(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn unique(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Unique, offset, size)
    }

    #[test]
    fn a_register_written_before_it_is_read_is_not_read() {
        // movzx edx, byte [rdi]: EDX = ZEXT(load); RDX = ZEXT(EDX).
        let ops = [
            R2ILOp::Load {
                dst: unique(0x100, 1),
                space: SpaceId::Ram,
                addr: reg(0x38, 8),
            },
            R2ILOp::IntZExt {
                dst: reg(0x10, 4),
                src: unique(0x100, 1),
            },
            R2ILOp::IntZExt {
                dst: reg(0x10, 8),
                src: reg(0x10, 4),
            },
        ];
        let accesses = register_accesses(&ops).unwrap();
        assert_eq!(accesses.reads, vec![reg(0x38, 8)]);
        assert_eq!(accesses.writes, vec![reg(0x10, 8)]);
    }

    #[test]
    fn a_read_and_write_of_one_register_is_both() {
        // add rsi, rdi: RSI = RSI + RDI.
        let ops = [R2ILOp::IntAdd {
            dst: reg(0x30, 8),
            a: reg(0x30, 8),
            b: reg(0x38, 8),
        }];
        let accesses = register_accesses(&ops).unwrap();
        assert_eq!(accesses.reads, vec![reg(0x30, 8), reg(0x38, 8)]);
        assert_eq!(accesses.writes, vec![reg(0x30, 8)]);
    }

    #[test]
    fn neighbouring_flags_stay_apart_and_overlaps_join() {
        // Two one-byte flags side by side, then AL and AH joined by AX.
        let ops = [
            R2ILOp::Copy {
                dst: reg(0x200, 1),
                src: reg(0x1, 1),
            },
            R2ILOp::Copy {
                dst: reg(0x201, 1),
                src: reg(0x0, 1),
            },
            R2ILOp::Copy {
                dst: reg(0x202, 1),
                src: reg(0x0, 2),
            },
        ];
        let accesses = register_accesses(&ops).unwrap();
        assert_eq!(accesses.reads, vec![reg(0x0, 2)]);
        assert_eq!(
            accesses.writes,
            vec![reg(0x200, 1), reg(0x201, 1), reg(0x202, 1)]
        );
    }

    #[test]
    fn a_write_a_local_branch_can_skip_kills_no_later_read() {
        let ops = [
            R2ILOp::CBranch {
                target: Varnode::new(SpaceId::Const, 2, 4),
                cond: reg(0x206, 1),
            },
            R2ILOp::Copy {
                dst: reg(0x0, 8),
                src: Varnode::new(SpaceId::Const, 0, 8),
            },
            R2ILOp::Copy {
                dst: reg(0x10, 8),
                src: reg(0x0, 8),
            },
        ];
        let accesses = register_accesses(&ops).unwrap();
        assert_eq!(accesses.reads, vec![reg(0x206, 1), reg(0x0, 8)]);
        assert_eq!(accesses.writes, vec![reg(0x0, 8), reg(0x10, 8)]);
    }

    #[test]
    fn lanes_that_fill_a_register_are_that_register() {
        let lanes = vec![
            reg(0x1208, 4),
            reg(0x1200, 4),
            reg(0x1204, 4),
            reg(0x120c, 4),
            reg(0x200, 1),
        ];
        let joined = join_tiles(lanes, |vn| *vn == reg(0x1200, 16));
        assert_eq!(joined, vec![reg(0x1200, 16), reg(0x200, 1)]);
        // Neighbouring flags fill no register, so stay apart.
        let flags = vec![reg(0x200, 1), reg(0x201, 1)];
        assert_eq!(
            join_tiles(flags.clone(), |vn| *vn == reg(0x1200, 16)),
            flags
        );
    }

    #[test]
    fn an_address_nothing_uses_is_not_read() {
        // nop dword [rax + rax]: the operand's address is computed and dropped.
        let ops = [R2ILOp::IntAdd {
            dst: unique(0x200, 8),
            a: reg(0x0, 8),
            b: reg(0x0, 8),
        }];
        assert_eq!(
            register_accesses(&ops).unwrap(),
            RegisterAccesses::default()
        );
    }

    #[test]
    fn an_unimplemented_operation_states_no_accesses() {
        let ops = [
            R2ILOp::Unimplemented,
            R2ILOp::Copy {
                dst: reg(0x0, 4),
                src: reg(0x4, 4),
            },
        ];
        assert_eq!(register_accesses(&ops), None);
    }

    #[test]
    fn a_load_nothing_uses_still_reads_its_address() {
        let ops = [R2ILOp::Load {
            dst: unique(0x200, 8),
            space: SpaceId::Ram,
            addr: reg(0x0, 8),
        }];
        assert_eq!(register_accesses(&ops).unwrap().reads, vec![reg(0x0, 8)]);
    }

    #[test]
    fn a_partly_written_register_is_still_read() {
        // AL written, then EAX read: its upper bytes are the entry value's.
        let ops = [
            R2ILOp::Copy {
                dst: reg(0x0, 1),
                src: Varnode::new(SpaceId::Const, 1, 1),
            },
            R2ILOp::Copy {
                dst: reg(0x10, 4),
                src: reg(0x0, 4),
            },
        ];
        assert_eq!(register_accesses(&ops).unwrap().reads, vec![reg(0x0, 4)]);
    }
}
