//! An instruction's temporaries at offsets its own operations decide (ROADMAP D36).

use std::collections::BTreeMap;

use crate::{R2ILOp, SpaceId, Varnode};

/// Lay out one instruction's temporaries by first appearance, each after the last, or refuse overlapping ones
/// untouched: the offset depends on the operations, never on Sleigh's allocator, which a spec edit renumbers. `O(n log t)`.
pub fn number_temporaries(ops: &mut [R2ILOp]) -> Result<(), TemporariesOverlap> {
    let mut placed: BTreeMap<(u64, u32), u64> = BTreeMap::new();
    let mut next = 0u64;
    let temporaries = ops
        .iter()
        .flat_map(|op| op.inputs().into_iter().chain(op.output()))
        .filter(|varnode| varnode.space == SpaceId::Unique);
    for varnode in temporaries {
        placed
            .entry((varnode.offset, varnode.size))
            .or_insert_with(|| {
                let at = next;
                next += u64::from(varnode.size.max(1));
                at
            });
    }
    disjoint(placed.keys())?;
    let place = |varnode: &mut Varnode| {
        if varnode.space == SpaceId::Unique {
            varnode.offset = placed[&(varnode.offset, varnode.size)];
        }
    };
    for op in ops {
        op.inputs_mut().into_iter().for_each(place);
        op.output_mut().into_iter().for_each(place);
    }
    Ok(())
}

/// Two of one instruction's temporaries that share a byte, which no layout keeps apart and together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporariesOverlap {
    pub first: Varnode,
    pub second: Varnode,
}

impl std::fmt::Display for TemporariesOverlap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (first, second) = (&self.first, &self.second);
        write!(
            f,
            "temporaries {:#x}:{} and {:#x}:{} overlap",
            first.offset, first.size, second.offset, second.size
        )
    }
}

impl std::error::Error for TemporariesOverlap {}

/// Whether no two temporaries share a byte, which makes the layout a renaming (`whole_unique_reads`).
fn disjoint<'a>(sorted: impl Iterator<Item = &'a (u64, u32)>) -> Result<(), TemporariesOverlap> {
    let mut furthest: Option<(u64, u32)> = None;
    let end = |(offset, size): (u64, u32)| offset + u64::from(size.max(1));
    for &(offset, size) in sorted {
        if let Some(reach) = furthest.filter(|&reach| offset < end(reach)) {
            return Err(TemporariesOverlap {
                first: Varnode::unique(reach.0, reach.1),
                second: Varnode::unique(offset, size),
            });
        }
        if furthest.is_none_or(|reach| end((offset, size)) > end(reach)) {
            furthest = Some((offset, size));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(base: u64) -> Vec<R2ILOp> {
        vec![
            R2ILOp::IntAnd {
                dst: Varnode::unique(base + 0x300, 8),
                a: Varnode::register(0, 8),
                b: Varnode::register(0, 8),
            },
            R2ILOp::IntAnd {
                dst: Varnode::unique(base, 1),
                a: Varnode::unique(base + 0x300, 8),
                b: Varnode::constant(1, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::register(8, 1),
                src: Varnode::unique(base, 1),
            },
        ]
    }

    #[test]
    fn offsets_follow_first_appearance_not_the_allocator() {
        let mut low = ops(0x1000);
        let mut high = ops(0xe1100);
        number_temporaries(&mut low).expect("disjoint");
        number_temporaries(&mut high).expect("disjoint");
        assert_eq!(format!("{low:?}"), format!("{high:?}"));
        assert_eq!(low[0].output(), Some(&Varnode::unique(0, 8)));
        assert_eq!(low[1].output(), Some(&Varnode::unique(8, 1)));
        assert_eq!(low[2].inputs(), vec![&Varnode::unique(8, 1)]);
    }

    #[test]
    fn overlapping_temporaries_refuse_and_stay_as_they_are() {
        // A local loop reads bytes 4..8 of the eight-byte write that follows it in op order.
        let lifted = vec![
            R2ILOp::Copy {
                dst: Varnode::register(0, 4),
                src: Varnode::unique(0x104, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x100, 8),
                src: Varnode::register(8, 8),
            },
            R2ILOp::CBranch {
                target: Varnode::constant(-2i64 as u64, 8),
                cond: Varnode::register(16, 1),
            },
        ];
        let mut ops = lifted.clone();
        let overlap = TemporariesOverlap {
            first: Varnode::unique(0x100, 8),
            second: Varnode::unique(0x104, 4),
        };
        assert_eq!(number_temporaries(&mut ops), Err(overlap));
        assert_eq!(ops, lifted);
    }
}
