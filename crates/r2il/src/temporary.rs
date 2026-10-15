//! An instruction's temporaries at offsets its own operations decide (ROADMAP D36).

use std::collections::BTreeMap;

use crate::{R2ILOp, SpaceId, Varnode};

/// Lay out one instruction's temporaries by first appearance, each after the last: the offset depends
/// on the operations, never on Sleigh's allocator, which a specification edit renumbers. `O(n log t)`.
pub fn number_temporaries(ops: &mut [R2ILOp]) {
    let mut placed: BTreeMap<(u64, u32), u64> = BTreeMap::new();
    let mut next = 0u64;
    let mut place = |varnode: &mut Varnode| {
        if varnode.space != SpaceId::Unique {
            return;
        }
        varnode.offset = *placed
            .entry((varnode.offset, varnode.size))
            .or_insert_with(|| {
                let at = next;
                next += u64::from(varnode.size.max(1));
                at
            });
    };
    for op in ops {
        op.inputs_mut().into_iter().for_each(&mut place);
        op.output_mut().into_iter().for_each(&mut place);
    }
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
        number_temporaries(&mut low);
        number_temporaries(&mut high);
        assert_eq!(format!("{low:?}"), format!("{high:?}"));
        assert_eq!(low[0].output(), Some(&Varnode::unique(0, 8)));
        assert_eq!(low[1].output(), Some(&Varnode::unique(8, 1)));
        assert_eq!(low[2].inputs(), vec![&Varnode::unique(8, 1)]);
    }
}
