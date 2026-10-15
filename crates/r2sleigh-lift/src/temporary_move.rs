//! The D36 gate's seam: Sleigh's temporaries moved as a specification resync would move them.

use std::sync::OnceLock;

use r2il::{R2ILOp, SpaceId, Varnode};

/// How `R2S_MOVE_TEMPORARIES` moves each instruction's raw temporaries: `shift` or `reverse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TemporaryMove {
    Shift,
    Reverse,
}

/// The move this process makes, read once; output must not depend on it (ROADMAP D36). An unknown
/// move panics: a gate that ignored a misspelt knob would pass without moving anything.
pub(crate) fn requested() -> Option<TemporaryMove> {
    static MOVE: OnceLock<Option<TemporaryMove>> = OnceLock::new();
    *MOVE.get_or_init(
        || match std::env::var("R2S_MOVE_TEMPORARIES").ok()?.as_str() {
            "shift" => Some(TemporaryMove::Shift),
            "reverse" => Some(TemporaryMove::Reverse),
            other => panic!("R2S_MOVE_TEMPORARIES is `shift` or `reverse`, not `{other}`"),
        },
    )
}

/// Move every temporary keeping what the operations compute: overlapping temporaries move together.
pub(crate) fn move_temporaries(ops: &mut [R2ILOp], how: TemporaryMove) {
    const BASE: u64 = 0x4000_0000;
    let mut ranges = Vec::new();
    for op in ops.iter() {
        for varnode in op.inputs().into_iter().chain(op.output()) {
            if varnode.space == SpaceId::Unique {
                ranges.push((
                    varnode.offset,
                    varnode.offset + u64::from(varnode.size.max(1)),
                ));
            }
        }
    }
    ranges.sort_unstable();
    // Clusters of overlapping ranges, each with where it lands.
    let mut clusters: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        match clusters.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => clusters.push((start, end)),
        }
    }
    let mut landing = vec![0u64; clusters.len()];
    let mut at = BASE;
    for index in (0..clusters.len()).rev() {
        landing[index] = at;
        at += clusters[index].1 - clusters[index].0 + 0x10;
    }
    let mut moved = |varnode: &mut Varnode| {
        if varnode.space != SpaceId::Unique {
            return;
        }
        varnode.offset = match how {
            TemporaryMove::Shift => varnode.offset + BASE,
            TemporaryMove::Reverse => {
                let index = clusters.partition_point(|cluster| cluster.0 <= varnode.offset) - 1;
                landing[index] + (varnode.offset - clusters[index].0)
            }
        };
    };
    for op in ops {
        op.inputs_mut().into_iter().for_each(&mut moved);
        op.output_mut().into_iter().for_each(&mut moved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversal_keeps_a_piece_inside_its_holder() {
        let mut ops = vec![
            R2ILOp::Copy {
                dst: Varnode::unique(0x100, 8),
                src: Varnode::register(0, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x200, 4),
                src: Varnode::unique(0x104, 4),
            },
        ];
        move_temporaries(&mut ops, TemporaryMove::Reverse);
        let holder = ops[0].output().unwrap().offset;
        let piece = ops[1].inputs()[0].offset;
        assert_eq!(piece, holder + 4);
        assert!(ops[1].output().unwrap().offset < holder);
    }
}
