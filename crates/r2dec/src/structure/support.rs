//! Fixtures for the structure tests: a CFG from terminators, and statements observed as a block's.

use r2ssa::cfg::{BasicBlock, BlockTerminator, CFG};

use crate::ast::{CExpr, CStmt, test_render_observation_id};

pub(crate) fn cfg(entry: u64, blocks: &[(u64, BlockTerminator)]) -> CFG {
    let mut cfg = CFG::new(entry);
    for (addr, _) in blocks {
        cfg.add_block(BasicBlock::new(*addr));
    }
    for (addr, terminator) in blocks {
        cfg.set_terminator(*addr, terminator.clone());
    }
    cfg
}

/// A statement observed as belonging to `block`.
pub(crate) fn at(block: u64, stmt: CStmt) -> CStmt {
    CStmt::observe_one(
        test_render_observation_id(u32::try_from(block).expect("small address")),
        stmt,
    )
}

pub(crate) fn expr() -> CStmt {
    CStmt::Expr(CExpr::IntLit(0))
}

pub(crate) fn cond() -> CExpr {
    CExpr::IntLit(1)
}

pub(crate) fn branch(target: u64) -> BlockTerminator {
    BlockTerminator::Branch { target }
}

pub(crate) fn cond_branch(true_target: u64, false_target: u64) -> BlockTerminator {
    BlockTerminator::ConditionalBranch {
        true_target,
        false_target,
    }
}
