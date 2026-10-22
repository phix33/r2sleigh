//! Loop rotation: `for (;;)` written as `while` or `do-while` where the loop is one, with the test's
//! markers on the loop for the certificate (`doc/adr-structure-dominator-tree.md` §5, 2026-10-22).

use crate::ast::{BinaryOp, CExpr, CStmt, UnaryOp};

/// Write each `for (;;)` of the tree as the loop it is, where it is one; the number written.
/// O(statements): each loop is read once, from the statements at the top and bottom of its body.
pub(crate) fn rotate(stmt: &mut CStmt) -> usize {
    match stmt {
        CStmt::Observed { stmt, .. } => rotate(stmt),
        CStmt::Block(stmts) => stmts.iter_mut().map(rotate).sum(),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => rotate(then_body) + else_body.as_deref_mut().map_or(0, rotate),
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => rotate(body),
        CStmt::Switch { cases, default, .. } => {
            let in_cases: usize = (cases.iter_mut())
                .flat_map(|case| case.body.iter_mut())
                .map(rotate)
                .sum();
            in_cases + default.iter_mut().flatten().map(rotate).sum::<usize>()
        }
        CStmt::For {
            init: None,
            cond: None,
            update: None,
            body,
        } => {
            let inner = rotate(body);
            let Some(shape) = read(body) else {
                return inner;
            };
            let taken = std::mem::replace(&mut **body, CStmt::Empty);
            *stmt = build(taken, shape);
            inner + 1
        }
        CStmt::For { body, .. } => rotate(body),
        _ => 0,
    }
}

/// What kind of loop an infinite loop's body is, and on which arm of its test it leaves.
struct Shape {
    latch: bool,
    leaves_on_true: bool,
}

/// The loop the body of an infinite loop makes, if its test is first or last.
fn read(body: &CStmt) -> Option<Shape> {
    let stmts = live(body);
    let (last, before) = stmts.split_last()?;
    let (_, on_true, on_false) = parts(last)?;
    let (stay, leaves_on_true) = match (is_break(on_true), is_break(on_false)) {
        (false, true) => (on_true, false),
        (true, false) => (on_false, true),
        _ => return None,
    };
    if before.is_empty() {
        // The header's test: it stays in the loop on one arm and leaves on the other.
        return Some(Shape {
            latch: false,
            leaves_on_true,
        });
    }
    // The latch's test: nothing else goes back to the top of the body, since a `continue` of a
    // `do-while` reaches the test, and the arm that stays does nothing more.
    (is_empty(stay) && !before.iter().any(|stmt| continues(stmt))).then_some(Shape {
        latch: true,
        leaves_on_true,
    })
}

/// The loop statement for a body [`read`] took apart, which carries the test's markers.
fn build(body: CStmt, shape: Shape) -> CStmt {
    let mut stmts = Vec::new();
    flatten(body, &mut stmts);
    let Some(CStmt::Observed { ids, stmt }) = stmts.pop() else {
        unreachable!("read found the marked test last");
    };
    let CStmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = *stmt
    else {
        unreachable!("read found an if with both arms");
    };
    let (stay, test) = match shape.leaves_on_true {
        true => (*else_body, negated(cond)),
        false => (*then_body, cond),
    };
    let looped = match shape.latch {
        true => CStmt::DoWhile {
            body: Box::new(CStmt::Block(stmts)),
            cond: test,
        },
        false => CStmt::While {
            cond: test,
            body: Box::new(stay),
        },
    };
    CStmt::Observed {
        ids,
        stmt: Box::new(looped),
    }
}

/// The statements of a body that do something: no empty statement, and blocks looked through.
pub(super) fn live(stmt: &CStmt) -> Vec<&CStmt> {
    match stmt {
        CStmt::Block(stmts) => stmts.iter().flat_map(live).collect(),
        CStmt::Empty => Vec::new(),
        other => vec![other],
    }
}

/// [`live`], moving the statements out.
pub(super) fn flatten(stmt: CStmt, into: &mut Vec<CStmt>) {
    match stmt {
        CStmt::Block(stmts) => stmts.into_iter().for_each(|stmt| flatten(stmt, into)),
        CStmt::Empty => {}
        other => into.push(other),
    }
}

/// A marked `if` with both arms: its test and arms.
pub(super) fn parts(stmt: &CStmt) -> Option<(&CExpr, &CStmt, &CStmt)> {
    let CStmt::Observed { stmt: inner, .. } = stmt else {
        return None;
    };
    let CStmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = &**inner
    else {
        return None;
    };
    Some((cond, then_body, else_body))
}

/// Whether an arm is a `break` and nothing else.
pub(super) fn is_break(arm: &CStmt) -> bool {
    matches!(live(arm).as_slice(), [CStmt::Break])
}

/// Whether an arm does nothing: it falls to the top of the loop on its own, or says `continue`.
pub(super) fn is_empty(arm: &CStmt) -> bool {
    matches!(live(arm).as_slice(), [] | [CStmt::Continue])
}

/// Whether `stmt` has a `continue` for the loop around it: those of a loop inside it are its own.
pub(super) fn continues(stmt: &CStmt) -> bool {
    match stmt {
        CStmt::Continue => true,
        CStmt::Observed { stmt, .. } => continues(stmt),
        CStmt::Block(stmts) => stmts.iter().any(continues),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => continues(then_body) || else_body.as_deref().is_some_and(continues),
        // A `continue` passes through a `switch` to the loop around it.
        CStmt::Switch { cases, default, .. } => {
            (cases.iter().flat_map(|case| case.body.iter())).any(continues)
                || default.iter().flatten().any(continues)
        }
        _ => false,
    }
}

/// The test that holds where `test` does not. A chain's atoms (marked) take the `!` and the
/// connectives swap; an integer comparison swaps to its opposite (floats have none, `FLt`).
fn negated(test: CExpr) -> CExpr {
    match test {
        CExpr::Binary {
            op: op @ (BinaryOp::And | BinaryOp::Or),
            left,
            right,
        } if marked(&left) || marked(&right) => {
            let flipped = if op == BinaryOp::And {
                BinaryOp::Or
            } else {
                BinaryOp::And
            };
            CExpr::binary(flipped, negated(*left), negated(*right))
        }
        CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } if marked(&operand) => *operand,
        atom if marked(&atom) => CExpr::unary(UnaryOp::Not, atom),
        plain => {
            let mut opposite = plain.clone();
            match super::condition::opposite(&mut opposite) {
                true => opposite,
                false => CExpr::unary(UnaryOp::Not, plain),
            }
        }
    }
}

/// Whether a test is a chain's: some part of it carries a block's marker, which the lowering never puts there.
fn marked(expr: &CExpr) -> bool {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        if matches!(expr, CExpr::Observed { .. }) {
            return true;
        }
        pending.extend(expr.children());
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::test_render_observation_id;

    fn marker(block: u32, stmt: CStmt) -> CStmt {
        CStmt::observe_one(test_render_observation_id(block), stmt)
    }

    fn work(block: u32) -> CStmt {
        marker(block, CStmt::Expr(CExpr::int(i64::from(block))))
    }

    /// The test of `block`, which prints as its address.
    fn test(block: u32, on_true: CStmt, on_false: CStmt) -> CStmt {
        marker(
            block,
            CStmt::if_stmt(CExpr::int(i64::from(block)), on_true, Some(on_false)),
        )
    }

    fn forever(stmts: Vec<CStmt>) -> CStmt {
        CStmt::For {
            init: None,
            cond: None,
            update: None,
            body: Box::new(CStmt::Block(stmts)),
        }
    }

    fn brk() -> CStmt {
        CStmt::Block(vec![CStmt::Break])
    }

    fn nothing() -> CStmt {
        CStmt::Block(vec![CStmt::Empty])
    }

    fn rotated_once(mut body: CStmt) -> (CStmt, usize) {
        let count = rotate(&mut body);
        (body, count)
    }

    #[test]
    fn a_body_that_is_its_test_with_a_break_on_one_arm_is_a_while() {
        let (looped, count) = rotated_once(forever(vec![test(
            0x10,
            CStmt::Block(vec![work(0x20)]),
            brk(),
        )]));
        assert_eq!(count, 1);
        let CStmt::Observed { ids, stmt } = &looped else {
            panic!("the loop carries the test's marker");
        };
        assert_eq!(ids.iter().map(|id| id.index()).collect::<Vec<_>>(), [0x10]);
        let CStmt::While { cond, body } = &**stmt else {
            panic!("a while");
        };
        assert!(matches!(cond, CExpr::IntLit(0x10)), "not negated: {cond:?}");
        assert!(matches!(&**body, CStmt::Block(stmts) if stmts.len() == 1));
    }

    #[test]
    fn the_loop_stays_on_the_arm_that_does_not_break_so_a_break_on_the_true_arm_negates() {
        let (looped, _) = rotated_once(forever(vec![test(
            0x10,
            brk(),
            CStmt::Block(vec![work(0x20)]),
        )]));
        let CStmt::Observed { stmt, .. } = &looped else {
            panic!("marked");
        };
        let CStmt::While { cond, .. } = &**stmt else {
            panic!("a while");
        };
        assert!(
            matches!(
                cond,
                CExpr::Unary {
                    op: UnaryOp::Not,
                    ..
                }
            ),
            "{cond:?}"
        );
    }

    #[test]
    fn an_integer_comparison_that_is_negated_is_its_opposite() {
        let mut symbols = crate::symbol::SymbolTable::new();
        let x = CExpr::var(symbols.declare_or_reuse("x"));
        let less = CExpr::binary(BinaryOp::Lt, x.clone(), CExpr::int(9));
        let CExpr::Binary { op, .. } = negated(less) else {
            panic!("a comparison");
        };
        assert_eq!(op, BinaryOp::Ge);
        let float = CExpr::binary(BinaryOp::FLt, x, CExpr::int(9));
        assert!(
            matches!(negated(float), CExpr::Unary { .. }),
            "no float opposite"
        );
    }

    #[test]
    fn a_body_that_ends_in_its_test_is_a_do_while_when_nothing_else_goes_back() {
        // for (;;) { work; if (t) {} else break; }
        let (looped, count) = rotated_once(forever(vec![work(0x20), test(0x10, nothing(), brk())]));
        assert_eq!(count, 1);
        let CStmt::Observed { ids, stmt } = &looped else {
            panic!("marked");
        };
        assert_eq!(ids.iter().map(|id| id.index()).collect::<Vec<_>>(), [0x10]);
        let CStmt::DoWhile { body, .. } = &**stmt else {
            panic!("a do-while");
        };
        assert!(matches!(&**body, CStmt::Block(stmts) if stmts.len() == 1));
    }

    #[test]
    fn a_continue_before_the_test_keeps_the_loop_infinite() {
        // A `continue` of a do-while reaches its test, so it cannot be the one of the `for`.
        let early = CStmt::If {
            cond: CExpr::int(1),
            then_body: Box::new(CStmt::Continue),
            else_body: None,
        };
        let body = forever(vec![work(0x20), early, test(0x10, nothing(), brk())]);
        let (looped, count) = rotated_once(body);
        assert_eq!(count, 0);
        assert!(matches!(looped, CStmt::For { .. }));
        // The same continue inside an inner loop is that loop's own.
        let inner = forever(vec![CStmt::Continue]);
        let (_, count) = rotated_once(forever(vec![
            work(0x20),
            inner,
            test(0x10, nothing(), brk()),
        ]));
        assert!(count >= 1);
    }

    #[test]
    fn a_test_whose_arms_do_more_than_break_or_stay_is_no_loop_test() {
        // The exit arm copies a variable before it breaks: it is not the loop's exit alone.
        let copies = CStmt::Block(vec![CStmt::Expr(CExpr::int(7)), CStmt::Break]);
        let (_, count) = rotated_once(forever(vec![work(0x20), test(0x10, nothing(), copies)]));
        assert_eq!(count, 0);
        // Both arms break: it is not a test that loops.
        let (_, count) = rotated_once(forever(vec![test(0x10, brk(), brk())]));
        assert_eq!(count, 0);
        // The staying arm of a latch does work of its own: that is step 3's copies, not an empty arm.
        let (_, count) = rotated_once(forever(vec![
            work(0x20),
            test(0x10, CStmt::Block(vec![CStmt::Expr(CExpr::int(7))]), brk()),
        ]));
        assert_eq!(count, 0);
    }

    #[test]
    fn a_label_at_the_top_keeps_the_header_a_header_of_a_for() {
        // A goto reaches the header: there is no place for its label in a `while`.
        let (looped, count) = rotated_once(forever(vec![
            CStmt::Label("L".to_owned()),
            test(0x10, CStmt::Block(vec![work(0x20)]), brk()),
        ]));
        assert_eq!(count, 0);
        assert!(matches!(looped, CStmt::For { .. }));
    }

    // -- The certificate reads the rotated loop as it read the `for`.

    use super::super::certify::{ControlCertificate, StatementRole, certify};
    use r2ssa::cfg::{BasicBlock, BlockTerminator, CFG};
    use r2ssa::domtree::DomTree;

    fn cfg(entry: u64, blocks: &[(u64, BlockTerminator)]) -> CFG {
        let mut cfg = CFG::new(entry);
        for (addr, _) in blocks {
            cfg.add_block(BasicBlock::new(*addr));
        }
        for (addr, terminator) in blocks {
            cfg.set_terminator(*addr, terminator.clone());
        }
        cfg
    }

    fn branch(target: u64) -> BlockTerminator {
        BlockTerminator::Branch { target }
    }

    fn cond_branch(true_target: u64, false_target: u64) -> BlockTerminator {
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
        }
    }

    fn certified(body: &CStmt, cfg: &CFG) -> ControlCertificate {
        certify(
            body,
            cfg,
            &DomTree::compute(cfg),
            cfg.entry,
            &|id| Some(u64::from(id.index())),
            &|_| None,
            &|_| StatementRole::Plain,
            &|_| true,
        )
    }

    /// The loop written as placement and `shape` leave it, and as `rotate` writes it: both must certify.
    fn both_certify(body: CStmt, cfg: &CFG) -> CStmt {
        let before = certified(&body, cfg);
        assert!(before.ok(), "the for: {before} {:?}", before.violations);
        let mut after = body;
        assert_eq!(rotate(&mut after), 1);
        let rotated = certified(&after, cfg);
        assert!(
            rotated.ok(),
            "the rotation: {rotated} {:?}",
            rotated.violations
        );
        after
    }

    fn exit() -> CStmt {
        marker(0x50, CStmt::Return(None))
    }

    #[test]
    fn a_while_certifies_as_the_for_it_was() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x50)),
                (0x30, branch(0x20)),
                (0x50, BlockTerminator::Return),
            ],
        );
        let stay = CStmt::Block(vec![work(0x30)]);
        let body = CStmt::Block(vec![
            work(0x10),
            forever(vec![test(0x20, stay, brk())]),
            exit(),
        ]);
        let rotated = both_certify(body, &cfg);
        let CStmt::Block(stmts) = &rotated else {
            panic!("a block");
        };
        assert!(matches!(stmts[1].unobserved(), CStmt::While { .. }));
    }

    #[test]
    fn a_do_while_certifies_as_the_for_it_was() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, branch(0x30)),
                (0x30, cond_branch(0x20, 0x50)),
                (0x50, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            work(0x10),
            forever(vec![work(0x20), test(0x30, nothing(), brk())]),
            exit(),
        ]);
        let rotated = both_certify(body, &cfg);
        let CStmt::Block(stmts) = &rotated else {
            panic!("a block");
        };
        assert!(matches!(stmts[1].unobserved(), CStmt::DoWhile { .. }));
    }

    #[test]
    fn a_header_that_tests_a_chain_is_a_while_over_the_chain() {
        // while (a && b): the second test is read through, and its marker is on the atom.
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x25, 0x50)),
                (0x25, cond_branch(0x30, 0x50)),
                (0x30, branch(0x20)),
                (0x50, BlockTerminator::Return),
            ],
        );
        let atom = |block: u32| {
            CExpr::observe_one(
                test_render_observation_id(block),
                CExpr::int(i64::from(block)),
            )
        };
        let chain = CExpr::binary(BinaryOp::And, atom(0x20), atom(0x25));
        let header = marker(
            0x20,
            CStmt::if_stmt(chain, CStmt::Block(vec![work(0x30)]), Some(brk())),
        );
        let body = CStmt::Block(vec![work(0x10), forever(vec![header]), exit()]);
        let rotated = both_certify(body, &cfg);
        let CStmt::Block(stmts) = &rotated else {
            panic!("a block");
        };
        assert!(matches!(
            stmts[1].unobserved(),
            CStmt::While {
                cond: CExpr::Binary { .. },
                ..
            }
        ));
    }

    #[test]
    fn a_loop_whose_rotation_leaves_no_block_in_its_body_fails_the_certificate_and_stays_a_for() {
        // The header branches to itself: `while (c) {}` owns no block, which the certificate
        // reads as an operation's own loop, so the stage that wrote it is not kept.
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x20, 0x50)),
                (0x50, BlockTerminator::Return),
            ],
        );
        let body = CStmt::Block(vec![
            work(0x10),
            forever(vec![test(0x20, nothing(), brk())]),
            exit(),
        ]);
        let before = certified(&body, &cfg);
        assert!(before.ok(), "the for: {before} {:?}", before.violations);
        let mut after = body;
        assert_eq!(rotate(&mut after), 1);
        assert!(!certified(&after, &cfg).ok());
    }
}
