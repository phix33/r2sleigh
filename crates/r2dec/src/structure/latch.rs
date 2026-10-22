//! Latch copies written before the latch's test, so a rotated loop is a `do-while`
//! (`doc/adr-structure-dominator-tree.md` §5, 2026-10-22).

use std::collections::{BTreeMap, BTreeSet};

use super::rotate::{continues, flatten, is_break, live, parts};
use crate::ast::{BinaryOp, CExpr, CStmt};
use crate::symbol::SymbolId;

/// Write the copies of each latch before its test where the C text allows; the number of loops.
/// O(statements) for the reads of the whole function, once, and O(loop) for each latch.
pub(crate) fn hoist(root: &mut CStmt) -> usize {
    let mut total = BTreeMap::new();
    count_reads(root, &mut total);
    walk(root, &total)
}

fn walk(stmt: &mut CStmt, total: &BTreeMap<SymbolId, usize>) -> usize {
    match stmt {
        CStmt::Observed { stmt, .. } => walk(stmt, total),
        CStmt::Block(stmts) => stmts.iter_mut().map(|stmt| walk(stmt, total)).sum(),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => walk(then_body, total) + else_body.as_deref_mut().map_or(0, |e| walk(e, total)),
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => walk(body, total),
        CStmt::Switch { cases, default, .. } => {
            let in_cases: usize = (cases.iter_mut())
                .flat_map(|case| case.body.iter_mut())
                .map(|stmt| walk(stmt, total))
                .sum();
            in_cases
                + default
                    .iter_mut()
                    .flatten()
                    .map(|stmt| walk(stmt, total))
                    .sum::<usize>()
        }
        CStmt::For {
            init: None,
            cond: None,
            update: None,
            body,
        } => {
            let inner = walk(body, total);
            let Some(stay_is_true) = may_hoist(body, total) else {
                return inner;
            };
            let taken = std::mem::replace(&mut **body, CStmt::Empty);
            **body = moved(taken, stay_is_true);
            inner + 1
        }
        CStmt::For { body, .. } => walk(body, total),
        _ => 0,
    }
}

/// Whether the latch's copies may be written before its test, and if so whether the arm that
/// stays is the test's true arm.
fn may_hoist(body: &CStmt, total: &BTreeMap<SymbolId, usize>) -> Option<bool> {
    let stmts = live(body);
    let (last, before) = stmts.split_last()?;
    let (test, on_true, on_false) = parts(last)?;
    // The loop leaves on one arm and goes back on the other, which does nothing but copy.
    let (stay, stay_is_true) = match (is_break(on_true), is_break(on_false)) {
        (false, true) => (on_true, true),
        (true, false) => (on_false, false),
        _ => return None,
    };
    // Nothing else goes back to the top, or the loop is not a `do-while` once the copies are out.
    if before.is_empty() || before.iter().any(|stmt| continues(stmt)) || !pure(test) {
        return None;
    }
    let targets: BTreeSet<SymbolId> = copies_of(stay)?.into_iter().collect();
    // The test reads none of what is written, and nothing outside this loop reads it.
    let mut read_by_test = BTreeMap::new();
    count_expr_reads(test, &mut read_by_test);
    if targets
        .iter()
        .any(|target| read_by_test.contains_key(target))
    {
        return None;
    }
    let mut inside = BTreeMap::new();
    count_reads(body, &mut inside);
    let read_beyond = |target: &SymbolId| total.get(target) != inside.get(target);
    (!targets.iter().any(read_beyond)).then_some(stay_is_true)
}

/// The variables an arm assigns, when it is plain assignments to variables and nothing else but a
/// closing `continue`.
fn copies_of(arm: &CStmt) -> Option<Vec<SymbolId>> {
    let mut statements = live(arm);
    if matches!(statements.last(), Some(CStmt::Continue)) {
        statements.pop();
    }
    let targets: Option<Vec<SymbolId>> = statements
        .into_iter()
        .map(|stmt| match stmt {
            CStmt::Expr(CExpr::Binary {
                op: BinaryOp::Assign,
                left,
                ..
            }) => match &**left {
                CExpr::Var(target) => Some(*target),
                _ => None,
            },
            _ => None,
        })
        .collect();
    targets.filter(|targets| !targets.is_empty())
}

/// The body with the stay arm's statements ahead of the test and the arm itself empty.
fn moved(body: CStmt, stay_is_true: bool) -> CStmt {
    let mut stmts = Vec::new();
    flatten(body, &mut stmts);
    let Some(CStmt::Observed { ids, stmt }) = stmts.pop() else {
        unreachable!("the test was found last");
    };
    let CStmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = *stmt
    else {
        unreachable!("the test was an if with both arms");
    };
    let (stay, leave) = match stay_is_true {
        true => (*then_body, *else_body),
        false => (*else_body, *then_body),
    };
    let mut copies = Vec::new();
    flatten(stay, &mut copies);
    copies.retain(|stmt| !matches!(stmt, CStmt::Continue));
    stmts.extend(copies);
    let (on_true, on_false) = match stay_is_true {
        true => (CStmt::Empty, leave),
        false => (leave, CStmt::Empty),
    };
    stmts.push(CStmt::Observed {
        ids,
        stmt: Box::new(CStmt::if_stmt(cond, on_true, Some(on_false))),
    });
    CStmt::Block(stmts)
}

/// Whether evaluating a test only reads: no call, no assignment, no increment.
fn pure(expr: &CExpr) -> bool {
    let mut calls = false;
    let mut pending = vec![expr];
    while let Some(node) = pending.pop() {
        calls |= matches!(node.unobserved(), CExpr::Call { .. });
        pending.extend(node.children());
    }
    !calls && !super::certify::writes(expr)
}

/// How often each variable is read in `stmt`: a plain assignment's target is written, not read.
fn count_reads(stmt: &CStmt, into: &mut BTreeMap<SymbolId, usize>) {
    stmt.visit_exprs(&mut |root| count_expr_reads(root, into));
}

fn count_expr_reads(expr: &CExpr, into: &mut BTreeMap<SymbolId, usize>) {
    match expr.unobserved() {
        CExpr::Var(symbol) => *into.entry(*symbol).or_default() += 1,
        CExpr::Binary {
            op: BinaryOp::Assign,
            left,
            right,
        } if matches!(left.unobserved(), CExpr::Var(_)) => count_expr_reads(right, into),
        other => {
            for child in other.children() {
                count_expr_reads(child, into);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{UnaryOp, test_render_observation_id};
    use crate::symbol::SymbolTable;

    struct Fixture {
        symbols: SymbolTable,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                symbols: SymbolTable::new(),
            }
        }

        fn var(&mut self, name: &str) -> CExpr {
            CExpr::var(self.symbols.declare_or_reuse(name))
        }
    }

    fn marker(block: u32, stmt: CStmt) -> CStmt {
        CStmt::observe_one(test_render_observation_id(block), stmt)
    }

    fn assign(target: &CExpr, value: CExpr) -> CStmt {
        CStmt::Expr(CExpr::assign(target.clone(), value))
    }

    fn latch(test: CExpr, stay: Vec<CStmt>) -> CStmt {
        marker(
            0x30,
            CStmt::if_stmt(
                test,
                CStmt::Block(stay),
                Some(CStmt::Block(vec![CStmt::Break])),
            ),
        )
    }

    fn forever(stmts: Vec<CStmt>) -> CStmt {
        CStmt::Block(vec![CStmt::For {
            init: None,
            cond: None,
            update: None,
            body: Box::new(CStmt::Block(stmts)),
        }])
    }

    fn work(block: u32) -> CStmt {
        marker(block, CStmt::Expr(CExpr::int(i64::from(block))))
    }

    /// The loop of `forever`, after `hoist`: its body's statements.
    fn body_after(root: CStmt) -> (Vec<CStmt>, usize) {
        body_after_at(root, 0)
    }

    /// The same, for the loop that is statement `at` of the outer block.
    fn body_after_at(mut root: CStmt, at: usize) -> (Vec<CStmt>, usize) {
        let count = hoist(&mut root);
        let CStmt::Block(outer) = root else {
            panic!("a block");
        };
        let CStmt::For { body, .. } = &outer[at] else {
            panic!("a for");
        };
        let CStmt::Block(stmts) = &**body else {
            panic!("a block body");
        };
        (stmts.clone(), count)
    }

    #[test]
    fn copies_a_test_does_not_read_are_written_before_it() {
        // for (;;) { work; if (a != n) { x = a; } else { break; } } with `x` read nowhere else.
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let root = forever(vec![
            work(0x20),
            latch(test, vec![assign(&x, a.clone()), CStmt::Continue]),
        ]);
        let (stmts, count) = body_after(root);
        assert_eq!(count, 1);
        // work; x = a; if (...) {} else { break; }
        assert_eq!(stmts.len(), 3, "{stmts:?}");
        assert!(matches!(&stmts[1], CStmt::Expr(_)));
        let CStmt::Observed { stmt, .. } = &stmts[2] else {
            panic!("the test stays marked");
        };
        let CStmt::If { then_body, .. } = &**stmt else {
            panic!("an if");
        };
        assert!(matches!(&**then_body, CStmt::Empty));
    }

    #[test]
    fn the_stay_arm_on_the_false_side_is_emptied_too() {
        let mut f = Fixture::new();
        let (x, a) = (f.var("x"), f.var("a"));
        let test = CExpr::binary(BinaryOp::Eq, a.clone(), CExpr::int(0));
        let latch = marker(
            0x30,
            CStmt::if_stmt(
                test,
                CStmt::Block(vec![CStmt::Break]),
                Some(CStmt::Block(vec![assign(&x, a)])),
            ),
        );
        let (stmts, count) = body_after(forever(vec![work(0x20), latch]));
        assert_eq!(count, 1);
        let CStmt::Observed { stmt, .. } = &stmts[2] else {
            panic!("marked");
        };
        let CStmt::If { else_body, .. } = &**stmt else {
            panic!("an if");
        };
        assert!(matches!(else_body.as_deref(), Some(CStmt::Empty)));
    }

    #[test]
    fn a_copy_the_test_reads_stays_on_the_arm() {
        // The test reads `x`, which the copy writes: after the move it would see the new value.
        let mut f = Fixture::new();
        let (x, a) = (f.var("x"), f.var("a"));
        let test = CExpr::binary(BinaryOp::Ne, x.clone(), CExpr::int(0));
        let root = forever(vec![work(0x20), latch(test, vec![assign(&x, a)])]);
        let (_, count) = body_after(root);
        assert_eq!(count, 0);
    }

    #[test]
    fn a_copy_something_after_the_loop_reads_stays_on_the_arm() {
        // `x` is read after the loop; the exit would see the copy it never made.
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let mut root = forever(vec![work(0x20), latch(test, vec![assign(&x, a)])]);
        let CStmt::Block(outer) = &mut root else {
            panic!("a block");
        };
        outer.push(CStmt::Return(Some(x)));
        let (_, count) = body_after(root);
        assert_eq!(count, 0);
    }

    #[test]
    fn a_write_before_the_loop_is_no_read_after_it() {
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        let CStmt::Block(mut outer) = forever(vec![work(0x20), latch(test, vec![assign(&x, a)])])
        else {
            panic!("a block");
        };
        outer.insert(0, assign(&x, CExpr::int(0)));
        outer.push(CStmt::Return(Some(CExpr::int(1))));
        let (_, count) = body_after_at(CStmt::Block(outer), 1);
        assert_eq!(count, 1);
    }

    #[test]
    fn a_test_that_calls_or_writes_keeps_its_copies_where_they_are() {
        let mut f = Fixture::new();
        let (x, a) = (f.var("x"), f.var("a"));
        let call = CExpr::call(
            CExpr::var(f.symbols.declare_or_reuse("probe")),
            vec![a.clone()],
        );
        let root = forever(vec![work(0x20), latch(call, vec![assign(&x, a.clone())])]);
        assert_eq!(body_after(root).1, 0);
        let bump = CExpr::unary(UnaryOp::PostInc, a.clone());
        let root = forever(vec![work(0x20), latch(bump, vec![assign(&x, a)])]);
        assert_eq!(body_after(root).1, 0);
    }

    #[test]
    fn a_latch_that_does_more_than_copy_or_a_continue_before_it_is_left_alone() {
        let mut f = Fixture::new();
        let (x, a, n) = (f.var("x"), f.var("a"), f.var("n"));
        let test = CExpr::binary(BinaryOp::Ne, a.clone(), n);
        // The arm also stores through a pointer.
        let store = CStmt::Expr(CExpr::assign(
            CExpr::Deref(Box::new(a.clone())),
            CExpr::int(1),
        ));
        let root = forever(vec![
            work(0x20),
            latch(test.clone(), vec![assign(&x, a.clone()), store]),
        ]);
        assert_eq!(body_after(root).1, 0);
        // A `continue` before the latch reaches the top, which the copies would skip.
        let early = CStmt::If {
            cond: CExpr::int(1),
            then_body: Box::new(CStmt::Continue),
            else_body: None,
        };
        let root = forever(vec![work(0x20), early, latch(test, vec![assign(&x, a)])]);
        assert_eq!(body_after(root).1, 0);
    }
}
