//! Terminal tails, `doc/adr-structure-dominator-tree.md` §5.
//!
//! Placement writes a block with no way on once, behind a label, and every site that reaches it
//! jumps or falls into it. A source that returned in several places reads as that block at each
//! of them. A copy carries the block's whole (empty) out-edge set, which is what the
//! certificate asks of a block written twice, so a copy placed where the edge did not go is
//! refused there.

use std::collections::BTreeMap;

use super::shape::{Evidence, Occurrences};
use crate::ast::CStmt;

/// The most statements a block may have to be read as a tail.
const TAIL_LIMIT: usize = 4;

/// Each `goto` to a labelled terminal block of at most [`TAIL_LIMIT`] statements becomes a copy
/// of it, and the block goes once nothing falls into it; then a `return` of a merge of
/// pairwise-distinct values, which the arms of one conditional fall to, is copied into those
/// arms. `O(size of the tree)` plus the copies, at most [`TAIL_LIMIT`] per site.
pub(super) fn inline_tails(occ: &mut Occurrences, ev: &Evidence<'_>, stmt: &mut CStmt) {
    let mut tails = BTreeMap::new();
    each_sequence(stmt, &mut |seq| {
        for item in seq.iter() {
            if let CStmt::Block(items) = item
                && let Some((Some(label), tail)) = parse(items, ev)
            {
                tails.insert(label, tail);
            }
        }
    });
    if !tails.is_empty() {
        replace_gotos(occ, &tails, stmt);
        each_sequence(stmt, &mut |seq| remove_dead_tails(&tails, ev, seq));
        super::shape::drop_unreferenced_labels(stmt);
    }
    join_returns(occ, ev, stmt);
}

/// A `return` of a merge of pairwise-distinct values, which the arms of one conditional fall
/// to, is copied into those arms.
fn join_returns(occ: &mut Occurrences, ev: &Evidence<'_>, stmt: &mut CStmt) {
    each_sequence(stmt, &mut |seq| join_in_sequence(occ, ev, seq));
}

/// Every statement sequence in the tree, a sequence after the ones nested in it.
fn each_sequence(stmt: &mut CStmt, visit: &mut dyn FnMut(&mut Vec<CStmt>)) {
    match stmt {
        CStmt::Observed { stmt, .. } => each_sequence(stmt, visit),
        CStmt::Block(seq) => {
            seq.iter_mut().for_each(|item| each_sequence(item, visit));
            visit(seq);
        }
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            each_sequence(then_body, visit);
            if let Some(else_body) = else_body {
                each_sequence(else_body, visit);
            }
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                each_sequence(init, visit);
            }
            each_sequence(body, visit);
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => each_sequence(body, visit),
        CStmt::Switch { cases, default, .. } => {
            let bodies = (cases.iter_mut().map(|case| &mut case.body)).chain(default.iter_mut());
            for body in bodies {
                body.iter_mut().for_each(|item| each_sequence(item, visit));
                visit(body);
            }
        }
        _ => {}
    }
}

/// The label and live statements of a block that has no way on: at most [`TAIL_LIMIT`]
/// expression statements, the last a `return` or a call to a callee that never returns, with no
/// residual or gap in it (a copy would be a second site of the same unproven cell).
fn parse(items: &[CStmt], ev: &Evidence<'_>) -> Option<(Option<String>, Vec<CStmt>)> {
    let mut label = None;
    let mut stmts = Vec::new();
    gather(items, &mut label, &mut stmts).then_some(())?;
    let live = stmts
        .iter()
        .map(CStmt::unobserved)
        .filter(|stmt| !matches!(stmt, CStmt::Empty))
        .collect::<Vec<_>>();
    let (last, before) = live.split_last()?;
    let ends = |stmt: &CStmt| match stmt {
        CStmt::Return(_) => true,
        CStmt::Expr(_) => (ev.never_returns)(stmt),
        _ => false,
    };
    (live.len() <= TAIL_LIMIT && ends(last) && !before.iter().any(|stmt| ends(stmt)))
        .then_some((label, stmts))
}

fn gather(items: &[CStmt], label: &mut Option<String>, out: &mut Vec<CStmt>) -> bool {
    // Markers of empty statements are kept with the text but are not counted by the limit.
    items.iter().all(|item| {
        out.len() <= 2 * TAIL_LIMIT
            && match item {
                CStmt::Label(name) if out.is_empty() && label.is_none() => {
                    *label = Some(name.clone());
                    true
                }
                CStmt::Empty | CStmt::Comment(_) => true,
                CStmt::Block(inner) => gather(inner, label, out),
                other => {
                    let plain = match other.unobserved() {
                        CStmt::Expr(expr) => !crate::prelude::holds_residual(expr),
                        CStmt::Return(value) => {
                            !value.as_ref().is_some_and(crate::prelude::holds_residual)
                        }
                        CStmt::Empty => true,
                        _ => false,
                    };
                    out.push(other.clone());
                    plain
                }
            }
    })
}

fn blank(stmt: &CStmt) -> bool {
    matches!(stmt, CStmt::Empty | CStmt::Comment(_))
}

/// `stmts` as one statement.
fn one(mut stmts: Vec<CStmt>) -> CStmt {
    match stmts.len() {
        0 => CStmt::Empty,
        1 => stmts.remove(0),
        _ => CStmt::Block(stmts),
    }
}

/// The copy of a tail for one more site: every marker minted anew.
fn copies(occ: &mut Occurrences, tail: &[CStmt]) -> Vec<CStmt> {
    tail.iter().map(|stmt| occ.fresh(stmt)).collect()
}

fn replace_gotos(occ: &mut Occurrences, tails: &BTreeMap<String, Vec<CStmt>>, stmt: &mut CStmt) {
    match stmt {
        CStmt::Goto(name) => {
            if let Some(tail) = tails.get(name) {
                *stmt = one(copies(occ, tail));
            }
        }
        CStmt::Observed { stmt, .. } => replace_gotos(occ, tails, stmt),
        CStmt::Block(seq) => replace_in_sequence(occ, tails, seq),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            replace_gotos(occ, tails, then_body);
            if let Some(else_body) = else_body {
                replace_gotos(occ, tails, else_body);
            }
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                replace_gotos(occ, tails, init);
            }
            replace_gotos(occ, tails, body);
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
            replace_gotos(occ, tails, body);
        }
        CStmt::Switch { cases, default, .. } => {
            let bodies = (cases.iter_mut().map(|case| &mut case.body)).chain(default.iter_mut());
            for body in bodies {
                replace_in_sequence(occ, tails, body);
            }
        }
        _ => {}
    }
}

/// A sequence with each `goto` to a tail spliced as the tail's statements.
fn replace_in_sequence(
    occ: &mut Occurrences,
    tails: &BTreeMap<String, Vec<CStmt>>,
    seq: &mut Vec<CStmt>,
) {
    let mut at = 0;
    while at < seq.len() {
        let tail = match &seq[at] {
            CStmt::Goto(name) => tails.get(name),
            _ => None,
        };
        match tail {
            Some(tail) => {
                let copied = copies(occ, tail);
                let count = copied.len();
                seq.splice(at..=at, copied);
                at += count;
            }
            None => {
                replace_gotos(occ, tails, &mut seq[at]);
                at += 1;
            }
        }
    }
}

/// A tail that every jump to has been copied from, and that the statement before it cannot
/// complete into, is reached by nothing and goes.
fn remove_dead_tails(
    tails: &BTreeMap<String, Vec<CStmt>>,
    ev: &Evidence<'_>,
    seq: &mut Vec<CStmt>,
) {
    let mut at = 0;
    while at < seq.len() {
        let was_tail = matches!(&seq[at], CStmt::Block(items)
            if parse(items, ev).is_some_and(|(label, _)| label.is_some_and(|l| tails.contains_key(&l))));
        let before = seq[..at].iter().rev().find(|stmt| !blank(stmt));
        match (was_tail, before) {
            (true, Some(before)) if !completes(before, ev) => {
                seq.remove(at);
            }
            _ => at += 1,
        }
    }
}

/// Whether control can leave `stmt` by reaching its end. Conservative: a construct this does not
/// read completes.
fn completes(stmt: &CStmt, ev: &Evidence<'_>) -> bool {
    match stmt {
        CStmt::Observed { stmt, .. } => completes(stmt, ev),
        CStmt::Block(items) => {
            (items.iter().rev().find(|stmt| !blank(stmt))).is_none_or(|last| completes(last, ev))
        }
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            completes(then_body, ev)
                || else_body
                    .as_ref()
                    .is_none_or(|else_body| completes(else_body, ev))
        }
        CStmt::Goto(_) | CStmt::Return(_) | CStmt::Break | CStmt::Continue => false,
        CStmt::Expr(_) => !(ev.never_returns)(stmt),
        CStmt::For {
            cond: None, body, ..
        } => breaks_out(body),
        _ => true,
    }
}

/// Whether a `break` in `stmt` leaves the loop whose body it is, not a loop or switch inside it.
fn breaks_out(stmt: &CStmt) -> bool {
    match stmt {
        CStmt::Break => true,
        CStmt::Observed { stmt, .. } => breaks_out(stmt),
        CStmt::Block(items) => items.iter().any(breaks_out),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => breaks_out(then_body) || else_body.as_deref().is_some_and(breaks_out),
        _ => false,
    }
}

/// `return x;` after a conditional whose arms fall into it, `x` a merge of distinct values: the
/// compiler joined returns of different values, and each arm that fell returns its own.
fn join_in_sequence(occ: &mut Occurrences, ev: &Evidence<'_>, seq: &mut Vec<CStmt>) {
    let mut at = 1;
    while at < seq.len() {
        let Some(tail) = guarded_return(occ, ev, &seq[at]) else {
            at += 1;
            continue;
        };
        let before = seq[..at].iter().rposition(|stmt| !blank(stmt));
        let ends = before.and_then(|before| falling_ends(&seq[before], ev));
        let (Some(before), Some(2..)) = (before, ends) else {
            at += 1;
            continue;
        };
        let template = tail.clone();
        let mut original = Some(tail);
        let mut next = || match original.take() {
            Some(first) => first,
            None => template.iter().map(|stmt| occ.fresh(stmt)).collect(),
        };
        append_to_ends(&mut seq[before], ev, &mut next);
        seq.remove(at);
    }
}

/// The text of a block that is only a `return` of a merge of distinct values, and that no `goto`
/// names (its label, if placement wrote one, has gone).
fn guarded_return(occ: &Occurrences, ev: &Evidence<'_>, stmt: &CStmt) -> Option<Vec<CStmt>> {
    let CStmt::Block(items) = stmt else {
        return None;
    };
    let (None, stmts) = parse(items, ev)? else {
        return None;
    };
    let [only] = stmts
        .iter()
        .filter(|stmt| !matches!(stmt.unobserved(), CStmt::Empty))
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    let returns_value = matches!(only.unobserved(), CStmt::Return(Some(_)));
    let distinct = only
        .observation_ids()
        .iter()
        .filter_map(|id| occ.block_of(*id))
        .any(|block| (ev.distinct_return)(block));
    (returns_value && distinct).then_some(stmts)
}

/// How many arm ends of `stmt` complete into what follows it; `None` where an arm ends in a
/// construct this does not read.
fn falling_ends(stmt: &CStmt, ev: &Evidence<'_>) -> Option<usize> {
    match stmt {
        CStmt::Observed { stmt, .. } => falling_ends(stmt, ev),
        CStmt::Block(items) => match items.iter().rev().find(|stmt| !blank(stmt)) {
            Some(last) => falling_ends(last, ev),
            None => Some(1),
        },
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            let then_ends = falling_ends(then_body, ev)?;
            let else_ends = match else_body {
                Some(else_body) => falling_ends(else_body, ev)?,
                None => 1,
            };
            Some(then_ends + else_ends)
        }
        CStmt::Goto(_) | CStmt::Return(_) | CStmt::Break | CStmt::Continue => Some(0),
        CStmt::Expr(_) => Some(usize::from(!(ev.never_returns)(stmt))),
        CStmt::Empty | CStmt::Comment(_) => Some(1),
        _ => None,
    }
}

/// Put the next copy at every arm end [`falling_ends`] counts, in the same order.
fn append_to_ends(stmt: &mut CStmt, ev: &Evidence<'_>, next: &mut dyn FnMut() -> Vec<CStmt>) {
    match stmt {
        CStmt::Observed { stmt, .. } => append_to_ends(stmt, ev, next),
        CStmt::Block(items) => match items.iter().rposition(|stmt| !blank(stmt)) {
            Some(last)
                if matches!(items[last].unobserved(), CStmt::If { .. } | CStmt::Block(_)) =>
            {
                append_to_ends(&mut items[last], ev, next);
            }
            Some(last) if falling_ends(&items[last], ev) == Some(0) => {}
            _ => items.extend(next()),
        },
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            append_to_ends(then_body, ev, next);
            match else_body {
                Some(else_body) => append_to_ends(else_body, ev, next),
                None => *else_body = Some(Box::new(one(next()))),
            }
        }
        CStmt::Empty => *stmt = one(next()),
        _ if falling_ends(stmt, ev) == Some(0) => {}
        other => {
            let mut stmts = vec![std::mem::replace(other, CStmt::Empty)];
            stmts.extend(next());
            *other = CStmt::Block(stmts);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{CExpr, CType};
    use crate::prelude::ResidualCause;
    use crate::structure::certify::{StatementRole, certify};
    use crate::structure::shape::shape;
    use crate::structure::support::{at, branch, cfg, cond, cond_branch, expr};
    use crate::symbol::ExternalKind;
    use r2ssa::cfg::{BlockTerminator, CFG};
    use r2ssa::domtree::DomTree;

    const EXIT: &str = "exit";

    fn ret(value: i64) -> CStmt {
        CStmt::Return(Some(CExpr::IntLit(value)))
    }

    /// A call to `exit`, which every test here declares never returns.
    fn exit() -> CStmt {
        let callee = CExpr::External {
            name: EXIT.to_owned(),
            kind: ExternalKind::Function,
        };
        CStmt::Expr(CExpr::call(callee, Vec::new()))
    }

    fn never_returns(stmt: &CStmt) -> bool {
        matches!(stmt, CStmt::Expr(CExpr::Call { func, .. })
            if matches!(&**func, CExpr::External { name, .. } if name == EXIT))
    }

    /// An edge copy: a statement no block owns.
    fn copy(value: i64) -> CStmt {
        CStmt::Expr(CExpr::IntLit(value))
    }

    fn goto(label: &str) -> CStmt {
        CStmt::Goto(label.to_owned())
    }

    fn label(name: &str) -> CStmt {
        CStmt::Label(name.to_owned())
    }

    fn block(stmts: Vec<CStmt>) -> CStmt {
        CStmt::Block(stmts)
    }

    fn branching(then_body: CStmt, else_body: CStmt) -> CStmt {
        CStmt::if_stmt(cond(), then_body, Some(else_body))
    }

    fn count(stmt: &CStmt, pick: &dyn Fn(&CStmt) -> bool) -> usize {
        let mut total = usize::from(pick(stmt));
        let mut add = |inner: &CStmt| total += count(inner, pick);
        match stmt {
            CStmt::Observed { stmt, .. } => add(stmt),
            CStmt::Block(stmts) => stmts.iter().for_each(add),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                add(then_body);
                else_body.iter().for_each(|body| add(body));
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                add(body);
            }
            CStmt::Switch { cases, default, .. } => (cases.iter().flat_map(|case| &case.body))
                .chain(default.iter().flatten())
                .for_each(add),
            _ => {}
        }
        total
    }

    fn gotos(stmt: &CStmt) -> usize {
        count(stmt, &|stmt| matches!(stmt, CStmt::Goto(_)))
    }

    fn returns(stmt: &CStmt) -> usize {
        count(stmt, &|stmt| matches!(stmt, CStmt::Return(_)))
    }

    fn exits(stmt: &CStmt) -> usize {
        count(stmt, &never_returns)
    }

    fn labels(stmt: &CStmt) -> usize {
        count(stmt, &|stmt| matches!(stmt, CStmt::Label(_)))
    }

    /// The tree shaped, and the certificate's reading of the result. `distinct` names the return
    /// blocks whose value is a merge of pairwise-distinct values; `names` maps labels to blocks.
    fn shaped(
        body: CStmt,
        cfg: &CFG,
        names: &[(&str, u64)],
        distinct: &[u64],
    ) -> (CStmt, crate::structure::certify::ControlCertificate) {
        let blocks = (0..0x100u64).collect::<Vec<_>>();
        let mut occurrences = Occurrences::new(blocks.clone(), blocks);
        let distinct_return = |block: u64| distinct.contains(&block);
        let evidence = Evidence {
            never_returns: &never_returns,
            distinct_return: &distinct_return,
        };
        let body = shape(&mut occurrences, &evidence, body);
        let label_block = |name: &str| {
            names
                .iter()
                .find(|(label, _)| *label == name)
                .map(|(_, block)| *block)
        };
        let certificate = certify(
            &body,
            cfg,
            &DomTree::compute(cfg),
            cfg.entry,
            &|id| occurrences.block_of(id),
            &label_block,
            &|stmt| match never_returns(stmt) {
                true => StatementRole::Ends,
                false => StatementRole::Plain,
            },
            &|_| false,
        );
        (body, certificate)
    }

    /// 0x10 tests; 0x20 and 0x30 each copy a value in and meet at the return 0x40.
    fn diamond() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        )
    }

    /// The tree placement writes for [`diamond`]: both arms copy and jump to the merge.
    fn diamond_tree(tail: Vec<CStmt>) -> CStmt {
        let arm =
            |block: u64, value: i64| block_of(vec![at(block, expr()), copy(value), goto("L0")]);
        let mut merge = vec![label("L0")];
        merge.extend(tail);
        block(vec![
            at(0x10, expr()),
            at(0x10, branching(arm(0x20, 1), arm(0x30, 2))),
            block(merge),
        ])
    }

    fn block_of(stmts: Vec<CStmt>) -> CStmt {
        CStmt::Block(stmts)
    }

    #[test]
    fn a_return_of_a_merge_of_distinct_values_is_copied_into_the_arms_that_fall_to_it() {
        let (body, certificate) = shaped(
            diamond_tree(vec![at(0x40, ret(7))]),
            &diamond(),
            &[("L0", 0x40)],
            &[0x40],
        );
        assert!(certificate.ok(), "{certificate}");
        assert_eq!((returns(&body), gotos(&body), labels(&body)), (2, 0, 0));
        assert_eq!(certificate.duplicated, vec![0x40]);
    }

    #[test]
    fn a_return_of_a_value_the_edges_do_not_all_differ_in_stays_one_return() {
        let (body, certificate) = shaped(
            diamond_tree(vec![at(0x40, ret(7))]),
            &diamond(),
            &[("L0", 0x40)],
            &[],
        );
        assert!(certificate.ok(), "{certificate}");
        assert_eq!((returns(&body), gotos(&body)), (1, 0));
        assert!(certificate.duplicated.is_empty());
    }

    #[test]
    fn a_side_effect_before_the_return_is_not_a_return_to_copy_into_arms() {
        let tail = vec![at(0x40, expr()), at(0x40, ret(7))];
        let (body, certificate) = shaped(diamond_tree(tail), &diamond(), &[("L0", 0x40)], &[0x40]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(returns(&body), 1);
    }

    #[test]
    fn the_arms_of_nested_conditionals_each_get_a_return() {
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, cond_branch(0x50, 0x60)),
                (0x30, branch(0x40)),
                (0x50, branch(0x40)),
                (0x60, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let inner = branching(
            block_of(vec![at(0x50, expr()), copy(1), goto("L0")]),
            block_of(vec![at(0x60, expr()), copy(2), goto("L0")]),
        );
        let outer = branching(
            block_of(vec![at(0x20, expr()), at(0x20, inner)]),
            block_of(vec![at(0x30, expr()), copy(3), goto("L0")]),
        );
        let body = block(vec![
            at(0x10, expr()),
            at(0x10, outer),
            block(vec![label("L0"), at(0x40, ret(7))]),
        ]);
        let (body, certificate) = shaped(body, &cfg, &[("L0", 0x40)], &[0x40]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!((returns(&body), gotos(&body)), (3, 0));
    }

    #[test]
    fn one_arm_falling_to_the_return_is_not_a_join() {
        // The other arm returns on its own: the return has one way in by fall-through.
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, BlockTerminator::Return),
                (0x30, branch(0x40)),
                (0x40, BlockTerminator::Return),
            ],
        );
        let body = block(vec![
            at(0x10, expr()),
            at(
                0x10,
                branching(
                    at(0x20, ret(1)),
                    block_of(vec![at(0x30, expr()), copy(2), at(0x40, ret(7))]),
                ),
            ),
        ]);
        let (body, certificate) = shaped(body, &cfg, &[], &[0x40]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(returns(&body), 2);
    }

    #[test]
    fn a_return_something_still_jumps_to_is_not_copied_away() {
        // `join_returns` alone, on a tree whose label a `goto` still names: the block must stay.
        let blocks = (0..0x100u64).collect::<Vec<_>>();
        let mut occurrences = Occurrences::new(blocks.clone(), blocks);
        let evidence = Evidence {
            never_returns: &never_returns,
            distinct_return: &|_| true,
        };
        let arm = |block: u64| block_of(vec![at(block, expr()), copy(1)]);
        let mut body = block(vec![
            at(0x10, branching(arm(0x20), arm(0x30))),
            block(vec![label("L0"), at(0x40, ret(7))]),
            block(vec![at(0x50, goto("L0"))]),
        ]);
        join_returns(&mut occurrences, &evidence, &mut body);
        assert_eq!((returns(&body), gotos(&body), labels(&body)), (1, 1, 1));
    }

    /// A loop of 0x20, 0x30 and 0x35 that leaves for the returns 0x40 (from its header) and 0x50
    /// (from two blocks, so only a `goto` reaches it).
    fn loop_with_two_exits() -> CFG {
        cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x30, 0x40)),
                (0x30, cond_branch(0x35, 0x50)),
                (0x35, cond_branch(0x20, 0x50)),
                (0x40, BlockTerminator::Return),
                (0x50, BlockTerminator::Return),
            ],
        )
    }

    /// The tree placement writes for it: `tail` is the text of 0x50 after its label.
    fn loop_tree(tail: Vec<CStmt>) -> CStmt {
        let latch = at(
            0x35,
            CStmt::if_stmt(cond(), CStmt::Continue, Some(goto("L50"))),
        );
        let inner = block_of(vec![
            at(0x30, expr()),
            at(
                0x30,
                branching(block_of(vec![at(0x35, expr()), latch]), goto("L50")),
            ),
        ]);
        let header = block_of(vec![
            at(0x20, expr()),
            at(0x20, branching(inner, goto("L40"))),
        ]);
        let mut shared = vec![label("L50")];
        shared.extend(tail);
        block(vec![
            at(0x10, expr()),
            CStmt::For {
                init: None,
                cond: None,
                update: None,
                body: Box::new(header),
            },
            block(vec![label("L40"), at(0x40, ret(1))]),
            block(shared),
        ])
    }

    const LOOP_LABELS: [(&str, u64); 2] = [("L40", 0x40), ("L50", 0x50)];

    #[test]
    fn a_return_every_jump_reaches_is_written_at_each_jump_and_the_block_goes() {
        let (body, certificate) = shaped(
            loop_tree(vec![at(0x50, ret(7))]),
            &loop_with_two_exits(),
            &LOOP_LABELS,
            &[],
        );
        assert!(certificate.ok(), "{certificate}");
        // The header's exit is a `break` to the return after the loop; the other two exits return.
        assert_eq!((returns(&body), gotos(&body), labels(&body)), (3, 0, 0));
        assert_eq!(certificate.duplicated, vec![0x50]);
    }

    #[test]
    fn a_call_that_never_returns_is_a_tail_too() {
        let (body, certificate) = shaped(
            loop_tree(vec![at(0x50, expr()), at(0x50, exit())]),
            &loop_with_two_exits(),
            &LOOP_LABELS,
            &[],
        );
        assert!(certificate.ok(), "{certificate}");
        assert_eq!((exits(&body), gotos(&body)), (2, 0));
    }

    #[test]
    fn a_tail_of_four_statements_is_copied_and_one_of_five_stays_shared() {
        let tail = |statements: usize| {
            let mut tail = vec![at(0x50, expr()); statements - 1];
            tail.push(at(0x50, ret(7)));
            tail
        };
        let cfg = loop_with_two_exits();
        let (four, certificate) = shaped(loop_tree(tail(4)), &cfg, &LOOP_LABELS, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!((gotos(&four), labels(&four)), (0, 0));
        let (five, certificate) = shaped(loop_tree(tail(5)), &cfg, &LOOP_LABELS, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!((gotos(&five), labels(&five)), (2, 1));
    }

    #[test]
    fn a_block_that_goes_on_is_not_a_tail() {
        // 0x50 jumps to the merge 0x80: copying it would copy an edge the certificate finds twice.
        let body = loop_tree(vec![at(0x50, expr()), goto("L80")]);
        let (shaped_body, _) = shaped(body, &loop_with_two_exits(), &LOOP_LABELS, &[]);
        let to = |name: &'static str| {
            count(
                &shaped_body,
                &move |stmt| matches!(stmt, CStmt::Goto(n) if n == name),
            )
        };
        assert_eq!((to("L50"), to("L80")), (2, 1));
    }

    #[test]
    fn a_tail_holding_a_residual_is_not_copied() {
        let residual =
            crate::prelude::residual(&CType::uint(64), ResidualCause::Gap).expect("a residual");
        let tail = vec![at(0x50, CStmt::Expr(residual)), at(0x50, ret(7))];
        let (body, certificate) =
            shaped(loop_tree(tail), &loop_with_two_exits(), &LOOP_LABELS, &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!(gotos(&body), 2);
    }

    #[test]
    fn a_tail_the_text_above_falls_into_stays_beside_its_copies() {
        // 0x20 jumps to the return 0x50 or goes on to 0x30, which falls into 0x50 as well.
        let cfg = cfg(
            0x10,
            &[
                (0x10, branch(0x20)),
                (0x20, cond_branch(0x50, 0x30)),
                (0x30, branch(0x50)),
                (0x50, BlockTerminator::Return),
            ],
        );
        let body = block(vec![
            at(0x10, expr()),
            at(0x20, expr()),
            at(0x20, CStmt::if_stmt(cond(), goto("L50"), None)),
            at(0x30, expr()),
            block(vec![label("L50"), at(0x50, ret(7))]),
        ]);
        let (body, certificate) = shaped(body, &cfg, &[("L50", 0x50)], &[]);
        assert!(certificate.ok(), "{certificate}");
        assert_eq!((returns(&body), gotos(&body), labels(&body)), (2, 0, 0));
    }

    /// The leaf statements of `stmt` in text order, an expression or return of a literal as its value.
    fn leaves(stmt: &CStmt, out: &mut Vec<String>) {
        match stmt {
            CStmt::Observed { stmt, .. } => leaves(stmt, out),
            CStmt::Block(stmts) => stmts.iter().for_each(|stmt| leaves(stmt, out)),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                leaves(then_body, out);
                else_body.iter().for_each(|body| leaves(body, out));
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                leaves(body, out);
            }
            CStmt::Expr(CExpr::IntLit(value)) => out.push(format!("e{value}")),
            CStmt::Return(Some(CExpr::IntLit(value))) => out.push(format!("r{value}")),
            CStmt::Goto(_) => out.push("goto".to_owned()),
            _ => {}
        }
    }

    fn texts(stmt: &CStmt) -> Vec<String> {
        let mut out = Vec::new();
        leaves(stmt, &mut out);
        out
    }

    #[test]
    fn a_copy_of_a_tail_keeps_every_statement_of_the_original_in_order() {
        let tail = vec![at(0x50, copy(11)), at(0x50, copy(12)), at(0x50, ret(7))];
        let (body, certificate) =
            shaped(loop_tree(tail), &loop_with_two_exits(), &LOOP_LABELS, &[]);
        assert!(certificate.ok(), "{certificate}");
        let texts = texts(&body);
        let whole = texts.windows(3).filter(|run| run == &["e11", "e12", "r7"]);
        assert_eq!(whole.count(), 2, "{texts:?}");
        assert_eq!(texts.iter().filter(|text| *text == "e11").count(), 2);
    }

    #[test]
    fn a_copy_the_graph_does_not_have_is_refused_by_the_certificate() {
        // The caller claims a return where the block goes on: copies of it are refused, not written.
        let cfg = cfg(
            0x10,
            &[
                (0x10, cond_branch(0x20, 0x30)),
                (0x20, branch(0x40)),
                (0x30, branch(0x40)),
                (0x40, branch(0x10)),
            ],
        );
        let (_, certificate) = shaped(
            diamond_tree(vec![at(0x40, ret(7))]),
            &cfg,
            &[("L0", 0x40)],
            &[0x40],
        );
        assert!(!certificate.ok(), "{certificate}");
    }
}
