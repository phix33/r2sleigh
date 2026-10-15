//! One resolved body per function, as queries (doc/adr-resolved-bodies.md, P6 and P7).
//!
//! A function whose result a callee's statement could prove is resolved again against that callee
//! resolved, bottom-up over the components of those demands; under `aa`, so is one whose arity
//! a callee's could make exact. Members of one component read each other as resolved alone, so an
//! arity a cycle hands on stays a floor.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::analysis::{CalleeReads, Shared, callee_read};
use super::{ProgramInputs, Source, View};
use crate::native::{CalleeRead, Unreadable};
use crate::query::db::{Db, Hold, Query, Retention};

/// A function by its entry and whether it is Thumb.
type Node = (u64, bool);

/// Which owners a resolution waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Demand {
    /// The callees whose stated result could prove a function's: every request.
    Result,
    /// Those, and the callees whose stated arity could make a floor exact: the closure over them
    /// is paid only once `aa` surveyed the program (doc/adr-resolved-bodies.md, "Arity").
    Arity,
}

/// The strongly connected component a function is in, over the edges to the owners its demand
/// names. SM's summaries reuse it (ROADMAP P7, SM).
pub(super) struct Component;

/// A component's members in address order, shared by every member's answer: O(k) for k members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Members {
    pub(super) members: std::rc::Rc<[Node]>,
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Component {
    type Key = (Node, Demand);
    type Value = Members;
    const NAME: &'static str = "component";
    const RETENTION: Retention = Retention::Held;

    /// Tarjan's algorithm from `root` over owner edges, O(V + E) over what it reaches; every component it closes is deposited.
    fn compute(db: &Db<ProgramInputs<S>>, &(root, demand): &(Node, Demand)) -> Members {
        let view = View::new(db, true);
        let mut search = Search::default();
        search.run(root, |node| owners(db, &view, node, demand));
        let own = search.of[&root];
        let answers = search.closed.iter().enumerate();
        let answers = answers.filter(|(at, _)| *at != own);
        let answers = answers.flat_map(|(_, members)| {
            let each = members.members.iter();
            each.map(|node| ((*node, demand), members.clone()))
        });
        db.deposit::<Component>(answers.collect::<Vec<_>>());
        search.closed.swap_remove(own)
    }
}

/// The bodies whose statement could prove this function's result or arity, resolved alone; an
/// import's is its declaration's.
fn owners<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    view: &View<'_, S>,
    node: Node,
    demand: Demand,
) -> Vec<Node> {
    let read = db
        .get::<CalleeReads>(&node)
        .expect("a read asks for no demand");
    bodies(view, &read.0, demand)
}

/// The bodies among the owners a read's demand names, in address order, each in the instruction
/// set it is entered in.
fn bodies<S: Source + 'static>(view: &View<'_, S>, read: &CalleeRead, demand: Demand) -> Vec<Node> {
    let arity = match demand {
        Demand::Result => None,
        Demand::Arity => Some(&read.owners.arity),
    };
    let owners = read.owners.result.iter().chain(arity.into_iter().flatten());
    let owners = owners.copied().collect::<BTreeSet<_>>().into_iter();
    let bodies = owners.filter(|owner| crate::native::Program::import_at(view, *owner).is_none());
    bodies.map(|owner| (owner, view.thumb_at(owner))).collect()
}

/// One function resolved against the resolved callees its result or arity waits on.
pub(super) struct Resolved;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Resolved {
    type Key = (Node, Demand);
    type Value = Shared<CalleeRead>;
    const NAME: &'static str = "resolved";
    const RETENTION: Retention = Retention::Held;

    /// Work: one preparation per function whose result or arity an owner outside its component could prove.
    fn compute(db: &Db<ProgramInputs<S>>, &(node, demand): &(Node, Demand)) -> Shared<CalleeRead> {
        let alone = db
            .get::<CalleeReads>(&node)
            .expect("a read asks for no resolution");
        let view = View::new(db, true);
        let owners = bodies(&view, &alone.0, demand);
        if owners.is_empty() {
            return (*alone).clone();
        }
        let cycle = db
            .get::<Component>(&(node, demand))
            .expect("a component asks for no resolution");
        let outside = owners
            .into_iter()
            .filter(|owner| !cycle.members.contains(owner));
        let mut resolved = Vec::new();
        for owner in outside {
            let read = db
                .get::<Resolved>(&(owner, demand))
                .expect("demands below a cycle close");
            resolved.push((owner.0, Arc::clone(&read.0)));
        }
        // An owner the request stopped decides nothing, and no answer standing on the stop is held.
        if resolved
            .iter()
            .any(|(_, read)| matches!(read.facts, Err(Unreadable::Stopped)))
        {
            return Shared(Arc::new(CalleeRead {
                interface: None,
                facts: Err(Unreadable::Stopped),
                owners: Default::default(),
            }));
        }
        // Resolving again pays only where some owner now states its result or an exact arity.
        let proves = |(_, read): &(u64, Arc<CalleeRead>)| {
            let Some(interface) = read.interface.as_ref() else {
                return false;
            };
            let returns = interface.return_kind() != r2source::SourceFunctionReturn::Unproven;
            read.facts.is_ok() && (returns || interface.arity().is_exact())
        };
        if !resolved.iter().any(proves) {
            return (*alone).clone();
        }
        Shared(Arc::new(callee_read(db, node, &resolved)))
    }

    fn hold(value: &Shared<CalleeRead>) -> Hold {
        match value.0.facts {
            Err(Unreadable::Stopped) => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}

/// One frame of the search: a function, its callees, and the next callee to visit.
struct Frame {
    node: Node,
    callees: Vec<Node>,
    next: usize,
}

#[derive(Default)]
struct Search {
    index: BTreeMap<Node, usize>,
    low: BTreeMap<Node, usize>,
    stack: Vec<Node>,
    on_stack: BTreeSet<Node>,
    /// Which closed component each function is in.
    of: BTreeMap<Node, usize>,
    closed: Vec<Members>,
}

impl Search {
    /// The search terminates: each function is pushed once, and each frame advances over finitely many callees.
    fn run(&mut self, root: Node, callees: impl Fn(Node) -> Vec<Node>) {
        let mut frames = vec![self.open(root, &callees)];
        while let Some(frame) = frames.last_mut() {
            let node = frame.node;
            let Some(&callee) = frame.callees.get(frame.next) else {
                frames.pop();
                self.finish(node, frames.last().map(|caller| caller.node));
                continue;
            };
            frame.next += 1;
            match self.index.get(&callee) {
                None => frames.push(self.open(callee, &callees)),
                Some(&index) if self.on_stack.contains(&callee) => self.lower(node, index),
                Some(_) => {}
            }
        }
    }

    /// `node` has visited every callee: its caller's low link takes its own, and it may close a component.
    fn finish(&mut self, node: Node, caller: Option<Node>) {
        if let Some(caller) = caller {
            self.lower(caller, self.low[&node]);
        }
        self.close(node);
    }

    /// Lower `node`'s low link to `to` where that is lower.
    fn lower(&mut self, node: Node, to: usize) {
        let low = self.low[&node].min(to);
        self.low.insert(node, low);
    }

    fn open(&mut self, node: Node, callees: &impl Fn(Node) -> Vec<Node>) -> Frame {
        let index = self.index.len();
        self.index.insert(node, index);
        self.low.insert(node, index);
        self.stack.push(node);
        self.on_stack.insert(node);
        let callees = callees(node);
        Frame {
            node,
            callees,
            next: 0,
        }
    }

    /// Where `node` is the first of its component on the stack, pop the component.
    fn close(&mut self, node: Node) {
        if self.low[&node] != self.index[&node] {
            return;
        }
        let at = self
            .stack
            .iter()
            .rposition(|held| *held == node)
            .expect("on the stack");
        let mut members = self.stack.split_off(at);
        members.sort_unstable();
        let id = self.closed.len();
        for member in &members {
            self.on_stack.remove(member);
            self.of.insert(*member, id);
        }
        self.closed.push(Members {
            members: members.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn components(edges: &[(u64, u64)], root: u64) -> Vec<Vec<u64>> {
        let mut search = Search::default();
        let callees = |(at, _): Node| {
            let out = edges.iter().filter(|(from, _)| *from == at);
            out.map(|(_, to)| (*to, false)).collect()
        };
        search.run((root, false), callees);
        let closed = search.closed.iter();
        closed
            .map(|closed| closed.members.iter().map(|(at, _)| *at).collect())
            .collect()
    }

    #[test]
    fn a_component_closes_after_every_component_it_calls() {
        // 1 demands 2 and 3; 2 and 4 demand each other; 3 demands itself; 4 demands 5.
        let edges = [(1, 2), (1, 3), (2, 4), (4, 2), (3, 3), (4, 5)];
        assert_eq!(
            components(&edges, 1),
            [vec![5], vec![2, 4], vec![3], vec![1]]
        );
    }
}
