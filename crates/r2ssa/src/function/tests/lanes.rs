//! A call argument is the low lane of its carrier only where the lane's definition stands behind
//! the call (ROADMAP D68, doc/adr-decompiler-rewrite.md "D2's spelling order").

use super::*;
use crate::{
    CallSiteId, InstPayload, SourceCallArgumentSpec, SourceCallResult, SourceCallSiteIdentity,
    SourceCallSiteInterface, SourceFunctionInterface,
};
use r2il::ArchSpec;

const VECTOR: u64 = 0x100;
const MERGE: u64 = 0x100c;
const READER: u64 = 0x1010;
const CALLER: u64 = 0x1018;

fn storage(offset: u64, size: u32) -> CanonicalStorageId {
    CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size,
    }
}

/// A block of `ops`, each stamped as its own instruction.
fn block(addr: u64, ops: Vec<R2ILOp>) -> R2ILBlock {
    let mut block = R2ILBlock::new(addr, 4);
    for op in ops {
        block.push(op);
    }
    for index in 0..block.ops.len() {
        let returns = matches!(block.ops[index], R2ILOp::Return { .. });
        block.stamp_instruction(index, addr + if returns { 2 } else { 0 });
    }
    block
}

fn lane_read() -> Vec<R2ILOp> {
    vec![
        R2ILOp::Subpiece {
            dst: make_unique(0x200, 4),
            src: make_reg(VECTOR, 16),
            offset: 0,
        },
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr: make_const(0x3000, 8),
            val: make_unique(0x200, 4),
        },
    ]
}

/// Two arms load a vector register that merges at `MERGE`, which branches to `READER` (reads its low
/// lane) or `CALLER` (calls with it). `lane_in_the_merge` moves that read above the branch.
fn lane_call(lane_in_the_merge: bool) -> SsaArtifact {
    let mut arch = ArchSpec::new("lane-test");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("v", VECTOR, 16));
    let carrier = r2il::RegisterStorage {
        offset: VECTOR,
        size: 16,
    };
    let bound = |written, carrier, lsb_bit_offset, size_bits| r2il::RegisterProjection {
        written,
        disposition: r2il::RegisterProjectionDisposition::Bound {
            carrier,
            slice: r2il::RegisterBitSlice {
                lsb_bit_offset,
                size_bits,
            },
        },
    };
    let mut projections = vec![bound(carrier, carrier, 0, 128)];
    for lane in 0..4u32 {
        let offset = VECTOR + 4 * u64::from(lane);
        arch.add_register(RegisterDef::sub(format!("v{lane}"), offset, 4, "v"));
        let written = r2il::RegisterStorage { offset, size: 4 };
        projections.push(bound(written, carrier, 32 * u64::from(lane), 32));
    }
    for (name, offset, size) in [("cond", 0x40, 1), ("lr", 0x80, 8), ("sp", 0x88, 8)] {
        arch.add_register(RegisterDef::new(name, offset, size));
        let own = r2il::RegisterStorage { offset, size };
        projections.push(bound(own, own, 0, u64::from(size) * 8));
    }
    // The file lists its projections in the order of the storage they are for.
    projections.sort_by_key(|projection| projection.written);
    arch.register_projections = projections;
    // As x86 writes `xmm1` from memory: the low lane loaded, the three above it zeroed.
    let load = |addr| {
        let mut ops = vec![R2ILOp::Load {
            dst: make_reg(VECTOR, 4),
            space: SpaceId::Ram,
            addr: make_const(addr, 8),
        }];
        ops.extend((1..4).map(|lane| R2ILOp::Copy {
            dst: make_reg(VECTOR + 4 * lane, 4),
            src: make_const(0, 4),
        }));
        ops
    };
    let branch = |target| R2ILOp::Branch {
        target: make_const(target, 8),
    };
    let conditional = |target| R2ILOp::CBranch {
        target: make_const(target, 8),
        cond: make_reg(0x40, 1),
    };
    let ret = || R2ILOp::Return {
        target: make_reg(0x80, 8),
    };
    let callee = make_ram(0x4000, 8);
    let mut merge = if lane_in_the_merge {
        lane_read()
    } else {
        Vec::new()
    };
    merge.push(conditional(CALLER));
    let mut reader = if lane_in_the_merge {
        Vec::new()
    } else {
        lane_read()
    };
    reader.push(ret());
    let blocks = [
        block(0x1000, vec![conditional(0x1008)]),
        block(0x1004, [load(0x2000), vec![branch(MERGE)]].concat()),
        block(0x1008, [load(0x2010), vec![branch(MERGE)]].concat()),
        block(MERGE, merge),
        block(READER, reader),
        block(
            CALLER,
            vec![
                R2ILOp::Call {
                    target: callee.clone(),
                },
                ret(),
            ],
        ),
    ];
    let revision = b"lane-call";
    let interface = SourceFunctionInterface::new_exact(
        revision.to_vec(),
        "lane-abi",
        [],
        SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(0x80, 8)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(0x88, 8)))
    .expect("a function interface");
    let call = SourceCallSiteInterface::new(
        revision.to_vec(),
        SourceCallSiteIdentity::new(CALLER, CanonicalStorageId::from_varnode(&callee)),
        true,
        "lane-abi",
        [SourceCallArgumentSpec::new(0, storage(VECTOR, 4))],
        false,
        false,
        SourceCallResult::Void,
    )
    .expect("a call interface");
    crate::testing::prepared(
        &blocks,
        &crate::Arch::from(arch),
        Some(interface),
        vec![call],
        [storage(0x88, 8)],
    )
    .expect("the lane call prepares")
}

/// The call's one argument, and the instruction that defines a value, as `(block, is a phi)`.
fn the_argument(artifact: &SsaArtifact) -> SourceCallArgumentFact {
    let boundary =
        (artifact.facts().boundaries.calls.get(&CallSiteId(0))).expect("the call's boundary");
    let [argument] = boundary.arguments.as_slice() else {
        panic!("one argument: {boundary:?}");
    };
    *argument
}

fn defined_in(artifact: &SsaArtifact, value: ValueId) -> (u64, bool) {
    let graph = artifact.graph();
    let inst = graph
        .def_inst(value)
        .and_then(|inst| graph.inst(inst))
        .expect("a value the function defines");
    let block = graph.block(inst.block).expect("its block").addr;
    (block, matches!(inst.payload, InstPayload::Phi { .. }))
}

/// The value the low-lane read in `block` defines.
fn lane_defined_in(artifact: &SsaArtifact, block: u64) -> ValueId {
    let graph = artifact.graph();
    graph
        .insts
        .iter()
        .filter(|inst| {
            graph
                .block(inst.block)
                .is_some_and(|held| held.addr == block)
        })
        .find(|inst| matches!(&inst.payload, InstPayload::Op(SSAOp::Subpiece { .. })))
        .and_then(|inst| inst.output)
        .expect("a low lane read there")
}

#[test]
fn a_low_lane_read_on_the_other_arm_is_not_the_calls_argument() {
    // The lane is a view of the merge's vector, defined in `READER`, which does not dominate `CALLER`:
    // the argument is the merge itself, the carrier that does.
    let artifact = lane_call(false);
    let argument = the_argument(&artifact);
    let SourceCallArgumentValue::Value(value) = argument.value else {
        panic!("a value: {argument:?}");
    };
    assert_eq!(defined_in(&artifact, value), (MERGE, true));
    assert_eq!(artifact.graph().var(value).size, 16);
    assert_eq!(argument.lane_of, None);
    assert_ne!(value, lane_defined_in(&artifact, READER));
}

#[test]
fn a_low_lane_read_before_the_branch_is_the_calls_argument() {
    // The same lane read in the merge stands behind both arms: the argument narrows to it, as it did.
    let artifact = lane_call(true);
    let argument = the_argument(&artifact);
    let lane = lane_defined_in(&artifact, MERGE);
    assert_eq!(argument.value, SourceCallArgumentValue::Value(lane));
    let carrier = argument.lane_of.expect("the carrier the lane is of");
    assert_eq!(defined_in(&artifact, carrier), (MERGE, true));
    assert_eq!(artifact.graph().var(lane).size, 4);
}

/// The fact family `validate_boundary_values` names when `forge` puts `lane` (defined on the `READER`
/// arm, behind neither the call, the merge's branch nor either return of `CALLER`) in its place.
fn refused_for(
    artifact: &SsaArtifact,
    fact: &str,
    forge: impl FnOnce(&mut crate::PreparedFunctionFacts),
) -> &'static str {
    let mut forged = artifact.facts().clone();
    forge(&mut forged);
    let refused =
        crate::integrity::validate_boundary_values(artifact.function(), artifact.graph(), &forged)
            .expect_err(&format!("a value defined on the other arm is no {fact}"));
    assert_eq!(
        refused.rule(),
        crate::IntegrityRule::BoundaryValueNotDominated
    );
    let crate::SsaIntegrityError::BoundaryValueNotDominated { fact, .. } = refused else {
        panic!("{refused:?}");
    };
    fact
}

/// A change to the facts that puts a value out of its read's scope.
type Forge = Box<dyn Fn(&mut crate::PreparedFunctionFacts)>;

#[test]
fn a_boundary_fact_naming_a_value_its_read_does_not_stand_behind_is_refused() {
    use crate::semantic::SwitchPredicateFact;
    use crate::{CallBoundaryValueFact, SourceReturnAddressFact, SourceReturnStackPointerFact};
    let artifact = lane_call(false);
    crate::integrity::validate_boundary_values(
        artifact.function(),
        artifact.graph(),
        artifact.facts(),
    )
    .expect("the facts the collector states hold");
    let lane = lane_defined_in(&artifact, READER);
    let SourceCallArgumentValue::Value(carrier) = the_argument(&artifact).value else {
        panic!("the carrier is a value");
    };
    // The return in `CALLER`, which the `READER` arm does not lead to.
    let caller_return = |facts: &crate::PreparedFunctionFacts, graph: &crate::SsaGraph| {
        facts
            .boundaries
            .returns
            .iter()
            .map(|(at, _)| at)
            .find(|at| {
                graph
                    .walk_start(*at)
                    .is_some_and(|(block, _)| block == CALLER)
            })
            .expect("a return in the calling block")
    };
    let slot = CallBoundarySlot::Register {
        index: 0,
        storage: storage(0x80, 8),
    };
    let graph = artifact.graph();
    let at = caller_return(artifact.facts(), graph);
    let cases: Vec<(&str, Forge)> = vec![
        (
            "call argument",
            Box::new(move |f| {
                let call = f
                    .boundaries
                    .calls
                    .get_mut(&CallSiteId(0))
                    .expect("the call");
                call.arguments[0].value = SourceCallArgumentValue::Value(lane);
            }),
        ),
        (
            "call argument carrier",
            Box::new(move |f| {
                let argument = &mut f
                    .boundaries
                    .calls
                    .get_mut(&CallSiteId(0))
                    .expect("the call")
                    .arguments[0];
                argument.value = SourceCallArgumentValue::Value(carrier);
                argument.lane_of = Some(lane);
            }),
        ),
        (
            "call target",
            Box::new(move |f| {
                f.call_sites
                    .by_id
                    .values_mut()
                    .for_each(|site| site.target = lane);
            }),
        ),
        (
            "return value",
            Box::new(move |f| {
                let ret = f.boundaries.returns.get_mut(at).expect("the return");
                ret.values.push(CallBoundaryValueFact { slot, value: lane });
            }),
        ),
        (
            "return address",
            Box::new(move |f| {
                let ret = f.boundaries.returns.get_mut(at).expect("the return");
                let storage = storage(0x80, 8);
                ret.return_address = Some(SourceReturnAddressFact {
                    storage,
                    value: lane,
                });
            }),
        ),
        (
            "exit stack pointer",
            Box::new(move |f| {
                let ret = f.boundaries.returns.get_mut(at).expect("the return");
                let storage = storage(0x88, 8);
                ret.exit_stack_pointer = Some(SourceReturnStackPointerFact::ReachingValue {
                    storage,
                    value: lane,
                });
            }),
        ),
        (
            "branch condition",
            Box::new(move |f| {
                f.predicates
                    .predicates
                    .values_mut()
                    .for_each(|p| p.condition = lane)
            }),
        ),
        (
            "switch selector",
            Box::new(move |f| {
                f.predicates.switches.insert(
                    MERGE,
                    SwitchPredicateFact {
                        block_addr: MERGE,
                        selector: Some(lane),
                        cases: Vec::new(),
                        default: None,
                    },
                );
            }),
        ),
    ];
    for (fact, forge) in cases {
        assert_eq!(refused_for(&artifact, fact, forge), fact);
    }
}

#[test]
fn a_value_is_defined_before_the_operations_after_its_definition_and_not_those_up_to_it() {
    let artifact = lane_call(true);
    let (function, graph) = (artifact.function(), artifact.graph());
    let before = |value, block, ordinal| {
        crate::integrity::defined_before(function, graph, value, block, ordinal)
    };
    // An operation's output is defined for the operations after it, not for itself or the ones before.
    let lane = lane_defined_in(&artifact, MERGE);
    let (block, ordinal) = graph
        .def_inst(lane)
        .and_then(|inst| graph.walk_start(inst))
        .expect("the lane is an operation's output");
    assert!(!before(lane, block, ordinal));
    assert!(before(lane, block, ordinal + 1));
    assert!(before(lane, block, usize::MAX));
    // A phi is defined at its block's entry, for every operation in it.
    let carrier = (the_argument(&artifact).lane_of).expect("the carrier the lane is of");
    assert_eq!(defined_in(&artifact, carrier), (MERGE, true));
    assert!(before(carrier, MERGE, 0));
    // The merge dominates both arms below it.
    assert!(before(carrier, CALLER, 0));
    assert!(before(lane, READER, 0));
    assert!(before(lane, CALLER, 0));
    // A value the function was entered with, and a constant, are defined before everything.
    let entry = artifact
        .graph()
        .values
        .iter()
        .find(|v| artifact.graph().def_inst(v.id).is_none());
    assert!(entry.is_some_and(|value| before(value.id, CALLER, 0)));
    // A definition on one arm reaches neither the other arm nor the merge above it.
    let other_arm = lane_call(false);
    let lane = lane_defined_in(&other_arm, READER);
    let (function, graph) = (other_arm.function(), other_arm.graph());
    let on_the_arm =
        |block, ordinal| crate::integrity::defined_before(function, graph, lane, block, ordinal);
    assert!(!on_the_arm(CALLER, 0) && !on_the_arm(MERGE, usize::MAX));
    assert!(on_the_arm(READER, usize::MAX));
}
