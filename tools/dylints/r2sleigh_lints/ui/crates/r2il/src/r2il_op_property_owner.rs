#![allow(dead_code)]

struct Varnode(u64);

enum R2ILOp {
    Copy { dst: Varnode, src: Varnode },
    Select { dst: Varnode, cond: Varnode },
    Call { target: Varnode },
    CallInd { target: Varnode },
    Nop,
}

// r2il owns these properties; its own lists are not restatements.
impl R2ILOp {
    fn output(&self) -> Option<&Varnode> {
        match self {
            R2ILOp::Copy { dst, .. } | R2ILOp::Select { dst, .. } => Some(dst),
            _ => None,
        }
    }

    fn is_call(&self) -> bool {
        matches!(self, R2ILOp::Call { .. } | R2ILOp::CallInd { .. })
    }
}

fn main() {
    let op = R2ILOp::Nop;
    let _ = (op.output().is_some(), op.is_call());
}
