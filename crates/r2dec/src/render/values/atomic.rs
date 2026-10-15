//! One atomic access as a call to the helper wrapping the GCC and Clang builtin for its operation,
//! width and ordering (`prelude`), its value read assigned where something reads it. A maximum, a
//! minimum, 128 bits or an unstated ordering has no builtin and stays a gap.

use r2ssa::{AtomicOp, AtomicUpdateOp, InstId, MachineType, SemanticObligationKind, ValueId};

use super::Values;
use crate::ast::{CExpr, CStmt, CType};
use crate::prelude::{self, AtomicOrder, Helper};

impl Values<'_> {
    /// `name = helper((void *)address, operands...)`, or the call alone where nothing reads it.
    pub(super) fn atomic(
        &self,
        inst: InstId,
        access: &AtomicOp<ValueId>,
        output: Option<ValueId>,
    ) -> Option<CStmt> {
        if !self.little_endian || access.space != r2il::SpaceId::Ram {
            return None;
        }
        let bits = match self.value_type(access.dst)? {
            MachineType::Integer { width_bits, .. } => width_bits,
            _ => return None,
        };
        let op = match &access.update {
            AtomicUpdateOp::Fetch { op, .. } => prelude::AtomicOp::Fetch(*op),
            AtomicUpdateOp::CompareExchange { .. } => prelude::AtomicOp::CompareExchange,
        };
        let helper = Helper::atomic(op, bits, AtomicOrder::of(access.ordering)?)?;
        let unsigned = CType::Int {
            bits,
            signedness: r2types::Signedness::Unsigned,
        };
        let address = self.operand(access.addr, inst)?;
        let mut args = vec![CExpr::cast(CType::Pointer(Box::new(CType::Void)), address)];
        for operand in access.operands() {
            if !matches!(self.value_type(*operand)?, MachineType::Integer { .. }) {
                return None;
            }
            args.push(CExpr::cast(unsigned.clone(), self.operand(*operand, inst)?));
        }
        let call = helper.call(args);
        let named = output.and_then(|output| Some((output, self.names[output.0 as usize]?.0)));
        Some(match named {
            Some((output, name)) => {
                self.mark_discharged(output);
                self.assign_value(output, name, call)
            }
            None => CStmt::Expr(call),
        })
    }

    /// Whether `inst` is a plain access of an instruction whose accesses are one indivisible
    /// access with no typed statement (r2ssa owes its atomicity), which no plain C states.
    pub(super) fn owes_atomicity(&self, inst: InstId) -> bool {
        self.inventory
            .obligations_for_inst(inst)
            .any(|obligation| obligation.id.kind == SemanticObligationKind::Atomicity)
    }
}
