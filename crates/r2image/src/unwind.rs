//! What the binary's call-frame information says about each function's frame.
//!
//! `.eh_frame` survives `strip --strip-all`: the C++ runtime and every
//! unwinder need it, so a stripped binary still states, for each function it
//! covers, where the function starts and ends and where it saves each register
//! it preserves. That is a fact the container states, not one inferred from
//! the code, and the frame partition takes its save slots as boundaries no
//! local may cross.
//!
//! Each save is placed relative to the stack pointer on entry. The CFI places
//! it relative to the CFA, and the CFA at the function's first address is the
//! entry stack pointer plus a constant the CIE states (`rsp + 8` on x86-64,
//! `sp + 0` on AArch64). A frame whose CFA at entry is not stated that way, or
//! is not stated from the stack pointer, has its extent read and its saves
//! refused: a slot placed from a guessed CFA would be a guessed boundary.
//!
//! The first row also states how control enters the frame: in the state a call
//! leaves, or in some other, as a split-off part of a function is entered by
//! its parent's jump with the parent's frame.
//!
//! It fails closed per entry. An FDE that does not parse is skipped; the rest
//! of the section is still read.

use std::collections::BTreeMap;

pub use r2abi::frames::{FrameEntry, UnwindFrame, UnwindFrames};

/// What a call leaves for the architectures whose CFI this reads, in DWARF register numbers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CallState {
    stack_pointer: u16,
    /// The CFA's offset from the stack pointer just after a call.
    cfa: i64,
    /// Where the call stored the return address, as a column and a CFA offset; `None` where it stays in a register.
    return_slot: Option<(u16, i64)>,
}

/// The state a call leaves; `None` for an architecture not stated here, which reads every
/// frame's extent, no saves and no entry state.
pub(crate) fn call_state(architecture: object::Architecture) -> Option<CallState> {
    use object::Architecture as A;
    let (stack_pointer, cfa, return_slot) = match architecture {
        A::X86_64 | A::X86_64_X32 => (7, 8, Some((16, -8))),
        A::I386 => (4, 4, Some((8, -4))),
        A::Aarch64 | A::Aarch64_Ilp32 => (31, 0, None),
        A::Arm => (13, 0, None),
        A::Riscv32 | A::Riscv64 => (2, 0, None),
        _ => return None,
    };
    Some(CallState {
        stack_pointer,
        cfa,
        return_slot,
    })
}

/// Read every frame `.eh_frame` and `.debug_frame` describe.
pub(crate) fn read(file: &object::File<'_>) -> UnwindFrames {
    use object::{Object as _, ObjectSection as _};
    let endian = match file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };
    let call = call_state(file.architecture());
    let address_size = if file.is_64() { 8 } else { 4 };
    let section = |name: &str| {
        file.section_by_name(name)
            .and_then(|section| Some((section.address(), section.data().ok()?)))
    };
    let mut bases = gimli::BaseAddresses::default();
    if let Some((address, _)) = section(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(address);
    }
    if let Some((address, _)) = section(".text") {
        bases = bases.set_text(address);
    }
    if let Some((address, _)) = section(".got") {
        bases = bases.set_got(address);
    }
    let mut frames = UnwindFrames::default();
    if let Some((address, data)) = section(".eh_frame") {
        let mut eh_frame = gimli::EhFrame::new(data, endian);
        eh_frame.set_address_size(address_size);
        let bases = bases.clone().set_eh_frame(address);
        read_section(&eh_frame, &bases, call, &mut frames);
    }
    if let Some((_, data)) = section(".debug_frame") {
        let mut debug_frame = gimli::DebugFrame::new(data, endian);
        debug_frame.set_address_size(address_size);
        read_section(&debug_frame, &bases, call, &mut frames);
    }
    frames
}

fn read_section<'a, S>(
    section: &S,
    bases: &gimli::BaseAddresses,
    call: Option<CallState>,
    frames: &mut UnwindFrames,
) where
    S: gimli::UnwindSection<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    S::Offset: gimli::UnwindOffset<usize>,
{
    let mut context = gimli::UnwindContext::new();
    let mut entries = section.entries(bases);
    loop {
        let entry = match entries.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            // A malformed length stops the walk: nothing after it can be found.
            Err(_) => break,
        };
        let gimli::CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) =
            partial.parse(|section, bases, offset| section.cie_from_offset(bases, offset))
        else {
            continue;
        };
        if fde.len() == 0 {
            continue;
        }
        let start = fde.initial_address();
        let Some(end) = start.checked_add(fde.len()) else {
            continue;
        };
        let (entry, saves) = call
            .and_then(|call| rows(section, bases, &mut context, &fde, call))
            .unwrap_or_default();
        frames.insert(UnwindFrame {
            start,
            end,
            saves,
            entry,
        });
    }
}

/// How control enters the frame, and where the function saves each register from the stack
/// pointer on entry.
///
/// A save keeps its place for the rest of the function, so the union over every row is the set
/// of save slots; there are none when the first row's CFA is not the stack pointer plus a
/// constant, since the entry stack pointer is then not what the offsets are measured from.
fn rows<'a, S>(
    section: &S,
    bases: &gimli::BaseAddresses,
    context: &mut gimli::UnwindContext<usize>,
    fde: &gimli::FrameDescriptionEntry<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    call: CallState,
) -> Option<(FrameEntry, BTreeMap<u16, i64>)>
where
    S: gimli::UnwindSection<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    S::Offset: gimli::UnwindOffset<usize>,
{
    let mut table = fde.rows(section, bases, context).ok()?;
    // The first row is the state at the frame's first address.
    let first = table.next_row().ok()??;
    let entry = entered(first, call);
    let cfa = match first.cfa() {
        gimli::CfaRule::RegisterAndOffset { register, offset }
            if register.0 == call.stack_pointer =>
        {
            *offset
        }
        _ => return Some((entry, BTreeMap::new())),
    };
    let mut saves = BTreeMap::new();
    let mut save = |row: &gimli::UnwindTableRow<usize>| {
        for (register, rule) in row.registers() {
            if let gimli::RegisterRule::Offset(offset) = rule {
                // Saved at CFA + offset, and the CFA is the entry stack
                // pointer plus the constant the first row states.
                saves.insert(register.0, cfa.checked_add(*offset)?);
            }
        }
        Some(())
    };
    save(first)?;
    while let Some(row) = table.next_row().ok()? {
        save(row)?;
    }
    Some((entry, saves))
}

/// Whether a frame's first row is the state `call` leaves: a fragment is entered with its parent's frame.
fn entered(first: &gimli::UnwindTableRow<usize>, call: CallState) -> FrameEntry {
    entry_of(
        first.cfa(),
        first.registers().map(|(r, rule)| (r.0, rule)),
        call,
    )
}

/// A call's state where the CFA and every rule say so, a mid-function state only where they
/// positively state one, and unstated where a rule is an expression this does not evaluate.
fn entry_of<'r>(
    cfa: &gimli::CfaRule<usize>,
    mut rules: impl Iterator<Item = (u16, &'r gimli::RegisterRule<usize>)>,
    call: CallState,
) -> FrameEntry {
    use gimli::RegisterRule as R;
    let called_cfa = match cfa {
        gimli::CfaRule::RegisterAndOffset { register, offset } => {
            register.0 == call.stack_pointer && *offset == call.cfa
        }
        gimli::CfaRule::Expression(_) => return FrameEntry::Unstated,
    };
    let mut saved = false;
    let read = rules.try_for_each(|(register, rule)| {
        match rule {
            R::Undefined | R::SameValue => {}
            R::Offset(offset) if call.return_slot == Some((register, *offset)) => {}
            R::Offset(_) | R::ValOffset(_) | R::Register(_) => saved = true,
            _ => return Err(()),
        }
        Ok(())
    });
    match (read, called_cfa && !saved) {
        (Err(()), _) => FrameEntry::Unstated,
        (Ok(()), true) => FrameEntry::Called,
        (Ok(()), false) => FrameEntry::MidFunction,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86_64: CallState = CallState {
        stack_pointer: 7,
        cfa: 8,
        return_slot: Some((16, -8)),
    };

    #[test]
    fn an_entry_rule_this_does_not_evaluate_leaves_the_entry_unstated() {
        let at_call = gimli::CfaRule::RegisterAndOffset {
            register: gimli::Register(7),
            offset: 8,
        };
        let expression = gimli::UnwindExpression {
            offset: 0,
            length: 1,
        };
        let returned = gimli::RegisterRule::Offset(-8);
        let pushed = gimli::RegisterRule::Offset(-16);
        let opaque = gimli::RegisterRule::Expression(expression);
        let entry = |cfa: &gimli::CfaRule<usize>, rules: &[(u16, &gimli::RegisterRule<usize>)]| {
            entry_of(cfa, rules.iter().copied(), X86_64)
        };
        assert_eq!(entry(&at_call, &[(16, &returned)]), FrameEntry::Called);
        assert_eq!(
            entry(&at_call, &[(16, &returned), (6, &pushed)]),
            FrameEntry::MidFunction
        );
        assert_eq!(
            entry(&at_call, &[(16, &returned), (6, &opaque)]),
            FrameEntry::Unstated
        );
        let by_expression = gimli::CfaRule::Expression(expression);
        assert_eq!(
            entry(&by_expression, &[(16, &returned)]),
            FrameEntry::Unstated
        );
        let moved = gimli::CfaRule::RegisterAndOffset {
            register: gimli::Register(7),
            offset: 16,
        };
        assert_eq!(entry(&moved, &[(16, &returned)]), FrameEntry::MidFunction);
    }

    fn frames_of(bytes: &[u8]) -> UnwindFrames {
        let file = object::File::parse(bytes).expect("an object");
        read(&file)
    }

    /// The DWARF fixture is a clang x86-64 ELF; its `.eh_frame` describes every
    /// function. Each frame's first save is the return address (column 16) at
    /// the entry stack pointer itself, and a frame-pointer prologue saves rbp
    /// (column 6) in the eight bytes below it.
    #[test]
    fn every_frame_states_its_extent_and_where_the_return_address_is() {
        let frames = frames_of(include_bytes!("../tests/data/dwarf_prototypes.elf"));
        assert!(!frames.is_empty());
        for frame in frames.frames() {
            assert!(frame.start < frame.end, "{frame:?}");
            assert_eq!(frame.saves.get(&16), Some(&0), "{frame:?}");
            if let Some(rbp) = frame.saves.get(&6) {
                assert_eq!(*rbp, -8, "{frame:?}");
            }
        }
        let first = frames.frames().next().expect("a frame");
        assert_eq!(frames.covering(first.start), Some(first));
        assert_eq!(frames.covering(first.end), frames.at(first.end));
        assert!(
            frames
                .frames()
                .any(|frame| frame.saves.get(&6) == Some(&-8)),
            "a frame-pointer prologue saves rbp: {frames:?}"
        );
        assert!(
            frames
                .frames()
                .all(|frame| frame.entry == FrameEntry::Called),
            "every frame begins a function: {frames:?}"
        );
    }

    /// GCC's `.cold` part has an FDE of its own whose first row is its parent's state at the
    /// jump; the parent and a leaf begin in the state a call leaves (`cold_fragment.py`).
    #[test]
    fn a_frame_entered_with_its_parent_s_state_is_a_fragment() {
        let frames = frames_of(include_bytes!("../tests/data/cold_fragment.elf"));
        let entry = |start| frames.at(start).map(|frame| frame.entry);
        assert_eq!(entry(0x401000), Some(FrameEntry::Called));
        assert_eq!(entry(0x401010), Some(FrameEntry::MidFunction));
        assert_eq!(entry(0x401020), Some(FrameEntry::Called));
        // The fragment's saves are measured from the stack pointer at its own first address.
        let cold = frames.at(0x401010).expect("the fragment's frame");
        assert_eq!(cold.saves.get(&3), Some(&0));
    }

    /// `strip --strip-all` keeps `.eh_frame`: the stripped twin states the
    /// same frames.
    #[test]
    fn a_stripped_binary_states_the_same_frames() {
        let full = frames_of(include_bytes!("../tests/data/dwarf_prototypes.elf"));
        let stripped = frames_of(include_bytes!(
            "../tests/data/dwarf_prototypes_stripped.elf"
        ));
        assert_eq!(full, stripped);
    }
}
