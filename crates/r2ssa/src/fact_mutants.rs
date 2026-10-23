//! Test only (feature `fact_mutants`): state a lane as before ROADMAP D68, unasked, with the check of the
//! sealed facts kept or skipped, so each defence is shown to hold alone.

/// How this thread's boundary facts are stated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Facts {
    /// As in production: a lane only where it has run, and the facts checked.
    Sound,
    /// A lane taken without asking, the facts still checked: r2ssa refuses the function.
    UnsoundLanes,
    /// A lane taken without asking and the facts unchecked: only the renderer's guard is left.
    UnsoundLanesUnchecked,
}

#[cfg(feature = "fact_mutants")]
mod on {
    use super::Facts;
    use std::cell::Cell;

    thread_local! {
        static STATED: Cell<Facts> = const { Cell::new(Facts::Sound) };
    }

    /// Run `body` with this thread's facts stated as `facts`, then restore what was set.
    pub fn with_facts<T>(facts: Facts, body: impl FnOnce() -> T) -> T {
        struct Restore(Facts);
        impl Drop for Restore {
            fn drop(&mut self) {
                STATED.with(|slot| slot.set(self.0));
            }
        }
        let _restore = Restore(STATED.with(|slot| slot.replace(facts)));
        body()
    }

    pub(crate) fn unsound_lanes() -> bool {
        STATED.with(Cell::get) != Facts::Sound
    }

    pub(crate) fn facts_unchecked() -> bool {
        STATED.with(Cell::get) == Facts::UnsoundLanesUnchecked
    }
}

#[cfg(feature = "fact_mutants")]
pub use on::with_facts;
#[cfg(feature = "fact_mutants")]
pub(crate) use on::{facts_unchecked, unsound_lanes};

#[cfg(not(feature = "fact_mutants"))]
pub(crate) const fn unsound_lanes() -> bool {
    false
}

#[cfg(not(feature = "fact_mutants"))]
pub(crate) const fn facts_unchecked() -> bool {
    false
}
