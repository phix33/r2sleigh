//! The write order of a placement, which the order-invariance gate permutes (ROADMAP D58); without
//! the `placement_mutants` feature there is one order and no branch.

#[cfg(not(feature = "placement_mutants"))]
pub(crate) use off::WriteOrder;
#[cfg(feature = "placement_mutants")]
pub use on::{WriteOrder, with_write_order};

#[cfg(not(feature = "placement_mutants"))]
mod off {
    /// The only order: the facts' own.
    #[derive(Clone, Copy)]
    pub(crate) struct WriteOrder;

    impl WriteOrder {
        pub(crate) const fn current() -> Self {
            Self
        }

        pub(crate) const fn inlines_exits(self) -> bool {
            true
        }

        pub(crate) fn exits(self, _: &mut [u64]) {}

        pub(crate) fn merges(self, _: &mut [u64]) {}
    }
}

#[cfg(feature = "placement_mutants")]
mod on {
    use std::cell::Cell;
    use std::sync::OnceLock;

    /// How a placement orders what it writes. Every verdict D2 gives must be the same under all four.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WriteOrder {
        /// Reverse postorder, exits inlined where their edge leaves the loop.
        Natural,
        /// O1: no exit is inlined, so each is written after its loop.
        KeepExits,
        /// O2: the exits of each loop in reverse of their reverse postorder.
        ExitsReversed,
        /// O3: the merges of each region in reverse of their reverse postorder.
        MergesReversed,
    }

    thread_local! {
        static OVERRIDE: Cell<Option<WriteOrder>> = const { Cell::new(None) };
    }

    /// Run `body` with placements ordered by `order` on this thread, then restore what was set.
    pub fn with_write_order<T>(order: WriteOrder, body: impl FnOnce() -> T) -> T {
        struct Restore(Option<WriteOrder>);
        impl Drop for Restore {
            fn drop(&mut self) {
                OVERRIDE.with(|slot| slot.set(self.0));
            }
        }
        let _restore = Restore(OVERRIDE.with(|slot| slot.replace(Some(order))));
        body()
    }

    /// `R2SLEIGH_WRITE_ORDER` = `o1`, `o2` or `o3`, read once, for the corpus sweep.
    fn from_env() -> WriteOrder {
        static ENV: OnceLock<WriteOrder> = OnceLock::new();
        *ENV.get_or_init(|| match std::env::var("R2SLEIGH_WRITE_ORDER").as_deref() {
            Ok("o1") => WriteOrder::KeepExits,
            Ok("o2") => WriteOrder::ExitsReversed,
            Ok("o3") => WriteOrder::MergesReversed,
            _ => WriteOrder::Natural,
        })
    }

    impl WriteOrder {
        pub(crate) fn current() -> Self {
            OVERRIDE.with(Cell::get).unwrap_or_else(from_env)
        }

        pub(crate) fn inlines_exits(self) -> bool {
            self != Self::KeepExits
        }

        pub(crate) fn exits(self, list: &mut [u64]) {
            if self == Self::ExitsReversed {
                list.reverse();
            }
        }

        pub(crate) fn merges(self, list: &mut [u64]) {
            if self == Self::MergesReversed {
                list.reverse();
            }
        }
    }
}
