// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Based on the code of typed-arena:
//
// SPDX-FileCopyrightText: © 2016 The typed-arena developers <https://github.com/thomcc/rust-typed-arena>
// SPDX-License-Identifier: MIT

//! # Foundation Arena.
//!
//! This crate provides an alternative to the [`typed_arena`] crate that does
//! not use the heap. Instead, the [`Arena`] type statically allocates
//! memory at compile-time by passing the `N` type parameter.
//!
//! # Examples
//!
//! ```rust
//! use foundation_arena::Arena;
//!
//! let arena: Arena<u32, 8> = Arena::new();
//! let one: &mut u32 = arena.alloc(1).unwrap();
//! let two: &mut u32 = arena.alloc(2).unwrap();
//!
//! println!("{one} {two}");
//! ```

#![no_std]

use core::{
    cell::{Cell, UnsafeCell},
    mem::MaybeUninit,
};

pub mod boxed;

/// An arena of objects of type `T`.
pub struct Arena<T, const N: usize> {
    /// Each slot is written at most once. `UnsafeCell` permits initializing a
    /// new slot through `&self` without creating a mutable reference to the
    /// complete backing array, which would invalidate references to earlier
    /// slots.
    storage: UnsafeCell<[MaybeUninit<T>; N]>,
    len: Cell<usize>,
}

impl<T, const N: usize> Arena<T, N> {
    /// Construct a new arena.
    pub const fn new() -> Self {
        Self {
            storage: UnsafeCell::new([const { MaybeUninit::uninit() }; N]),
            len: Cell::new(0),
        }
    }

    /// Allocates an item in the arena, returning a mutable reference to that
    /// item.
    ///
    /// If there's not enough space left in the arena, then the item is
    /// returned as-is.
    ///
    /// Values allocated directly are not dropped when the arena is dropped.
    /// Use [`boxed::Box`] when the value needs drop glue.
    ///
    /// # Safety invariants
    ///
    /// - `len` increases monotonically, so no two successful allocations use
    ///   the same slot.
    /// - A mutable reference is created only for the newly initialized slot.
    ///   Later allocations access other slots only through raw pointers and
    ///   never create a mutable reference to the complete backing array.
    /// - The returned reference is tied to the arena, so safe code cannot
    ///   outlive the arena or reset a slot while that reference exists.
    pub fn alloc(&self, item: T) -> Result<&mut T, T> {
        let slot = self.len.get();
        if slot == N {
            return Err(item);
        }

        let ptr = self.slot_ptr(slot);
        // SAFETY: `slot < N`, the slot is uninitialized, and the monotonic
        // allocation index ensures no other reference can point at it.
        unsafe { ptr.write(item) };

        self.len.set(slot + 1);

        // SAFETY: the slot was initialized above and is uniquely owned by
        // this allocation for the lifetime of the arena.
        Ok(unsafe { &mut *ptr })
    }

    fn slot_ptr(&self, slot: usize) -> *mut T {
        // SAFETY: callers ensure `slot < N`. Casting the raw pointer avoids
        // creating a reference to the whole array.
        unsafe {
            self.storage
                .get()
                .cast::<MaybeUninit<T>>()
                .add(slot)
                .cast::<T>()
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::{boxed::Box, Arena};

    #[test]
    fn allocates_distinct_slots_up_to_capacity() {
        let arena: Arena<u32, 2> = Arena::new();

        let first = arena.alloc(11).unwrap();
        let second = arena.alloc(22).unwrap();

        assert_eq!((*first, *second), (11, 22));
        assert_eq!(arena.alloc(33), Err(33));
    }

    #[test]
    fn earlier_allocation_remains_usable_after_later_allocation() {
        let arena: Arena<u32, 2> = Arena::new();

        let first = arena.alloc(11).unwrap();
        let second = arena.alloc(22).unwrap();

        // This is the arena's intended contract: successful allocations own
        // distinct, stable slots for as long as the arena is alive. Before
        // the allocator redesign, Miri reports UB when `first` is used here.
        *first += 1;
        *second += 1;

        assert_eq!((*first, *second), (12, 23));
    }

    #[test]
    fn counts_zero_sized_allocations_toward_capacity() {
        let arena: Arena<(), 2> = Arena::new();

        let first = arena.alloc(()).unwrap();
        let second = arena.alloc(()).unwrap();

        assert_eq!((*first, *second), ((), ()));
        assert_eq!(arena.alloc(()), Err(()));
    }

    #[test]
    fn boxed_value_is_dropped_once() {
        #[derive(Debug)]
        struct DropCounter<'a>(&'a Cell<u8>);

        impl Drop for DropCounter<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let drops = Cell::new(0);
        let arena: Arena<DropCounter, 1> = Arena::new();
        let value = Box::new_in(DropCounter(&drops), &arena).unwrap();

        drop(value);
        assert_eq!(drops.get(), 1);
    }
}
