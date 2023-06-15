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

use core::{cell::RefCell, mem::MaybeUninit};

pub mod boxed;

/// An arena of objects of type `T`.
pub struct Arena<T, const N: usize> {
    storage: RefCell<Chunk<T, N>>,
}

impl<T, const N: usize> Arena<T, N> {
    /// Construct a new arena.
    pub const fn new() -> Self {
        Self {
            storage: RefCell::new(Chunk::new()),
        }
    }

    /// Allocates an item in the arena, returning a mutable reference to that
    /// item.
    ///
    /// If there's not enough space left in the arena, then the item is
    /// returned as-is.
    pub fn alloc(&self, item: T) -> Result<&mut T, T> {
        let mut storage = self.storage.borrow_mut();
        let len = storage.len();
        storage.push(item)?;
        Ok(unsafe { &mut *storage.as_mut_ptr().add(len) })
    }
}

struct Chunk<T, const N: usize> {
    buffer: [MaybeUninit<T>; N],
    len: usize,
}

impl<T, const N: usize> Chunk<T, N> {
    const ELEM: MaybeUninit<T> = MaybeUninit::uninit();
    const INIT: [MaybeUninit<T>; N] = [Self::ELEM; N];

    pub const fn new() -> Self {
        Self {
            buffer: Self::INIT,
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, item: T) -> Result<(), T> {
        if self.len < N {
            unsafe {
                *self.buffer.get_unchecked_mut(self.len) = MaybeUninit::new(item);
                self.len += 1;
            }
            Ok(())
        } else {
            Err(item)
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.buffer.as_mut_ptr() as *mut T
    }
}
