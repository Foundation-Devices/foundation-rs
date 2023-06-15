// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Based on code from bumpalo and Rust std.

/// Alternative to `std::boxed::Box`, but using an arena allcator.
///
/// # Example
///
/// Recursive data structure:
///
/// ```rust
/// use foundation_arena::{Arena, boxed::Box};
///
/// let a: Arena<_, 2> = Arena::new();
/// let b: Arena<_, 2> = Arena::new();
///
/// #[derive(Debug, PartialEq)]
/// enum List<'a, T> {
///     Cons(T, Box<'a, List<'a, T>>),
///     Nil,
/// }
///
/// let list = List::<i32>::Cons(
///     1,
///     Box::new_in(List::Cons(2, Box::new_in(List::Nil, &a).unwrap()), &a).unwrap(),
/// );
///
/// let clone = List::<i32>::Cons(
///     1,
///     Box::new_in(List::Cons(2, Box::new_in(List::Nil, &b).unwrap()), &b).unwrap(),
/// );
///
/// println!("{:?}", list);
///
/// assert_eq!(list, clone);
/// ```
use core::{ops::Deref, ptr};

use crate::Arena;

#[derive(Debug)]
pub struct Box<'a, T>(&'a mut T);

impl<'a, T> Box<'a, T> {
    pub fn new_in<const N: usize>(x: T, arena: &'a Arena<T, N>) -> Result<Self, T> {
        arena.alloc(x).map(Self)
    }
}

impl<'a, T> Deref for Box<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<'a, 'b, T: PartialEq> PartialEq<Box<'b, T>> for Box<'a, T> {
    fn eq(&self, other: &Box<'b, T>) -> bool {
        PartialEq::eq(&**self, &**other)
    }

    fn ne(&self, other: &Box<'b, T>) -> bool {
        PartialEq::ne(&**self, &**other)
    }
}

impl<'a, T> Drop for Box<'a, T> {
    fn drop(&mut self) {
        unsafe { ptr::drop_in_place(self.0) }
    }
}
