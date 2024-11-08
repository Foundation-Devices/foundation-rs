// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # Heapless [`Rc`] type.
//!
//! This is a reference countable pointer for Rust, imitating the official
//! `alloc::rc::Rc` pointer but without using the heap.
//!
//! This requires the user to create a [`NonNull`] [`RcInner`] type allocated
//! by their own mean that won't be de-allocated, essentially leaking this
//! memory, or in other words, it should have a `'static` lifetime.
//!
//! For example by using [`Box::leak`] or by using a global mutable static
//! variable.
//!
//! Notes:
//!
//! Consider splitting this code into a separate crate.

use core::{cell::Cell, fmt, marker::PhantomData, ops::Deref, ptr, ptr::NonNull};

pub struct Rc<T> {
    ptr: NonNull<RcInner<T>>,
    phantom: PhantomData<RcInner<T>>,
}

pub struct RcInner<T> {
    strong: Cell<usize>,
    value: T,
}

impl<T> RcInner<T> {
    pub const fn new(value: T) -> Self {
        Self {
            strong: Cell::new(1),
            value,
        }
    }

    fn inc_strong(&self) {
        let strong = self.strong.get().wrapping_add(1);
        self.strong.set(strong);

        if strong == 0 {
            panic!("the reference count overflowed");
        }
    }

    fn dec_strong(&self) {
        let strong = self.strong.get() - 1;
        self.strong.set(strong);
    }
}

impl<T> Rc<T> {
    /// Construct a [`Rc`] from the inner value.
    pub unsafe fn from_inner(inner: NonNull<RcInner<T>>) -> Self {
        Self {
            ptr: inner,
            phantom: PhantomData,
        }
    }

    #[inline(always)]
    fn inner(&self) -> &RcInner<T> {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Deref for Rc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner().value
    }
}

impl<T> AsRef<T> for Rc<T> {
    fn as_ref(&self) -> &T {
        &**self
    }
}

impl<T> Clone for Rc<T> {
    fn clone(&self) -> Self {
        unsafe {
            self.inner().inc_strong();
            Self::from_inner(self.ptr)
        }
    }
}

impl<T> Drop for Rc<T> {
    fn drop(&mut self) {
        self.inner().dec_strong();

        // Just drop the value after reaching 0, no de-allocation happens.
        if self.inner().strong.get() == 0 {
            unsafe {
                ptr::drop_in_place(&mut (*self.ptr.as_ptr()).value);
            }
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Rc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
