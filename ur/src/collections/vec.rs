// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

use core::ops::{Deref, DerefMut};

/// Error that can occur when reserving memory on a [`Vec`].
#[derive(Debug)]
pub struct TryReserveError;

/// A vector collection.
pub trait Vec<T>:
    AsMut<[T]>
    + AsRef<[T]>
    + Default
    + Deref<Target = [T]>
    + DerefMut<Target = [T]>
    + Extend<T>
    + FromIterator<T>
{
    /// Clear the collection.
    fn clear(&mut self);

    /// Returns the capacity of the collection.
    fn capacity(&self) -> usize;

    /// Reserve additional capacity for the collection.
    fn reserve(&mut self, capacity: usize);

    /// Resize the collection to the new length using `value` as the default
    /// value for new elements.
    fn try_resize(&mut self, new_len: usize, value: T) -> Result<(), TryReserveError>
    where
        T: Clone;

    /// Push a new element to the back of the collection.
    fn try_push(&mut self, value: T) -> Result<(), TryReserveError>;

    /// Pop an element from the back of the collection.
    fn pop(&mut self) -> Option<T>;

    /// Remove an element from the collection using it's index.
    fn remove(&mut self, index: usize) -> T;

    /// Retain elements.
    fn retain_mut<F>(&mut self, f: F)
    where
        F: FnMut(&mut T) -> bool;

    /// Try extending the vector from an existing slice.
    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), TryReserveError>
    where
        T: Clone;
}

#[cfg(feature = "alloc")]
impl<T> Vec<T> for alloc::vec::Vec<T> {
    fn clear(&mut self) {
        alloc::vec::Vec::clear(self)
    }

    fn capacity(&self) -> usize {
        alloc::vec::Vec::capacity(self)
    }

    fn reserve(&mut self, capacity: usize) {
        alloc::vec::Vec::reserve(self, capacity)
    }

    fn try_resize(&mut self, new_len: usize, value: T) -> Result<(), TryReserveError>
    where
        T: Clone,
    {
        if new_len > self.len() {
            let additional = new_len - self.len();
            if alloc::vec::Vec::try_reserve(self, additional).is_err() {
                return Err(TryReserveError);
            }
        }

        alloc::vec::Vec::resize(self, new_len, value);
        Ok(())
    }

    fn try_push(&mut self, value: T) -> Result<(), TryReserveError> {
        alloc::vec::Vec::push(self, value);
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        alloc::vec::Vec::pop(self)
    }

    fn remove(&mut self, index: usize) -> T {
        alloc::vec::Vec::remove(self, index)
    }

    fn retain_mut<F>(&mut self, f: F)
    where
        F: FnMut(&mut T) -> bool,
    {
        alloc::vec::Vec::retain_mut(self, f)
    }

    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), TryReserveError>
    where
        T: Clone,
    {
        if alloc::vec::Vec::try_reserve(self, slice.len()).is_err() {
            return Err(TryReserveError);
        }

        alloc::vec::Vec::extend_from_slice(self, slice);

        Ok(())
    }
}

impl<T, const N: usize> Vec<T> for heapless::Vec<T, N> {
    fn clear(&mut self) {
        heapless::Vec::clear(self)
    }

    fn capacity(&self) -> usize {
        heapless::Vec::capacity(self)
    }

    fn reserve(&mut self, capacity: usize) {
        let remaining_capacity = heapless::Vec::capacity(self) - (self as &[_]).len();
        if remaining_capacity < capacity {
            panic!(
                "can't reserve more capacity, remaining {} and need {}",
                remaining_capacity,
                capacity - remaining_capacity
            );
        }
    }

    fn try_resize(&mut self, new_len: usize, value: T) -> Result<(), TryReserveError>
    where
        T: Clone,
    {
        heapless::Vec::resize(self, new_len, value).map_err(|_| TryReserveError)
    }

    fn try_push(&mut self, value: T) -> Result<(), TryReserveError> {
        heapless::Vec::push(self, value).map_err(|_| TryReserveError)
    }

    fn pop(&mut self) -> Option<T> {
        heapless::Vec::pop(self)
    }

    fn remove(&mut self, index: usize) -> T {
        heapless::Vec::remove(self, index)
    }

    fn retain_mut<F>(&mut self, f: F)
    where
        F: FnMut(&mut T) -> bool,
    {
        heapless::Vec::retain_mut(self, f)
    }

    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), TryReserveError>
    where
        T: Clone,
    {
        heapless::Vec::extend_from_slice(self, slice).map_err(|_| TryReserveError)
    }
}
