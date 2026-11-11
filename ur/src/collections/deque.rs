// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

/// A double-ended queue.
pub trait Deque<T>: Default {
    /// Push an element on the back of the queue.
    fn push_back(&mut self, item: T) -> Result<(), T>;

    /// Number of queued elements.
    fn len(&self) -> usize;

    /// Push an element on the front of the queue.
    fn pop_front(&mut self) -> Option<T>;

    /// Remove all the elements.
    fn clear(&mut self);

    /// Returns `true` if the queue is empty.
    fn is_empty(&self) -> bool;
}

#[cfg(feature = "alloc")]
impl<T> Deque<T> for alloc::collections::VecDeque<T> {
    fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.try_reserve(1).is_err() {
            return Err(value);
        }
        alloc::collections::VecDeque::push_back(self, value);
        Ok(())
    }

    fn len(&self) -> usize {
        alloc::collections::VecDeque::len(self)
    }

    fn pop_front(&mut self) -> Option<T> {
        alloc::collections::VecDeque::pop_front(self)
    }

    fn clear(&mut self) {
        alloc::collections::VecDeque::clear(self)
    }

    fn is_empty(&self) -> bool {
        alloc::collections::VecDeque::is_empty(self)
    }
}

impl<T, const N: usize> Deque<T> for heapless::Deque<T, N> {
    fn push_back(&mut self, value: T) -> Result<(), T> {
        heapless::Deque::push_back(self, value)
    }

    fn len(&self) -> usize {
        heapless::Deque::len(self)
    }

    fn pop_front(&mut self) -> Option<T> {
        heapless::Deque::pop_front(self)
    }

    fn clear(&mut self) {
        heapless::Deque::clear(self)
    }

    fn is_empty(&self) -> bool {
        heapless::Deque::is_empty(self)
    }
}
