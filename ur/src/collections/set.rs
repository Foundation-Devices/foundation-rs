// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

use core::hash::{BuildHasher, Hash};

/// A set collection.
pub trait Set<T>: Clone + Default + Extend<T> {
    /// Iterator type over the elements of the set.
    type Iter<'a>: Iterator<Item = &'a T>
    where
        T: 'a,
        Self: 'a;

    /// Insert a new item into set set.
    fn insert(&mut self, value: T) -> Result<bool, T>;

    /// Remove an item from set set.
    fn remove(&mut self, value: &T) -> bool;

    /// Return the first element of the set.
    fn first(&self) -> Option<&T>;

    /// Check if the set contains `value`.
    fn contains(&mut self, value: &T) -> bool;

    /// Check `other` is a subset.
    fn is_subset(&self, other: &Self) -> bool;

    /// Number of elements in the set.
    fn len(&self) -> usize;

    /// Remove all elements from the set.
    fn clear(&mut self);

    /// Returns `true` if the set is empty.
    #[must_use]
    fn is_empty(&self) -> bool;

    /// Subtract one set from another.
    fn sub(&self, other: &Self) -> Self;

    /// Returns an iterator over the set elements.
    #[must_use]
    fn iter(&self) -> Self::Iter<'_>;
}

#[cfg(feature = "alloc")]
impl<T> Set<T> for alloc::collections::BTreeSet<T>
where
    T: Clone + Ord,
{
    type Iter<'a> = alloc::collections::btree_set::Iter<'a, T> where T: 'a, Self: 'a;

    fn insert(&mut self, value: T) -> Result<bool, T> {
        Ok(alloc::collections::BTreeSet::insert(self, value))
    }

    fn remove(&mut self, value: &T) -> bool {
        alloc::collections::BTreeSet::remove(self, value)
    }

    fn first(&self) -> Option<&T> {
        alloc::collections::BTreeSet::first(self)
    }

    fn contains(&mut self, value: &T) -> bool {
        alloc::collections::BTreeSet::contains(self, value)
    }

    fn is_subset(&self, other: &Self) -> bool {
        alloc::collections::BTreeSet::is_subset(self, other)
    }

    fn len(&self) -> usize {
        alloc::collections::BTreeSet::len(self)
    }

    fn clear(&mut self) {
        alloc::collections::BTreeSet::clear(self)
    }

    fn is_empty(&self) -> bool {
        alloc::collections::BTreeSet::is_empty(self)
    }

    fn sub(&self, other: &Self) -> Self {
        self - other
    }

    fn iter(&self) -> Self::Iter<'_> {
        alloc::collections::BTreeSet::iter(self)
    }
}

impl<T, S, const N: usize> Set<T> for heapless::IndexSet<T, S, N>
where
    T: Clone + Eq + Hash,
    S: BuildHasher + Clone + Default,
{
    type Iter<'a> = heapless::IndexSetIter<'a, T>
    where
        T: 'a,
        Self: 'a;

    fn insert(&mut self, value: T) -> Result<bool, T> {
        heapless::IndexSet::insert(self, value)
    }

    fn remove(&mut self, value: &T) -> bool {
        heapless::IndexSet::remove(self, value)
    }

    fn first(&self) -> Option<&T> {
        heapless::IndexSet::first(self)
    }

    fn contains(&mut self, value: &T) -> bool {
        heapless::IndexSet::contains(self, value)
    }

    fn is_subset(&self, other: &Self) -> bool {
        heapless::IndexSet::is_subset(self, other)
    }

    fn len(&self) -> usize {
        heapless::IndexSet::len(self)
    }

    fn clear(&mut self) {
        heapless::IndexSet::clear(self)
    }

    fn is_empty(&self) -> bool {
        heapless::IndexSet::is_empty(self)
    }

    fn sub(&self, other: &Self) -> Self {
        let mut result = heapless::IndexSet::default();
        result.extend(self.difference(other).cloned());
        result
    }

    fn iter(&self) -> Self::Iter<'_> {
        heapless::IndexSet::iter(self)
    }
}
