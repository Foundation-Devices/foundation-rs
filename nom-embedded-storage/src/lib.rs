// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # embedded-storage-nom
//!
//! Implementation of [`nom`] traits for [`embedded_storage::nor_flash`] to
//! allow parsing directly from a storage device.
//!
//! Ideally this should be implemented for `embedded-io` traits but for the
//! sake of simplicity for Passport we just use [`embedded_storage`].

#![cfg_attr(not(feature = "std"), no_std)]

use core::{
    cell::RefCell,
    iter::Enumerate,
    ops::Deref,
    ops::{Range, RangeFrom, RangeFull, RangeTo},
};
use embedded_storage::nor_flash::ReadNorFlash;
use heapless::Vec;
use nom::{
    Compare, CompareResult, FindSubstring, FindToken, InputIter, InputLength, InputTake, Needed,
    Slice,
};

pub mod rc;

use crate::rc::Rc;

/// A byte slice in the NOR flash storage.
#[derive(Debug)]
pub struct Bytes<S, const N: usize> {
    offset: usize,
    len: usize,
    storage: Rc<RefCell<S>>,
    buffer: RefCell<Vec<u8, N>>,
}

impl<S, const N: usize> Bytes<S, N>
where
    S: ReadNorFlash,
{
    /// Create a byte slice from `storage` of `len` bytes at `offset`.
    ///
    /// # Return value
    ///
    /// If `offset` combined with `len` is past the capacity of `storage`
    /// an error is returned.
    pub fn new(offset: usize, len: usize, storage: Rc<RefCell<S>>) -> Result<Self, Error> {
        // We expect to read at least one byte from the flash.
        if S::READ_SIZE > 1 {
            return Err(Error::UnsupportedReadSize);
        }

        let capacity = if let Ok(s) = storage.try_borrow() {
            s.capacity()
        } else {
            return Err(Error::AlreadyBorrowed);
        };

        if offset + len > capacity {
            return Err(Error::OutOfBounds {
                offset,
                len,
                capacity,
            });
        }

        Ok(Self {
            offset,
            len,
            storage,
            buffer: RefCell::new(Vec::new()),
        })
    }

    /// Find `needle` in haystack (self), returning the position of the found
    /// byte or None if not found.
    pub fn memchr(&self, needle: u8) -> Result<usize, FindTokenError<S::Error>> {
        let mut pos = 0;

        while pos < self.len() {
            let mut buffer = self.buffer.borrow_mut();
            buffer.clear();
            buffer
                .resize(self.len().min(N), 0)
                .expect("size should be less than or equal to N");

            let offset = match u32::try_from(self.offset + pos) {
                Ok(v) => v,
                Err(_) => return Err(FindTokenError::OffsetOverflow),
            };

            if let Err(e) = self.storage.borrow_mut().read(offset, &mut buffer) {
                return Err(FindTokenError::Io(e));
            }

            // We found the needle in this chunk, so return the found
            // position inside of the chunk plus the current offset.
            if let Some(byte_position) = memchr::memchr(needle, &buffer[..]) {
                return Ok(pos + byte_position);
            }

            pos += self.len().min(N);
        }

        Err(FindTokenError::NotFound)
    }
}

impl<S, const N: usize> Bytes<S, N> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return an iterator over [`Bytes`].
    pub fn iter(&self) -> BytesIter<S, N> {
        BytesIter {
            inner: Bytes {
                offset: self.offset,
                len: self.len,
                storage: Rc::clone(&self.storage),
                buffer: RefCell::new(Vec::new()),
            },
            pos: 0,
        }
    }
}

impl<S, const N: usize> Clone for Bytes<S, N> {
    fn clone(&self) -> Self {
        Self {
            offset: self.offset,
            len: self.len,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        }
    }
}

impl<S, const N: usize> PartialEq for Bytes<S, N>
where
    S: ReadNorFlash,
{
    fn eq(&self, other: &Self) -> bool {
        if other.len() != self.len() {
            return false;
        }

        if other.is_empty() != self.is_empty() {
            return false;
        }

        let mut pos = 0;
        while pos < self.len() {
            let offset0 = match u32::try_from(self.offset + pos) {
                Ok(v) => v,
                Err(_) => return false,
            };

            let offset1 = match u32::try_from(other.offset + pos) {
                Ok(v) => v,
                Err(_) => return false,
            };

            let len = self.len().min(N);

            let mut buffer0 = self.buffer.borrow_mut();
            buffer0.clear();
            buffer0
                .resize(len, 0)
                .expect("chunk size should be less than or equal to N");

            // NOTE: We can't use other.buffer here because the user can
            // pass &self as other, and we already borrowed that one.
            let mut buffer1 = Vec::<u8, N>::new();
            buffer1.clear();
            buffer1
                .resize(len, 0)
                .expect("chunk size should be less than or equal to N");

            if let Err(e) = self.storage.borrow_mut().read(offset0, &mut buffer0) {
                log::error!("failed to compare bytes (self): {e:?}");
                return false;
            }

            if let Err(e) = self.storage.borrow_mut().read(offset1, &mut buffer1) {
                log::error!("failed to compare bytes (other): {e:?}");
                return false;
            }

            pos += self.len().min(N);

            if buffer0.deref() != buffer1.deref() {
                return false;
            }
        }

        true
    }
}

/// An iterator over [`Bytes`].
#[derive(Debug)]
pub struct BytesIter<S, const N: usize> {
    inner: Bytes<S, N>,
    pos: usize,
}

impl<S, const N: usize> Iterator for BytesIter<S, N>
where
    S: ReadNorFlash,
{
    type Item = u8;

    // TODO: Optimize this by pre-fetching N bytes when needed.
    fn next(&mut self) -> Option<Self::Item> {
        log::trace!("next byte: pos={}", self.pos);
        if self.pos >= self.inner.len() {
            return None;
        }

        let mut buf = [0; 1];
        let mut storage = self.inner.storage.borrow_mut();
        let offset = match u32::try_from(self.inner.offset + self.pos) {
            Ok(v) => v,
            Err(_) => return None,
        };

        self.pos += 1;
        match storage.read(offset, &mut buf) {
            Ok(()) => {
                log::trace!("next byte: value={}", buf[0]);
                Some(buf[0])
            }
            Err(e) => {
                log::error!("failed to iterate over bytes: {e:?}");
                None
            }
        }
    }
}

/// Errors that can happen when using [`Bytes`].
#[derive(Debug)]
pub enum Error {
    AlreadyBorrowed,
    OutOfBounds {
        offset: usize,
        len: usize,
        capacity: usize,
    },
    UnsupportedReadSize,
}

impl<S, const N: usize> InputLength for Bytes<S, N> {
    fn input_len(&self) -> usize {
        self.len()
    }
}

impl<S, const N: usize> InputTake for Bytes<S, N> {
    fn take(&self, count: usize) -> Self {
        log::trace!("take {count} bytes, length is {}", self.len());

        if count > self.len() {
            panic!("tried to take {count}, but the length is {}", self.len());
        }

        Self {
            offset: self.offset,
            len: count,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        }
    }

    fn take_split(&self, count: usize) -> (Self, Self) {
        log::trace!("split {count} bytes, length is {}", self.len());

        if count > self.len() {
            panic!("tried to take {count}, but the length is {}", self.len());
        }

        let prefix = Self {
            offset: self.offset,
            len: count,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        };

        let suffix = Self {
            offset: self.offset + count,
            len: self.len - count,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        };

        log::trace!("prefix length {}, suffix length {}", prefix.len(), suffix.len());

        (suffix, prefix)
    }
}

impl<S, const N: usize> InputIter for Bytes<S, N>
where
    S: ReadNorFlash,
{
    type Item = u8;
    type Iter = Enumerate<BytesIter<S, N>>;
    type IterElem = BytesIter<S, N>;

    fn iter_indices(&self) -> Self::Iter {
        self.iter().enumerate()
    }

    fn iter_elements(&self) -> Self::IterElem {
        self.iter()
    }

    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.iter().position(predicate)
    }

    fn slice_index(&self, count: usize) -> Result<usize, Needed> {
        log::trace!("slice index {count}");

        if self.len() >= count {
            Ok(count)
        } else {
            Err(Needed::new(count - self.len()))
        }
    }
}

impl<S, const N: usize> Slice<Range<usize>> for Bytes<S, N> {
    fn slice(&self, range: Range<usize>) -> Self {
        if range.is_empty() {
            return Self {
                offset: self.offset,
                len: 0,
                storage: Rc::clone(&self.storage),
                buffer: RefCell::new(Vec::new()),
            };
        }

        let new_len = range.end - range.start;
        if new_len > self.len() {
            panic!(
                "tried to slice past the length, start {}, end {}, length {}",
                range.start,
                range.end,
                self.len(),
            );
        }

        let new_offset = self.offset + range.start;

        log::trace!(
            "slice bytes (Range): {range:?} old_len={} old_offset={} new_len={} new_offset={}",
            self.len,
            self.offset,
            new_len,
            new_offset,
        );

        Self {
            offset: new_offset,
            len: new_len,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        }
    }
}

impl<S, const N: usize> Slice<RangeTo<usize>> for Bytes<S, N> {
    fn slice(&self, range: RangeTo<usize>) -> Self {
        if range.end > self.len() {
            panic!(
                "tried to take {}, but the length is {}",
                range.end,
                self.len()
            );
        }

        log::trace!(
            "slice bytes (RangeTo): {range:?} old_len={} new_len={}",
            self.len,
            range.end,
        );

        Self {
            offset: self.offset,
            len: range.end,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        }
    }
}

impl<S, const N: usize> Slice<RangeFrom<usize>> for Bytes<S, N>
where
    S: ReadNorFlash,
{
    fn slice(&self, range: RangeFrom<usize>) -> Self {
        let new_offset = self.offset + range.start;
        if new_offset >= self.storage.borrow().capacity() {
            panic!(
                "tried to slice past the capacity, starting point is {}, capacity is {}",
                new_offset,
                self.storage.borrow().capacity(),
            );
        }

        let new_len = self.len - range.start;
        if new_len > self.len {
            panic!("tried to take {new_len}, but the length is {}", self.len());
        }

        log::trace!("old_offset={} old_len={}", self.offset, self.len);
        log::trace!("slice bytes (RangeFrom): {range:?} new_offset={new_offset} new_len={new_len}");

        Self {
            offset: new_offset,
            len: new_len,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        }
    }
}

impl<S, const N: usize> Slice<RangeFull> for Bytes<S, N> {
    fn slice(&self, _: RangeFull) -> Self {
        Self {
            offset: self.offset,
            len: self.len,
            storage: Rc::clone(&self.storage),
            buffer: RefCell::new(Vec::new()),
        }
    }
}

impl<'a, S, const N: usize> Compare<&'a [u8]> for Bytes<S, N>
where
    S: ReadNorFlash,
{
    fn compare(&self, t: &'a [u8]) -> CompareResult {
        if t.len() > self.len() {
            return CompareResult::Incomplete;
        }

        if t.is_empty() != self.is_empty() {
            return CompareResult::Error;
        }

        let mut pos = 0;
        for chunk in t.chunks(N) {
            let mut buffer = self.buffer.borrow_mut();
            buffer.clear();
            buffer
                .resize(chunk.len(), 0)
                .expect("chunk size should be less than or equal to N");

            let offset = match u32::try_from(self.offset + pos) {
                Ok(v) => v,
                Err(_) => return CompareResult::Error,
            };

            if let Err(e) = self.storage.borrow_mut().read(offset, &mut buffer) {
                log::error!("failed compare bytes: {e:?}");
                return CompareResult::Error;
            }
            pos += chunk.len();

            if &buffer[..] != chunk {
                return CompareResult::Error;
            }
        }

        log::trace!("comparing {t:?} succeed");

        CompareResult::Ok
    }

    fn compare_no_case(&self, t: &'a [u8]) -> CompareResult {
        if t.len() > self.len() {
            return CompareResult::Incomplete;
        }

        if t.is_empty() != self.is_empty() {
            return CompareResult::Error;
        }

        let mut pos = 0;
        for chunk in t.chunks(N) {
            let mut buffer = self.buffer.borrow_mut();
            buffer.clear();
            buffer
                .resize(chunk.len(), 0)
                .expect("chunk size should be less than or equal to N");

            let offset = match u32::try_from(self.offset + pos) {
                Ok(v) => v,
                Err(_) => return CompareResult::Error,
            };

            if let Err(e) = self.storage.borrow_mut().read(offset, &mut buffer) {
                log::error!("failed compare bytes (no case): {e:?}");
                return CompareResult::Error;
            }
            pos += chunk.len();

            if buffer
                .iter()
                .zip(chunk)
                .any(|(a, b)| lowercase_byte(*a) != lowercase_byte(*b))
            {
                return CompareResult::Error;
            }
        }

        CompareResult::Ok
    }
}

// Taken from:
//
// - <https://github.com/rust-bakery/nom/blob/54557471141b73ca3b2d07be88d6709a43495b10/src/traits.rs#L884-L889>.
//
// To match the `nom::Compare` implementations.
fn lowercase_byte(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A' + b'a',
        _ => c,
    }
}

// Based on:
//
// - <https://github.com/rust-bakery/nom/blob/54557471141b73ca3b2d07be88d6709a43495b10/src/traits.rs#L1033-L1065>
//
// Adapted for [`embedded-storage`].
impl<'a, S, const N: usize> FindSubstring<&'a [u8]> for Bytes<S, N>
where
    S: ReadNorFlash,
{
    fn find_substring(&self, substr: &'a [u8]) -> Option<usize> {
        if substr.len() > self.len() {
            return None;
        }

        let (&substr_first, substr_rest) = match substr.split_first() {
            Some(split) => split,
            // An empty substring is found at position 0
            // This matches the behavior of str.find("").
            None => return Some(0),
        };

        if substr_rest.is_empty() {
            match self.memchr(substr_first) {
                Ok(v) => return Some(v),
                Err(e) => {
                    log::error!("failed to find token: {e:?}");
                    return None;
                }
            }
        }

        let mut offset = 0;
        let haystack = self.slice(..self.len() - substr_rest.len());

        loop {
            let position = match haystack.slice(offset..).memchr(substr_first) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("failed to find substring: {e:?}");
                    break;
                }
            };

            offset += position;
            let next_offset = offset + 1;
            let maybe_substr_rest = self.slice(next_offset..).slice(..substr_rest.len());

            if maybe_substr_rest.compare(substr_rest) == CompareResult::Ok {
                return Some(offset);
            }

            offset += next_offset;
        }

        None
    }
}

impl<S, const N: usize> FindToken<u8> for Bytes<S, N>
where
    S: ReadNorFlash,
{
    fn find_token(&self, token: u8) -> bool {
        self.memchr(token).is_ok()
    }
}

#[derive(Debug)]
pub enum FindTokenError<E> {
    NotFound,
    OffsetOverflow,
    Io(E),
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::{cell::RefCell, ptr::NonNull};

    use super::*;
    use crate::rc::{Rc, RcInner};

    #[derive(Debug)]
    struct Storage<'a>(&'a [u8]);

    #[derive(Debug)]
    struct Error;

    impl embedded_storage::nor_flash::NorFlashError for Error {
        fn kind(&self) -> embedded_storage::nor_flash::NorFlashErrorKind {
            embedded_storage::nor_flash::NorFlashErrorKind::Other
        }
    }

    impl<'a> embedded_storage::nor_flash::ErrorType for Storage<'a> {
        type Error = Error;
    }

    impl<'a> embedded_storage::nor_flash::ReadNorFlash for Storage<'a> {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            let offset = usize::try_from(offset).unwrap();
            if offset + bytes.len() > self.0.len() {
                return Err(Error);
            }

            bytes.copy_from_slice(&self.0[offset..offset + bytes.len()]);

            Ok(())
        }

        fn capacity(&self) -> usize {
            self.0.len()
        }
    }

    macro_rules! assert_eq_iterators {
        ($x:expr, $y:expr) => {
            for (x, y) in $x.zip($y) {
                assert_eq!(x, y, "iterators elements should be equal");
            }
        };
    }

    #[test]
    fn test_iter_elements() {
        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        assert_eq_iterators!(s.iter_elements(), original.iter().copied());
    }

    #[test]
    fn test_iter_indices() {
        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        assert_eq_iterators!(s.iter_indices(), original.iter().copied().enumerate());
    }

    #[test]
    fn test_slice() {
        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        println!("test core::ops::Range");
        let a = s.slice(0..4);
        let b = &original[0..4];
        assert_eq!(a.len(), b.len(), "length should be equal");
        assert_eq_iterators!(s.iter_elements(), original.iter().copied());

        println!("test core::ops::RangeTo");
        let a = s.slice(..5);
        let b = &original[..5];
        assert_eq!(a.len(), b.len(), "length should be equal");
        assert_eq_iterators!(s.iter_elements(), original.iter().copied());

        println!("test core::ops::RangeFrom");
        let a = s.slice(3..);
        let b = &original[3..];

        assert_eq!(a.len(), b.len(), "length should be equal");
        assert_eq_iterators!(s.iter_elements(), original.iter().copied());

        println!("test core::ops::RangeFull");
        let a = s.slice(..);
        let b = &original[..];

        assert_eq!(a.len(), b.len(), "length should be equal");
        assert_eq_iterators!(s.iter_elements(), original.iter().copied());
    }

    #[test]
    fn test_find_substring() {
        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        for (i, &c) in original.iter().enumerate() {
            assert_eq!(s.find_substring(&[c]), Some(i));
        }

        assert_eq!(s.find_substring(b"123"), Some(4));
        assert_eq!(s.find_substring(b"abcd"), Some(0));
        assert_eq!(s.find_substring(b"cd"), Some(2));
        assert_eq!(s.find_substring(&[]), Some(0));
    }

    #[test]
    fn test_find_token() {
        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        for &c in original.iter() {
            assert!(
                s.find_token(c),
                "failed to find token {}",
                char::from_u32(u32::from(c)).unwrap()
            );
        }
    }

    #[test]
    fn test_compare() {
        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        assert_eq!(
            s.compare(original),
            CompareResult::Ok,
            "bytes should be equal"
        );
        assert_eq!(
            s.compare(b"abcd1234"),
            CompareResult::Incomplete,
            "there should not enough bytes to compare"
        );
        assert_eq!(s.compare(&[]), CompareResult::Error, "should not be equal");
        assert_eq!(
            s.compare_no_case(b"ABCD123"),
            CompareResult::Ok,
            "case-insensitive comparison should succeed"
        );
    }

    #[test]
    fn test_partial_eq() {
        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s0 = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        let original = b"abcd123";
        let storage = NonNull::from(Box::leak(Box::new(RcInner::new(RefCell::new(Storage(
            original,
        ))))));
        let storage = unsafe { Rc::from_inner(storage) };
        let s1 = Bytes::<_, 16>::new(0, original.len(), storage).unwrap();

        assert_eq!(s0, s0, "same bytes should be equal");
        assert_eq!(s1, s1, "same bytes should be equal");
        assert_eq!(s0, s1);
        assert_eq!(s0.slice(2..), s1.slice(2..));
        assert_ne!(s0.slice(3..), s1.slice(2..));
        assert_ne!(s0.slice(2..), s1.slice(3..));
        assert_eq!(s0.slice(2..4).len(), 2);
        assert_eq!(s1.slice(2..4).len(), 2);
        assert_ne!(s0.slice(2..4), s1.slice(4..6));
    }
}
