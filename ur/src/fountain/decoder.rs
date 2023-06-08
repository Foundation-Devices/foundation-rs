// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Decoder.

use core::fmt;

use crate::{
    collections::{Deque, Set, Vec},
    fountain::part::MessageDescription,
    fountain::{
        chooser,
        chooser::BaseFragmentChooser,
        part::{IndexedPart, Part},
    },
};

/// A [`decoder`](BaseDecoder) that uses [`alloc`] collection types.
#[cfg(feature = "alloc")]
pub type Decoder = BaseDecoder<Alloc>;

/// A [`decoder`](BaseDecoder) that uses fixed-capacity collection types.
pub type HeaplessDecoder<
    const MAX_MESSAGE_LEN: usize,
    const MAX_MIXED_PARTS: usize,
    const MAX_FRAGMENT_LEN: usize,
    const MAX_SEQUENCE_COUNT: usize,
    const QUEUE_SIZE: usize,
> = BaseDecoder<
    Heapless<MAX_MESSAGE_LEN, MAX_MIXED_PARTS, MAX_FRAGMENT_LEN, MAX_SEQUENCE_COUNT, QUEUE_SIZE>,
>;

impl<
        const MAX_MESSAGE_LEN: usize,
        const MAX_MIXED_PARTS: usize,
        const MAX_FRAGMENT_LEN: usize,
        const MAX_SEQUENCE_COUNT: usize,
        const QUEUE_SIZE: usize,
    >
    HeaplessDecoder<
        MAX_MESSAGE_LEN,
        MAX_MIXED_PARTS,
        MAX_FRAGMENT_LEN,
        MAX_SEQUENCE_COUNT,
        QUEUE_SIZE,
    >
{
    /// Constructs a new [`HeaplessDecoder`].
    pub const fn new() -> Self {
        Self {
            message: heapless::Vec::new(),
            mixed_parts: heapless::Vec::new(),
            received: heapless::IndexSet::new(),
            queue: heapless::Deque::new(),
            fragment_chooser: chooser::HeaplessFragmentChooser::new(),
            message_description: None,
        }
    }
}

/// A decoder capable of receiving and recombining fountain-encoded transmissions.
///
/// # Examples
///
/// See the [`crate::fountain`] module documentation for an example.
#[derive(Default)]
pub struct BaseDecoder<T: Types> {
    message: T::Message,
    mixed_parts: T::MixedParts,
    received: T::Indexes,
    queue: T::Queue,
    fragment_chooser: BaseFragmentChooser<T::Chooser>,
    message_description: Option<MessageDescription>,
}

impl<T: Types> BaseDecoder<T> {
    /// Receives a fountain-encoded part into the decoder.
    ///
    /// # Examples
    ///
    /// See the [`crate::fountain`] module documentation for an example.
    ///
    /// # Errors
    ///
    /// If the part would fail [`validate`] because it is inconsistent
    /// with previously received parts, an error will be returned.
    ///
    /// [`validate`]: BaseDecoder::is_part_consistent
    pub fn receive(&mut self, part: &Part) -> Result<bool, Error> {
        if self.is_complete() {
            return Ok(false);
        }

        if !part.is_valid() {
            return Err(Error::InvalidPart);
        }

        if self.is_empty() {
            let message_len = part.data.len() * usize::try_from(part.sequence_count).unwrap();
            if self.message.try_resize(message_len, 0).is_err() {
                return Err(Error::NotEnoughSpace {
                    needed: message_len,
                    capacity: self.message.capacity(),
                });
            }
            self.message_description = Some(part.to_message_description());
        } else if !self.is_part_consistent(part) {
            return Err(Error::InconsistentPart {
                received: part.to_message_description(),
                expected: self.message_description.clone().unwrap(),
            });
        }

        let indexes = self.fragment_chooser.choose_fragments(
            part.sequence,
            part.sequence_count,
            part.checksum,
        );

        let mut data = T::Fragment::default();
        if data.try_extend_from_slice(part.data).is_err() {
            return Err(Error::NotEnoughSpace {
                needed: part.data.len(),
                capacity: data.capacity(),
            });
        }

        let part = IndexedPart::new(data, indexes);
        self.queue.push_back(part);

        while !self.is_complete() && !self.queue.is_empty() {
            let part = self.queue.pop_front().unwrap();
            if part.is_simple() {
                self.process_simple(&part)?;
            } else {
                self.process_mixed(part);
            }
        }
        Ok(!self.is_complete())
    }

    /// Checks whether a [`Part`] is receivable by the decoder.
    ///
    /// This can fail if other parts were previously received whose
    /// metadata (such as number of segments) is inconsistent with the
    /// present [`Part`]. Note that a fresh decoder will always return
    /// false here.
    #[must_use]
    pub fn is_part_consistent(&self, part: &Part) -> bool {
        match self.message_description {
            Some(ref message_description) => part == message_description,
            None => false,
        }
    }

    /// If [`complete`], returns the decoded message, `None` otherwise.
    ///
    /// # Errors
    ///
    /// If an inconsistent internal state is detected, an error will be returned.
    ///
    /// # Examples
    ///
    /// See the [`crate::fountain`] module documentation for an example.
    ///
    /// [`complete`]: BaseDecoder::is_complete
    pub fn message(&self) -> Result<Option<&[u8]>, Error> {
        if self.is_complete() {
            if self.message[self.message_description.as_ref().unwrap().message_length..]
                .iter()
                .any(|&b| b != 0)
            {
                return Err(Error::InvalidPadding);
            }

            Ok(Some(
                &self.message[..self.message_description.as_ref().unwrap().message_length],
            ))
        } else {
            Ok(None)
        }
    }

    /// Returns whether the decoder is complete and hence the message available.
    ///
    /// # Examples
    ///
    /// See the [`crate::fountain`] module documentation for an example.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        if self.is_empty() {
            return false;
        }

        self.received.len()
            == self
                .message_description
                .as_ref()
                .unwrap()
                .sequence_count
                .try_into()
                .unwrap()
    }

    /// Calculate estimated percentage of completion.
    pub fn estimated_percent_complete(&self) -> f64 {
        if self.is_complete() {
            return 1.0;
        }

        if self.is_empty() {
            return 0.0;
        }

        let estimated_input_parts =
            f64::from(self.message_description.as_ref().unwrap().sequence_count) * 1.75;
        let received_parts = u32::try_from(self.received.len()).unwrap();
        f64::min(0.99, f64::from(received_parts) / estimated_input_parts)
    }

    /// Returns `true` if the decoder doesn't contain any data.
    ///
    /// Once a part is successfully [received](Self::receive) this method will
    /// return `false`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.message.is_empty()
            && self.mixed_parts.is_empty()
            && self.received.is_empty()
            && self.queue.is_empty()
            && self.message_description.is_none()
    }

    /// Clear the decoder so that it can be used again.
    pub fn clear(&mut self) {
        self.message.clear();
        self.mixed_parts.clear();
        self.received.clear();
        self.queue.clear();
        self.message_description = None;

        debug_assert!(self.is_empty());
    }

    fn reduce_mixed(&mut self, part: &IndexedPart<T::Fragment, T::Indexes>) {
        self.mixed_parts.retain_mut(|mixed_part| {
            mixed_part.reduce(part);

            if mixed_part.is_simple() {
                self.queue.push_back(mixed_part.clone());
            }

            !mixed_part.is_simple()
        });
    }

    fn process_simple(&mut self, part: &IndexedPart<T::Fragment, T::Indexes>) -> Result<(), Error> {
        let index = *part.indexes.first().unwrap();
        if self.received.contains(&index) {
            return Ok(());
        }

        self.reduce_mixed(part);

        let offset = index * self.message_description.as_ref().unwrap().fragment_length;
        self.message[offset..offset + self.message_description.as_ref().unwrap().fragment_length]
            .copy_from_slice(&part.data);
        self.received
            .insert(index)
            .map_err(|_| Error::TooManyFragments)?;

        Ok(())
    }

    fn process_mixed(&mut self, mut part: IndexedPart<T::Fragment, T::Indexes>) {
        for mixed_part in (&self.mixed_parts as &[IndexedPart<T::Fragment, T::Indexes>]).iter() {
            if part.indexes == mixed_part.indexes {
                return;
            }
        }

        // Reduce this part by all simple parts.
        for &index in self.received.iter() {
            let offset = index * self.message_description.as_ref().unwrap().fragment_length;
            part.reduce_by_simple(
                &self.message
                    [offset..offset + self.message_description.as_ref().unwrap().fragment_length],
                index,
            );
            if part.is_simple() {
                break;
            }
        }

        // Then reduce this part by all the mixed parts.
        if !part.is_simple() {
            for mixed_part in self.mixed_parts.iter() {
                part.reduce(mixed_part);
                if part.is_simple() {
                    break;
                }
            }
        }

        if part.is_simple() {
            self.queue.push_back(part);
        } else {
            self.reduce_mixed(&part);
            self.mixed_parts.try_push(part).ok();
        }
    }
}

/// Types for [`BaseDecoder`].
pub trait Types: Default {
    /// Decoded message buffer.
    type Message: Vec<u8>;

    /// Mixed parts storage.
    type MixedParts: Vec<IndexedPart<Self::Fragment, Self::Indexes>>;

    /// Fragment buffer.
    type Fragment: Clone + Vec<u8>;

    /// Indexes storage.
    type Indexes: PartialEq + Set<usize>;

    /// Part queue.
    type Queue: Deque<IndexedPart<Self::Fragment, Self::Indexes>>;

    /// Fragment chooser types.
    type Chooser: chooser::Types;
}

/// [`alloc`] types for [`BaseDecoder`].
#[derive(Default)]
#[cfg(feature = "alloc")]
pub struct Alloc;

#[cfg(feature = "alloc")]
impl Types for Alloc {
    type Message = alloc::vec::Vec<u8>;
    type MixedParts =
        alloc::vec::Vec<IndexedPart<alloc::vec::Vec<u8>, alloc::collections::BTreeSet<usize>>>;
    type Fragment = alloc::vec::Vec<u8>;
    type Indexes = alloc::collections::BTreeSet<usize>;
    type Queue = alloc::collections::VecDeque<
        IndexedPart<alloc::vec::Vec<u8>, alloc::collections::BTreeSet<usize>>,
    >;
    type Chooser = chooser::Alloc;
}

/// [`heapless`] types for [`BaseDecoder`].
#[derive(Default)]
pub struct Heapless<
    const MAX_MESSAGE_LEN: usize,
    const MAX_MIXED_PARTS: usize,
    const MAX_FRAGMENT_LEN: usize,
    const MAX_SEQUENCE_COUNT: usize,
    const QUEUE_SIZE: usize,
>;

impl<
        const MAX_MESSAGE_LEN: usize,
        const MAX_MIXED_PARTS: usize,
        const MAX_FRAGMENT_LEN: usize,
        const MAX_SEQUENCE_COUNT: usize,
        const QUEUE_SIZE: usize,
    > Types
    for Heapless<MAX_MESSAGE_LEN, MAX_MIXED_PARTS, MAX_FRAGMENT_LEN, MAX_SEQUENCE_COUNT, QUEUE_SIZE>
{
    type Message = heapless::Vec<u8, MAX_MESSAGE_LEN>;

    type MixedParts = heapless::Vec<
        IndexedPart<
            heapless::Vec<u8, MAX_FRAGMENT_LEN>,
            heapless::FnvIndexSet<usize, MAX_SEQUENCE_COUNT>,
        >,
        MAX_MIXED_PARTS,
    >;

    type Fragment = heapless::Vec<u8, MAX_FRAGMENT_LEN>;

    type Indexes = heapless::FnvIndexSet<usize, MAX_SEQUENCE_COUNT>;

    type Queue = heapless::Deque<
        IndexedPart<
            heapless::Vec<u8, MAX_FRAGMENT_LEN>,
            heapless::FnvIndexSet<usize, MAX_SEQUENCE_COUNT>,
        >,
        QUEUE_SIZE,
    >;

    type Chooser = chooser::Heapless<MAX_SEQUENCE_COUNT>;
}

/// Errors that can happen during decoding.
#[derive(Debug)]
pub enum Error {
    /// The padding is invalid.
    InvalidPadding,
    /// The received part is inconsistent with the previously received ones.
    InconsistentPart {
        /// The description of the message from the received part.
        received: MessageDescription,
        /// The expected description of the message originated from the previous parts scanned.
        expected: MessageDescription,
    },
    /// The received part is empty.
    InvalidPart,
    /// Not enough space to receive the part.
    NotEnoughSpace {
        /// Needed space.
        needed: usize,
        /// Current capacity.
        capacity: usize,
    },
    /// Too many fragments.
    TooManyFragments,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPadding => write!(f, "Invalid padding")?,
            Error::InconsistentPart { received, expected } => {
                write!(f, "Inconsistent part: ")?;

                if received.sequence_count != expected.sequence_count {
                    write!(
                        f,
                        "sequence count mismatch (received {}, expected {}). ",
                        received.sequence_count, expected.sequence_count
                    )?;
                }

                if received.message_length != expected.message_length {
                    write!(
                        f,
                        "message length mismatch (received {}, expected {}). ",
                        received.message_length, expected.message_length
                    )?;
                }

                if received.checksum != expected.checksum {
                    write!(
                        f,
                        "checksum mismatch (received {:X}, expected {:X}). ",
                        received.checksum, expected.checksum
                    )?;
                }

                if received.fragment_length != expected.fragment_length {
                    write!(
                        f,
                        "checksum mismatch (received {:X}, expected {:X}). ",
                        received.fragment_length, expected.fragment_length
                    )?;
                }
            }
            Error::InvalidPart => write!(f, "The scanned part is empty")?,
            Error::NotEnoughSpace { needed, capacity } => {
                write!(f, "Not enough space: needed {needed}, capacity {capacity}")?
            }
            Error::TooManyFragments => write!(f, "Too many fragments for the current message")?,
        };
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
#[cfg(feature = "alloc")]
pub mod tests {
    use super::*;
    use crate::fountain::fragment_length;
    use crate::{fountain::Encoder, xoshiro::test_utils::make_message};

    const MESSAGE_SIZE: usize = 32767;
    const MAX_FRAGMENT_LEN: usize = 1000;
    const MAX_SEQUENCE_COUNT: usize = 64;
    const MAX_MESSAGE_SIZE: usize =
        fragment_length(MESSAGE_SIZE, MAX_FRAGMENT_LEN) * MAX_SEQUENCE_COUNT;
    const SEED: &str = "Wolf";

    fn message() -> alloc::vec::Vec<u8> {
        make_message(SEED, MESSAGE_SIZE)
    }

    #[test]
    fn test_decoder() {
        fn test<T: Types>(decoder: &mut BaseDecoder<T>) {
            let message = message();
            let mut encoder = Encoder::new();
            encoder.start(&message, MAX_FRAGMENT_LEN);
            while !decoder.is_complete() {
                assert_eq!(decoder.message().unwrap(), None);
                let part = encoder.next_part();
                let _next = decoder.receive(&part).unwrap();
            }
            assert_eq!(decoder.message().unwrap(), Some(message.as_slice()));
        }

        let mut heapless_decoder: HeaplessDecoder<
            MAX_MESSAGE_SIZE,
            MAX_SEQUENCE_COUNT,
            MAX_FRAGMENT_LEN,
            MAX_SEQUENCE_COUNT,
            MAX_SEQUENCE_COUNT,
        > = HeaplessDecoder::new();
        let mut decoder = Decoder::default();

        test(&mut heapless_decoder);
        test(&mut decoder);
    }

    #[test]
    fn test_decoder_skip_some_simple_fragments() {
        let message = make_message(SEED, MESSAGE_SIZE);
        let mut encoder = Encoder::new();
        encoder.start(&message, MAX_FRAGMENT_LEN);
        let mut decoder = Decoder::default();
        let mut skip = false;
        while !decoder.is_complete() {
            let part = encoder.next_part();
            if !skip {
                let _next = decoder.receive(&part);
            }
            skip = !skip;
        }
        assert_eq!(decoder.message().unwrap(), Some(message.as_slice()));
    }

    #[test]
    fn test_decoder_receive_return_value() {
        let message = make_message(SEED, MESSAGE_SIZE);
        let mut encoder = Encoder::new();
        encoder.start(&message, MAX_FRAGMENT_LEN);
        let mut decoder = Decoder::default();
        let part = encoder.next_part();
        assert!(decoder.receive(&part).unwrap());
        // non-valid
        let mut part = encoder.next_part();
        part.checksum += 1;
        // TODO:
        // assert!(matches!(
        //     decoder.receive(&part),
        //     Err(Error::InconsistentPart)
        // ));
        // decoder complete
        while !decoder.is_complete() {
            let part = encoder.next_part();
            decoder.receive(&part).unwrap();
        }
        let part = encoder.next_part();
        assert!(!decoder.receive(&part).unwrap());
    }

    #[test]
    fn test_decoder_part_validation() {
        fn test<T: Types>(decoder: &mut BaseDecoder<T>) {
            let mut encoder = Encoder::new();
            encoder.start("foo".as_bytes(), 2);

            let mut part = encoder.next_part();
            assert!(decoder.receive(&part).unwrap());
            assert!(decoder.is_part_consistent(&part));
            part.checksum += 1;
            assert!(!decoder.is_part_consistent(&part));
            part.checksum -= 1;
            part.message_length += 1;
            assert!(!decoder.is_part_consistent(&part));
            part.message_length -= 1;
            part.sequence_count += 1;
            assert!(!decoder.is_part_consistent(&part));
            part.sequence_count -= 1;
            part.data = &[0];
            assert!(!decoder.is_part_consistent(&part));
        }

        let mut heapless_decoder: HeaplessDecoder<8, 8, 8, 8, 8> = HeaplessDecoder::new();
        let mut decoder = Decoder::default();

        test(&mut heapless_decoder);
        test(&mut decoder);
    }

    #[test]
    fn test_empty_decoder_empty_part() {
        fn test<T: Types>(decoder: &mut BaseDecoder<T>) {
            let mut part = Part {
                sequence: 12,
                sequence_count: 8,
                message_length: 100,
                checksum: 0x1234_5678,
                data: &[1, 5, 3, 3, 5],
            };

            // Check sequence_count.
            part.sequence_count = 0;
            assert!(matches!(decoder.receive(&part), Err(Error::InvalidPart)));
            part.sequence_count = 8;

            // Check message_length.
            part.message_length = 0;
            assert!(matches!(decoder.receive(&part), Err(Error::InvalidPart)));
            part.message_length = 100;

            // Check data.
            part.data = &[];
            assert!(matches!(decoder.receive(&part), Err(Error::InvalidPart)));
            part.data = &[1, 5, 3, 3, 5];

            // Should not validate as there aren't any previous parts received.
            assert!(!decoder.is_part_consistent(&part));
        }

        let mut heapless_decoder: HeaplessDecoder<100, 8, 5, 8, 8> = HeaplessDecoder::new();
        let mut decoder = Decoder::default();

        test(&mut heapless_decoder);
        test(&mut decoder);
    }
}
