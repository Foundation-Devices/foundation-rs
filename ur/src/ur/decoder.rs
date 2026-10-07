// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Decoder.

use crate::{
    bytewords::{self, Style},
    collections::Vec,
    fountain,
    ur::UR,
};
use core::{fmt, str};

/// A decoder.
#[cfg(feature = "alloc")]
pub type Decoder = BaseDecoder<Alloc>;

/// A static decoder.
///
/// Does not allocate memory.
pub type HeaplessDecoder<
    const MAX_MESSAGE_LEN: usize,
    const MAX_MIXED_PARTS: usize,
    const MAX_FRAGMENT_LEN: usize,
    const MAX_SEQUENCE_COUNT: usize,
    const QUEUE_SIZE: usize,
    const MAX_UR_TYPE: usize,
> = BaseDecoder<
    Heapless<
        MAX_MESSAGE_LEN,
        MAX_MIXED_PARTS,
        MAX_FRAGMENT_LEN,
        MAX_SEQUENCE_COUNT,
        QUEUE_SIZE,
        MAX_UR_TYPE,
    >,
>;

impl<
        const MAX_MESSAGE_LEN: usize,
        const MAX_MIXED_PARTS: usize,
        const MAX_FRAGMENT_LEN: usize,
        const MAX_SEQUENCE_COUNT: usize,
        const QUEUE_SIZE: usize,
        const MAX_UR_TYPE: usize,
    >
    HeaplessDecoder<
        MAX_MESSAGE_LEN,
        MAX_MIXED_PARTS,
        MAX_FRAGMENT_LEN,
        MAX_SEQUENCE_COUNT,
        QUEUE_SIZE,
        MAX_UR_TYPE,
    >
{
    /// Construct a new [`HeaplessDecoder`].
    pub const fn new() -> Self {
        Self {
            fountain: fountain::decoder::HeaplessDecoder::new(),
            fragment: heapless::Vec::new(),
            ur_type: heapless::Vec::new(),
        }
    }
}

/// A uniform resource decoder able to receive URIs that encode a fountain part.
///
/// # Examples
///
/// See the [`crate`] module documentation for an example.
#[derive(Default)]
pub struct BaseDecoder<T: Types> {
    fountain: fountain::decoder::BaseDecoder<T::Decoder>,
    fragment: T::Fragment,
    ur_type: T::URType,
}

impl<T: Types> BaseDecoder<T> {
    /// Receives a URI representing a CBOR and `bytewords`-encoded fountain part
    /// into the decoder.
    ///
    /// # Examples
    ///
    /// See the [`crate`] module documentation for examples.
    ///
    /// # Errors
    ///
    /// This function may error along all the necessary decoding steps:
    ///  - The string may not be a well-formed URI according to the uniform resource scheme
    ///  - The URI payload may not be a well-formed `bytewords` string
    ///  - The decoded byte payload may not be valid CBOR
    ///  - The CBOR-encoded fountain part may be inconsistent with previously received ones
    ///
    /// In all these cases, an error will be returned.
    pub fn receive(&mut self, ur: UR) -> Result<(), Error> {
        if !ur.is_multi_part() {
            return Err(Error::NotMultiPart);
        }

        if !self.ur_type.is_empty() && (&self.ur_type as &[_]) != ur.as_type().as_bytes() {
            return Err(Error::InconsistentType);
        }

        let part = if !ur.is_deserialized() {
            let bytewords = ur
                .as_bytewords()
                .expect("resource shouldn't be deserialized at this point");

            let size = bytewords::validate(bytewords, Style::Minimal)?;
            // Three CBOR heads fit even when encoded with eight-byte arguments.
            let mut prefix = [0; 27];
            let (bytes, _) = bytewords::decoder(bytewords, Style::Minimal)?;
            let mut prefix_len = 0;
            for (index, byte) in bytes.take(prefix.len()).enumerate() {
                prefix[index] = byte.ok_or(bytewords::DecodeError::InvalidWord {
                    position: Some(index),
                })?;
                prefix_len += 1;
            }
            let inner = fountain::part::decode_sequence(&mut minicbor::Decoder::new(
                &prefix[..prefix_len],
            ))?;
            let outer = (ur.sequence().unwrap(), ur.sequence_count().unwrap());
            if outer != inner {
                return Err(Error::InconsistentSequence { outer, inner });
            }

            // An array head, four integer heads and a byte-string head use at most 54 bytes.
            if size > self.fountain.max_fragment_len().saturating_add(54) {
                return Err(Error::FragmentTooBig { size });
            }
            self.fragment.clear();
            self.fragment
                .try_resize(size, 0)
                .map_err(|_| Error::FragmentTooBig { size })?;

            bytewords::decode_to_slice(bytewords, &mut self.fragment, Style::Minimal)?;
            Some(minicbor::decode(&self.fragment[..size])?)
        } else {
            None
        };

        let part = part.as_ref().unwrap_or_else(|| ur.as_part().unwrap());

        let mut ur_type = T::URType::default();
        if self.ur_type.is_empty() {
            ur_type
                .try_extend_from_slice(ur.as_type().as_bytes())
                .map_err(|_| Error::URTypeTooBig {
                    size: ur.as_type().len(),
                })?;
        }
        if let Err(error) = self.fountain.receive(part) {
            if self.fountain.is_empty() {
                self.ur_type.clear();
            }
            return Err(error.into());
        }
        if self.ur_type.is_empty() {
            self.ur_type = ur_type;
        }
        Ok(())
    }

    /// Returns the reassembled-message buffer limit, in bytes.
    #[must_use]
    pub fn max_message_len(&self) -> usize {
        self.fountain.max_message_len()
    }

    /// Bounds the reassembled-message buffer to `len` bytes.
    ///
    /// Applies to the next message; call `clear` to discard an active message.
    /// Parts describing a longer message are rejected before allocation.
    pub fn set_max_message_len(&mut self, len: usize) {
        self.fountain.set_max_message_len(len);
    }

    /// Return the fragment, mixed-part and queue limits for new messages.
    pub fn limits(&self) -> fountain::decoder::Limits {
        self.fountain.limits()
    }

    /// Set resource limits and discard the active message.
    pub fn set_limits(&mut self, limits: fountain::decoder::Limits) {
        self.clear();
        self.fountain.set_limits(limits);
    }

    /// Returns whether the decoder is complete and hence the message available.
    ///
    /// # Examples
    ///
    /// See the [`crate`] module documentation for an example.
    #[must_use]
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.fountain.is_complete()
    }

    /// Returns the UR type.
    pub fn ur_type(&self) -> Option<&str> {
        if !self.ur_type.is_empty() {
            Some(str::from_utf8(&self.ur_type).unwrap())
        } else {
            None
        }
    }

    /// If [`complete`], returns the decoded message, `None` otherwise.
    ///
    /// # Errors
    ///
    /// If an inconsistent internal state is detected, an error will be
    /// returned.
    ///
    /// # Examples
    ///
    /// See the [`crate`] documentation for an example.
    ///
    /// [`complete`]: BaseDecoder::is_complete
    #[inline]
    pub fn message(&self) -> Result<Option<&[u8]>, Error> {
        self.fountain.message().map_err(Error::from)
    }

    /// Calculate estimated percentage of completion.
    #[inline]
    pub fn estimated_percent_complete(&self) -> f64 {
        self.fountain.estimated_percent_complete()
    }

    /// Returns `true` if the decoder doesn't contain any data.
    ///
    /// Once a part is successfully [received](Self::receive) this method will
    /// return `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use foundation_ur::fountain::HeaplessDecoder;
    /// let decoder: HeaplessDecoder<8, 8, 8, 8, 8> = HeaplessDecoder::new();
    /// assert!(decoder.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fountain.is_empty()
    }

    /// Clear the decoder so that it can be used again.
    pub fn clear(&mut self) {
        self.fountain.clear();
        self.fragment.clear();
        self.ur_type.clear();
    }
}

/// Types for [`BaseDecoder`].
pub trait Types: Default {
    /// Fountain decoder.
    type Decoder: fountain::decoder::Types;

    /// CBOR decoding buffer.
    type Fragment: Vec<u8>;

    /// The UR type.
    type URType: Vec<u8>;
}

/// [`alloc`] types for [`BaseDecoder`].
#[derive(Default)]
#[cfg(feature = "alloc")]
pub struct Alloc;

#[cfg(feature = "alloc")]
impl Types for Alloc {
    type Decoder = fountain::decoder::Alloc;

    type Fragment = alloc::vec::Vec<u8>;

    type URType = alloc::vec::Vec<u8>;
}

/// [`heapless`] types for [`BaseDecoder`].
#[derive(Default)]
pub struct Heapless<
    const MAX_MESSAGE_LEN: usize,
    const MAX_MIXED_PARTS: usize,
    const MAX_FRAGMENT_LEN: usize,
    const MAX_SEQUENCE_COUNT: usize,
    const QUEUE_SIZE: usize,
    const MAX_UR_TYPE: usize,
>;

impl<
        const MAX_MESSAGE_LEN: usize,
        const MAX_MIXED_PARTS: usize,
        const MAX_FRAGMENT_LEN: usize,
        const MAX_SEQUENCE_COUNT: usize,
        const QUEUE_SIZE: usize,
        const MAX_UR_TYPE: usize,
    > Types
    for Heapless<
        MAX_MESSAGE_LEN,
        MAX_MIXED_PARTS,
        MAX_FRAGMENT_LEN,
        MAX_SEQUENCE_COUNT,
        QUEUE_SIZE,
        MAX_UR_TYPE,
    >
{
    type Decoder = fountain::decoder::Heapless<
        MAX_MESSAGE_LEN,
        MAX_MIXED_PARTS,
        MAX_FRAGMENT_LEN,
        MAX_SEQUENCE_COUNT,
        QUEUE_SIZE,
    >;

    type Fragment = heapless::Vec<u8, MAX_FRAGMENT_LEN>;

    type URType = heapless::Vec<u8, MAX_UR_TYPE>;
}

/// Errors that can happen during decoding.
#[derive(Debug)]
pub enum Error {
    /// CBOR decoding error.
    Cbor(minicbor::decode::Error),
    /// Fountain decoder error.
    Fountain(fountain::decoder::Error),
    /// Bytewords decoding error.
    Bytewords(bytewords::DecodeError),
    /// The part received is not multi-part.
    NotMultiPart,
    /// The received part is too big to decode.
    FragmentTooBig {
        /// The size of the received fragment.
        size: usize,
    },
    /// The received part contained an UR type that is too big for the decoder.
    URTypeTooBig {
        /// The size of the UR type.
        size: usize,
    },
    /// The UR type of this fragment is not consistent.
    InconsistentType,
    /// The sequence number and count in the UR path do not match the ones in the
    /// part it carries.
    InconsistentSequence {
        /// Sequence number and count taken from the UR path.
        outer: (u32, u32),
        /// Sequence number and count taken from the fountain part.
        inner: (u32, u32),
    },
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "CBOR decoding error: {e}"),
            Error::Fountain(e) => write!(f, "Fountain decoding error: {e}"),
            Error::Bytewords(e) => write!(f, "Bytewords decoding error: {e}"),
            Error::NotMultiPart => write!(f, "The Uniform Resource is not multi-part"),
            Error::FragmentTooBig { size } => write!(
                f,
                "The fragment size ({size} bytes) is too big for the decoder"
            ),
            Error::URTypeTooBig { size } => {
                write!(f, "The UR type ({size} bytes) is too big for the decoder")
            }
            Error::InconsistentType => write!(
                f,
                "The received fragment is not consistent with the type of the previous fragments"
            ),
            Error::InconsistentSequence { outer, inner } => write!(
                f,
                "The UR path describes part {}-{} but it carries part {}-{}",
                outer.0, outer.1, inner.0, inner.1
            ),
        }
    }
}

impl From<minicbor::decode::Error> for Error {
    fn from(e: minicbor::decode::Error) -> Self {
        Self::Cbor(e)
    }
}

impl From<bytewords::DecodeError> for Error {
    fn from(e: bytewords::DecodeError) -> Self {
        Self::Bytewords(e)
    }
}

impl From<fountain::decoder::Error> for Error {
    fn from(e: fountain::decoder::Error) -> Self {
        Self::Fountain(e)
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;
    use crate::ur::{tests::make_message_ur, Encoder};
    use alloc::{format, string::String, string::ToString};

    /// Rewrite the `<sequence>-<count>` path segment, leaving the fragment alone.
    fn with_path(ur: &str, sequence: u32, sequence_count: u32) -> String {
        let mut parts = ur.splitn(3, '/');
        let head = parts.next().unwrap();
        let _indices = parts.next().unwrap();
        let fragment = parts.next().unwrap();

        format!("{head}/{sequence}-{sequence_count}/{fragment}")
    }

    #[test]
    fn test_a_rejected_fragment_leaves_no_type_behind() {
        let message = make_message_ur(200, "Wolf");
        let mut encoder = Encoder::new();
        encoder.start("bytes", &message, 50);
        assert!(encoder.sequence_count() > 1);
        let disguised = with_path(&encoder.next_part().to_string(), 1, 1);

        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.receive(UR::parse(&disguised).unwrap()),
            Err(Error::InconsistentSequence { .. })
        ));

        // The rejection must not have recorded "bytes", or the decoder is stuck
        // on a type it never accepted until somebody clears it.
        assert_eq!(decoder.ur_type(), None);

        let mut other = Encoder::new();
        other.start("crypto-psbt", &message, 50);
        let valid = other.next_part().to_string();

        decoder.receive(UR::parse(&valid).unwrap()).unwrap();
        assert_eq!(decoder.ur_type(), Some("crypto-psbt"));
    }

    #[test]
    fn test_a_part_declaring_more_fragments_than_capacity_is_refused() {
        // Outer and inner metadata agree, and one byte over eight fragments is
        // within the message limit, so only the chooser's own capacity stands in
        // the way. It used to panic reserving index storage.
        let serialized = UR::MultiPartDeserialized {
            ur_type: "bytes",
            fragment: crate::fountain::part::Part {
                sequence: 9,
                sequence_count: 8,
                message_length: 8,
                checksum: 0,
                data: &[1],
            },
        }
        .to_string();

        // The fourth parameter is MAX_SEQUENCE_COUNT: 4, against a declared 8.
        let mut decoder = HeaplessDecoder::<32, 4, 128, 4, 4, 16>::new();
        assert!(matches!(
            decoder.receive(UR::parse(&serialized).unwrap()),
            Err(Error::Fountain(
                fountain::decoder::Error::SequenceCountTooLarge { count: 8, limit: 4 }
            ))
        ));
        assert_eq!(decoder.ur_type(), None);
    }

    #[test]
    fn test_path_hiding_a_larger_sequence_is_rejected() {
        let message = make_message_ur(200, "Wolf");
        let mut encoder = Encoder::new();
        encoder.start("bytes", &message, 50);
        assert!(encoder.sequence_count() > 1);

        // Two different parts of a multipart message, both wearing a 1-1 path. A
        // caller gating on the path sees two copies of one single part.
        let first = with_path(&encoder.next_part().to_string(), 1, 1);
        let second = with_path(&encoder.next_part().to_string(), 1, 1);

        let mut decoder = Decoder::default();
        for disguised in [first, second] {
            assert!(matches!(
                decoder.receive(UR::parse(&disguised).unwrap()),
                Err(Error::InconsistentSequence { .. })
            ));
        }

        assert!(!decoder.is_complete());
        assert_eq!(decoder.message().unwrap(), None);
    }

    #[test]
    fn test_inner_sequence_past_its_count_is_rejected() {
        let message = make_message_ur(200, "Wolf");
        let mut encoder = Encoder::new();
        encoder.start("bytes", &message, 50);

        // Parts past the sequence count are mixed parts, so this one's inner
        // sequence is greater than its inner count.
        let count = encoder.sequence_count();
        let mut part = encoder.next_part();
        for _ in 0..count {
            part = encoder.next_part();
        }
        let part = part.to_string();
        assert!(part.starts_with(&format!("ur:bytes/{}-{count}/", count + 1)));

        let disguised = with_path(&part, 1, 1);

        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.receive(UR::parse(&disguised).unwrap()),
            Err(Error::InconsistentSequence { .. })
        ));
    }

    #[test]
    fn test_mismatched_count_alone_is_rejected() {
        let message = make_message_ur(200, "Wolf");
        let mut encoder = Encoder::new();
        encoder.start("bytes", &message, 50);

        let count = encoder.sequence_count();
        let part = encoder.next_part().to_string();

        // Right sequence number, wrong count.
        let disguised = with_path(&part, 1, count + 1);

        let mut decoder = Decoder::default();
        assert!(matches!(
            decoder.receive(UR::parse(&disguised).unwrap()),
            Err(Error::InconsistentSequence { .. })
        ));
    }

    #[test]
    fn test_untouched_parts_still_decode() {
        let message = make_message_ur(200, "Wolf");
        let mut encoder = Encoder::new();
        encoder.start("bytes", &message, 50);

        // Through the string form, so this is the same UR::MultiPart path the
        // checks above reject.
        let mut decoder = Decoder::default();
        while !decoder.is_complete() {
            let part = encoder.next_part().to_string();
            decoder.receive(UR::parse(&part).unwrap()).unwrap();
        }

        assert_eq!(decoder.message().unwrap(), Some(message.as_slice()));
    }
}
