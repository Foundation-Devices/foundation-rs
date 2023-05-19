// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Parts.

use core::{fmt, ops::DerefMut};

use crate::{
    bytewords,
    collections::{Set, Vec},
    fountain::{chooser, chooser::BaseFragmentChooser, util::xor_into},
};

/// Description of how a message is split into parts.
///
/// This structure is a subset of the information of a [`Part`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageDescription {
    /// The total sequence count.
    pub sequence_count: u32,
    /// The total message length, in bytes, excluding the padding bytes size.
    pub message_length: usize,
    /// The CRC32 checksum of the entire message.
    pub checksum: u32,
    /// The length of a single fragment.
    pub fragment_length: usize,
}

/// A part emitted by a fountain [encoder](crate::fountain::BaseEncoder).
///
/// Most commonly, this is obtained by calling [`next_part`] on the encoder.
///
/// [`next_part`]: crate::fountain::BaseEncoder::next_part
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Part<'a> {
    /// The sequence number of this part. Can be higher than
    /// [`sequence_count`](Self::sequence_count).
    pub sequence: u32,
    /// The total sequence count of the entire message.
    pub sequence_count: u32,
    /// The total message length, in bytes, excluding the padding bytes size.
    pub message_length: usize,
    /// The CRC32 checksum of the entire message.
    pub checksum: u32,
    /// The data of this part.
    ///
    /// If [`sequence`](Self::sequence), is higher than
    /// [`sequence_count`](Self::sequence_count) it's very likely that the data
    /// data contained is mixed, however there may be some cases where the
    /// former is true and this is a "simple part".
    pub data: &'a [u8],
}

impl<'a> Part<'a> {
    /// Returns `true` if this part is valid.
    ///
    /// Verifies that:
    ///
    /// - `sequence`, `sequence_count` are positive values.
    /// - `message_length` is a positive value and is .
    /// - `data` contains data and is smaller or equal to `message_length`.
    pub fn is_valid(&self) -> bool {
        self.sequence > 0
            && self.sequence_count > 0
            && self.message_length > 0
            && !self.data.is_empty()
            && self.data.len() <= self.message_length
    }

    /// Calculate the indexes contained on this [`Part`].
    ///
    /// **Note:** this is a costly operating that can take a lot of memory in
    /// the stack or the heap depending on the
    /// [fragment chooser types](chooser::Types) used.
    pub fn indexes<C, I>(&self) -> I
    where
        C: chooser::Types,
        I: Set<usize>,
    {
        BaseFragmentChooser::<C>::default().choose_fragments(
            self.sequence,
            self.sequence_count,
            self.checksum,
        )
    }

    /// Convert this [`Part`] into an [`IndexedPart`].
    ///
    /// **Note:** this is a costly operating that can take a lot of memory in
    /// the stack or the heap depending on the
    /// [fragment chooser types](chooser::Types) used.
    pub fn into_indexed_part<C, D, I>(self) -> IndexedPart<D, I>
    where
        C: chooser::Types,
        D: Vec<u8>,
        I: Set<usize>,
    {
        let mut data = D::default();
        if data.try_extend_from_slice(self.data).is_err() {
            panic!("not enough capacity to store IndexedPart data");
        }

        IndexedPart::new(data, self.indexes::<C, I>())
    }

    /// Returns the maximum length that an encoded `Part` can have excluding
    /// the `data` contents.
    pub const fn max_encoded_len() -> usize {
        #[rustfmt::skip]
        const MAX_CBOR: &[u8] = &[
            0x85,                                                     // array(5)
                0x1A, 0xFF, 0xFF, 0xFF, 0xFF,                         // unsigned(0xFFFFFFF)
                0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // unsigned(0xFFFFFFFFFFFFFFFF)
                0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // unsigned(0xFFFFFFFFFFFFFFFF)
                0x1A, 0xFF, 0xFF, 0xFF, 0xFF,                         // unsigned(0xFFFFFFF)
                0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // bytes(0xFFFFFFFFFFFFFFFF)
        ];

        MAX_CBOR.len()
    }

    /// Convert this [`Part`] to a [`MessageDescription`].
    pub fn to_message_description(&self) -> MessageDescription {
        MessageDescription {
            sequence_count: self.sequence_count,
            message_length: self.message_length,
            checksum: self.checksum,
            fragment_length: self.data.len(),
        }
    }
}

/// Display this [`Part`] as encoded bytewords.
impl<'a> fmt::Display for Part<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use custom minicbor writer that writes directly to `Formatter` instead of
        // using an intermediate buffer, so CBOR is directly encoded as bytewords.
        let mut encoder = minicbor::Encoder::new(bytewords::minicbor::Writer::new(f));
        encoder.encode(self).map_err(|_| fmt::Error)?;

        // Call finish to write CRC32 at the end.
        encoder.into_writer().finish()?;

        Ok(())
    }
}

impl<'a> PartialEq<MessageDescription> for Part<'a> {
    fn eq(&self, other: &MessageDescription) -> bool {
        self.sequence_count == other.sequence_count
            && self.message_length == other.message_length
            && self.checksum == other.checksum
            && self.data.len() == other.fragment_length
    }
}

/// Encodes [`Part`] to it's CBOR representation.
impl<'a, C> minicbor::Encode<C> for Part<'a> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(5)?
            .u32(self.sequence)?
            .u64(
                self.sequence_count
                    .try_into()
                    .map_err(|_| minicbor::encode::Error::message("expected u64"))?,
            )?
            .u64(
                self.message_length
                    .try_into()
                    .map_err(|_| minicbor::encode::Error::message("expected u64"))?,
            )?
            .u32(self.checksum)?
            .bytes(self.data)?;

        Ok(())
    }
}

/// Decodes [`Part`] from it's CBOR representation.
impl<'b, C> minicbor::Decode<'b, C> for Part<'b> {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        if !matches!(d.array()?, Some(5)) {
            return Err(minicbor::decode::Error::message(
                "invalid CBOR array length",
            ));
        }

        Ok(Self {
            sequence: d.u32()?,
            sequence_count: d.u32()?,
            message_length: d
                .u32()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("expected usize"))?,
            checksum: d.u32()?,
            data: d.bytes()?,
        })
    }
}

/// A part with the indexes of the simple parts mixed.
#[derive(Debug, Clone)]
pub struct IndexedPart<D, I> {
    /// The data of this part.
    pub data: D,
    /// The indexes contained in this part.
    pub indexes: I,
}

impl<D, I> IndexedPart<D, I> {
    /// Create a new [`IndexedPart`] from `data` and the indexes of the parts
    /// mixed in `data`.
    pub fn new(data: D, indexes: I) -> Self {
        Self { data, indexes }
    }

    /// Returns `true` if the part is simple.
    ///
    /// A part is simple if it only contains a single mixed, e.g: the data is
    /// already decoded (or unmixed).
    #[inline]
    pub fn is_simple(&self) -> bool
    where
        I: Set<usize>,
    {
        self.indexes.len() == 1
    }

    /// Reduce this part by another part.
    ///
    /// # Panics
    ///
    /// This function panics if this part is already simple.
    pub fn reduce(&mut self, part: &IndexedPart<D, I>)
    where
        D: DerefMut<Target = [u8]>,
        I: Set<usize>,
    {
        if self.indexes.len() == 1 {
            return;
        }

        if part.indexes.is_subset(&self.indexes) {
            self.indexes = self.indexes.sub(&part.indexes);
            xor_into(&mut self.data, &part.data);
        }
    }

    /// Reduce this part by a simple part.
    ///
    /// # Panics
    ///
    /// This function panics if this part is already simple.
    pub fn reduce_by_simple(&mut self, data: &[u8], index: usize)
    where
        D: DerefMut<Target = [u8]>,
        I: Set<usize>,
    {
        assert!(self.indexes.len() > 1, "cannot reduce a simple part");

        if self.indexes.contains(&index) {
            self.indexes.remove(&index);
            xor_into(&mut self.data, data);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_part_cbor_roundtrip() {
        const PART: Part = Part {
            sequence: 12,
            sequence_count: 8,
            message_length: 100,
            checksum: 0x1234_5678,
            data: &[1, 5, 3, 3, 5],
        };

        let mut cbor = alloc::vec::Vec::new();
        minicbor::encode(&PART, &mut cbor).unwrap();

        let part2: Part = minicbor::decode(&cbor).unwrap();
        assert_eq!(part2, PART);

        let mut cbor2 = alloc::vec::Vec::new();
        minicbor::encode(&part2, &mut cbor2).unwrap();
        assert_eq!(cbor, cbor2);
    }

    #[test]
    fn test_part_cbor_decode() {
        // 0x18 is the first byte value that doesn't directly encode a u8,
        // but implies a following value
        assert!(minicbor::decode::<'_, Part>(&[0x18]).is_err());
        // the top-level item must be an array
        assert!(minicbor::decode::<'_, Part>(&[0x1]).is_err());
        // the array must be of length five
        assert!(minicbor::decode::<'_, Part>(&[0x84, 0x1, 0x2, 0x3, 0x4]).is_err());
        assert!(minicbor::decode::<'_, Part>(&[0x86, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6]).is_err());
        // the first item must be an unsigned integer
        assert!(
            minicbor::decode::<'_, Part>(&[0x85, 0x41, 0x1, 0x2, 0x3, 0x4, 0x41, 0x1]).is_err()
        );
        // the second item must be an unsigned integer
        assert!(
            minicbor::decode::<'_, Part>(&[0x85, 0x1, 0x41, 0x2, 0x3, 0x4, 0x41, 0x1]).is_err()
        );
        // the third item must be an unsigned integer
        assert!(
            minicbor::decode::<'_, Part>(&[0x85, 0x1, 0x2, 0x41, 0x3, 0x4, 0x41, 0x1]).is_err()
        );
        // the fourth item must be an unsigned integer
        assert!(
            minicbor::decode::<'_, Part>(&[0x85, 0x1, 0x2, 0x3, 0x41, 0x4, 0x41, 0x1]).is_err()
        );
        // the fifth item must be byte string
        assert!(minicbor::decode::<'_, Part>(&[0x85, 0x1, 0x2, 0x3, 0x4, 0x5]).is_err());
        assert!(minicbor::decode::<'_, Part>(&[0x85, 0x1, 0x2, 0x3, 0x4, 0x5]).is_err());
        minicbor::decode::<'_, Part>(&[0x85, 0x1, 0x2, 0x3, 0x4, 0x41, 0x5]).unwrap();
    }

    #[test]
    fn test_part_cbor_decode_unsigned_types() {
        // u8
        minicbor::decode::<'_, Part>(&[0x85, 0x1, 0x2, 0x3, 0x4, 0x41, 0x5]).unwrap();
        // u16
        minicbor::decode::<'_, Part>(&[
            0x85, 0x19, 0x1, 0x2, 0x19, 0x3, 0x4, 0x19, 0x5, 0x6, 0x19, 0x7, 0x8, 0x41, 0x5,
        ])
        .unwrap();
        // u32
        minicbor::decode::<'_, Part>(&[
            0x85, 0x1a, 0x1, 0x2, 0x3, 0x4, 0x1a, 0x5, 0x6, 0x7, 0x8, 0x1a, 0x9, 0x10, 0x11, 0x12,
            0x1a, 0x13, 0x14, 0x15, 0x16, 0x41, 0x5,
        ])
        .unwrap();
        // u64
        assert!(minicbor::decode::<'_, Part>(&[
            0x85, 0x1b, 0x1, 0x2, 0x3, 0x4, 0xa, 0xb, 0xc, 0xd, 0x1a, 0x5, 0x6, 0x7, 0x8, 0x1a,
            0x9, 0x10, 0x11, 0x12, 0x1a, 0x13, 0x14, 0x15, 0x16, 0x41, 0x5,
        ])
        .is_err());
        assert!(minicbor::decode::<'_, Part>(&[
            0x85, 0x1a, 0x1, 0x2, 0x3, 0x4, 0x1b, 0x5, 0x6, 0x7, 0x8, 0xa, 0xb, 0xc, 0xd, 0x1a,
            0x9, 0x10, 0x11, 0x12, 0x1a, 0x13, 0x14, 0x15, 0x16, 0x41, 0x5,
        ])
        .is_err());
        assert!(minicbor::decode::<'_, Part>(&[
            0x85, 0x1a, 0x1, 0x2, 0x3, 0x4, 0x1a, 0x5, 0x6, 0x7, 0x8, 0x1b, 0x9, 0x10, 0x11, 0x12,
            0xa, 0xb, 0xc, 0xd, 0x1a, 0x13, 0x14, 0x15, 0x16, 0x41, 0x5,
        ])
        .is_err());
        assert!(minicbor::decode::<'_, Part>(&[
            0x85, 0x1a, 0x1, 0x2, 0x3, 0x4, 0x1a, 0x5, 0x6, 0x7, 0x8, 0x1a, 0x9, 0x10, 0x11, 0x12,
            0x1b, 0x13, 0x14, 0x15, 0x16, 0xa, 0xb, 0xc, 0xd, 0x41, 0x5,
        ])
        .is_err());
    }
}
