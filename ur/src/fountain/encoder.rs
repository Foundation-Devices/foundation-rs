// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Encoder.

use crate::{
    collections::{Set, Vec},
    fountain::{
        chooser,
        part::Part,
        util::{div_ceil, fragment_length, xor_into},
    },
    CRC32,
};

/// A encoder.
#[cfg(feature = "alloc")]
pub type Encoder<'a> = BaseEncoder<'a, Alloc>;

#[cfg(feature = "alloc")]
impl<'a> Encoder<'a> {
    /// Construct a new [`Encoder`].
    pub const fn new() -> Self {
        Self {
            message: None,
            fragment_length: 0,
            checksum: 0,
            current_sequence: 0,
            chooser: chooser::FragmentChooser::new(),
            data: alloc::vec::Vec::new(),
            indexes: alloc::collections::BTreeSet::new(),
        }
    }
}

/// A static encoder.
pub type HeaplessEncoder<'a, const MAX_FRAGMENT_LEN: usize, const MAX_SEQUENCE_COUNT: usize> =
    BaseEncoder<'a, Heapless<MAX_FRAGMENT_LEN, MAX_SEQUENCE_COUNT>>;

impl<'a, const MAX_FRAGMENT_LEN: usize, const MAX_SEQUENCE_COUNT: usize>
    HeaplessEncoder<'a, MAX_FRAGMENT_LEN, MAX_SEQUENCE_COUNT>
{
    /// Constructs a new [`HeaplessEncoder`].
    pub const fn new() -> Self {
        Self {
            message: None,
            fragment_length: 0,
            checksum: 0,
            current_sequence: 0,
            chooser: chooser::HeaplessFragmentChooser::new(),
            data: heapless::Vec::new(),
            indexes: heapless::IndexSet::new(),
        }
    }
}

/// An encoder capable of emitting fountain-encoded transmissions.
///
/// # Examples
///
/// See the [`crate::fountain`] module documentation for an example.
pub struct BaseEncoder<'a, T: Types> {
    message: Option<&'a [u8]>,
    fragment_length: usize,
    checksum: u32,
    current_sequence: u32,
    chooser: chooser::BaseFragmentChooser<T::Chooser>,
    data: T::Data,
    indexes: T::Indexes,
}

impl<'a, T: Types> BaseEncoder<'a, T> {
    /// Start encoding a new message.
    ///
    /// # Panics
    ///
    /// This function panics if:
    ///
    /// - The message is empty.
    /// - The maximum fragment length is zero.
    /// - The maximum fragment length is large than what `T::Data` can
    /// hold.
    pub fn start(&mut self, message: &'a [u8], max_fragment_length: usize) {
        use std::fmt;

        assert!(!message.is_empty(), "message must not be empty");
        assert_ne!(
            max_fragment_length, 0,
            "fragment length must be greater than zero"
        );

        self.fragment_length = fragment_length(message.len(), max_fragment_length);
        self.message = Some(message);
        self.checksum = CRC32.checksum(message);
        self.current_sequence = 0;

        self.data.clear();
        let error_message = format!("fragment_length: {}\nmessage.len(): {}\nmax_fragment_length: {}", self.fragment_length, message.len(), max_fragment_length);
        self.data
            .try_resize(self.fragment_length, 0)
            .expect(&error_message);
    }

    /// Returns the current count of how many parts have been emitted.
    #[must_use]
    #[inline]
    pub fn current_sequence(&self) -> u32 {
        self.current_sequence
    }

    /// Returns the number of segments the original message has been split up into.
    #[must_use]
    pub fn sequence_count(&self) -> u32 {
        div_ceil(self.message.unwrap().len(), self.fragment_length)
            .try_into()
            .unwrap()
    }

    /// Returns whether all original segments have been emitted at least once.
    /// The fountain encoding is defined as doing this before combining segments
    /// with each other. Thus, this is equivalent to checking whether
    /// [`current_sequence`] >= [`fragment_count`].
    ///
    /// [`fragment_count`]: BaseEncoder::sequence_count
    /// [`current_sequence`]: BaseEncoder::current_sequence
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.current_sequence >= self.sequence_count()
    }

    /// Returns the next part to be emitted by the fountain encoder.
    /// After all parts of the original message have been emitted once,
    /// the fountain encoder will emit the result of xor-ing together the parts
    /// selected by the Xoshiro RNG (which could be a single part).
    ///
    /// # Examples
    ///
    /// See the [`crate::fountain`] module documentation for an example.
    pub fn next_part(&mut self) -> Part {
        self.current_sequence = self.current_sequence.wrapping_add(1);

        self.indexes = self.chooser.choose_fragments(
            self.current_sequence,
            self.sequence_count(),
            self.checksum,
        );

        self.data.fill(0);
        for &index in self.indexes.iter() {
            let fragment = self
                .message
                .map(|msg| &msg[index * self.fragment_length..])
                .unwrap();
            let fragment = fragment.get(..self.fragment_length).unwrap_or(fragment);

            xor_into(&mut self.data[..fragment.len()], fragment);
            for b in self.data[fragment.len()..].iter_mut() {
                *b ^= 0;
            }
        }

        Part {
            sequence: self.current_sequence,
            sequence_count: self.sequence_count(),
            message_length: self.message.unwrap().len(),
            checksum: self.checksum,
            data: &self.data,
        }
    }
}

/// Types for [`BaseEncoder`].
pub trait Types: Default {
    /// Fragment chooser types.
    type Chooser: chooser::Types;

    /// Data buffer.
    type Data: Vec<u8>;

    /// Indexes.
    type Indexes: Set<usize>;
}

/// [`alloc`] types for [`BaseEncoder`].
#[derive(Default)]
#[cfg(feature = "alloc")]
pub struct Alloc;

#[cfg(feature = "alloc")]
impl Types for Alloc {
    type Chooser = chooser::Alloc;
    type Data = alloc::vec::Vec<u8>;
    type Indexes = alloc::collections::BTreeSet<usize>;
}

/// [`heapless`] types for [`BaseEncoder`].
#[derive(Default)]
pub struct Heapless<const MAX_FRAGMENT_LEN: usize, const MAX_SEQUENCE_COUNT: usize>;

impl<const MAX_FRAGMENT_LEN: usize, const MAX_SEQUENCE_COUNT: usize> Types
    for Heapless<MAX_FRAGMENT_LEN, MAX_SEQUENCE_COUNT>
{
    type Chooser = chooser::Heapless<MAX_SEQUENCE_COUNT>;
    type Data = heapless::Vec<u8, MAX_FRAGMENT_LEN>;
    type Indexes = heapless::FnvIndexSet<usize, MAX_SEQUENCE_COUNT>;
}

#[cfg(test)]
#[cfg(feature = "alloc")]
pub mod tests {
    use super::*;
    use crate::xoshiro::test_utils::make_message;

    #[test]
    fn test_encoder_fragment_split() {
        const EXPECTED_FRAGMENTS: &[&str] = &[
            "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f965e25ee29039f",
            "df8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3ec4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f595e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff173f021c0e6f65b05c0a494e50791",
            "270a0050a73ae69b6725505a2ec8a5791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d41977fa6f78dc07eecd072aae5bc8a852397e06034dba6a0b570",
            "797c3a89b16673c94838d884923b8186ee2db5c98407cab15e13678d072b43e406ad49477c2e45e85e52ca82a94f6df7bbbe7afbed3a3a830029f29090f25217e48d1f42993a640a67916aa7480177354cc7440215ae41e4d02eae9a1912",
            "33a6d4922a792c1b7244aa879fefdb4628dc8b0923568869a983b8c661ffab9b2ed2c149e38d41fba090b94155adbed32f8b18142ff0d7de4eeef2b04adf26f2456b46775c6c20b37602df7da179e2332feba8329bbb8d727a138b4ba7a5",
            "03215eda2ef1e953d89383a382c11d3f2cad37a4ee59a91236a3e56dcf89f6ac81dd4159989c317bd649d9cbc617f73fe10033bd288c60977481a09b343d3f676070e67da757b86de27bfca74392bac2996f7822a7d8f71a489ec6180390",
            "089ea80a8fcd6526413ec6c9a339115f111d78ef21d456660aa85f790910ffa2dc58d6a5b93705caef1091474938bd312427021ad1eeafbd19e0d916ddb111fabd8dcab5ad6a6ec3a9c6973809580cb2c164e26686b5b98cfb017a337968",
            "c7daaa14ae5152a067277b1b3902677d979f8e39cc2aafb3bc06fcf69160a853e6869dcc09a11b5009f91e6b89e5b927ab1527a735660faa6012b420dd926d940d742be6a64fb01cdc0cff9faa323f02ba41436871a0eab851e7f5782d10",
            "fbefde2a7e9ae9dc1e5c2c48f74f6c824ce9ef3c89f68800d44587bedc4ab417cfb3e7447d90e1e417e6e05d30e87239d3a5d1d45993d4461e60a0192831640aa32dedde185a371ded2ae15f8a93dba8809482ce49225daadfbb0fec629e",
            "23880789bdf9ed73be57fa84d555134630e8d0f7df48349f29869a477c13ccca9cd555ac42ad7f568416c3d61959d0ed568b2b81c7771e9088ad7fd55fd4386bafbf5a528c30f107139249357368ffa980de2c76ddd9ce4191376be0e6b5",
            "170010067e2e75ebe2d2904aeb1f89d5dc98cd4a6f2faaa8be6d03354c990fd895a97feb54668473e9d942bb99e196d897e8f1b01625cf48a7b78d249bb4985c065aa8cd1402ed2ba1b6f908f63dcd84b66425df00000000000000000000"
        ];

        let message = make_message("Wolf", 1024);
        let mut encoder = Encoder::new();
        encoder.start(&message, 100);

        assert_eq!(
            usize::try_from(encoder.sequence_count()).unwrap(),
            EXPECTED_FRAGMENTS.len()
        );
        for &expected_fragment in EXPECTED_FRAGMENTS.iter() {
            let part = encoder.next_part();
            assert_eq!(hex::encode(part.data), expected_fragment);
        }
    }

    #[test]
    fn test_encoder() {
        const EXPECTED_DATA: [&str; 20] = [
            "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
            "cba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a",
            "8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f",
            "965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3e",
            "c4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f59",
            "5e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff1",
            "73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
            "791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22",
            "951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d0000000000",
            "330f0f33a05eead4f331df229871bee733b50de71afd2e5a79f196de09",
            "3b205ce5e52d8c24a52cffa34c564fa1af3fdffcd349dc4258ee4ee828",
            "dd7bf725ea6c16d531b5f03254783803048ca08b87148daacd1cd7a006",
            "760be7ad1c6187902bbc04f539b9ee5eb8ea6833222edea36031306c01",
            "5bf4031217d2c3254b088fa7553778b5003632f46e21db129416f65b55",
            "73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
            "b8546ebfe2048541348910267331c643133f828afec9337c318f71b7df",
            "23dedeea74e3a0fb052befabefa13e2f80e4315c9dceed4c8630612e64",
            "d01a8daee769ce34b6b35d3ca0005302724abddae405bdb419c0a6b208",
            "3171c5dc365766eff25ae47c6f10e7de48cfb8474e050e5fe997a6dc24",
            "e055c2433562184fa71b4be94f262e200f01c6f74c284b0dc6fae6673f",
        ];

        let message = make_message("Wolf", 256);
        let mut encoder = Encoder::new();
        encoder.start(&message, 30);

        for (i, data) in EXPECTED_DATA
            .iter()
            .map(|v| hex::decode(v).unwrap())
            .enumerate()
        {
            let sequence = u32::try_from(i).unwrap();
            let expected_part = Part {
                sequence: sequence + 1,
                sequence_count: 9,
                message_length: 256,
                checksum: 23_570_951,
                data: &data,
            };

            assert_eq!(encoder.current_sequence(), sequence);
            assert_eq!(encoder.next_part(), expected_part);
        }
    }

    #[test]
    fn test_fountain_encoder_is_complete() {
        let message = make_message("Wolf", 256);
        let mut encoder = Encoder::new();
        encoder.start(&message, 30);
        for _ in 0..encoder.sequence_count() {
            encoder.next_part();
        }
        assert!(encoder.is_complete());
    }

    #[test]
    fn test_encoder_part_cbor() {
        const MAX_FRAGMENT_LENGTH: usize = 30;
        const MESSAGE_SIZE: usize = 256;
        const SEQUENCE_COUNT: usize = div_ceil(MESSAGE_SIZE, MAX_FRAGMENT_LENGTH);
        const EXPECTED_PARTS_CBOR: [&str; 20] = [
            "8501091901001a0167aa07581d916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
            "8502091901001a0167aa07581dcba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a",
            "8503091901001a0167aa07581d8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f",
            "8504091901001a0167aa07581d965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3e",
            "8505091901001a0167aa07581dc4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f59",
            "8506091901001a0167aa07581d5e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff1",
            "8507091901001a0167aa07581d73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
            "8508091901001a0167aa07581d791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22",
            "8509091901001a0167aa07581d951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d0000000000",
            "850a091901001a0167aa07581d330f0f33a05eead4f331df229871bee733b50de71afd2e5a79f196de09",
            "850b091901001a0167aa07581d3b205ce5e52d8c24a52cffa34c564fa1af3fdffcd349dc4258ee4ee828",
            "850c091901001a0167aa07581ddd7bf725ea6c16d531b5f03254783803048ca08b87148daacd1cd7a006",
            "850d091901001a0167aa07581d760be7ad1c6187902bbc04f539b9ee5eb8ea6833222edea36031306c01",
            "850e091901001a0167aa07581d5bf4031217d2c3254b088fa7553778b5003632f46e21db129416f65b55",
            "850f091901001a0167aa07581d73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
            "8510091901001a0167aa07581db8546ebfe2048541348910267331c643133f828afec9337c318f71b7df",
            "8511091901001a0167aa07581d23dedeea74e3a0fb052befabefa13e2f80e4315c9dceed4c8630612e64",
            "8512091901001a0167aa07581dd01a8daee769ce34b6b35d3ca0005302724abddae405bdb419c0a6b208",
            "8513091901001a0167aa07581d3171c5dc365766eff25ae47c6f10e7de48cfb8474e050e5fe997a6dc24",
            "8514091901001a0167aa07581de055c2433562184fa71b4be94f262e200f01c6f74c284b0dc6fae6673f",
        ];

        let message = make_message("Wolf", MESSAGE_SIZE);
        let mut encoder = Encoder::new();
        encoder.start(&message, MAX_FRAGMENT_LENGTH);
        assert_eq!(
            encoder.sequence_count(),
            u32::try_from(SEQUENCE_COUNT).unwrap()
        );

        for expected_cbor in EXPECTED_PARTS_CBOR.iter().map(|v| hex::decode(v).unwrap()) {
            let mut cbor = alloc::vec::Vec::new();
            minicbor::encode(encoder.next_part(), &mut cbor).unwrap();

            assert_eq!(cbor, expected_cbor);
        }
    }

    #[test]
    #[should_panic(expected = "fragment length must be greater than zero")]
    fn test_encoder_zero_max_length() {
        let mut encoder = Encoder::new();
        encoder.start("foo".as_bytes(), 0);
    }

    #[test]
    #[should_panic(expected = "message must not be empty")]
    fn test_encoder_empty_message() {
        let mut encoder = Encoder::new();
        encoder.start("".as_bytes(), 20);
    }
}
