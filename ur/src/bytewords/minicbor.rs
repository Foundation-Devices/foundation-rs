// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! [`minicbor`] bytewords writer.
//!
//! The [`Writer`] structure allows `minicbor` to encode CBOR directly as bytewords
//! by writing it into a [`formatter`](fmt::Formatter) without any allocations.
//!
//! This removes the need for an intermediate buffer.

use core::fmt;

use crate::{bytewords::constants::MINIMALS, CRC32};

/// [`minicbor`] bytewords writer.
pub struct Writer<W> {
    writer: W,
    digest: crc::Digest<'static, u32>,
}

impl<W> Writer<W>
where
    W: fmt::Write,
{
    /// Construct a new [`Writer`].
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            digest: CRC32.digest(),
        }
    }

    /// Finish bytewords writer by writing the checksum.
    pub fn finish(mut self) -> Result<W, fmt::Error> {
        let crc = self.digest.finalize();
        for b in crc.to_be_bytes() {
            self.writer.write_str(MINIMALS[b as usize])?;
        }
        Ok(self.writer)
    }
}

impl<W> minicbor::encode::Write for Writer<W>
where
    W: fmt::Write,
{
    type Error = fmt::Error;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        for &b in buf {
            self.writer.write_str(MINIMALS[b as usize])?;
        }
        self.digest.update(buf);
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use minicbor::encode::Write;

    const INPUT_LEN: usize = 100;
    const INPUT: [u8; INPUT_LEN] = [
        245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212, 19,
        159, 17, 37, 239, 240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242, 254,
        147, 204, 66, 163, 216, 175, 191, 72, 169, 54, 32, 60, 144, 230, 210, 137, 184, 197, 33,
        113, 88, 14, 157, 31, 177, 46, 1, 115, 205, 69, 225, 150, 65, 235, 58, 144, 65, 240, 133,
        69, 113, 247, 63, 53, 242, 165, 160, 144, 26, 13, 79, 237, 133, 71, 82, 69, 254, 165, 138,
        41, 85, 24,
    ];

    const OUTPUT_LEN: usize = (INPUT_LEN + 4) * 2;
    const OUTPUT: [u8; OUTPUT_LEN]= *b"yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwne\
                                       bydawswtzcbdjnrsdawzdsksurdtnsrywzzemusf\
                                       fwottppersfdptencxfnmhvatdldroskcljshdba\
                                       ntctpadmadjksnfevymtfpwmftmhfpwtlpfejsyl\
                                       fhecwzonnbmhcybtgwwelpflgmfezeonledtgocs\
                                       fzhycypf";

    #[test]
    fn test_writer() {
        let mut output: heapless::Vec<u8, OUTPUT_LEN> = heapless::Vec::new();
        let mut writer = Writer::new(&mut output);
        writer.write_all(&INPUT).unwrap();
        assert_eq!(writer.finish().unwrap(), &OUTPUT);
    }
}
