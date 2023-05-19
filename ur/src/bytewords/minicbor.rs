// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! [`minicbor`] bytewords writer.
//!
//! The [`Writer`] structure allows `minicbor` to encode CBOR directly as bytewords
//! by writing it into a [`formatter`](fmt::Formatter) without any allocations.

use core::fmt;

use crate::{bytewords::constants::MINIMALS, CRC32};

/// `minicbor` bytewords writer.
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
