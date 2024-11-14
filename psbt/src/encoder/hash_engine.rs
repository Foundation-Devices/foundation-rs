// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

/// Adapter struct that implements [`embedded_io::Write`] for
/// [`bitcoin_hashes::HashEngine`].
#[derive(Debug)]
pub struct HashEngine<E>(E);

impl<E> HashEngine<E> {
    pub fn into_inner(self) -> E {
        self.0
    }
}

impl<E> From<E> for HashEngine<E> {
    fn from(value: E) -> Self {
        Self(value)
    }
}

impl<E> embedded_io::ErrorType for HashEngine<E> {
    type Error = Infallible;
}

impl<E> embedded_io::Write for HashEngine<E>
where
    E: bitcoin_hashes::HashEngine,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.input(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// This type can't be constructed as writing to a hash engine never fails.
//
// TODO: Remove once ! (never type) is a thing in stable Rust.
#[derive(Debug)]
pub enum Infallible {}

impl embedded_io::Error for Infallible {
    fn kind(&self) -> embedded_io::ErrorKind {
        unreachable!();
    }
}
