// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! A scripted pool shared by the integration tests.

#![allow(dead_code)] // each test binary uses a different subset

use embedded_io_async::{ErrorType, Read, ReadReady, Write};

/// A transport that replays a scripted byte stream, optionally in fragments.
pub struct MockPool {
    rx: Vec<u8>,
    rx_pos: usize,
    /// Maximum number of bytes handed over per `read`, to model a peer that
    /// dribbles frames out across packets.
    chunk: usize,
    tx: Vec<u8>,
}

impl MockPool {
    pub fn new(rx: &[u8]) -> Self {
        Self::fragmented(rx, usize::MAX)
    }

    pub fn fragmented(rx: &[u8], chunk: usize) -> Self {
        Self {
            rx: rx.to_vec(),
            rx_pos: 0,
            chunk,
            tx: Vec::new(),
        }
    }
}

impl ErrorType for MockPool {
    type Error = embedded_io_async::ErrorKind;
}

impl Read for MockPool {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = (self.rx.len() - self.rx_pos).min(buf.len()).min(self.chunk);
        buf[..n].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + n]);
        self.rx_pos += n;
        Ok(n)
    }
}

impl ReadReady for MockPool {
    fn read_ready(&mut self) -> Result<bool, Self::Error> {
        Ok(self.rx_pos < self.rx.len())
    }
}

impl Write for MockPool {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Join frames into one newline-terminated byte stream.
pub fn stream(lines: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}
