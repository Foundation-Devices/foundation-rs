// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Stateful fuzzing of the Stratum client against a hostile pool.
//!
//! The corpus is a list of read chunks, so a single frame can be split across
//! reads and a single read can carry several frames. Between polls the harness
//! drives the request side of the state machine, which is what makes the
//! response branches reachable at all.
//!
//! Chunks are structured rather than raw bytes. A byte-level fuzzer will not
//! discover the literal `"mining.notify"` on its own, so it would never get
//! past `parse_method` and the per-field validation behind it would go
//! untested. Each chunk is therefore either free-form bytes — covering the
//! framing and JSON layers — or a well-formed envelope whose *fields* are
//! fuzzer-controlled, which is precisely the "recognized method, malformed
//! contents" shape this target exists to cover.
//!
//! Every operation is allowed to fail; the property under test is that none of
//! them panics and that polling always makes progress.
//!
//! This targets the default (`heapless`) build of the crate.

#![no_main]

use std::fmt::Write as _;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use arbitrary::Arbitrary;
use embedded_io_async::{ErrorType, Read, ReadReady, Write};
use libfuzzer_sys::fuzz_target;
use stratum_v1::{Client, Extensions, Share, VersionRolling};

const RX_BUF_SIZE: usize = 512;
const TX_BUF_SIZE: usize = 512;

/// Upper bound on poll iterations, so a corpus entry cannot spin forever.
const MAX_STEPS: usize = 256;

/// A JSON string field.
#[derive(Arbitrary, Debug)]
enum Text {
    /// Valid hex, of a fuzzer-chosen length. `odd` lops off the last character
    /// so odd-length hex is cheap to reach.
    Hex { bytes: Vec<u8>, odd: bool },
    /// Anything at all, including bytes that break the surrounding JSON.
    Raw(String),
}

impl Text {
    fn render(&self) -> String {
        match self {
            Text::Hex { bytes, odd } => {
                let mut out = String::with_capacity(bytes.len() * 2);
                for b in bytes {
                    let _ = write!(out, "{b:02x}");
                }
                if *odd {
                    out.pop();
                }
                out
            }
            Text::Raw(s) => s.clone(),
        }
    }
}

#[derive(Arbitrary, Debug)]
#[allow(clippy::large_enum_variant)] // Built once per corpus entry, never stored in bulk.
enum Frame {
    /// Free-form bytes: framing, terminators and the JSON layer.
    Raw(Vec<u8>),
    Notify {
        job_id: Text,
        prev_hash: Text,
        coinb1: Text,
        coinb2: Text,
        merkle: Vec<Text>,
        version: Text,
        nbits: Text,
        ntime: Text,
        clean_jobs: bool,
    },
    SetVersionMask(Text),
    SetDifficulty(f64),
    ConfigureResponse {
        id: u8,
        version_rolling: bool,
        mask: Text,
    },
    SubscribeResponse {
        id: u8,
        extranonce1: Text,
        extranonce2_size: usize,
    },
    BoolResponse {
        id: u8,
        result: bool,
    },
    ErrorResponse {
        id: u8,
        code: i16,
        message: Text,
    },
}

impl Frame {
    fn render(&self, out: &mut Vec<u8>) {
        let json = match self {
            Frame::Raw(bytes) => {
                out.extend_from_slice(bytes);
                return;
            }
            Frame::Notify {
                job_id,
                prev_hash,
                coinb1,
                coinb2,
                merkle,
                version,
                nbits,
                ntime,
                clean_jobs,
            } => {
                let merkle = merkle
                    .iter()
                    .map(|m| format!("\"{}\"", m.render()))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    r#"{{"id":null,"method":"mining.notify","params":["{}","{}","{}","{}",[{}],"{}","{}","{}",{}]}}"#,
                    job_id.render(),
                    prev_hash.render(),
                    coinb1.render(),
                    coinb2.render(),
                    merkle,
                    version.render(),
                    nbits.render(),
                    ntime.render(),
                    clean_jobs,
                )
            }
            Frame::SetVersionMask(mask) => format!(
                r#"{{"id":null,"method":"mining.set_version_mask","params":["{}"]}}"#,
                mask.render()
            ),
            Frame::SetDifficulty(difficulty) => format!(
                r#"{{"id":null,"method":"mining.set_difficulty","params":[{difficulty:?}]}}"#
            ),
            Frame::ConfigureResponse {
                id,
                version_rolling,
                mask,
            } => format!(
                r#"{{"error":null,"id":{},"result":{{"version-rolling":{},"version-rolling.mask":"{}"}}}}"#,
                id,
                version_rolling,
                mask.render()
            ),
            Frame::SubscribeResponse {
                id,
                extranonce1,
                extranonce2_size,
            } => format!(
                r#"{{"id":{},"error":null,"result":[[["mining.notify","1"]],"{}",{}]}}"#,
                id,
                extranonce1.render(),
                extranonce2_size
            ),
            Frame::BoolResponse { id, result } => {
                format!(r#"{{"id":{id},"error":null,"result":{result}}}"#)
            }
            Frame::ErrorResponse { id, code, message } => format!(
                r#"{{"id":{},"result":null,"error":[{},"{}",null]}}"#,
                id,
                code,
                message.render()
            ),
        };
        out.extend_from_slice(json.as_bytes());
    }
}

#[derive(Arbitrary, Debug)]
struct Chunk {
    frames: Vec<Frame>,
    /// Whether the chunk ends with a terminator. Leaving it off is what
    /// produces split frames and, at length, unterminated ones.
    terminated: bool,
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// One entry per `read`, in order.
    chunks: Vec<Chunk>,
}

/// A pool that hands back the fuzzer's bytes one scripted chunk at a time.
struct FuzzPool {
    chunks: Vec<Vec<u8>>,
    chunk: usize,
    offset: usize,
}

impl FuzzPool {
    fn remaining(&self) -> usize {
        self.chunks
            .iter()
            .enumerate()
            .skip(self.chunk)
            .map(|(i, c)| {
                if i == self.chunk {
                    c.len().saturating_sub(self.offset)
                } else {
                    c.len()
                }
            })
            .sum()
    }
}

impl ErrorType for FuzzPool {
    type Error = embedded_io_async::ErrorKind;
}

impl Read for FuzzPool {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        while self.chunk < self.chunks.len() {
            let current = &self.chunks[self.chunk];
            if self.offset >= current.len() {
                self.chunk += 1;
                self.offset = 0;
                continue;
            }
            let n = (current.len() - self.offset).min(buf.len());
            buf[..n].copy_from_slice(&current[self.offset..self.offset + n]);
            self.offset += n;
            return Ok(n);
        }
        Ok(0)
    }
}

impl ReadReady for FuzzPool {
    fn read_ready(&mut self) -> Result<bool, Self::Error> {
        Ok(self.remaining() > 0)
    }
}

impl Write for FuzzPool {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(buf.len())
    }
}

/// The mock transport never yields, so a future is always ready on first poll.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("the mock transport never pends"),
    }
}

fuzz_target!(|input: Input| {
    let chunks: Vec<Vec<u8>> = input
        .chunks
        .iter()
        .map(|chunk| {
            let mut bytes = Vec::new();
            for frame in &chunk.frames {
                frame.render(&mut bytes);
            }
            if chunk.terminated {
                bytes.push(b'\n');
            }
            bytes
        })
        .collect();

    let steps = (chunks.len() + 8).min(MAX_STEPS);
    let pool = FuzzPool {
        chunks,
        chunk: 0,
        offset: 0,
    };
    let mut client: Client<_, RX_BUF_SIZE, TX_BUF_SIZE> = Client::new(pool);
    client.enable_software_rolling(true, true, true);

    for _ in 0..steps {
        let _ = block_on(client.poll_message());

        // Advance the request side so the pending-request table is populated
        // and the fuzzer's responses can match a real request kind. Each of
        // these is a no-op until the handshake reaches the matching stage.
        let _ = block_on(client.send_configure(Extensions {
            version_rolling: Some(VersionRolling {
                mask: Some(0x1fff_e000),
                min_bit_count: Some(2),
            }),
            minimum_difficulty: None,
            subscribe_extranonce: None,
            info: None,
        }));
        let _ = block_on(client.send_connect(None));
        let _ = block_on(client.send_authorize(
            heapless::String::try_from("user").unwrap(),
            heapless::String::try_from("pass").unwrap(),
        ));
        let _ = block_on(client.send_submit(Share {
            job_id: heapless::String::try_from("job").unwrap(),
            extranonce2: heapless::Vec::from_slice(&[0, 0, 0, 1]).unwrap(),
            ntime: 0x504e_86ed,
            nonce: 0xb295_7c02,
            version_bits: None,
        }));

        // Exercises the version / extranonce2 / ntime rolling arithmetic with
        // whatever work the fuzzer managed to install.
        let _ = block_on(client.roll_job());
    }
});
