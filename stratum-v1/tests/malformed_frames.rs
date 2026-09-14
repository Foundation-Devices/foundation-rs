// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Malformed peer frame handling.
//!
//! These drive [`Client`] through its public API over a mock transport, the
//! way a pool would, and assert that arbitrary peer bytes turn into errors
//! rather than panics, stalls or poisoned buffers.

use embedded_io_async::{ErrorType, Read, ReadReady, Write};
use stratum_v1::{Client, Error, Extensions, Field, Message, VersionRolling};

const TX: usize = 512;
const RX: usize = 512;

/// A transport that replays a scripted byte stream, optionally in fragments.
struct MockPool {
    rx: Vec<u8>,
    rx_pos: usize,
    /// Maximum number of bytes handed over per `read`, to model a peer that
    /// dribbles frames out across packets.
    chunk: usize,
    tx: Vec<u8>,
}

impl MockPool {
    fn new(rx: &[u8]) -> Self {
        Self::fragmented(rx, usize::MAX)
    }

    fn fragmented(rx: &[u8], chunk: usize) -> Self {
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
}

type Outcome = Result<Option<Message>, Error>;

/// Poll `n` times and collect every outcome, so a test can assert on what the
/// client did across the whole exchange.
async fn poll_n<const N: usize>(client: &mut Client<MockPool, N, TX>, n: usize) -> Vec<Outcome> {
    let mut outcomes = Vec::with_capacity(n);
    for _ in 0..n {
        outcomes.push(client.poll_message().await);
    }
    outcomes
}

const SET_VERSION_MASK: &[u8] =
    br#"{"params":["1fffe000"],"id":null,"method":"mining.set_version_mask"}"#;
const SET_DIFFICULTY: &[u8] = br#"{"params":[2.5],"id":null,"method":"mining.set_difficulty"}"#;

/// A `mining.notify` whose previous-hash field is 8 characters instead of 64.
/// The parser used to slice it at fixed offsets regardless.
const SHORT_PREV_HASH: &[u8] = br#"{"id":null,"method":"mining.notify","params":["bf","4d16b6f8","01000000","072f736c7573682f",[],"00000002","1c2ac4af","504e86b9",false]}"#;

fn stream(lines: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

#[tokio::test]
async fn short_prev_hash_is_reported_not_panicked() {
    let mut client: Client<_, RX, TX> = Client::new(MockPool::new(&stream(&[SHORT_PREV_HASH])));

    let outcomes = poll_n(&mut client, 4).await;

    assert!(
        outcomes.iter().any(|o| matches!(
            o,
            Err(Error::InvalidFieldLength {
                field: Field::PrevHash,
                expected: 64,
                actual: 8
            })
        )),
        "{outcomes:?}"
    );
}

/// The audit reproduced two consecutive `IdNotFound` results for the same
/// unknown-ID line: the frame was reported but never consumed, so it sat at the
/// head of the buffer and every later poll re-parsed it.
#[tokio::test]
async fn unknown_response_id_does_not_poison_later_frames() {
    let mut client: Client<_, RX, TX> = Client::new(MockPool::new(&stream(&[
        br#"{"id":99,"result":true,"error":null}"#,
        SET_VERSION_MASK,
    ])));

    let outcomes = poll_n(&mut client, 5).await;

    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Err(Error::IdNotFound(99))))
            .count(),
        1,
        "the bad frame was replayed: {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Ok(Some(Message::VersionMask(0x1fff_e000))))),
        "the following frame never got through: {outcomes:?}"
    );
}

#[tokio::test]
async fn invalid_json_does_not_poison_later_frames() {
    let mut client: Client<_, RX, TX> = Client::new(MockPool::new(&stream(&[
        b"not json at all",
        SET_VERSION_MASK,
    ])));

    let outcomes = poll_n(&mut client, 5).await;

    assert_eq!(
        outcomes.iter().filter(|o| o.is_err()).count(),
        1,
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Ok(Some(Message::VersionMask(0x1fff_e000))))),
        "{outcomes:?}"
    );
}

/// A frame longer than the receive buffer can never be terminated. It used to
/// fill the buffer and then read into an empty remaining slice forever.
#[tokio::test]
async fn over_long_frame_is_dropped_and_the_client_resynchronizes() {
    const RX_SMALL: usize = 128;

    let mut bytes = vec![b'x'; 300];
    bytes.push(b'\n');
    bytes.extend_from_slice(&stream(&[SET_VERSION_MASK]));

    let mut client: Client<_, RX_SMALL, TX> = Client::new(MockPool::new(&bytes));

    let outcomes = poll_n(&mut client, 12).await;

    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Err(Error::LineTooLong))),
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Ok(Some(Message::VersionMask(0x1fff_e000))))),
        "no recovery after the over-long frame: {outcomes:?}"
    );
}

#[tokio::test]
async fn fragmented_reads_reassemble_multiple_frames() {
    let bytes = stream(&[SET_VERSION_MASK, SET_DIFFICULTY]);
    // One byte per read: every frame boundary lands mid-buffer.
    let mut client: Client<_, RX, TX> = Client::new(MockPool::fragmented(&bytes, 1));

    let outcomes = poll_n(&mut client, bytes.len() + 8).await;

    let messages: Vec<_> = outcomes.into_iter().flat_map(|o| o.unwrap()).collect();
    assert_eq!(
        messages,
        vec![Message::VersionMask(0x1fff_e000), Message::Difficulty(2.5)]
    );
}

/// `extranonce2_size` is chosen by the pool and drives a resize of the buffer
/// the client rolls, so it has to be bounded before it gets there.
#[tokio::test]
async fn oversized_extranonce2_size_is_rejected_and_leaves_the_session_alone() {
    let bytes = stream(&[
        br#"{"error":null,"id":1,"result":{"version-rolling":true,"version-rolling.mask":"1fffe000"}}"#,
        br#"{"id":2,"error":null,"result":[[["mining.notify","e26e1928"]],"e26e1928",64]}"#,
    ]);
    let mut client: Client<_, RX, TX> = Client::new(MockPool::new(&bytes));

    client
        .send_configure(Extensions {
            version_rolling: Some(VersionRolling {
                mask: Some(0x1fff_e000),
                min_bit_count: Some(2),
            }),
            minimum_difficulty: None,
            subscribe_extranonce: None,
            info: None,
        })
        .await
        .unwrap();

    // Reads the stream, then reports the configure response.
    assert_eq!(client.poll_message().await, Ok(None));
    assert_eq!(client.poll_message().await, Ok(Some(Message::Configured)));

    client.send_connect(None).await.unwrap();

    assert_eq!(
        client.poll_message().await,
        Err(Error::FieldTooLarge {
            field: Field::Extranonce2Size,
            max: stratum_v1::limits::EXTRANONCE2_SIZE_MAX,
            actual: 64,
        })
    );

    // The rejected response must not have marked the client as connected.
    assert_eq!(
        client
            .send_authorize("user".try_into().unwrap(), "pass".try_into().unwrap())
            .await,
        Err(Error::NotConnected)
    );
}

/// A zero version mask grants no rollable bits; rolling anyway shifted by 32.
#[tokio::test]
async fn zero_version_mask_does_not_panic_when_rolling() {
    let bytes = stream(&[
        br#"{"id":null,"method":"mining.notify","params":["bf","4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000","01000000","072f736c7573682f",[],"20000000","1c2ac4af","504e86b9",false]}"#,
        br#"{"params":["00000000"],"id":null,"method":"mining.set_version_mask"}"#,
    ]);
    let mut client: Client<_, RX, TX> = Client::new(MockPool::new(&bytes));
    client.enable_software_rolling(true, true, true);

    let outcomes = poll_n(&mut client, 5).await;
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Ok(Some(Message::VersionMask(0))))),
        "{outcomes:?}"
    );

    let job = client.roll_job().await.unwrap();
    assert_eq!(job.header.version, 0x2000_0000);
}
