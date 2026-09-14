// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Authorization credentials must not reach the log.
//!
//! Drives a full handshake against a mock pool with canary credentials and a
//! capturing logger installed at the most verbose level, then asserts that
//! neither canary appears anywhere in the captured output.
//!
//! This exercises the `log` backend. The `defmt-03` backend cannot be captured
//! in a host test — it needs its linker sections and an ELF to decode against —
//! but it does not need to be: `fmt` maps `debug!`/`trace!` onto both backends
//! with the *same arguments*, and the redaction happens before the macro is
//! invoked. Whatever a backend receives, it receives from
//! `Sensitivity::loggable`, whose behaviour is pinned by the unit tests in
//! `client::redact`.

#![cfg(feature = "log")]

use std::sync::{Mutex, OnceLock};

use embedded_io_async::{ErrorType, Read, ReadReady, Write};
use stratum_v1::{Client, Extensions, Info, Share, VersionRolling};

/// Strings that must never be logged. Distinctive enough that a substring
/// search cannot match them by accident, and split into a prefix and a worker
/// suffix so a partial leak is caught too.
const CANARY_TAG: &str = "CANARY7491";
const CANARY_WORKER: &str = "worker001";
const CANARY_PASS: &str = "CANARY7491PASSWORD";

const RX: usize = 1024;
const TX: usize = 1024;

// ---------------------------------------------------------------- capture ---

static CAPTURED: OnceLock<Mutex<String>> = OnceLock::new();

fn captured() -> &'static Mutex<String> {
    CAPTURED.get_or_init(|| Mutex::new(String::new()))
}

struct CapturingLogger;

impl log::Log for CapturingLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        use std::fmt::Write as _;
        let mut buf = captured().lock().unwrap();
        let _ = writeln!(buf, "[{}] {}", record.level(), record.args());
    }

    fn flush(&self) {}
}

// -------------------------------------------------------------- mock pool ---

struct MockPool {
    rx: Vec<u8>,
    rx_pos: usize,
    tx: Vec<u8>,
}

impl ErrorType for MockPool {
    type Error = embedded_io_async::ErrorKind;
}

impl Read for MockPool {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = (self.rx.len() - self.rx_pos).min(buf.len());
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

async fn poll_until_message(client: &mut Client<MockPool, RX, TX>) {
    for _ in 0..8 {
        if client.poll_message().await.unwrap().is_some() {
            return;
        }
    }
    panic!("the mock pool produced no message");
}

// ------------------------------------------------------------------- test ---

/// One test, not several: `log` allows a single logger per process, so the
/// transcript is shared and parallel tests would race on it.
#[tokio::test]
async fn credentials_never_reach_the_log() {
    log::set_boxed_logger(Box::new(CapturingLogger)).expect("no other logger is installed");
    log::set_max_level(log::LevelFilter::Trace);

    let user = format!("{CANARY_TAG}USER.{CANARY_WORKER}");

    let mut responses = Vec::new();
    for line in [
        r#"{"error":null,"id":1,"result":{"version-rolling":true,"version-rolling.mask":"1fffe000"}}"#.to_string(),
        r#"{"id":2,"error":null,"result":[[["mining.notify","1"]],"e26e1928",4]}"#.to_string(),
        r#"{"id":3,"result":true,"error":null}"#.to_string(),
        // Public-Pool echoes part of the submitted user in the error detail,
        // so the reply leaks what the request did.
        format!(r#"{{"id":4,"result":null,"error":[20,"Stale share",", {user}"]}}"#),
    ] {
        responses.extend_from_slice(line.as_bytes());
        responses.push(b'\n');
    }

    let mut client: Client<_, RX, TX> = Client::new(MockPool {
        rx: responses,
        rx_pos: 0,
        tx: Vec::new(),
    });

    client
        .send_configure(Extensions {
            version_rolling: Some(VersionRolling {
                mask: Some(0x1fff_e000),
                min_bit_count: Some(2),
            }),
            minimum_difficulty: None,
            subscribe_extranonce: None,
            info: Some(Info {
                connection_url: None,
                hw_version: None,
                sw_version: None,
                hw_id: None,
            }),
        })
        .await
        .unwrap();
    poll_until_message(&mut client).await;

    client.send_connect(None).await.unwrap();
    poll_until_message(&mut client).await;

    client
        .send_authorize(
            user.as_str().try_into().unwrap(),
            CANARY_PASS.try_into().unwrap(),
        )
        .await
        .unwrap();
    poll_until_message(&mut client).await;

    // `send_submit` reuses the stored user, so the share frame carries it too.
    #[cfg(feature = "alloc")]
    let extranonce2 = alloc_vec();
    #[cfg(not(feature = "alloc"))]
    let extranonce2 = heapless::Vec::from_slice(&[0, 0, 0, 1]).unwrap();

    client
        .send_submit(Share {
            job_id: "bf".try_into().unwrap(),
            extranonce2,
            ntime: 0x504e_86ed,
            nonce: 0xb295_7c02,
            version_bits: None,
        })
        .await
        .unwrap();
    poll_until_message(&mut client).await;

    let log = captured().lock().unwrap().clone();

    assert!(
        !log.contains(CANARY_PASS),
        "the pool password was logged:\n{log}"
    );
    assert!(!log.contains(&user), "the pool user was logged:\n{log}");
    // Catch a partial leak too, in case the user is ever split across records.
    assert!(
        !log.contains(CANARY_TAG),
        "part of a credential was logged:\n{log}"
    );
    assert!(
        !log.contains(CANARY_WORKER),
        "the worker name was logged:\n{log}"
    );

    // The transcript is only meaningful if logging actually happened, and an
    // authorization failure has to stay diagnosable: method, id and byte count
    // all survive redaction.
    assert!(log.contains("Send Authorize"), "nothing was logged:\n{log}");
    assert!(log.contains("Send Submit"), "nothing was logged:\n{log}");
    assert!(
        log.contains("<redacted"),
        "secret frames should be logged as redacted, not dropped:\n{log}"
    );
    // Frames with no credential in them stay legible.
    assert!(
        log.contains("mining.subscribe"),
        "public frames should still be logged in full:\n{log}"
    );
}

#[cfg(feature = "alloc")]
fn alloc_vec() -> Vec<u8> {
    vec![0, 0, 0, 1]
}
