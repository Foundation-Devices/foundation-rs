// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read access to the work and extranonces the client holds.

mod common;

use common::{stream, MockPool};
use stratum_v1::{Client, Extensions, Message};

const TX: usize = 512;
const RX: usize = 1024;

const COINB1: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008";
const COINB2: &str = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000";

fn notify(job_id: &str, clean_jobs: bool) -> Vec<u8> {
    format!(
        r#"{{"id":null,"method":"mining.notify","params":["{job_id}","4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000","{COINB1}","{COINB2}",[],"00000002","1c2ac4af","504e86b9",{clean_jobs}]}}"#
    )
    .into_bytes()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Poll until the client reports a message.
async fn next_message(client: &mut Client<MockPool, RX, TX>) -> Message {
    for _ in 0..8 {
        if let Some(msg) = client.poll_message().await.unwrap() {
            return msg;
        }
    }
    panic!("no message after 8 polls");
}

#[tokio::test]
async fn work_and_extranonces_are_readable_and_every_notify_is_reported() {
    let first = notify("bf", false);
    let second = notify("c0", true);
    let bytes = stream(&[
        br#"{"error":null,"id":1,"result":{}}"#,
        br#"{"id":2,"error":null,"result":[[["mining.notify","e26e1928"]],"e26e1928",4]}"#,
        &first,
        &second,
    ]);
    let mut client: Client<_, RX, TX> = Client::new(MockPool::new(&bytes));

    assert_eq!(client.work(), None);
    assert_eq!(client.extranonce1(), &[] as &[u8]);
    assert_eq!(client.extranonce2_size(), 0);

    client
        .send_configure(Extensions {
            version_rolling: None,
            minimum_difficulty: None,
            subscribe_extranonce: None,
            info: None,
        })
        .await
        .unwrap();
    assert_eq!(next_message(&mut client).await, Message::Configured);
    client.send_connect(None).await.unwrap();
    assert_eq!(next_message(&mut client).await, Message::Connected);

    assert_eq!(client.extranonce1(), &[0xe2, 0x6e, 0x19, 0x28]);
    assert_eq!(client.extranonce2_size(), 4);
    assert_eq!(client.work(), None);

    // A notify without clean_jobs is reported too.
    assert_eq!(
        next_message(&mut client).await,
        Message::Work { clean_jobs: false }
    );
    let work = client.work().unwrap();
    assert_eq!(work.job_id.as_str(), "bf");
    assert_eq!(work.coinb1.as_slice(), unhex(COINB1));
    assert_eq!(work.coinb2.as_slice(), unhex(COINB2));

    assert_eq!(
        next_message(&mut client).await,
        Message::Work { clean_jobs: true }
    );
    assert_eq!(client.work().unwrap().job_id.as_str(), "c0");
}
