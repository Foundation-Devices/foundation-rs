<!--
SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# stratum-v1

A `no_std` [Stratum v1] mining client. It builds the requests, parses the
pool's responses and notifications, and turns the work it receives into block
headers ready to hash.

The client is transport-agnostic: it drives anything that implements
[`embedded-io-async`]'s `Read`, `ReadReady` and `Write`, such as an
`embassy-net` TCP socket. It allocates nothing by default.

[Stratum v1]: https://en.bitcoin.it/wiki/Stratum_mining_protocol
[`embedded-io-async`]: https://crates.io/crates/embedded-io-async

## What it does

- Session setup: `mining.configure` (version rolling, minimum difficulty,
  extranonce subscription, info), `mining.subscribe`, `mining.authorize` and,
  optionally, `mining.suggest_difficulty`.
- Notifications: `mining.notify`, `mining.set_difficulty` and
  `mining.set_version_mask`.
- Job creation: `Client::roll_job` builds a `Job` (a block header plus the
  extranonce2 it used) from the current work, rolling the version, the
  extranonce2 and the ntime in software as enabled.
- Share submission with `mining.submit`, and a running count of accepted and
  rejected shares.
- Read access to the current work (`Client::work`) and to the extranonces
  (`Client::extranonce1`, `Client::extranonce2_size`), for example to decode
  the block height from the coinbase.

## Usage

`Client` takes the transport and two buffer sizes, for receiving and for
sending. A frame from the pool has to fit in the receive buffer.

```rust,ignore
use stratum_v1::{Client, Error, Extensions, Message, VersionRolling};

// `conn` implements embedded_io_async::{Read, ReadReady, Write}.
let mut client = Client::<_, 1480, 512>::new(conn);
client.enable_software_rolling(true, false, false);

client
    .send_configure(Extensions {
        version_rolling: Some(VersionRolling {
            mask: Some(0x1fff_e000),
            min_bit_count: Some(10),
        }),
        minimum_difficulty: None,
        subscribe_extranonce: None,
        info: None,
    })
    .await?;

loop {
    match client.poll_message().await {
        Ok(Some(Message::Configured)) => client.send_connect(None).await?,
        Ok(Some(Message::Connected)) => {
            client
                .send_authorize("user.worker".try_into().unwrap(), "x".try_into().unwrap())
                .await?
        }
        Ok(Some(Message::Authorized)) => { /* ready to submit shares */ }
        Ok(Some(Message::Work { clean_jobs })) => {
            // On `clean_jobs`, drop the jobs built from earlier work.
            let job = client.roll_job().await?;
            // Hash `job.header`, then `client.send_submit(..)` what is found.
        }
        Ok(Some(Message::Difficulty(_diff))) => { /* new share target */ }
        Ok(Some(Message::VersionMask(_mask))) => { /* bits the miner may roll */ }
        Ok(Some(Message::Share { accepted, rejected })) => { /* update the counters */ }
        // Nothing complete was buffered yet.
        Ok(None) => { /* wait a little before polling again */ }
        // The transport failed or the pool closed the connection.
        Err(Error::Network) => break,
        // A bad frame: it was dropped and the session carries on.
        Err(_e) => {}
    }
}
```

`poll_message` returns at most one message per call and does not wait for
data: when the transport has nothing ready it returns `Ok(None)` straight
away, so the caller sets the polling pace.

[`examples/tokio-cli.rs`](examples/tokio-cli.rs) is a complete client that
runs against public pools:

```sh
cargo run -p stratum-v1 --example stratum-v1-cli
```

## Untrusted input

The pool is not trusted. Arbitrary bytes from the peer produce an `Error`,
never a panic, in both the `heapless` and the `alloc` builds:

- every length that is used to slice or resize a buffer is validated first
  (see the `limits` module);
- a frame that fails to parse is consumed before its error is returned, so it
  cannot block the frames behind it, and the session state is left untouched;
- a frame longer than the receive buffer is dropped with `Error::LineTooLong`
  and the client resynchronizes on the next line;
- frames that carry the pool credentials are never logged in full.

The client is fuzzed; see [`fuzz/`](fuzz).

## Cargo features

| Feature | Effect |
| --- | --- |
| *(none)* | `heapless` strings and vectors with fixed capacities, no allocator needed. |
| `alloc` | `alloc::string::String` and `alloc::vec::Vec` in place of the `heapless` types. |
| `defmt-03` | Logging and `defmt::Format` implementations through [`defmt`]. |
| `log` | Logging through [`log`]. Cannot be combined with `defmt-03`. |
| `suggest-difficulty-notification` | `Client::send_suggest_difficulty`, sent as a notification. |
| `suggest-difficulty-request` | The same, sent as a request. Cannot be combined with the previous one. |

The public API uses [`heapless`] 0.9 types in the default build, so a
dependent crate has to use the same version of `heapless`.

[`defmt`]: https://crates.io/crates/defmt
[`log`]: https://crates.io/crates/log
[`heapless`]: https://crates.io/crates/heapless

## Minimum Supported Rust Version (MSRV)

Rust `1.95`.

## License

`GPL-3.0-or-later AND GPL-3.0-only`, as declared in [`Cargo.toml`](Cargo.toml).
