// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// #![allow(static_mut_refs)]

use stratum_v1::{Client, Extensions, Message, Share, VersionRolling};

use heapless::{String, Vec};
use inquire::Select;
use log::error;
use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{watch, Mutex},
};
/*
+------------------------+-------+-----------------------------------+---------------------------------------------------------------+
| Pool URL               | Port  | Web URL                           | Status                                                        |
+------------------------+-------+-----------------------------------+---------------------------------------------------------------+
| public-pool.io         | 21496 | https://web.public-pool.io        | Open Source Solo Bitcoin Mining Pool supporting open source   |
|                        |       |                                   | miners                                                        |
+------------------------+-------+-----------------------------------+---------------------------------------------------------------+
| pool.nerdminers.org    | 3333  | https://nerdminers.org            | The official Nerdminer pool site - Maintained by @golden-guy  |
+------------------------+-------+-----------------------------------+---------------------------------------------------------------+
| pool.nerdminer.io      | 3333  | https://nerdminer.io              | Maintained by CHMEX                                           |
+------------------------+-------+-----------------------------------+---------------------------------------------------------------+
| pool.pyblock.xyz       | 3333  | https://pool.pyblock.xyz/         | Maintained by curly60e                                        |
+------------------------+-------+-----------------------------------+---------------------------------------------------------------+
| pool.sethforprivacy.com| 3333  | https://pool.sethforprivacy.com/  | Maintained by @sethforprivacy - public-pool fork              |
+------------------------+-------+-----------------------------------+---------------------------------------------------------------+
*/
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let pool = Select::new(
        "Which Pool should be used?",
        vec![
            "Public-Pool",
            "NerdMiners.org",
            "NerdMiner.io",
            "PyBlock",
            "SethForPrivacy",
        ],
    )
    .prompt()?;

    let addr = match pool {
        // public-pool.io = 172.234.17.37:21496
        "Public-Pool" => SocketAddr::new(Ipv4Addr::new(172, 234, 17, 37).into(), 21496),
        // pool.nerdminers.org = 144.91.83.152:3333
        "NerdMiners.org" => SocketAddr::new(Ipv4Addr::new(144, 91, 83, 152).into(), 3333),
        // pool.nerdminer.io = 88.99.209.94:3333
        "NerdMiner.io" => SocketAddr::new(Ipv4Addr::new(88, 99, 209, 94).into(), 3333),
        // pool.pyblock.xyz = 172.81.181.23:3333
        "PyBlock" => SocketAddr::new(Ipv4Addr::new(172, 81, 181, 23).into(), 3333),
        // pool.sethforprivacy.com = 23.137.57.100:3333
        "SethForPrivacy" => SocketAddr::new(Ipv4Addr::new(23, 137, 57, 100).into(), 3333),
        _ => unreachable!(),
    };
    println!("Connecting to {}", addr);
    let stream = TcpStream::connect(addr).await?;

    println!("Connected");
    let conn = adapter::FromTokio::<TcpStream>::new(stream);

    let mut client = Client::<_, 1480, 512>::new(conn);
    client.enable_software_rolling(true, false, false);
    println!("Enabled software rolling");
    let client_tx = Arc::new(Mutex::new(client));
    let client_rx = Arc::clone(&client_tx);

    let (authorized_tx, mut authorized_rx) = watch::channel(false);

    tokio::spawn(async move {
        loop {
            println!("Waiting for message");
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut c = client_rx.lock().await;
            match c.poll_message().await {
                Ok(msg) => match msg {
                    Some(Message::Configured) => {
                        println!("Configured start connecting");
                        // c.send_connect(None).await.unwrap();
                        c.send_connect(Some(String::<32>::from_str("esp-miner-rs").unwrap()))
                            .await
                            .unwrap();
                    }
                    Some(Message::Connected) => {
                        println!("Connected start authorizing");
                        c.send_authorize(
                            match pool {
                                "Public-Pool" => String::<64>::from_str(
                                    "bc1qgaq3nk8yvd8294n6t27j8zwjcft9rm448f9tet",
                                )
                                .unwrap(),
                                "pool.nerdminers.org" => String::<64>::from_str(
                                    "bc1qgaq3nk8yvd8294n6t27j8zwjcft9rm448f9tet",
                                )
                                .unwrap(),
                                "Braiins" => String::<64>::from_str("slush.miner1").unwrap(),
                                _ => unreachable!(),
                            },
                            String::<64>::from_str("x").unwrap(),
                        )
                        .await
                        .unwrap();
                    }
                    Some(Message::Authorized) => {
                        println!("Authorized");
                        authorized_tx.send(true).unwrap();
                    }
                    Some(
                        a @ Message::Share {
                            accepted: _,
                            rejected: _,
                        },
                    ) => {
                        println!("Share: {:?}", a);
                        // TODO update the display if any
                    }
                    Some(Message::VersionMask(_mask)) => {
                        // TODO use mask for hardware version rolling is available
                    }
                    Some(Message::Difficulty(_diff)) => {
                        // TODO use diff to filter ASIC reported hits
                    }
                    Some(Message::CleanJobs) => {
                        // TODO clean the job queue and immediately start hashing a new job
                    }
                    None => {
                        println!("No message");
                    }
                },
                Err(e) => {
                    error!("Client receive_message error: {:?}", e);
                    panic!("Client receive_message error: {:?}", e);
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;
    {
        let mut c = client_tx.lock().await;
        let exts = Extensions {
            version_rolling: Some(VersionRolling {
                mask: Some(0x1fffe000),
                min_bit_count: Some(16),
            }),
            minimum_difficulty: Some(256),
            subscribe_extranonce: None,
            info: None,
        };
        c.send_configure(exts).await.unwrap();
    }
    println!("Waiting for authorization");
    authorized_rx.changed().await.unwrap();
    println!("Authorized 1");
    loop {
        // TODO: use client.roll_job() to get a new job at the rate the hardware need it
        tokio::time::sleep(Duration::from_millis(5000)).await;
        {
            let mut c = client_tx.lock().await;
            let mut extranonce2 = Vec::new();
            extranonce2.resize(4, 0).unwrap();
            extranonce2[3] = 0x01;
            let fake_share = Share {
                job_id: String::<64>::from_str("01").unwrap(), // TODO will come from the Job
                extranonce2,                                   // TODO will come from the Job
                ntime: 1722789905,                             // TODO will come from the Job
                nonce: 0,                                      // TODO will come from the ASIC hit
                version_bits: None, // TODO will come from the ASIC hit if hardware version rolling is enabled
            };
            c.send_submit(fake_share).await.unwrap();
        }
    }
}

trait Readable {
    fn poll_read_ready(
        &self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>>;
}

impl Readable for TcpStream {
    fn poll_read_ready(
        &self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        self.poll_read_ready(cx)
    }
}

mod adapter {
    use core::future::poll_fn;
    use core::pin::Pin;
    use core::task::Poll;

    /// Adapter from `tokio::io` traits.
    #[derive(Clone)]
    pub struct FromTokio<T: ?Sized> {
        inner: T,
    }

    impl<T> FromTokio<T> {
        /// Create a new adapter.
        pub fn new(inner: T) -> Self {
            Self { inner }
        }

        // /// Consume the adapter, returning the inner object.
        // pub fn into_inner(self) -> T {
        //     self.inner
        // }
    }

    // impl<T: ?Sized> FromTokio<T> {
    //     /// Borrow the inner object.
    //     pub fn inner(&self) -> &T {
    //         &self.inner
    //     }

    //     /// Mutably borrow the inner object.
    //     pub fn inner_mut(&mut self) -> &mut T {
    //         &mut self.inner
    //     }
    // }

    impl<T: ?Sized> embedded_io::ErrorType for FromTokio<T> {
        type Error = std::io::Error;
    }

    impl<T: tokio::io::AsyncRead + Unpin + ?Sized> embedded_io_async::Read for FromTokio<T> {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            // The current tokio implementation (https://github.com/tokio-rs/tokio/blob/tokio-1.33.0/tokio/src/io/poll_evented.rs#L165)
            // does not consider the case of buf.is_empty() as a special case,
            // which can cause Poll::Pending to be returned at the end of the stream when called with an empty buffer.
            // This poll will, however, never become ready, as no more bytes will be received.
            if buf.is_empty() {
                return Ok(0);
            }

            poll_fn(|cx| {
                let mut buf = tokio::io::ReadBuf::new(buf);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                    Poll::Ready(r) => match r {
                        Ok(()) => Poll::Ready(Ok(buf.filled().len())),
                        Err(e) => Poll::Ready(Err(e)),
                    },
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
        }
    }

    impl<T: super::Readable + Unpin + ?Sized> embedded_io_async::ReadReady for FromTokio<T> {
        fn read_ready(&mut self) -> Result<bool, Self::Error> {
            let h = tokio::runtime::Handle::current();

            tokio::task::block_in_place(|| {
                h.block_on(poll_fn(|cx| {
                    match Pin::new(&mut self.inner).poll_read_ready(cx) {
                        Poll::Ready(_) => Poll::Ready(Ok(true)),
                        Poll::Pending => Poll::Ready(Ok(false)),
                    }
                }))
            })
        }
    }

    impl<T: tokio::io::AsyncWrite + Unpin + ?Sized> embedded_io_async::Write for FromTokio<T> {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            match poll_fn(|cx| Pin::new(&mut self.inner).poll_write(cx, buf)).await {
                Ok(0) if !buf.is_empty() => Err(std::io::ErrorKind::WriteZero.into()),
                Ok(n) => Ok(n),
                Err(e) => Err(e),
            }
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            poll_fn(|cx| Pin::new(&mut self.inner).poll_flush(cx)).await
        }
    }
}
