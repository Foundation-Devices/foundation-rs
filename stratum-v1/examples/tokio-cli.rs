// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(static_mut_refs)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use heapless::{spsc::Queue, String, Vec};
use stratum_v1::{Client, Extensions, Share, VersionRolling, Work};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let addr = SocketAddr::new(Ipv4Addr::new(68, 235, 52, 36).into(), 21496); // PP

    // let addr = SocketAddr::new(Ipv4Addr::new(64, 225, 5, 77).into(), 3333); // braiins

    let stream = TcpStream::connect(addr).await?;
    let (stream_reader, stream_writer) = tokio::io::split(stream);

    let conn_reader = adapter::FromTokioRead::<ReadHalf<TcpStream>>::new(stream_reader);
    let conn_writer = adapter::FromTokioWrite::<WriteHalf<TcpStream>>::new(stream_writer);

    let vers_mask_queue: &'static mut Queue<u32, 2> = {
        static mut Q: Queue<u32, 2> = Queue::new();
        unsafe { &mut Q }
    };
    let (vers_mask_queue_prod, mut vers_mask_queue_cons) = vers_mask_queue.split();
    tokio::spawn(async move {
        loop {
            if let Some(mask) = vers_mask_queue_cons.dequeue() {
                println!("new version mask from Pool: {:x}", mask);
            }
        }
    });

    let diff_queue: &'static mut Queue<f64, 2> = {
        static mut Q: Queue<f64, 2> = Queue::new();
        unsafe { &mut Q }
    };
    let (diff_queue_prod, mut diff_queue_cons) = diff_queue.split();
    tokio::spawn(async move {
        loop {
            if let Some(diff) = diff_queue_cons.dequeue() {
                println!("new difficulty from Pool: {}", diff);
            }
        }
    });

    let work_queue: &'static mut Queue<Work, 2> = {
        static mut Q: Queue<Work, 2> = Queue::new();
        unsafe { &mut Q }
    };
    let (work_queue_prod, mut work_queue_cons) = work_queue.split();
    tokio::spawn(async move {
        loop {
            if let Some(work) = work_queue_cons.dequeue() {
                println!("new work from Pool: {:?}", work);
            }
        }
    });

    let (mut client_rx, mut client_tx) = Client::<_, _, 1480, 512>::new_rx_tx(
        conn_reader,
        conn_writer,
        vers_mask_queue_prod,
        diff_queue_prod,
        work_queue_prod,
    );

    tokio::spawn(async move {
        loop {
            if let Err(e) = client_rx.run().await {
                println!("client_rx error: {:?}", e);
            }
        }
    });

    let exts = Extensions {
        version_rolling: Some(VersionRolling {
            mask: Some(0x1fffe000),
            min_bit_count: Some(10),
        }),
        minimum_difficulty: None,
        subscribe_extranonce: None,
        info: None,
    };
    client_tx.send_configure(exts).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    client_tx
        .send_connect(Some(String::<32>::from_str("slush").unwrap()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    client_tx
        .send_authorize(
            String::<64>::from_str("1HLQGxzAQWnLore3fWHc2W8UP1CgMv1GKQ.miner1").unwrap(),
            // String::<32>::from_str("slush.miner1").unwrap(),
            String::<64>::from_str("password").unwrap(),
        )
        .await
        .unwrap();
    loop {
        tokio::time::sleep(Duration::from_millis(5000)).await;
        let mut extranonce2 = Vec::new();
        extranonce2.resize(4, 0).unwrap();
        extranonce2[3] = 0x01;
        let fake_share = Share {
            job_id: String::<64>::from_str("01").unwrap(),
            extranonce2,
            ntime: 1722789905,
            nonce: 0,
            version_bits: None,
        };
        client_tx.send_submit(fake_share).await.unwrap();
    }
}

mod adapter {
    use core::future::poll_fn;
    use core::pin::Pin;
    use core::task::Poll;

    /// Adapter from `tokio::io` traits.
    #[derive(Clone)]
    pub struct FromTokioRead<T: ?Sized> {
        inner: T,
    }

    impl<T> FromTokioRead<T> {
        /// Create a new adapter.
        pub fn new(inner: T) -> Self {
            Self { inner }
        }

        /// Consume the adapter, returning the inner object.
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    impl<T: ?Sized> FromTokioRead<T> {
        /// Borrow the inner object.
        pub fn inner(&self) -> &T {
            &self.inner
        }

        /// Mutably borrow the inner object.
        pub fn inner_mut(&mut self) -> &mut T {
            &mut self.inner
        }
    }

    impl<T: ?Sized> embedded_io::ErrorType for FromTokioRead<T> {
        type Error = std::io::Error;
    }

    impl<T: tokio::io::AsyncRead + Unpin + ?Sized> embedded_io_async::Read for FromTokioRead<T> {
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

    #[derive(Clone)]
    pub struct FromTokioWrite<T: ?Sized> {
        inner: T,
    }

    impl<T> FromTokioWrite<T> {
        /// Create a new adapter.
        pub fn new(inner: T) -> Self {
            Self { inner }
        }

        /// Consume the adapter, returning the inner object.
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    impl<T: ?Sized> FromTokioWrite<T> {
        /// Borrow the inner object.
        pub fn inner(&self) -> &T {
            &self.inner
        }

        /// Mutably borrow the inner object.
        pub fn inner_mut(&mut self) -> &mut T {
            &mut self.inner
        }
    }

    impl<T: ?Sized> embedded_io::ErrorType for FromTokioWrite<T> {
        type Error = std::io::Error;
    }

    impl<T: tokio::io::AsyncWrite + Unpin + ?Sized> embedded_io_async::Write for FromTokioWrite<T> {
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
