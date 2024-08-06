// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

mod job;
mod notification;
mod request;
mod response;

use crate::{Error, Result};
use job::{Job, JobCreator};
pub use notification::{Notification, Work};
pub use request::{Extensions, Info, Share, VersionRolling};
use request::{ReqIdKind, ReqKind};
use response::Subscription;

use embedded_io_async::{Read, Write};
use heapless::{
    spsc::{Consumer, Producer, Queue},
    FnvIndexMap, HistoryBuffer, String, Vec,
};

#[derive(Debug)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Client<R: Read, W: Write, const RX_BUF_SIZE: usize, const TX_BUF_SIZE: usize> {
    phantom_read: core::marker::PhantomData<R>,
    phantom_write: core::marker::PhantomData<W>,
}

// #[derive(Debug)]
// #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct ClientRx<R: Read, const BUF_SIZE: usize> {
    network_reader: R,
    buf: [u8; BUF_SIZE],
    pos: usize,
    reqs: FnvIndexMap<u64, ReqKind, 16>,
    job_creator: JobCreator,
    jobs: HistoryBuffer<Job, 16>,
    configuration: Option<Extensions>,
    subscriptions: Vec<Subscription, 2>,
    shares_accepted: u64,
    shares_rejected: u64,
    req_queue_cons: Consumer<'static, ReqIdKind, 32>,
    state_queue_prod: Producer<'static, ReqKind, 2>,
    vers_mask_queue_prod: Producer<'static, u32, 2>,
    diff_queue_prod: Producer<'static, f64, 2>,
    work_queue_prod: Producer<'static, Work, 2>,
}

// #[derive(Debug, PartialEq)]
// #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct ClientTx<W: Write, const BUF_SIZE: usize> {
    network_writer: W,
    buf: [u8; BUF_SIZE],
    req_id: u64,
    configured: bool,
    connected: bool,
    authorized: bool,
    pool_target_difficulty: f64,
    user: String<64>,
    req_queue_prod: Producer<'static, ReqIdKind, 32>,
    state_queue_cons: Consumer<'static, ReqKind, 2>,
    diff_queue_cons: Consumer<'static, f64, 2>,
}

impl<R: Read, W: Write, const RX_BUF_SIZE: usize, const TX_BUF_SIZE: usize>
    Client<R, W, RX_BUF_SIZE, TX_BUF_SIZE>
{
    pub fn new_rx_tx(
        network_reader: R,
        network_writer: W,
        vers_mask_queue_prod: Producer<'static, u32, 2>,
        work_queue_prod: Producer<'static, Work, 2>, // TODO: transform into local Job queue consumed by ClientTx
    ) -> (ClientRx<R, RX_BUF_SIZE>, ClientTx<W, TX_BUF_SIZE>) {
        let req_queue: &'static mut Queue<ReqIdKind, 32> = {
            static mut Q: Queue<ReqIdKind, 32> = Queue::new();
            unsafe { &mut Q }
        };
        let (req_queue_prod, req_queue_cons) = req_queue.split();
        let state_queue: &'static mut Queue<ReqKind, 2> = {
            static mut Q: Queue<ReqKind, 2> = Queue::new();
            unsafe { &mut Q }
        };
        let (state_queue_prod, state_queue_cons) = state_queue.split();
        let diff_queue: &'static mut Queue<f64, 2> = {
            static mut Q: Queue<f64, 2> = Queue::new();
            unsafe { &mut Q }
        };
        let (diff_queue_prod, diff_queue_cons) = diff_queue.split();
        (
            ClientRx {
                network_reader,
                buf: [0; RX_BUF_SIZE],
                pos: 0,
                reqs: FnvIndexMap::new(),
                job_creator: JobCreator::default(),
                jobs: HistoryBuffer::new(),
                configuration: None,
                subscriptions: Vec::new(),
                shares_accepted: 0,
                shares_rejected: 0,
                req_queue_cons,
                state_queue_prod,
                vers_mask_queue_prod,
                diff_queue_prod,
                work_queue_prod,
            },
            ClientTx {
                network_writer,
                buf: [0; TX_BUF_SIZE],
                req_id: 0,
                configured: false,
                connected: false,
                authorized: false,
                pool_target_difficulty: 0.0,
                user: String::new(),
                req_queue_prod,
                state_queue_cons,
                diff_queue_cons,
            },
        )
    }
}

impl<R: Read, const RX_BUF_SIZE: usize> ClientRx<R, RX_BUF_SIZE> {
    pub fn software_rolling(&mut self, version: bool, extranonce2: bool) {
        self.job_creator.version_rolling = version;
        self.job_creator.extranonce2_rolling = extranonce2;
    }

    pub async fn run(&mut self) -> Result<()> {
        while let Some(req) = self.req_queue_cons.dequeue() {
            debug!("ClientRx::run dequeue: {:?}", req.clone());
            self.reqs.insert(req.0, req.1).map_err(|_| Error::MapFull)?;
        }
        // TODO: maybe add some garbage collection here to remove old reqs never responded by Pool
        while let Some(i) = self.buf[..self.pos].iter().position(|&c| c == b'\n') {
            let line = &self.buf[..i];
            debug!(
                "pos: {}; i: {}; line: {:?}",
                self.pos,
                i,
                core::str::from_utf8(line)
            );
            if let Some(id) = response::parse_id(line)? {
                // it's a Response
                match self.reqs.get(&id) {
                    Some(ReqKind::Configure) => {
                        self.configuration = Some(response::parse_configure(line)?);
                        self.state_queue_prod
                            .enqueue(ReqKind::Configure)
                            .map_err(|_| Error::QueueFull)?;
                        self.reqs.remove(&id);
                        debug!("enqueue: {:?}, reqs: {:?}", ReqKind::Configure, self.reqs);
                    }
                    Some(ReqKind::Connect) => {
                        let conn = response::parse_connect(line)?;
                        self.subscriptions = conn.subscriptions;
                        self.job_creator
                            .set_extranonces(conn.extranonce1, conn.extranonce2_size)?;
                        self.state_queue_prod
                            .enqueue(ReqKind::Connect)
                            .map_err(|_| Error::QueueFull)?;
                        self.reqs.remove(&id);
                        debug!("enqueue: {:?}, reqs: {:?}", ReqKind::Connect, self.reqs);
                    }
                    Some(ReqKind::Authorize) => {
                        if response::parse_authorize(line)? {
                            self.state_queue_prod
                                .enqueue(ReqKind::Authorize)
                                .map_err(|_| Error::QueueFull)?;
                            self.reqs.remove(&id);
                            debug!("enqueue: {:?}, reqs: {:?}", ReqKind::Authorize, self.reqs);
                        }
                    }
                    Some(ReqKind::Submit) => {
                        match response::parse_submit(line) {
                            Ok(_) => self.shares_accepted += 1,
                            Err(Error::Pool {
                                code: _c, // TODO: use this code to differentiate why share has been rejected
                                message: _,
                                detail: _,
                            }) => self.shares_rejected += 1,
                            Err(e) => return Err(e),
                        }
                        self.reqs.remove(&id);
                        debug!("rx sumbit response, reqs: {:?}", self.reqs);
                    }
                    None => return Err(Error::IdNotFound(id)),
                }
            } else {
                // it's a Notification
                match notification::parse_method(line)? {
                    Notification::SetVersionMask => {
                        let mask = notification::parse_set_version_mask(line)?;
                        self.job_creator.set_version_mask(mask);
                        self.vers_mask_queue_prod
                            .enqueue(mask)
                            .map_err(|_| Error::QueueFull)?;
                    }
                    Notification::SetDifficulty => {
                        self.diff_queue_prod
                            .enqueue(notification::parse_set_difficulty(line)?)
                            .map_err(|_| Error::QueueFull)?;
                    }
                    Notification::Notify => {
                        let work = notification::parse_notify(line)?;
                        self.jobs.clear();
                        // while !self.jobs.is_full() {
                        self.jobs.write(self.job_creator.roll(&work)?);
                        // }
                        // if work.clean_jobs {
                        //     todo!("inform app to immediately change job")
                        // }
                        self.work_queue_prod
                            .enqueue(work)
                            .map_err(|_| Error::QueueFull)?;
                    }
                }
            }
            if self.pos > i + 1 {
                self.buf.copy_within(i + 1..self.pos, 0);
            }
            self.pos -= i + 1;
        }
        let n = self
            .network_reader
            .read(self.buf[self.pos..].as_mut())
            .await
            .map_err(|_| Error::NetworkError)?;
        trace!(
            "read {} bytes, pos {}: {:?}",
            n,
            self.pos,
            core::str::from_utf8(&self.buf[self.pos..self.pos + n])
        );
        self.pos += n;
        Ok(())
    }
}

impl<T: Write, const TX_BUF_SIZE: usize> ClientTx<T, TX_BUF_SIZE> {
    fn check_queues(&mut self) {
        if let Some(state) = self.state_queue_cons.dequeue() {
            debug!("dequeue req: {:?}", state);
            match state {
                ReqKind::Configure => self.configured = true,
                ReqKind::Connect => self.connected = true,
                ReqKind::Authorize => self.authorized = true,
                _ => unreachable!("unknown state: {:?}", state),
            }
        }
        if let Some(diff) = self.diff_queue_cons.dequeue() {
            debug!("dequeue diff: {:?}", diff);
            self.pool_target_difficulty = diff;
        }
    }

    fn prepare_req(&mut self, req_kind: ReqKind) -> Result<()> {
        self.req_id += 1;
        let req_id_kind = ReqIdKind(self.req_id, req_kind);
        self.req_queue_prod
            .enqueue(req_id_kind.clone())
            .map_err(|_| Error::QueueFull)?;
        debug!("enqueue: {:?}", req_id_kind);
        Ok(())
    }

    async fn send_req(&mut self, req_len: usize) -> Result<()> {
        self.buf[req_len] = 0x0a;
        self.network_writer
            .write_all(&self.buf[..req_len + 1])
            .await
            .map_err(|_| Error::NetworkError)
    }

    /// # Configure Client
    ///
    /// ## Parameters
    ///
    /// exts: a list of extensions to configure.
    ///
    pub async fn send_configure(&mut self, exts: Extensions) -> Result<()> {
        self.check_queues();
        if self.configured {
            return Err(Error::AlreadyConfigured);
        }
        self.prepare_req(ReqKind::Configure)?;
        let n = request::configure(self.req_id, exts, self.buf.as_mut_slice())?;
        self.send_req(n).await
    }

    /// # Connect Client
    ///
    /// ## Parameters
    ///
    /// identifier: a string to identify the client to the pool.
    ///
    pub async fn send_connect(&mut self, identifier: Option<String<32>>) -> Result<()> {
        self.check_queues();
        if !self.configured {
            return Err(Error::NotConfigured);
        }
        if self.connected {
            return Err(Error::AlreadyConnected);
        }
        self.prepare_req(ReqKind::Connect)?;
        let n = request::connect(self.req_id, identifier, self.buf.as_mut_slice())?;
        self.send_req(n).await
    }

    /// # Authorize Client
    ///
    /// ## Parameters
    ///
    /// user: a string with user name.
    ///       Usually composed by "<UserName>.<WorkerName>".
    ///
    /// pass: a string with user password.
    ///
    pub async fn send_authorize(&mut self, user: String<64>, pass: String<64>) -> Result<()> {
        self.check_queues();
        if !self.connected {
            return Err(Error::NotConnected);
        }
        if self.authorized {
            return Err(Error::AlreadyAuthorized);
        }
        self.prepare_req(ReqKind::Authorize)?;
        self.user = user.clone();
        let n = request::authorize(self.req_id, user, pass, self.buf.as_mut_slice())?;
        self.send_req(n).await
    }

    /// # Submit a Share
    ///
    /// ## Parameters
    ///
    /// job_id: a string with the Job ID given in the Mining Job Notification.
    ///
    /// extranonce2: a slice of 8-bits unsigned integer with the share's Extranonce2.
    ///
    /// ntime: a 32-bits unsigned integer with the share's nTime.
    ///
    /// nonce: a 32-bits unsigned integer with the share's nOnce.
    ///
    /// version_bits: an optional 32-bits unsigned integer with the share's version_bits.
    ///
    pub async fn send_submit(&mut self, share: Share, diff: f64) -> Result<()> {
        self.check_queues();
        if !self.authorized {
            return Err(Error::Unauthorized);
        }
        if diff < self.pool_target_difficulty {
            return Err(Error::LowDifficulty {
                share_diff: diff,
                pool_diff: self.pool_target_difficulty,
            });
        }
        self.prepare_req(ReqKind::Submit)?;
        let n = request::submit(
            self.req_id,
            self.user.clone(),
            share,
            self.buf.as_mut_slice(),
        )?;
        self.send_req(n).await
    }
}
