// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

mod job;
mod notification;
mod request;
mod response;

use crate::{Error, Result};
pub use job::Job;
use job::JobCreator;
use notification::Notification;
use request::ReqKind;
pub use request::{Extensions, Info, Share, VersionRolling};
use response::Subscription;

use embedded_io_async::{Read, ReadReady, Write};
use heapless::{FnvIndexMap, String, Vec};

#[derive(Debug)]
// #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Client<C: Read + ReadReady + Write, const RX_BUF_SIZE: usize, const TX_BUF_SIZE: usize> {
    network_conn: C,
    rx_buf: [u8; RX_BUF_SIZE],
    rx_free_pos: usize,
    tx_buf: [u8; TX_BUF_SIZE],
    reqs: FnvIndexMap<u64, ReqKind, 16>,
    job_creator: JobCreator,
    configuration: Option<Extensions>,
    subscriptions: Vec<Subscription, 2>,
    shares_accepted: u64,
    shares_rejected: u64,
    req_id: u64,
    connected: bool,
    authorized: bool,
    user: String<64>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub enum Message {
    Configured,
    Connected,
    Authorized,
    Share { accepted: u64, rejected: u64 },
    VersionMask(u32),
    Difficulty(f64),
    CleanJobs,
}

impl<C: Read + ReadReady + Write, const RX_BUF_SIZE: usize, const TX_BUF_SIZE: usize>
    Client<C, RX_BUF_SIZE, TX_BUF_SIZE>
{
    pub fn new(network_conn: C) -> Client<C, RX_BUF_SIZE, TX_BUF_SIZE> {
        Client {
            network_conn,
            rx_buf: [0; RX_BUF_SIZE],
            rx_free_pos: 0,
            tx_buf: [0; TX_BUF_SIZE],
            reqs: FnvIndexMap::new(),
            job_creator: JobCreator::default(),
            configuration: None,
            subscriptions: Vec::new(),
            shares_accepted: 0,
            shares_rejected: 0,
            req_id: 0,
            connected: false,
            authorized: false,
            user: String::new(),
        }
    }
}

impl<C: Read + ReadReady + Write, const RX_BUF_SIZE: usize, const TX_BUF_SIZE: usize>
    Client<C, RX_BUF_SIZE, TX_BUF_SIZE>
{
    pub fn enable_software_rolling(&mut self, version: bool, extranonce2: bool, ntime: bool) {
        self.job_creator.version_rolling = version;
        self.job_creator.extranonce2_rolling = extranonce2;
        self.job_creator.ntime_rolling = ntime;
        debug!(
            "Software Rolling Enabled : version: {}, extranonce2: {}, ntime: {}",
            version, extranonce2, ntime
        );
    }

    pub async fn roll_job(&mut self) -> Result<Job> {
        self.job_creator.roll()
    }

    pub async fn poll_message(&mut self) -> Result<Option<Message>> {
        let mut msg = None;
        let mut start = 0;

        while let Some(mut stop) = self.rx_buf[start..self.rx_free_pos]
            .iter()
            .position(|&c| c == b'\n')
        {
            stop += start;
            trace!("Buffer start: {:?}", &self.rx_buf[..start]);
            trace!("Current : {:?}", &self.rx_buf[start..stop]);
            trace!("Buffer end: {:?}", &self.rx_buf[stop..]);
            let line = &self.rx_buf[start..stop];
            trace!("Start: {}, Stop: {}", start, stop);
            debug!(
                "Received Message [{}..{}], free pos: {}",
                start, stop, self.rx_free_pos
            );
            trace!("{:?}", line);
            trace!("Self.reqs: {:?}", self.reqs);
            if let Some(id) = response::parse_id(line)? {
                // it's a Response
                match self.reqs.get(&id) {
                    Some(ReqKind::Configure) => {
                        self.configuration = Some(response::parse_configure(line)?);
                        self.reqs.remove(&id);
                        info!("Stratum v1 Client Configured");
                        msg = Some(Message::Configured);
                    }
                    Some(ReqKind::Connect) => {
                        let conn = response::parse_connect(line)?;
                        self.subscriptions = conn.subscriptions;
                        self.job_creator
                            .set_extranonces(conn.extranonce1, conn.extranonce2_size)?;
                        self.connected = true;
                        self.reqs.remove(&id);
                        info!("Stratum v1 Client Connected");
                        msg = Some(Message::Connected);
                    }
                    Some(ReqKind::Authorize) => {
                        if response::parse_authorize(line)? {
                            self.authorized = true;
                            self.reqs.remove(&id);
                            info!("Stratum v1 Client Authorized");
                            msg = Some(Message::Authorized);
                        }
                    }
                    Some(ReqKind::SuggestDifficulty) => {
                        self.reqs.remove(&id);
                        info!("Suggested Difficulty Accepted");
                    }
                    Some(ReqKind::Submit) => {
                        match response::parse_submit(line) {
                            Ok(_) => {
                                self.shares_accepted += 1;
                                info!(
                                    "Share #{} Accepted, count: {}/{}",
                                    id, self.shares_accepted, self.shares_rejected
                                );
                            }
                            Err(Error::Pool {
                                code: c, // TODO: use this code to differentiate why share has been rejected
                                message: _,
                                detail: _,
                            }) => {
                                self.shares_rejected += 1;
                                info!(
                                    "Share #{} Rejected, count: {}/{}, code: {}",
                                    id, self.shares_accepted, self.shares_rejected, c
                                );
                            }
                            Err(e) => return Err(e),
                        }
                        self.reqs.remove(&id);
                        msg = Some(Message::Share {
                            accepted: self.shares_accepted,
                            rejected: self.shares_rejected,
                        });
                    }
                    None => return Err(Error::IdNotFound(id)),
                }
            } else {
                // it's a Notification
                match notification::parse_method(line)? {
                    Notification::SetVersionMask => {
                        let mask = notification::parse_set_version_mask(line)?;
                        self.job_creator.set_version_mask(mask);
                        msg = Some(Message::VersionMask(mask));
                        info!("Set Version Mask: 0x{:x}", mask);
                    }
                    Notification::SetDifficulty => {
                        let diff = notification::parse_set_difficulty(line)?;
                        msg = Some(Message::Difficulty(diff));
                        info!("Set Difficulty: {}", diff);
                    }
                    Notification::Notify => {
                        let work = notification::parse_notify(line)?;
                        if work.clean_jobs {
                            msg = Some(Message::CleanJobs);
                        }
                        info!("New Work: {:?}", work);
                        self.job_creator.set_work(work)?;
                    }
                }
            }
            start = stop + 1;
            if msg.is_some() {
                break;
            }
        }
        trace!("start: {}, free pos: {}", start, self.rx_free_pos);
        if start > 0 && self.rx_free_pos > start {
            debug!("copy {} bytes @0", self.rx_free_pos - start);
            self.rx_buf.copy_within(start..self.rx_free_pos, 0);
            self.rx_free_pos -= start;
        } else if start == self.rx_free_pos {
            self.rx_free_pos = 0;
        }
        if self.network_conn.read_ready().map_err(|_| Error::Network)? {
            let n = self
                .network_conn
                .read(self.rx_buf[self.rx_free_pos..].as_mut())
                .await
                .map_err(|_| Error::Network)?;
            debug!("read {} bytes @{}", n, self.rx_free_pos);
            trace!(
                "read content {:?}",
                &self.rx_buf[self.rx_free_pos..self.rx_free_pos + n]
            );
            trace!(
                "read content as string {:?}",
                core::str::from_utf8(&self.rx_buf[self.rx_free_pos..self.rx_free_pos + n])
            );
            self.rx_free_pos += n;
        }
        Ok(msg)
    }

    fn prepare_req(&mut self, req_kind: ReqKind) -> Result<()> {
        self.req_id += 1;
        self.reqs
            .insert(self.req_id, req_kind)
            .map_err(|_| Error::MapFull)?;
        Ok(())
    }

    async fn send_req(&mut self, req_len: usize) -> Result<()> {
        self.tx_buf[req_len] = 0x0a;
        trace!("{:?}", &self.tx_buf[..req_len + 1]);
        self.network_conn
            .write_all(&self.tx_buf[..req_len + 1])
            .await
            .map_err(|_| Error::Network)
    }

    /// # Configure Client
    ///
    /// ## Parameters
    ///
    /// exts: a list of extensions to configure.
    ///
    pub async fn send_configure(&mut self, exts: Extensions) -> Result<()> {
        if self.configuration.is_some() {
            return Err(Error::AlreadyConfigured);
        }
        self.prepare_req(ReqKind::Configure)?;
        let n = request::configure(self.req_id, exts, self.tx_buf.as_mut_slice())?;
        debug!("Send Configure: {} bytes, id = {}", n, self.req_id);
        self.send_req(n).await
    }
    pub async fn send_suggest_difficulty(&mut self, difficulty: u32) -> Result<()> {
        if self.configuration.is_none() {
            return Err(Error::NotConfigured);
        }
        self.prepare_req(ReqKind::SuggestDifficulty)?;
        let n = request::suggest_difficulty(self.req_id, difficulty, self.tx_buf.as_mut_slice())?;
        debug!("Send Suggest Difficulty: {} bytes, id = {}", n, self.req_id);
        self.send_req(n).await
    }

    /// # Connect Client
    ///
    /// ## Parameters
    ///
    /// identifier: a string to identify the client to the pool.
    ///
    pub async fn send_connect(&mut self, identifier: Option<String<32>>) -> Result<()> {
        if self.configuration.is_none() {
            return Err(Error::NotConfigured);
        }
        if self.connected {
            return Err(Error::AlreadyConnected);
        }
        self.prepare_req(ReqKind::Connect)?;
        let n = request::connect(self.req_id, identifier, self.tx_buf.as_mut_slice())?;
        debug!("Send Connect: {} bytes, id = {}", n, self.req_id);
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
        if !self.connected {
            return Err(Error::NotConnected);
        }
        if self.authorized {
            return Err(Error::AlreadyAuthorized);
        }
        self.prepare_req(ReqKind::Authorize)?;
        self.user = user.clone();
        let n = request::authorize(self.req_id, user, pass, self.tx_buf.as_mut_slice())?;
        debug!("Send Authorize: {} bytes, id = {}", n, self.req_id);
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
    pub async fn send_submit(&mut self, share: Share) -> Result<()> {
        if !self.authorized {
            return Err(Error::Unauthorized);
        }
        self.prepare_req(ReqKind::Submit)?;
        let n = request::submit(
            self.req_id,
            self.user.clone(),
            share,
            self.tx_buf.as_mut_slice(),
        )?;
        debug!("Send Submit: {} bytes, id = {}", n, self.req_id);
        self.send_req(n).await
    }
}
