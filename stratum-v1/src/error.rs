// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use derive_more::From;

pub type Result<T> = core::result::Result<T, Error>;

/// Identifies the peer-supplied field a length error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub enum Field {
    /// `mining.notify` job identifier.
    JobId,
    /// `mining.notify` previous block hash.
    PrevHash,
    /// `mining.notify` first part of the coinbase transaction.
    Coinb1,
    /// `mining.notify` second part of the coinbase transaction.
    Coinb2,
    /// `mining.notify` merkle branch list.
    MerkleBranch,
    /// `mining.subscribe` response extranonce1.
    Extranonce1,
    /// `mining.subscribe` response extranonce2 size.
    Extranonce2Size,
    /// `mining.subscribe` response subscription list.
    Subscriptions,
    /// `mining.set_version_mask` parameter list.
    VersionMaskParams,
    /// `mining.set_difficulty` parameter list.
    DifficultyParams,
}

#[derive(Debug, Clone, From, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub enum Error {
    /// Client is already configured against the Pool
    AlreadyConfigured,
    /// Client is not configured against the Pool
    NotConfigured,
    /// Client is already connected to Pool
    AlreadyConnected,
    /// Client is not connected to Pool
    NotConnected,
    /// Client is already authorised by Pool
    AlreadyAuthorized,
    /// Client has not yet being authorized to submit a share
    Unauthorized,
    /// Client has received an unknown Notficiation from Pool
    UnknownNotification,

    /// A field received from the Pool has a length the protocol does not allow
    ///
    /// Returned for fields that are decoded at fixed offsets, where a shorter
    /// or longer value has no meaning.
    InvalidFieldLength {
        field: Field,
        expected: usize,
        actual: usize,
    },

    /// A field received from the Pool is over the maximum this client accepts
    ///
    /// See the [`limits`](crate::limits) module for the enforced maxima.
    FieldTooLarge {
        field: Field,
        max: usize,
        actual: usize,
    },

    /// The Pool sent a frame that does not fit in the receive buffer
    ///
    /// The buffered bytes are dropped and the client resynchronizes on the
    /// next line terminator.
    LineTooLong,

    /// The Pool sent a difficulty that is not a finite number
    InvalidDifficulty,

    /// One of the fixed size Vec or String si to small to contain the data
    #[cfg(not(feature = "alloc"))]
    FixedSizeTooSmall {
        fixed: usize,
        needed: usize,
    },

    /// The RPC Request has a bad format
    RpcBadRequest,
    /// The RPC Response is incoherent
    RpcResponseIncoherent,
    /// The Vec poped is empty
    VecEmpty,

    /// Queue is full
    QueueFull,

    /// Map is full
    #[cfg(not(feature = "alloc"))]
    MapFull,

    NoWork,

    /// Pool reported an error
    Pool {
        code: isize,
        message: tstring!(32),
        detail: Option<tstring!(32)>,
    },

    /// Network error
    // #[from]
    // Network(embedded_io::ErrorKind),
    Network,

    IdNotFound(u64),

    /// correspond to serde_json_core::ser:Error::BufferFull
    JsonBufferFull,
    /// correspond to all serde_json_core::de:Error
    #[from]
    JsonError(serde_json_core::de::Error),
    /// correspond to all json_rpc_types::Error
    RpcOther,
    /// correspond to heapless::Vec::push()
    #[cfg(not(feature = "alloc"))]
    VecFull,
    /// correspond to all faster_hex::Error
    #[from]
    HexError(faster_hex::Error),
}

#[rustversion::since(1.81)]
impl core::error::Error for Error {}

#[rustversion::since(1.81)]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
