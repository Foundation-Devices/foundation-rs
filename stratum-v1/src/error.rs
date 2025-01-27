// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use derive_more::From;

pub type Result<T> = core::result::Result<T, Error>;

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
