// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

#![macro_use]
#![allow(unused_macros)]

#[cfg(all(feature = "defmt-03", feature = "log"))]
compile_error!("You may not enable both `defmt` and `log` features.");

macro_rules! assert {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::assert!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::assert!($($x)*);
        }
    };
}

macro_rules! assert_eq {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::assert_eq!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::assert_eq!($($x)*);
        }
    };
}

macro_rules! assert_ne {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::assert_ne!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::assert_ne!($($x)*);
        }
    };
}

macro_rules! debug_assert {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::debug_assert!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::debug_assert!($($x)*);
        }
    };
}

macro_rules! debug_assert_eq {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::debug_assert_eq!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::debug_assert_eq!($($x)*);
        }
    };
}

macro_rules! debug_assert_ne {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::debug_assert_ne!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::debug_assert_ne!($($x)*);
        }
    };
}

macro_rules! todo {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::todo!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::todo!($($x)*);
        }
    };
}

macro_rules! unreachable {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::unreachable!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::unreachable!($($x)*);
        }
    };
}

macro_rules! panic {
    ($($x:tt)*) => {
        {
            #[cfg(not(feature = "defmt-03"))]
            ::core::panic!($($x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::panic!($($x)*);
        }
    };
}

macro_rules! trace {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::trace!($s $(, $x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::trace!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt-03")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! debug {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::debug!($s $(, $x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::debug!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt-03")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! info {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::info!($s $(, $x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::info!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt-03")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! warn {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::warn!($s $(, $x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::warn!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt-03")))]
            let _ = ($( & $x ),*);
        }
    };
}

macro_rules! error {
    ($s:literal $(, $x:expr)* $(,)?) => {
        {
            #[cfg(feature = "log")]
            ::log::error!($s $(, $x)*);
            #[cfg(feature = "defmt-03")]
            ::defmt::error!($s $(, $x)*);
            #[cfg(not(any(feature = "log", feature="defmt-03")))]
            let _ = ($( & $x ),*);
        }
    };
}

#[cfg(feature = "defmt-03")]
macro_rules! unwrap {
    ($($x:tt)*) => {
        ::defmt::unwrap!($($x)*)
    };
}

#[cfg(not(feature = "defmt-03"))]
macro_rules! unwrap {
    ($arg:expr) => {
        match $crate::fmt::Try::into_result($arg) {
            ::core::result::Result::Ok(t) => t,
            ::core::result::Result::Err(e) => {
                ::core::panic!("unwrap of `{}` failed: {:?}", ::core::stringify!($arg), e);
            }
        }
    };
    ($arg:expr, $($msg:expr),+ $(,)? ) => {
        match $crate::fmt::Try::into_result($arg) {
            ::core::result::Result::Ok(t) => t,
            ::core::result::Result::Err(e) => {
                ::core::panic!("unwrap of `{}` failed: {}: {:?}", ::core::stringify!($arg), ::core::format_args!($($msg,)*), e);
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NoneError;

#[allow(dead_code)]
pub trait Try {
    type Ok;
    type Error;
    fn into_result(self) -> Result<Self::Ok, Self::Error>;
}

impl<T> Try for Option<T> {
    type Ok = T;
    type Error = NoneError;

    #[inline]
    fn into_result(self) -> Result<T, NoneError> {
        self.ok_or(NoneError)
    }
}

impl<T, E> Try for Result<T, E> {
    type Ok = T;
    type Error = E;

    #[inline]
    fn into_result(self) -> Self {
        self
    }
}

#[cfg(feature = "alloc")]
macro_rules! tstring {
    ($l:expr) => {
        alloc::string::String
    };
}
#[cfg(not(feature = "alloc"))]
macro_rules! tstring {
    ($l:expr) => {
        heapless::String::<$l>
    };
}

#[cfg(feature = "alloc")]
macro_rules! hstring {
    ($l:expr, $s:expr) => {
        alloc::string::String::from($s)
    };
}
#[cfg(not(feature = "alloc"))]
macro_rules! hstring {
    ($l:expr, $s:expr) => {
        heapless::String::<$l>::from_str($s).unwrap()
    };
}

#[cfg(feature = "alloc")]
macro_rules! tvecstring {
    ($ls:expr, $lv:expr) => {
        alloc::vec::Vec<alloc::string::String>
    };
}

#[cfg(not(feature = "alloc"))]
macro_rules! tvecstring {
    ($ls:expr, $lv:expr) => {
        heapless::Vec::<heapless::String<$ls>, $lv>
    };
}

#[cfg(feature = "alloc")]
macro_rules! tvec {
    ($t:ident, $l:expr) => {
        alloc::vec::Vec<$t>
    };
}

#[cfg(not(feature = "alloc"))]
macro_rules! tvec {
    ($t:ident, $l:expr) => {
        heapless::Vec::<$t, $l>
    };
}

#[cfg(feature = "alloc")]
macro_rules! hvec {
    ($t:ident, $l:expr, $s:expr) => {
        alloc::vec::Vec::<$t>::from($s)
    };
}

#[cfg(not(feature = "alloc"))]
macro_rules! hvec {
    ($t:ident, $l:expr, $s:expr) => {
        heapless::Vec::<$t, $l>::from_slice(&$s).unwrap()
    };
}

#[cfg(feature = "alloc")]
macro_rules! hveca {
    ($t:ident, $la:expr, $l:expr, $s:expr) => {
        alloc::vec::Vec::<[$t; $la]>::from($s)
    };
}

#[cfg(not(feature = "alloc"))]
macro_rules! hveca {
    ($t:ident, $la:expr, $l:expr, $s:expr) => {
        heapless::Vec::<[$t; $la], $l>::from_slice(&$s).unwrap()
    };
}
