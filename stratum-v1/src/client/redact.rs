// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Log sensitivity of Stratum frames.
//!
//! `mining.authorize` carries the pool user and password, and `mining.submit`
//! repeats the user on every share. Writing those frames to the log verbatim
//! puts credentials into ordinary diagnostic output (CWE-532).
//!
//! Every frame the client logs is therefore routed through
//! [`Sensitivity::loggable`], and it is that function's return value — never a
//! buffer — that reaches a logging macro. Because the decision is made before
//! the macro is invoked, it holds identically for both backends
//! [`fmt`](crate::fmt) maps onto (`log` and `defmt-03`) and at every level:
//! neither backend can observe a value this module withheld.

/// Written in place of a frame that carries credentials.
pub(crate) const REDACTED: &str = "<redacted: carries credentials>";

/// Written in place of a frame that is not valid UTF-8.
pub(crate) const INVALID_UTF8: &str = "Invalid UTF-8";

/// Whether a frame may be written to the log verbatim.
///
/// The classification is about *credentials*, not about trust: a
/// [`Public`](Sensitivity::Public) frame may still hold attacker-controlled
/// bytes, it just cannot hold the pool user or password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sensitivity {
    /// Safe to log in full.
    ///
    /// Outgoing, this covers `mining.configure`, `mining.subscribe` and
    /// `mining.suggest_difficulty`: their parameters are the extension list,
    /// the optional device identifier and a difficulty number — connection
    /// metadata the caller chose to publish to the pool, none of it an
    /// authorization parameter.
    ///
    /// Incoming, this covers notifications and every response that is not
    /// matched to a pending `mining.authorize` or `mining.submit`.
    Public,

    /// Carries the pool user, the pool password, or both.
    ///
    /// Outgoing, this covers `mining.authorize` (user and password) and
    /// `mining.submit` (the user is repeated in every share).
    ///
    /// Incoming, this covers responses matched to one of those two requests:
    /// pools echo the submitted user back in error details, so the reply is as
    /// revealing as the request.
    Secret,
}

impl Sensitivity {
    /// The text to hand to a logging macro for `frame`.
    pub(crate) fn loggable<'a>(&self, frame: &'a [u8]) -> &'a str {
        match self {
            Sensitivity::Secret => REDACTED,
            Sensitivity::Public => core::str::from_utf8(frame).unwrap_or(INVALID_UTF8),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guarantee the whole module rests on: for a secret frame the return
    /// value is a fixed string that borrows nothing from the frame, so no
    /// backend and no level can reach the bytes.
    #[test]
    fn secret_frames_never_yield_their_contents() {
        let authorize = br#"{"id":1,"method":"mining.authorize","params":["worker.001","s3cr3t"]}"#;
        assert_eq!(Sensitivity::Secret.loggable(authorize), REDACTED);

        let submit = br#"{"id":2,"method":"mining.submit","params":["worker.001","bf"]}"#;
        assert_eq!(Sensitivity::Secret.loggable(submit), REDACTED);

        // Including when the frame is empty or not valid UTF-8.
        assert_eq!(Sensitivity::Secret.loggable(b""), REDACTED);
        assert_eq!(Sensitivity::Secret.loggable(&[0xff, 0xfe]), REDACTED);
    }

    #[test]
    fn public_frames_are_logged_verbatim() {
        let subscribe = br#"{"id":1,"method":"mining.subscribe","params":[]}"#;
        assert_eq!(
            Sensitivity::Public.loggable(subscribe),
            r#"{"id":1,"method":"mining.subscribe","params":[]}"#
        );

        assert_eq!(Sensitivity::Public.loggable(&[0xff, 0xfe]), INVALID_UTF8);
    }
}
