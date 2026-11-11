// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keeps pool credentials out of the log. Frames are classified before a logging
//! macro sees them, so this holds for both backends and at every level.

/// Written in place of a frame that carries credentials.
pub(crate) const REDACTED: &str = "<redacted: carries credentials>";

/// Written in place of a frame that is not valid UTF-8.
pub(crate) const INVALID_UTF8: &str = "Invalid UTF-8";

/// Whether a frame may be written to the log verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sensitivity {
    /// Carries no pool credential.
    Public,
    /// `mining.authorize`, `mining.submit`, or a reply to either: pools echo the
    /// submitted user back in error details.
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

    /// A secret frame yields a fixed string that borrows nothing from the frame.
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
