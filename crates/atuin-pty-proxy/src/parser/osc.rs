//! What the operating system commands (OSC) the proxy follows say.
//!
//! | Command                              | Meaning                              |
//! |--------------------------------------|--------------------------------------|
//! | `OSC 18188735 ; C ; <history id> ST` | Start of command output              |
//! | `OSC 18188735 ; D ; <history id> ST` | End of command output                |
//! | `OSC 0 ; <title> ST`, `1`, `2`       | The child set a window title or icon |
//!
//! `OSC` is `ESC ]`. `ST` is `BEL` (0x07) or `ESC \` (0x1B 0x5C).
//!
//! `OSC 18188735` is a private, Atuin-specific escape sequence. We use this to ensure that our
//! escape sequences don't conflict with any other program or terminal. 18188735 is `atuin`
//! interpreted as a base-36 number. It fits into a 32-bit signed integer, which many terminals use
//! for OSC numbers, and if truncated to a 16-bit or 8-bit integer, it produces results (35263, 191)
//! that also aren't in use. Additionally, no prefix of 18188735 of length 3 or greater is in use
//! either, in case a terminal only reads a fixed number of digits.

use atuin_client::history::HistoryId;
use winnow::Parser as _;
use winnow::combinator::{alt, preceded, terminated};
use winnow::token::{one_of, rest};

/// What an operating system command the proxy follows says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// `OSC 18188735 ; C ; <history id> ST` -- start of command output.
    OutputStart(HistoryId),
    /// `OSC 18188735 ; D ; <history id> ST` -- end of command output.
    OutputEnd(HistoryId),
    /// `OSC 0`, `1` or `2` -- the child set the window title, its icon name, or both.
    Title,
}

impl Event {
    /// The most of a command's text worth keeping to tell what it says.
    ///
    /// This is large enough to hold `18188735;C;` (11 bytes) plus the history ID in the longest
    /// format supported by the `uuid` crate (45 bytes for `urn:uuid:<hyphenated-uuid>`) -- 56 bytes
    /// total. A title is told by its first two bytes.
    pub const MAX_TEXT_LEN: usize = 64;

    /// What the command with this `text` says, if it is one the proxy follows.
    ///
    /// `text` may be only the first [`Self::MAX_TEXT_LEN`] bytes of a longer one. A marker cut that
    /// short would have an ID longer than any the `uuid` crate reads, so it can't pass for one.
    pub fn parse(mut text: &[u8]) -> Option<Self> {
        let id = || rest.verify_map(|id| std::str::from_utf8(id).ok()?.parse::<HistoryId>().ok());
        let event: Result<Self, ()> = alt((
            preceded(
                b"18188735;",
                alt((
                    preceded(b"C;", id()).map(Self::OutputStart),
                    preceded(b"D;", id()).map(Self::OutputEnd),
                )),
            ),
            terminated(one_of(b"012"), b';').value(Self::Title),
        ))
        .parse_next(&mut text);
        event.ok()
    }
}
