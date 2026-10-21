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
    pub fn parse(text: &[u8]) -> Option<Self> {
        let history_id = |id: &[u8]| std::str::from_utf8(id).ok()?.parse::<HistoryId>().ok();
        let mut fields = text.splitn(3, |&byte| byte == b';');
        match (fields.next()?, fields.next()?, fields.next()) {
            (b"18188735", b"C", Some(id)) => history_id(id).map(Self::OutputStart),
            (b"18188735", b"D", Some(id)) => history_id(id).map(Self::OutputEnd),
            (b"0" | b"1" | b"2", _, _) => Some(Self::Title),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const HID: &str = "00000000-0000-0000-0000-0000000000a1";

    fn hid() -> HistoryId {
        HID.parse().expect("valid history id")
    }

    #[rstest]
    #[case::start(format!("18188735;C;{HID}"), Some(Event::OutputStart(hid())))]
    #[case::end(format!("18188735;D;{HID}"), Some(Event::OutputEnd(hid())))]
    // The shell integration sends whatever `atuin history start` printed, which is the simple
    // (hyphen-less) form rather than the hyphenated one the other cases use.
    #[case::simple_history_id("18188735;D;000000000000000000000000000000a1".into(), Some(Event::OutputEnd(hid())))]
    #[case::window_and_icon("0;title".into(), Some(Event::Title))]
    #[case::icon("1;title".into(), Some(Event::Title))]
    #[case::window("2;title".into(), Some(Event::Title))]
    #[case::empty_title("2;".into(), Some(Event::Title))]
    #[case::semicolon_in_the_title("2;a;b".into(), Some(Event::Title))]
    #[case::no_title("2".into(), None)]
    #[case::directory("7;file:///tmp".into(), None)]
    #[case::pointer_shape("22;xterm".into(), None)]
    #[case::foreground_color("10;?".into(), None)]
    #[case::osc_133_start("133;C".into(), None)]
    #[case::osc_133_end(format!("133;D;0;history_id={HID}"), None)]
    #[case::missing_history_id("18188735;C".into(), None)]
    #[case::empty_history_id("18188735;D;".into(), None)]
    #[case::invalid_history_id("18188735;D;not-a-uuid".into(), None)]
    #[case::trailing_param(format!("18188735;D;{HID};extra"), None)]
    #[case::unknown_kind(format!("18188735;A;{HID}"), None)]
    #[case::kind_too_long(format!("18188735;CD;{HID}"), None)]
    #[case::missing_kind(format!("18188735;;{HID}"), None)]
    #[case::lowercase_kind(format!("18188735;c;{HID}"), None)]
    #[case::wrong_osc_number(format!("1818873;C;{HID}"), None)]
    #[case::longer_osc_number(format!("181887350;C;{HID}"), None)]
    #[case::bare_osc_number("18188735".into(), None)]
    #[case::empty("".into(), None)]
    fn reads_what_a_command_says(#[case] text: String, #[case] expected: Option<Event>) {
        assert_eq!(Event::parse(text.as_bytes()), expected);
    }
}
