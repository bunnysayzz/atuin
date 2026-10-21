//! Streaming parser for the child's output.
//!
//! The output arrives in whatever pieces a read returns, cut anywhere: inside an escape sequence,
//! or between the bytes of a UTF-8 character. [`Parser`] follows it through the states of a VT
//! parser (<https://vt100.net/emu/dec_ansi_parser>), the way `vte` implements them, and carries
//! only its state from one piece to the next. On the way it:
//!
//! * splits the output after each operating system command the proxy follows, with the [`Event`]
//!   the command says, and
//! * knows whether the output so far ends between sequences and characters, where bytes of the
//!   proxy's own can't change the meaning of the child's.
//!
//! A command counts only once it is terminated, with `BEL` or `ESC \`. Where terminals disagree the
//! parser errs towards waiting: C1 controls are text, because a UTF-8 terminal reads `0x9c` as part
//! of a character rather than as a string terminator.

mod osc;

pub use osc::Event;
use winnow::Parser as _;
use winnow::combinator::{alt, opt};
use winnow::stream::Stateful;
use winnow::token::{any, rest, take_till, take_until};

const ESC: u8 = 0x1B;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1A;

/// An event with the slice of data up to the end of its command.
///
/// Concatenating [`Self::data`] for every chunk, followed by [`EventChunks::trailing_data`],
/// exactly reproduces the bytes passed to [`Parser::push`].
#[derive(Debug, Clone, Copy)]
pub struct EventChunk<'a> {
    /// What the command said.
    pub event: Event,

    /// All the data between the last event and the end of this event's command.
    ///
    /// This includes the entire command itself.
    pub data: &'a [u8],

    /// The total length of the command corresponding to this event.
    pub osc_len: usize,
}

/// An iterator of events, created by [`Parser::push`].
///
/// After exhausting the iterator, you will likely want to call [`Self::trailing_data`] to get the
/// last chunk of data that was not yielded by the iterator. You may need to use
/// [`Iterator::by_ref`] when iterating to ensure you still have access to the iterator afterward.
///
/// Dropping the iterator follows whatever data it has not yet, so the parser always ends up past
/// everything pushed.
pub struct EventChunks<'parser, 'data> {
    parser: &'parser mut Parser,
    /// The data not yet yielded in a chunk.
    data: &'data [u8],
    /// How much of `data` the parser has followed.
    scanned: usize,
}

impl<'data> Iterator for EventChunks<'_, 'data> {
    type Item = EventChunk<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let (scanned, event) = self.parser.scan(&self.data[self.scanned..]);
        self.scanned += scanned;
        let event = event?;

        let (data, rest) = self.data.split_at(self.scanned);
        self.data = rest;
        self.scanned = 0;
        Some(EventChunk {
            event,
            data,
            osc_len: self.parser.command.len,
        })
    }
}

impl std::iter::FusedIterator for EventChunks<'_, '_> {}

impl Drop for EventChunks<'_, '_> {
    fn drop(&mut self) {
        for _ in self.by_ref() {}
    }
}

impl<'data> EventChunks<'_, 'data> {
    /// Get the last bit of data not yielded by this iterator.
    ///
    /// This method is intended to be called once the iterator has been exhausted.
    pub fn trailing_data(&self) -> &'data [u8] {
        self.data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Between sequences, with this many bytes of a UTF-8 character still to come.
    Ground {
        continuation: u8,
    },
    /// After `ESC`.
    Escape,
    /// After `ESC` and an intermediate byte.
    EscapeIntermediate,
    /// Inside a control sequence (`ESC [`).
    Csi,
    /// Inside an operating system command (`ESC ]`).
    Osc,
    /// After an `ESC` inside an operating system command, which ends the command, and terminates
    /// it if a `\` follows.
    OscEscape,
    /// Inside a device control string, or a start of string, privacy message or application
    /// program command.
    ControlString,
}

impl State {
    /// Between sequences and characters.
    const GROUND: Self = Self::Ground { continuation: 0 };
}

/// The operating system command the output is in, or was last in.
#[derive(Debug)]
struct Command {
    /// The start of the command's text, without the controls `vte` leaves out of it.
    kept: [u8; Event::MAX_TEXT_LEN],
    kept_len: usize,
    /// The length of the command so far, from its `ESC ]`.
    len: usize,
}

impl Command {
    /// A command that has just begun, with its `ESC ]`.
    const fn begun() -> Self {
        Self {
            kept: [0; Event::MAX_TEXT_LEN],
            kept_len: 0,
            len: 2,
        }
    }

    /// Follow a run of the command's text.
    fn push(&mut self, text: &[u8]) {
        self.len = self.len.saturating_add(text.len());
        for &byte in text.iter().filter(|&&byte| byte >= 0x20) {
            let Some(slot) = self.kept.get_mut(self.kept_len) else {
                return;
            };
            *slot = byte;
            self.kept_len += 1;
        }
    }

    /// End the command with a terminator `terminator_len` bytes long, returning what it said.
    fn end(&mut self, terminator_len: usize) -> Option<Event> {
        self.len = self.len.saturating_add(terminator_len);
        Event::parse(&self.kept[..self.kept_len])
    }
}

/// A streaming, zero-allocation parser for the child's output.
///
/// Feed arbitrary byte slices into [`Parser::push`]. The parser detects the commands it follows and
/// returns an iterator of [`EventChunk`]s, each containing an [`Event`] and the data up to that
/// point.
#[derive(Debug)]
pub struct Parser {
    state: State,
    command: Command,
}

/// A chunk of output, with the parser that carries its state from one chunk to the next.
///
/// Backtracking resets only the chunk, so a step changes the parser only once it has parsed what
/// it needs.
type Input<'data, 'parser> = Stateful<&'data [u8], &'parser mut Parser>;

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// Create a new parser in the initial (ground) state.
    pub const fn new() -> Self {
        Self {
            state: State::GROUND,
            command: Command::begun(),
        }
    }

    /// Process a chunk of bytes, yielding an [`EventChunk`] for every command the proxy follows,
    /// containing the event and all the data up to that point.
    pub fn push<'data>(&mut self, data: &'data [u8]) -> EventChunks<'_, 'data> {
        EventChunks {
            parser: self,
            data,
            scanned: 0,
        }
    }

    /// Whether the output is between escape sequences and characters, where bytes of our own can't
    /// change the meaning of the child's.
    pub const fn at_ground(&self) -> bool {
        matches!(self.state, State::GROUND)
    }

    /// Follow `data` up to the end of the first command the proxy follows, returning how much of
    /// `data` that took and what the command said, or all of `data` and nothing.
    fn scan(&mut self, data: &[u8]) -> (usize, Option<Event>) {
        let mut input = Input {
            input: data,
            state: self,
        };
        while !input.input.is_empty() {
            match Self::step(&mut input) {
                Ok(None) => {}
                Ok(Some(event)) => return (data.len() - input.input.len(), Some(event)),
                // No step fails on input that isn't empty. Were one to, the rest of the chunk
                // would still reach the terminal; only the parser would miss it.
                Err(()) => break,
            }
        }
        (data.len(), None)
    }

    /// Follow the input in its current state, up to the next change of state.
    fn step(input: &mut Input<'_, '_>) -> Result<Option<Event>, ()> {
        match input.state.state {
            State::Ground { continuation } => Self::text(input, continuation),
            State::Escape | State::OscEscape => Self::escape(input),
            State::EscapeIntermediate => {
                take_till(0.., |byte| matches!(byte, 0x30..=0x7E | ESC | CAN | SUB))
                    .parse_next(input)?;
                Self::end_of_sequence(input, State::EscapeIntermediate)
            }
            State::Csi => {
                take_till(0.., |byte| matches!(byte, 0x40..=0x7E | ESC | CAN | SUB))
                    .parse_next(input)?;
                Self::end_of_sequence(input, State::Csi)
            }
            State::Osc => Self::command(input),
            State::ControlString => {
                alt((take_until(0.., (ESC, CAN, SUB)), rest)).parse_next(input)?;
                Self::end_of_sequence(input, State::ControlString)
            }
        }
    }

    /// Plain text, up to the `ESC` that leads out of it.
    fn text(input: &mut Input<'_, '_>, continuation: u8) -> Result<Option<Event>, ()> {
        // Plain text is most of any output. Searching for its end with memchr is a ~10X improvement
        // over stepping through it.
        let text = alt((take_until(0.., ESC), rest)).parse_next(input)?;
        let continuation = Self::continuation_after(continuation, text);
        input.state.state = match opt(ESC).parse_next(input)? {
            Some(_) => State::Escape,
            None => State::Ground { continuation },
        };
        Ok(None)
    }

    /// The byte after an `ESC`.
    fn escape(input: &mut Input<'_, '_>) -> Result<Option<Event>, ()> {
        let byte = any.parse_next(input)?;
        let parser = &mut *input.state;
        if parser.state == State::OscEscape && byte == b'\\' {
            parser.state = State::GROUND;
            return Ok(parser.command.end(2));
        }
        parser.state = match byte {
            ESC => State::Escape,
            0x20..=0x2F => State::EscapeIntermediate,
            b'[' => State::Csi,
            b']' => {
                parser.command = Command::begun();
                State::Osc
            }
            b'P' | b'X' | b'^' | b'_' => State::ControlString,
            CAN | SUB | 0x30..=0x7E => State::GROUND,
            // A control is run without ending the escape, though it ends a command.
            _ => State::Escape,
        };
        Ok(None)
    }

    /// A command's text, and the byte that ends it.
    fn command(input: &mut Input<'_, '_>) -> Result<Option<Event>, ()> {
        let text = take_till(0.., (BEL, ESC, CAN, SUB)).parse_next(input)?;
        input.state.command.push(text);
        let Some(end) = opt(any).parse_next(input)? else {
            return Ok(None);
        };
        let parser = &mut *input.state;
        parser.state = if end == ESC {
            State::OscEscape
        } else {
            State::GROUND
        };
        // An `ESC` may yet terminate the command, and `CAN` or `SUB` cancel it.
        Ok(if end == BEL {
            parser.command.end(1)
        } else {
            None
        })
    }

    /// The byte that ends a sequence, if the input has it, or `unfinished` if not.
    fn end_of_sequence(input: &mut Input<'_, '_>, unfinished: State) -> Result<Option<Event>, ()> {
        input.state.state = match opt(any).parse_next(input)? {
            Some(ESC) => State::Escape,
            Some(_) => State::GROUND,
            None => unfinished,
        };
        Ok(None)
    }

    /// How many bytes of a UTF-8 character are still to come after `run`, if `continuation` were
    /// before it.
    fn continuation_after(continuation: u8, run: &[u8]) -> u8 {
        // A character has at most three bytes after its first, so whatever came before the last
        // three has ended or been cut short by them.
        let (start, continuation) = match run.len().checked_sub(3) {
            Some(start) => (start, 0),
            None => (0, continuation),
        };
        run[start..].iter().fold(continuation, |continuation, byte| match byte {
            0x80..=0xBF => continuation.saturating_sub(1),
            0xC2..=0xDF => 1,
            0xE0..=0xEF => 2,
            0xF0..=0xF4 => 3,
            _ => 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use atuin_client::history::HistoryId;
    use proptest::arbitrary::any;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    const HID: &str = "00000000-0000-0000-0000-0000000000a1";
    const HID_ONE: &str = "00000000-0000-0000-0000-000000000001";
    const HID_TWO: &str = "00000000-0000-0000-0000-000000000002";

    fn hid(s: &str) -> HistoryId {
        s.parse().expect("valid history id")
    }

    fn start(history_id: &str) -> Vec<u8> {
        format!("\x1b]18188735;C;{history_id}\x07").into_bytes()
    }

    fn end(history_id: &str) -> Vec<u8> {
        format!("\x1b]18188735;D;{history_id}\x07").into_bytes()
    }

    /// An owned copy of [`EventChunk`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OwnedChunk {
        event: Event,
        data: Vec<u8>,
        osc_len: usize,
    }

    /// The full result of one [`Parser::push`] call.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Push {
        chunks: Vec<OwnedChunk>,
        trailing_data: Vec<u8>,
    }

    impl Push {
        fn events(&self) -> Vec<Event> {
            self.chunks.iter().map(|chunk| chunk.event).collect()
        }
    }

    fn push(parser: &mut Parser, data: &[u8]) -> Push {
        let mut iter = parser.push(data);
        let chunks = iter
            .by_ref()
            .map(|chunk| OwnedChunk {
                event: chunk.event,
                data: chunk.data.to_vec(),
                osc_len: chunk.osc_len,
            })
            .collect();
        Push {
            chunks,
            trailing_data: iter.trailing_data().to_vec(),
        }
    }

    /// Push `data` through a fresh parser in a single call.
    fn parse(data: &[u8]) -> Push {
        push(&mut Parser::new(), data)
    }

    /// Collect all events from a single `push` call.
    fn parse_events(data: &[u8]) -> Vec<Event> {
        parse(data).events()
    }

    /// Whether a fresh parser given `data` ends up between sequences and characters.
    fn at_ground_after(data: &[u8]) -> bool {
        let mut parser = Parser::new();
        drop(parser.push(data));
        parser.at_ground()
    }

    // -- Basic event detection ------------------------------------------------

    #[rstest]
    #[case::start("C", Event::OutputStart(hid(HID)))]
    #[case::end("D", Event::OutputEnd(hid(HID)))]
    fn detects_event(
        #[case] kind: &str,
        #[case] expected: Event,
        #[values(b"\x07".as_slice(), b"\x1b\\".as_slice())] terminator: &[u8],
    ) {
        let data = [format!("\x1b]18188735;{kind};{HID}").as_bytes(), terminator].concat();
        assert_eq!(parse_events(&data), vec![expected]);
    }

    #[rstest]
    fn accepts_the_simple_history_id_encoding() {
        // The shell integration sends whatever `atuin history start` printed, which is the simple
        // (hyphen-less) form rather than the hyphenated one the other tests use.
        let data = b"\x1b]18188735;D;000000000000000000000000000000a1\x07";
        assert_eq!(parse_events(data), vec![Event::OutputEnd(hid(HID))]);
    }

    #[rstest]
    fn reports_the_length_of_the_marker() {
        let marker = end(HID);
        let result = parse(&[b"output".as_slice(), &marker].concat());

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].osc_len, marker.len());
    }

    #[rstest]
    #[case::window_and_icon(b"\x1b]0;title\x07", true)]
    #[case::icon(b"\x1b]1;title\x07", true)]
    #[case::window(b"\x1b]2;title\x07", true)]
    #[case::string_terminator(b"\x1b]2;title\x1b\\", true)]
    #[case::empty(b"\x1b]2;\x07", true)]
    #[case::semicolon_in_the_title(b"\x1b]2;a;b\x07", true)]
    #[case::control_in_the_number(b"\x1b]\x052;title\x07", true)]
    #[case::ended_by_cancel(b"\x1b]2;title\x18", false)]
    #[case::ended_by_another_sequence(b"\x1b]2;title\x1b[m", false)]
    #[case::unfinished(b"\x1b]2;title", false)]
    #[case::no_title(b"\x1b]2\x07", false)]
    #[case::directory(b"\x1b]7;file:///tmp\x07", false)]
    #[case::pointer_shape(b"\x1b]22;xterm\x07", false)]
    #[case::foreground_color(b"\x1b]10;?\x07", false)]
    #[case::inside_a_device_control_string(b"\x1bPq]2;title\x07\x1b\\", false)]
    fn detects_titles(#[case] data: &[u8], #[case] titled: bool) {
        assert_eq!(parse_events(data).contains(&Event::Title), titled);
    }

    // -- Multiple events / interleaved text in one push -----------------------

    #[rstest]
    fn emits_events_in_order_around_other_output() {
        let data = [
            b"$ ls\r\n".as_slice(),
            &start(HID_ONE),
            b"\x1b]0;title\x07file\r\n",
            &end(HID_ONE),
            b"\x1b[32m$\x1b[0m ",
            &start(HID_TWO),
            &end(HID_TWO),
        ]
        .concat();

        assert_eq!(parse_events(&data), vec![
            Event::OutputStart(hid(HID_ONE)),
            Event::Title,
            Event::OutputEnd(hid(HID_ONE)),
            Event::OutputStart(hid(HID_TWO)),
            Event::OutputEnd(hid(HID_TWO)),
        ]);
    }

    #[rstest]
    fn an_unterminated_osc_does_not_hide_the_next_marker() {
        let data = [b"\x1b]0;title".as_slice(), &start(HID)].concat();
        assert_eq!(parse_events(&data), vec![Event::OutputStart(hid(HID))]);
    }

    // -- Chunk data -----------------------------------------------------------

    #[rstest]
    fn splits_data_at_the_markers() {
        let data = [b"before".as_slice(), &start(HID), b"between", &end(HID), b"after"].concat();

        let result = parse(&data);
        let chunks: Vec<_> = result.chunks.iter().map(|chunk| chunk.data.clone()).collect();
        assert_eq!(chunks, vec![
            [b"before".as_slice(), &start(HID)].concat(),
            [b"between".as_slice(), &end(HID)].concat(),
        ]);
        assert_eq!(result.trailing_data, b"after");
    }

    #[rstest]
    // The parser has to return to the ground state once a sequence is terminated. Otherwise
    // plain output keeps accumulating in the parameter buffer, and a bare BEL in that output
    // fabricates an event out of it.
    #[case::output_after_a_foreign_osc(
        [b"\x1b]0;\x07".as_slice(), format!("18188735;D;{HID}\x07").as_bytes()].concat()
    )]
    #[case::output_after_a_marker(
        [start(HID).as_slice(), format!("18188735;D;{HID}\x07").as_bytes()].concat()
    )]
    fn output_after_a_sequence_is_not_parsed_as_parameters(#[case] data: Vec<u8>) {
        let events = parse_events(&data);
        assert!(!events.contains(&Event::OutputEnd(hid(HID))), "{events:?}");
    }

    #[rstest]
    #[case::bel(b"\x07".as_slice())]
    #[case::st(b"\x1b\\")]
    fn chunk_data_includes_the_terminator(#[case] terminator: &[u8]) {
        // A chunk that stopped one byte short would leave the marker looking unterminated
        // to whoever replays the data, and drop its final byte into the next chunk.
        let marker = [format!("\x1b]18188735;D;{HID}").as_bytes(), terminator].concat();
        let data = [b"out".as_slice(), &marker, b"rest"].concat();

        let result = parse(&data);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].data, [b"out".as_slice(), &marker].concat());
        assert_eq!(result.trailing_data, b"rest");
    }

    #[rstest]
    fn a_marker_split_across_pushes_is_reported_by_the_completing_push() {
        let (head, tail) = HID.split_at(20);
        let mut parser = Parser::new();

        let first = push(&mut parser, format!("out\x1b]18188735;D;{head}").as_bytes());
        assert!(first.chunks.is_empty());
        assert_eq!(first.trailing_data, format!("out\x1b]18188735;D;{head}").as_bytes());

        let second = push(&mut parser, format!("{tail}\x07rest").as_bytes());
        assert_eq!(second.events(), vec![Event::OutputEnd(hid(HID))]);
        assert_eq!(second.chunks[0].data, format!("{tail}\x07").as_bytes());
        assert_eq!(second.trailing_data, b"rest");
    }

    // -- Input that must not produce events -----------------------------------

    #[rstest]
    #[case::osc_7(b"\x1b]7;file:///home/user\x07".to_vec())]
    #[case::osc_133_start(b"\x1b]133;C\x07".to_vec())]
    #[case::osc_133_end(format!("\x1b]133;D;0;history_id={HID}\x07").into_bytes())]
    #[case::missing_history_id(b"\x1b]18188735;C\x07".to_vec())]
    #[case::empty_history_id(b"\x1b]18188735;D;\x07".to_vec())]
    #[case::invalid_history_id(b"\x1b]18188735;D;not-a-uuid\x07".to_vec())]
    #[case::trailing_param(format!("\x1b]18188735;D;{HID};extra\x07").into_bytes())]
    #[case::unknown_kind(format!("\x1b]18188735;A;{HID}\x07").into_bytes())]
    #[case::kind_too_long(format!("\x1b]18188735;CD;{HID}\x07").into_bytes())]
    #[case::missing_kind(format!("\x1b]18188735;;{HID}\x07").into_bytes())]
    #[case::lowercase_kind(format!("\x1b]18188735;c;{HID}\x07").into_bytes())]
    #[case::wrong_osc_number(format!("\x1b]1818873;C;{HID}\x07").into_bytes())]
    #[case::longer_osc_number(format!("\x1b]181887350;C;{HID}\x07").into_bytes())]
    #[case::bare_osc_number(b"\x1b]18188735\x07".to_vec())]
    #[case::empty_osc(b"\x1b]\x07".to_vec())]
    #[case::unterminated(format!("\x1b]18188735;C;{HID}").into_bytes())]
    // A UTF-8 terminal reads 0x9c as part of a character, so the marker is still open.
    #[case::c1_terminator([format!("\x1b]18188735;C;{HID}").as_bytes(), &[0x9C]].concat())]
    #[case::only_normal_text(b"just some regular terminal output\r\n".to_vec())]
    #[case::csi_only(b"\x1b[2J\x1b[H".to_vec())]
    fn ignores_input(#[case] data: Vec<u8>) {
        assert_eq!(parse_events(&data), vec![]);
    }

    // -- Buffer overflow (very long OSC) --------------------------------------

    #[rstest]
    // An OSC whose text overflows the buffer is dropped, without panicking...
    #[case::overlong_osc_is_dropped(b"\x1b]".to_vec(), vec![], vec![])]
    #[case::overlong_marker_is_dropped(
        format!("\x1b]18188735;D;{HID}").into_bytes(),
        vec![],
        vec![],
    )]
    // ...and the parser is back in a state where it recognises the next marker.
    #[case::parser_recovers(b"\x1b]0;".to_vec(), start(HID), vec![
        Event::Title,
        Event::OutputStart(hid(HID))
    ])]
    fn an_overlong_osc_does_not_panic(
        #[case] prefix: Vec<u8>,
        #[case] suffix: Vec<u8>,
        #[case] expected: Vec<Event>,
    ) {
        let mut data = prefix;
        data.extend(std::iter::repeat_n(b'x', Event::MAX_TEXT_LEN * 2));
        data.push(BEL);
        data.extend_from_slice(&suffix);

        assert_eq!(parse_events(&data), expected);
    }

    // -- Ground ---------------------------------------------------------------

    #[rstest]
    #[case::nothing(b"")]
    #[case::text(b"hello\r\n")]
    #[case::sgr(b"\x1b[1;31mred\x1b[0m")]
    #[case::charset(b"\x1b(B")]
    #[case::keypad(b"\x1b=")]
    #[case::string_terminator(b"\x1b\\")]
    #[case::title_bel(b"\x1b]0;title\x07")]
    #[case::title_st(b"\x1b]2;title\x1b\\")]
    #[case::device_control(b"\x1bP1$r0m\x1b\\")]
    #[case::application_command(b"\x1b_Gf=24;AAAA\x1b\\")]
    #[case::cancelled(b"\x1b[31\x18")]
    #[case::two_byte_character("é".as_bytes())]
    #[case::four_byte_character("🦀".as_bytes())]
    #[case::stray_continuation(b"\x80")]
    fn at_ground_after_complete_output(#[case] data: &[u8]) {
        assert!(at_ground_after(data));
    }

    #[rstest]
    #[case::escape(b"\x1b")]
    #[case::control_sequence(b"\x1b[1;3")]
    #[case::control_sequence_with_a_newline(b"\x1b[1\n")]
    #[case::charset(b"\x1b(")]
    #[case::command(b"\x1b]0;tit")]
    #[case::command_number(b"\x1b]13")]
    #[case::command_terminator(b"\x1b]0;title\x1b")]
    #[case::c1_terminator(b"\x1b]0;title\x9c")]
    #[case::device_control(b"\x1bP1$r0m")]
    #[case::device_control_bel(b"\x1bPq\x07")]
    #[case::first_of_two_bytes(&"é".as_bytes()[..1])]
    #[case::second_of_three_bytes(&"€".as_bytes()[..2])]
    #[case::third_of_four_bytes(&"🦀".as_bytes()[..3])]
    fn not_at_ground_inside_a_sequence(#[case] data: &[u8]) {
        assert!(!at_ground_after(data));
    }

    // -- Fused ----------------------------------------------------------------

    #[rstest]
    fn iterator_is_fused() {
        let data = [start(HID).as_slice(), b"tail"].concat();
        let mut parser = Parser::new();
        let mut iter = parser.push(&data);

        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
        assert_eq!(iter.trailing_data(), b"tail");
    }

    #[rstest]
    fn parser_default_matches_new() {
        assert_eq!(push(&mut Parser::default(), &start(HID)).events(), vec![Event::OutputStart(
            hid(HID)
        )]);
    }

    #[rstest]
    fn dropping_the_chunks_follows_the_rest_of_the_data() {
        // A caller that stops at the first event must not leave the parser behind the stream.
        let mut parser = Parser::new();
        let mut chunks = parser.push(b"\x1b]2;title\x07\x1b[31");
        assert_eq!(chunks.next().map(|chunk| chunk.event), Some(Event::Title));
        drop(chunks);

        assert!(!parser.at_ground());
    }

    // -- Properties -----------------------------------------------------------

    /// Bytes drawn mostly from the characters escape sequences are built of, so that generated
    /// input is dense with sequences that are complete, partial, or nearly markers.
    fn stream() -> impl Strategy<Value = Vec<u8>> {
        let piece = prop_oneof![
            Just(start(HID)),
            Just(end(HID_ONE)),
            Just(b"\x1b]18188735;".to_vec()),
            Just(b"\x1b]0;title\x07".to_vec()),
            Just(b"\x1b]2;".to_vec()),
            Just(b"\x1b]7;".to_vec()),
            Just(b"\x1b[1;31m".to_vec()),
            Just(b"\x1b[1;3".to_vec()),
            Just(b"\x1bP1$r".to_vec()),
            Just(b"\x1b_".to_vec()),
            Just(b"\x1b(".to_vec()),
            Just(b"\x1b".to_vec()),
            Just(b"\x07".to_vec()),
            Just(b"\x1b\\".to_vec()),
            Just(vec![CAN]),
            Just(vec![SUB]),
            Just(vec![0x9C]),
            Just("é€🦀".as_bytes().to_vec()),
            Just(vec![0xE2]),
            Just(vec![0x82]),
            prop::collection::vec(any::<u8>(), 0..8),
        ];
        prop::collection::vec(piece, 0..16).prop_map(|pieces| pieces.concat())
    }

    /// What pushing `data` split at the given points made of it: every event, every byte handed
    /// back, and whether it ended at ground.
    fn push_split(data: &[u8], splits: &[prop::sample::Index]) -> (Vec<Event>, Vec<u8>, bool) {
        let mut cuts: Vec<usize> = splits.iter().map(|index| index.index(data.len() + 1)).collect();
        cuts.push(0);
        cuts.push(data.len());
        cuts.sort_unstable();

        let mut parser = Parser::new();
        let mut events = Vec::new();
        let mut rebuilt = Vec::new();
        for window in cuts.windows(2) {
            let result = push(&mut parser, &data[window[0]..window[1]]);
            events.extend(result.events());
            for chunk in result.chunks {
                rebuilt.extend(chunk.data);
            }
            rebuilt.extend(result.trailing_data);
        }
        (events, rebuilt, parser.at_ground())
    }

    /// Records what `vte` does: each character it prints, and `None` for anything else.
    #[derive(Default)]
    struct Reference {
        actions: Vec<Option<char>>,
    }

    impl vte::Perform for Reference {
        fn print(&mut self, c: char) {
            self.actions.push(Some(c));
        }

        fn execute(&mut self, _byte: u8) {
            self.actions.push(None);
        }

        fn hook(&mut self, _: &vte::Params, _: &[u8], _: bool, _: char) {
            self.actions.push(None);
        }

        fn put(&mut self, _byte: u8) {
            self.actions.push(None);
        }

        fn osc_dispatch(&mut self, _: &[&[u8]], _bell_terminated: bool) {
            self.actions.push(None);
        }

        fn csi_dispatch(&mut self, _: &vte::Params, _: &[u8], _: bool, _: char) {
            self.actions.push(None);
        }

        fn esc_dispatch(&mut self, _: &[u8], _: bool, _: u8) {
            self.actions.push(None);
        }
    }

    proptest! {
        /// Whatever the parser makes of the stream, every byte handed to it has to come back out:
        /// the caller passes this data straight on to a terminal.
        #[rstest]
        fn chunks_and_trailing_data_reconstruct_the_input(
            data in stream(),
            splits in prop::collection::vec(any::<prop::sample::Index>(), 0..6),
        ) {
            let (_, rebuilt, _) = push_split(&data, &splits);
            prop_assert_eq!(rebuilt, data);
        }

        /// Output reaches the proxy in whatever pieces the pty hands over, so where it is cut must
        /// make no difference to what the parser makes of it.
        #[rstest]
        fn reads_output_the_same_however_it_is_cut(
            data in stream(),
            splits in prop::collection::vec(any::<prop::sample::Index>(), 0..6),
        ) {
            let (events, _, at_ground) = push_split(&data, &splits);
            prop_assert_eq!((events, at_ground), (parse_events(&data), at_ground_after(&data)));
        }

        /// Bytes written where the parser claims ground must reach a real parser as text of their
        /// own, not as part of something the child started: `vte` given an `X` there prints just
        /// the `X`.
        #[rstest]
        fn agrees_with_vte_on_where_bytes_can_go(data in stream()) {
            let mut parser = vte::Parser::new();
            let mut reference = Reference::default();
            parser.advance(&mut reference, &data);

            if at_ground_after(&data) {
                reference.actions.clear();
                parser.advance(&mut reference, b"X");
                prop_assert_eq!(reference.actions, [Some('X')], "vte was mid-sequence after {:?}", data);
            }
        }
    }
}
