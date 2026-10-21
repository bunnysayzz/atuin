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

const ESC: u8 = 0x1B;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1A;

/// An event with the slice of data up to the end of its command.
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

/// A read of the child's output, with what the parser found in it.
///
/// Concatenating [`EventChunk::data`] for every chunk, followed by [`Self::trailing_data`],
/// exactly reproduces [`Self::data`].
#[derive(Debug)]
pub struct Output {
    data: Vec<u8>,
    /// Each event, with where its command ends in `data`.
    events: Vec<Found>,
    at_ground: bool,
}

impl Output {
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The output, cut after each command the proxy follows.
    pub fn chunks(&self) -> impl Iterator<Item = EventChunk<'_>> {
        let starts = std::iter::once(0).chain(self.events.iter().map(|found| found.end));
        self.events.iter().zip(starts).map(|(found, start)| EventChunk {
            event: found.event,
            data: &self.data[start..found.end],
            osc_len: found.osc_len,
        })
    }

    /// The output after the last command the proxy follows.
    pub fn trailing_data(&self) -> &[u8] {
        &self.data[self.events.last().map_or(0, |found| found.end)..]
    }

    /// Whether the output ends between sequences and characters, where bytes of the proxy's own
    /// can't change the meaning of the child's.
    pub const fn at_ground(&self) -> bool {
        self.at_ground
    }
}

/// An event, and where its command ends in the output it was found in.
#[derive(Debug, Clone, Copy)]
struct Found {
    event: Event,
    end: usize,
    osc_len: usize,
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

/// A streaming parser for the child's output.
///
/// Feed each read of the output into [`Parser::read`], however the reads cut it. The parser returns
/// the read as an [`Output`], with the [`Event`]s of the commands it follows.
pub struct Parser {
    state: State,
    command: Command,
}

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

    /// Follow `data`, the next read of the child's output.
    pub fn read(&mut self, data: Vec<u8>) -> Output {
        let mut events = Vec::new();
        let mut end = 0;
        loop {
            let (scanned, event) = self.scan(&data[end..]);
            end += scanned;
            let Some(event) = event else {
                break;
            };
            events.push(Found {
                event,
                end,
                osc_len: self.command.len,
            });
        }
        Output {
            data,
            events,
            at_ground: self.state == State::GROUND,
        }
    }

    /// Follow `data` up to the end of the first command the proxy follows, returning how much of
    /// `data` that took and what the command said, or all of `data` and nothing.
    fn scan(&mut self, data: &[u8]) -> (usize, Option<Event>) {
        let mut rest = data;
        loop {
            match self.state {
                // Plain text is most of any output, and only an `ESC` leads out of it. Searching
                // for it with memchr is a ~10X improvement over stepping through the text.
                State::Ground { continuation } => {
                    let Some(escape) = memchr::memchr(ESC, rest) else {
                        self.state = State::Ground {
                            continuation: Self::continuation_after(continuation, rest),
                        };
                        return (data.len(), None);
                    };
                    self.state = State::Escape;
                    rest = &rest[escape + 1..];
                }
                // Only these lead out of a command's text.
                State::Osc => {
                    let end = rest
                        .iter()
                        .position(|byte| matches!(*byte, BEL | ESC | CAN | SUB))
                        .unwrap_or(rest.len());
                    let (text, tail) = rest.split_at(end);
                    self.command.push(text);
                    rest = tail;
                }
                State::Escape
                | State::EscapeIntermediate
                | State::Csi
                | State::OscEscape
                | State::ControlString => {}
            }
            let Some((&byte, tail)) = rest.split_first() else {
                return (data.len(), None);
            };
            rest = tail;
            if let Some(event) = self.advance(byte) {
                return (data.len() - rest.len(), Some(event));
            }
        }
    }

    /// Follow one byte, returning what the command it terminated said.
    fn advance(&mut self, byte: u8) -> Option<Event> {
        self.state = match (self.state, byte) {
            (State::Ground { .. }, ESC) => State::Escape,
            (State::Ground { continuation }, _) => State::Ground {
                continuation: Self::continuation_after(continuation, &[byte]),
            },
            (State::Osc, BEL) => {
                self.state = State::GROUND;
                return self.command.end(1);
            }
            (State::OscEscape, b'\\') => {
                self.state = State::GROUND;
                return self.command.end(2);
            }
            // These two end any sequence, an unfinished command included.
            (_, CAN | SUB) => State::GROUND,
            (State::Osc, ESC) => State::OscEscape,
            (_, ESC) => State::Escape,
            (State::Escape | State::OscEscape, 0x20..=0x2F) => State::EscapeIntermediate,
            (State::Escape | State::OscEscape, b'[') => State::Csi,
            (State::Escape | State::OscEscape, b']') => {
                self.command = Command::begun();
                State::Osc
            }
            (State::Escape | State::OscEscape, b'P' | b'X' | b'^' | b'_') => State::ControlString,
            (State::Escape | State::OscEscape | State::EscapeIntermediate, 0x30..=0x7E)
            | (State::Csi, 0x40..=0x7E) => State::GROUND,
            (State::Osc, _) => {
                self.command.push(&[byte]);
                State::Osc
            }
            // A control after the `ESC` ends the command, though not the escape.
            (State::OscEscape, _) => State::Escape,
            // Anything else leaves a sequence where it was: its parameters, intermediates and
            // text, and the controls a terminal runs or ignores in the middle of it.
            (state, _) => state,
        };
        None
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

    /// The full result of one [`Parser::read`] call.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Read {
        chunks: Vec<OwnedChunk>,
        trailing_data: Vec<u8>,
        at_ground: bool,
    }

    impl Read {
        fn events(&self) -> Vec<Event> {
            self.chunks.iter().map(|chunk| chunk.event).collect()
        }
    }

    fn read(parser: &mut Parser, data: &[u8]) -> Read {
        let output = parser.read(data.to_vec());
        Read {
            chunks: output
                .chunks()
                .map(|chunk| OwnedChunk {
                    event: chunk.event,
                    data: chunk.data.to_vec(),
                    osc_len: chunk.osc_len,
                })
                .collect(),
            trailing_data: output.trailing_data().to_vec(),
            at_ground: output.at_ground(),
        }
    }

    /// Read `data` with a fresh parser.
    fn parse(data: &[u8]) -> Read {
        read(&mut Parser::new(), data)
    }

    /// Collect all events from a single read.
    fn parse_events(data: &[u8]) -> Vec<Event> {
        parse(data).events()
    }

    /// Whether a fresh parser given `data` ends up between sequences and characters.
    fn at_ground_after(data: &[u8]) -> bool {
        parse(data).at_ground
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
    fn reports_the_length_of_the_marker() {
        let marker = end(HID);
        let result = parse(&[b"output".as_slice(), &marker].concat());

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunks[0].osc_len, marker.len());
    }

    #[rstest]
    #[case::bel(b"\x1b]2;title\x07", true)]
    #[case::string_terminator(b"\x1b]2;title\x1b\\", true)]
    #[case::control_in_the_number(b"\x1b]\x052;title\x07", true)]
    #[case::ended_by_cancel(b"\x1b]2;title\x18", false)]
    #[case::ended_by_another_sequence(b"\x1b]2;title\x1b[m", false)]
    #[case::unfinished(b"\x1b]2;title", false)]
    #[case::inside_a_device_control_string(b"\x1bPq]2;title\x07\x1b\\", false)]
    fn detects_titles(#[case] data: &[u8], #[case] titled: bool) {
        assert_eq!(parse_events(data).contains(&Event::Title), titled);
    }

    // -- Multiple events / interleaved text in one read -----------------------

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
    fn splits_data_after_each_marker(
        #[values(b"\x07".as_slice(), b"\x1b\\".as_slice())] terminator: &[u8],
    ) {
        // A chunk that stopped one byte short would leave the marker looking unterminated to
        // whoever replays the data, and drop its final byte into the next chunk.
        let opening = [format!("\x1b]18188735;C;{HID}").as_bytes(), terminator].concat();
        let closing = [format!("\x1b]18188735;D;{HID}").as_bytes(), terminator].concat();
        let data = [b"before".as_slice(), &opening, b"between", &closing, b"after"].concat();

        let result = parse(&data);
        let chunks: Vec<_> = result.chunks.iter().map(|chunk| chunk.data.clone()).collect();
        assert_eq!(chunks, vec![
            [b"before".as_slice(), &opening].concat(),
            [b"between".as_slice(), &closing].concat(),
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
    fn a_marker_split_across_reads_is_reported_by_the_completing_read() {
        let (head, tail) = HID.split_at(20);
        let mut parser = Parser::new();

        let first = read(&mut parser, format!("out\x1b]18188735;D;{head}").as_bytes());
        assert!(first.chunks.is_empty());
        assert_eq!(first.trailing_data, format!("out\x1b]18188735;D;{head}").as_bytes());

        let second = read(&mut parser, format!("{tail}\x07rest").as_bytes());
        assert_eq!(second.events(), vec![Event::OutputEnd(hid(HID))]);
        assert_eq!(second.chunks[0].data, format!("{tail}\x07").as_bytes());
        assert_eq!(second.trailing_data, b"rest");
    }

    // -- Input that must not produce events -----------------------------------

    #[rstest]
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

    /// What reading `data` split at the given points made of it: every event, every byte handed
    /// back, and whether it ended at ground.
    fn read_split(data: &[u8], splits: &[prop::sample::Index]) -> (Vec<Event>, Vec<u8>, bool) {
        let mut cuts: Vec<usize> = splits.iter().map(|index| index.index(data.len() + 1)).collect();
        cuts.push(0);
        cuts.push(data.len());
        cuts.sort_unstable();

        let mut parser = Parser::new();
        let mut events = Vec::new();
        let mut rebuilt = Vec::new();
        let mut at_ground = true;
        for window in cuts.windows(2) {
            let result = read(&mut parser, &data[window[0]..window[1]]);
            events.extend(result.events());
            for chunk in result.chunks {
                rebuilt.extend(chunk.data);
            }
            rebuilt.extend(result.trailing_data);
            at_ground = result.at_ground;
        }
        (events, rebuilt, at_ground)
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
            let (_, rebuilt, _) = read_split(&data, &splits);
            prop_assert_eq!(rebuilt, data);
        }

        /// Output reaches the proxy in whatever pieces the pty hands over, so where it is cut must
        /// make no difference to what the parser makes of it.
        #[rstest]
        fn reads_output_the_same_however_it_is_cut(
            data in stream(),
            splits in prop::collection::vec(any::<prop::sample::Index>(), 0..6),
        ) {
            let (events, _, at_ground) = read_split(&data, &splits);
            prop_assert_eq!((events, at_ground), (parse_events(&data), at_ground_after(&data)));
        }

        /// The parser is at ground exactly where bytes reach a real parser as text of their own,
        /// not as part of something the child started: where `vte` given an `X` prints just the
        /// `X`.
        #[rstest]
        fn agrees_with_vte_on_where_bytes_can_go(data in stream()) {
            let mut parser = vte::Parser::new();
            let mut reference = Reference::default();
            parser.advance(&mut reference, &data);
            reference.actions.clear();
            parser.advance(&mut reference, b"X");
            let vte_at_ground = reference.actions == [Some('X')];

            // Where the stream breaks UTF-8, the parser may still wait for the rest of a character
            // `vte` has already given up on. Waiting is safe; the other way round is not.
            let at_ground = at_ground_after(&data);
            if at_ground || std::str::from_utf8(&data).is_ok() {
                prop_assert_eq!(at_ground, vte_at_ground, "after {:?}", data);
            }
        }
    }
}
