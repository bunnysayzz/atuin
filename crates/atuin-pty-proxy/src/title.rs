//! Names the program in the foreground in the title of the terminal the proxy runs in.
//!
//! A terminal that names the program running in it, in a tab or a window title, finds the proxy in
//! the foreground of its pty and shows `atuin` whatever the user runs. The proxy does what tmux's
//! `automatic-rename` does for a window name: it looks at the foreground process group of the pty
//! its child runs on, at most every 500ms while there is output and every second without, and
//! titles the terminal (`OSC 0`) with the name of the group's leader.
//!
//! A title the child sets itself, with `OSC 0`, `1` or `2`, wins over the proxy's. tmux keeps a
//! window's name apart from its pane's title and never has to choose; the proxy does:
//!
//! * One the shell sets stands until a program sets another. A shell that titles the terminal
//!   keeps doing so around the commands it runs.
//! * One a program sets stands while its process group stays in the foreground, and the proxy
//!   takes over again once it has gone, rather than leave a finished program's title behind.
//!
//! The [`ForegroundUpdater`](crate::foreground::ForegroundUpdater) looks, and hands the [`Leader`]
//! it finds to the task that forwards the child's output. That task writes the title between two of
//! its writes, once [`TerminalTitle`], which follows the output, says the title would land outside
//! of any escape sequence.

use std::ffi::OsStr;

use atuin_common::os::unix::process;
use rustix::process::Pid;

use crate::foreground::Foreground;
use crate::parser::{Event, Parser};

/// The leader of the process group in the foreground, as a look at the foreground found it.
pub struct Leader {
    group: Pid,
    /// The leader's name, fit for a title.
    name: String,
}

impl Leader {
    /// The leader of the process group in `foreground`'s foreground, if it can be named.
    ///
    /// Blocks: the name is read from the process table.
    pub fn of(foreground: &Foreground) -> Option<Self> {
        let group = foreground.group()?;
        let name = Self::printable(&process::name(group)?)?;
        Some(Self { group, name })
    }

    /// `name` without its control characters, if anything is left.
    ///
    /// A process can call itself anything, and a control character would end the title early and
    /// leave the rest of the name for the terminal to run.
    fn printable(name: &OsStr) -> Option<String> {
        let name: String = name.to_string_lossy().chars().filter(|c| !c.is_control()).collect();
        (!name.is_empty()).then_some(name)
    }
}

/// Who set the title the terminal shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// The proxy, or nobody yet.
    Proxy,
    /// The shell, until a program sets a title.
    Shell,
    /// The program leading this process group, while the group is in the foreground.
    Program(Pid),
}

impl Owner {
    /// The owner of a title set while `group` was in the foreground of `shell`'s pty.
    fn of_title_set_with(group: Option<Pid>, shell: Option<Pid>) -> Self {
        match group {
            Some(group) if Some(group) != shell => Self::Program(group),
            // With nothing in the foreground to own it, the title is safest with the shell, which
            // keeps it the longest.
            _ => Self::Shell,
        }
    }

    /// The owner once `group` is in the foreground.
    fn with_foreground(self, group: Pid) -> Self {
        match self {
            Self::Program(program) if program != group => Self::Proxy,
            Self::Proxy | Self::Shell | Self::Program(_) => self,
        }
    }
}

/// What the proxy knows of the terminal's title, from following everything written to it.
pub struct TerminalTitle {
    foreground: Foreground,
    /// Follows everything written to the terminal so far.
    output: Parser,
    owner: Owner,
    /// The title the proxy set, while the terminal still shows it.
    shown: Option<String>,
}

impl TerminalTitle {
    pub fn new(foreground: Foreground) -> Self {
        Self {
            foreground,
            output: Parser::new(),
            owner: Owner::Proxy,
            shown: None,
        }
    }

    /// Follow the child's `data` on its way to the terminal.
    pub fn track(&mut self, data: &[u8]) {
        if self.output.push(data).any(|chunk| chunk.event == Event::Title) {
            // The program that set the title has most likely not left the foreground yet.
            self.owner = Owner::of_title_set_with(self.foreground.group(), self.foreground.child());
            self.shown = None;
        }
    }

    /// The sequence that titles the terminal after `leader`, unless the child's own title stands or
    /// the terminal shows that title already.
    ///
    /// The sequence must reach the terminal before any more of the child's output.
    pub fn retitle(&mut self, leader: Leader) -> Option<Vec<u8>> {
        // A program may have taken the foreground, and set a title that must stand, since the look
        // that found `leader`. The next look names it.
        if self.foreground.group() != Some(leader.group) || !self.output.at_ground() {
            return None;
        }
        self.owner = self.owner.with_foreground(leader.group);
        if self.owner != Owner::Proxy || self.shown.as_ref() == Some(&leader.name) {
            return None;
        }
        let sequence = format!("\x1b]0;{}\x07", leader.name).into_bytes();
        self.shown = Some(leader.name);
        Some(sequence)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use rstest::{fixture, rstest};

    use super::*;
    use crate::foreground;

    const SHELL: i32 = 100;
    const VIM: i32 = 200;
    const LESS: i32 = 300;

    fn pid(raw: i32) -> Pid {
        Pid::from_raw(raw).expect("a test pid is positive")
    }

    #[rstest]
    #[case::by_the_shell(Some(SHELL), Some(SHELL), Owner::Shell)]
    #[case::by_a_program(Some(VIM), Some(SHELL), Owner::Program(pid(VIM)))]
    #[case::by_a_program_of_an_unknown_shell(Some(VIM), None, Owner::Program(pid(VIM)))]
    #[case::with_nothing_in_the_foreground(None, Some(SHELL), Owner::Shell)]
    fn a_title_belongs_to_whoever_was_in_the_foreground(
        #[case] group: Option<i32>,
        #[case] shell: Option<i32>,
        #[case] owner: Owner,
    ) {
        assert_eq!(Owner::of_title_set_with(group.map(pid), shell.map(pid)), owner);
    }

    #[rstest]
    #[case::program_still_in_the_foreground(
        Owner::Program(pid(VIM)),
        VIM,
        Owner::Program(pid(VIM))
    )]
    #[case::program_gone_back_to_the_shell(Owner::Program(pid(VIM)), SHELL, Owner::Proxy)]
    #[case::program_gone_to_another(Owner::Program(pid(VIM)), LESS, Owner::Proxy)]
    #[case::shell_while_a_program_runs(Owner::Shell, VIM, Owner::Shell)]
    #[case::proxy(Owner::Proxy, VIM, Owner::Proxy)]
    fn only_a_programs_title_lapses_when_it_leaves_the_foreground(
        #[case] owner: Owner,
        #[case] group: i32,
        #[case] expected: Owner,
    ) {
        assert_eq!(owner.with_foreground(pid(group)), expected);
    }

    #[rstest]
    #[case::plain("vim", Some("vim"))]
    #[case::escape("vim\x1b]0;pwned\x07", Some("vim]0;pwned"))]
    #[case::newline("vim\n", Some("vim"))]
    #[case::c1_terminator("vim\u{9c}", Some("vim"))]
    #[case::unicode("ñvim", Some("ñvim"))]
    #[case::only_controls("\x1b\x07", None)]
    #[case::empty("", None)]
    fn titles_carry_no_control_characters(#[case] name: &str, #[case] expected: Option<&str>) {
        assert_eq!(Leader::printable(OsStr::new(name)).as_deref(), expected);
    }

    /// `/bin/sh` on a pty of its own, and the title of a terminal its output goes to.
    struct Shell {
        title: TerminalTitle,
        pid: Pid,
        /// The terminal, for typing at the shell.
        input: File,
        child: Box<dyn portable_pty::Child + Send + Sync>,
    }

    impl Shell {
        /// Wait for the foreground to be `shell`'s, or not, then return it.
        fn foreground_settles(&self, shells: bool) -> Pid {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(group) = self.title.foreground.group()
                    && (group == self.pid) == shells
                {
                    return group;
                }
                assert!(Instant::now() < deadline, "the foreground never changed hands");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Run `sleep` in the foreground and wait for it to get there.
        fn sleep(&mut self) {
            writeln!(self.input, "sleep 30").expect("write to pty");
            let group = self.foreground_settles(false);
            // The shell hands the foreground to its child before the child execs `sleep`.
            let deadline = Instant::now() + Duration::from_secs(10);
            while process::name(group).as_deref() != Some(OsStr::new("sleep")) {
                assert!(Instant::now() < deadline, "the shell's child never became sleep");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// Interrupt the program in the foreground and wait for the shell to take it back.
        fn interrupt(&mut self) {
            self.input.write_all(&[0x03]).expect("write to pty");
            self.foreground_settles(true);
        }

        /// Look at the foreground, as the updater does.
        fn leader(&self) -> Leader {
            Leader::of(&self.title.foreground).expect("the foreground has a leader")
        }

        /// What the proxy writes to the terminal after looking at the foreground now.
        fn retitle(&mut self) -> Option<Vec<u8>> {
            let leader = self.leader();
            self.title.retitle(leader)
        }

        fn titled(name: &str) -> Vec<u8> {
            format!("\x1b]0;{name}\x07").into_bytes()
        }

        fn shell_title(&self) -> Vec<u8> {
            let name = process::name(self.pid).expect("the shell has a name");
            Self::titled(&name.to_string_lossy())
        }
    }

    impl Drop for Shell {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[fixture]
    fn shell() -> Shell {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("failed to open pty");
        let child = pair.slave.spawn_command(CommandBuilder::new("/bin/sh")).expect("spawn shell");
        drop(pair.slave);

        // A shell whose output has nowhere to go stalls once the pty fills.
        let mut drain = pair.master.try_clone_reader().expect("clone pty reader");
        let (printed, prompt) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while drain.read(&mut buf).is_ok_and(|read| read > 0) {
                let _ = printed.send(());
            }
        });
        // Until then, the shell may not have exec'd, and is named after the test.
        prompt.recv_timeout(Duration::from_secs(10)).expect("the shell never printed a prompt");

        let pid = Pid::from_raw(child.process_id().expect("shell pid").cast_signed()).unwrap();
        let shell = Shell {
            title: TerminalTitle::new(Foreground::new(pair.master.as_ref(), Some(pid))),
            pid,
            input: File::from(foreground::pty_parent_fd(pair.master.as_ref()).unwrap()),
            child,
        };
        shell.foreground_settles(true);
        shell
    }

    #[rstest]
    fn names_the_program_in_the_foreground(mut shell: Shell) {
        assert_eq!(shell.retitle(), Some(shell.shell_title()));

        shell.sleep();
        assert_eq!(shell.retitle(), Some(Shell::titled("sleep")));
    }

    #[rstest]
    fn does_not_repeat_a_title_the_terminal_shows(mut shell: Shell) {
        assert_eq!(shell.retitle(), Some(shell.shell_title()));
        assert_eq!(shell.retitle(), None);
    }

    #[rstest]
    fn a_look_the_foreground_has_moved_on_from_titles_nothing(mut shell: Shell) {
        // The updater looks off the thread that writes, so a program can take the foreground
        // before what the look found is written.
        let stale = shell.leader();
        shell.sleep();

        assert_eq!(shell.title.retitle(stale), None);
    }

    #[rstest]
    fn a_programs_title_stands_until_it_leaves_the_foreground(mut shell: Shell) {
        shell.sleep();
        // What vim's `set title` sends.
        shell.title.track(b"\x1b]2;file.txt - VIM\x07");
        assert_eq!(shell.retitle(), None);

        shell.interrupt();
        assert_eq!(shell.retitle(), Some(shell.shell_title()));
    }

    #[rstest]
    fn a_title_the_shell_sets_stands_while_its_commands_run(mut shell: Shell) {
        shell.title.track(b"\x1b]0;~/project\x07");
        assert_eq!(shell.retitle(), None);

        shell.sleep();
        assert_eq!(shell.retitle(), None);

        shell.interrupt();
        assert_eq!(shell.retitle(), None);
    }

    #[rstest]
    fn titles_wait_for_an_escape_sequence_to_finish(mut shell: Shell) {
        shell.title.track(b"\x1b[3");
        assert_eq!(shell.retitle(), None);

        shell.title.track(b"1m");
        assert_eq!(shell.retitle(), Some(shell.shell_title()));
    }
}
