//! The wire format between the injected hook payload and the analyst-side tools.
//!
//! Everything here is deliberately dependency-light: the payload links this
//! module with `default-features = false` so nothing in the injected DLL pulls in
//! a binary parser. The format is JSON Lines - one self-contained record per
//! line, flushed as it is produced - so a trace stays readable even when the
//! target crashes or kills itself halfway through.

use serde::{Deserialize, Serialize};

use crate::entropy::Stats;

/// Format version. Bumped whenever a field changes meaning; the CLI refuses a
/// trace it does not understand rather than silently misreading it.
pub const TRACE_VERSION: u32 = 1;

/// Where in the hijacked call this record was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Captured at the function's first instruction, before it ran.
    Entry,
    /// Captured after the original function returned, before control goes back
    /// to the caller. This is where an in-place decrypt becomes observable.
    Return,
}

/// One captured buffer, with the statistics that make it interesting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Buffer {
    /// The argument name from the signature rule that named it.
    pub name: String,
    /// Address in the target's address space.
    pub addr: u64,
    /// Length actually read (may be less than the reported length if the capture
    /// was clamped by `max_bytes` or truncated by an unreadable page).
    pub len: usize,
    /// Length the target claimed, before clamping.
    pub reported_len: usize,
    pub stats: Stats,
    pub sha256: String,
    /// Path of the dump on disk, relative to the capture directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dump: Option<String>,
    /// Set when the buffer could not be read in full.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<String>,
}

/// A scalar argument recovered from a register or the stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scalar {
    pub name: String,
    pub value: u64,
}

/// One hook firing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub version: u32,
    /// Monotonic counter, assigned by the payload. Entry and Return records for
    /// the same call share a `call_id`.
    pub seq: u64,
    pub call_id: u64,
    /// Nanoseconds since the payload started. Wall-clock is deliberately not
    /// recorded; a sample that fingerprints its analysis window should not get
    /// a free signal from us.
    pub elapsed_ns: u64,
    pub thread_id: u64,
    /// The `id` of the rule that placed this hook.
    pub target_id: String,
    pub symbol: String,
    pub function_va: u64,
    pub phase: Phase,
    /// The caller's return address, so an analyst can walk back to the caller.
    pub return_address: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scalars: Vec<Scalar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buffers: Vec<Buffer>,
}

/// Non-fatal problems the payload wants the analyst to see, interleaved with
/// events in the same stream so ordering is preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub version: u32,
    pub seq: u64,
    pub elapsed_ns: u64,
    pub level: NoteLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteLevel {
    Info,
    Warning,
    Error,
}

impl NoteLevel {
    pub fn label(self) -> &'static str {
        match self {
            NoteLevel::Info => "INFO",
            NoteLevel::Warning => "WARNING",
            NoteLevel::Error => "ERROR",
        }
    }
}

/// A line in the trace stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum Record {
    Event(Event),
    Note(Note),
}

impl Record {
    pub fn version(&self) -> u32 {
        match self {
            Record::Event(e) => e.version,
            Record::Note(n) => n.version,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            Record::Event(e) => e.seq,
            Record::Note(n) => n.seq,
        }
    }

    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Parse a JSON Lines trace, skipping blank lines.
///
/// A malformed line is reported with its 1-based line number rather than
/// aborting the whole parse, because a truncated final line is the normal
/// outcome when a sample terminates the process mid-write.
pub fn parse_lines(input: &str) -> (Vec<Record>, Vec<String>) {
    let mut records = Vec::new();
    let mut problems = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Record>(line) {
            Ok(r) => {
                if r.version() != TRACE_VERSION {
                    problems.push(format!(
                        "line {}: trace version {} is not supported (expected {})",
                        i + 1,
                        r.version(),
                        TRACE_VERSION
                    ));
                    continue;
                }
                records.push(r);
            }
            Err(e) => problems.push(format!("line {}: {}", i + 1, e)),
        }
    }
    (records, problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{Class, Stats};

    fn stats() -> Stats {
        Stats {
            len: 16,
            entropy: 7.9,
            chi_square: 255.0,
            printable_ratio: 0.0,
            distinct_bytes: 16,
            class: Class::Encrypted,
        }
    }

    fn event(seq: u64, phase: Phase) -> Event {
        Event {
            version: TRACE_VERSION,
            seq,
            call_id: 1,
            elapsed_ns: seq * 1000,
            thread_id: 42,
            target_id: "rust.crypto.demo".into(),
            symbol: "demo::decrypt".into(),
            function_va: 0x1400_1000,
            phase,
            return_address: 0x1400_2000,
            scalars: vec![Scalar {
                name: "len".into(),
                value: 16,
            }],
            buffers: vec![Buffer {
                name: "buffer".into(),
                addr: 0x2000,
                len: 16,
                reported_len: 16,
                stats: stats(),
                sha256: "00".into(),
                dump: Some("blobs/0001.bin".into()),
                truncated_reason: None,
            }],
        }
    }

    #[test]
    fn records_round_trip_through_jsonl() {
        let line = Record::Event(event(1, Phase::Entry)).to_line().unwrap();
        assert!(
            !line.contains('\n'),
            "a record must occupy exactly one line"
        );
        let (records, problems) = parse_lines(&line);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(records.len(), 1);
        match &records[0] {
            Record::Event(e) => {
                assert_eq!(e.phase, Phase::Entry);
                assert_eq!(e.buffers[0].name, "buffer");
            }
            _ => panic!("expected an event"),
        }
    }

    #[test]
    fn a_truncated_tail_does_not_discard_earlier_records() {
        let good = Record::Event(event(1, Phase::Entry)).to_line().unwrap();
        let input = format!("{good}\n{{\"record\":\"event\",\"vers");
        let (records, problems) = parse_lines(&input);
        assert_eq!(records.len(), 1);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].starts_with("line 2:"));
    }

    #[test]
    fn a_future_version_is_refused_rather_than_misread() {
        let mut e = event(1, Phase::Entry);
        e.version = TRACE_VERSION + 1;
        let (records, problems) = parse_lines(&Record::Event(e).to_line().unwrap());
        assert!(records.is_empty());
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("not supported"));
    }

    #[test]
    fn notes_and_events_share_the_stream() {
        let note = Record::Note(Note {
            version: TRACE_VERSION,
            seq: 2,
            elapsed_ns: 5,
            level: NoteLevel::Warning,
            message: "prologue was not hot-patchable".into(),
        });
        let input = format!(
            "{}\n{}\n",
            Record::Event(event(1, Phase::Entry)).to_line().unwrap(),
            note.to_line().unwrap()
        );
        let (records, problems) = parse_lines(&input);
        assert!(problems.is_empty());
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].seq(), 2);
    }
}
