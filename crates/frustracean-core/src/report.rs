//! Correlating a raw trace into the thing an analyst actually wants: a list of
//! moments where opaque bytes became readable ones, and what they turned into.
//!
//! The trace is a flat stream of entry/return records. A hijacked call is only
//! *evidence* of unpacking when the same buffer is measurably less random on the
//! way out than it was on the way in - so the report pairs records by `call_id`,
//! computes an entropy delta per buffer, and ranks by how much was recovered.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::entropy::{Class, Delta};
use crate::signature::{Comparison, Expect};
use crate::trace::{Buffer, Event, NoteLevel, Phase, Record};

/// One buffer observed across a complete hijacked call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackEvent {
    pub call_id: u64,
    pub target_id: String,
    pub symbol: String,
    pub thread_id: u64,
    pub buffer: String,
    pub delta: Delta,
    pub class_before: Class,
    pub class_after: Class,
    pub bytes: usize,
    pub sha256_before: String,
    pub sha256_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dump: Option<String>,
    /// The entropy moved the way the rule said it would.
    pub met_expectation: bool,
    /// Entropy fell far enough to call this a genuine unpack.
    pub confirmed: bool,
}

impl UnpackEvent {
    /// How interesting this is, for ranking. Recovered volume matters, but a
    /// large entropy drop on a small buffer (a decrypted C2 URL, say) is worth
    /// more than a marginal drop on a large one.
    ///
    /// The magnitude of the move is used, not the signed drop: an encrypt hook
    /// catching data on its way out is as much a finding as a decrypt hook
    /// catching it on the way in.
    pub fn score(&self) -> f64 {
        let magnitude = (self.bytes as f64).max(1.0).log2();
        self.delta.drop().abs() * magnitude
    }

    /// Which way this went, in a word. An `entropy_rise` target is confirming a
    /// *pack*, and calling that an unpack in the report is simply wrong.
    pub fn direction(&self) -> &'static str {
        if self.delta.drop() > 0.0 {
            "unpack"
        } else if self.delta.drop() < 0.0 {
            "pack"
        } else {
            "no change"
        }
    }
}

/// A call that fired but produced no usable pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncompleteCall {
    pub call_id: u64,
    pub target_id: String,
    pub symbol: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub records: usize,
    pub calls: usize,
    pub complete_calls: usize,
    /// Buffer transitions observed, in either direction.
    pub transitions: usize,
    /// Transitions that moved the way their rule predicted, far enough to mean it.
    pub confirmed_transitions: usize,
    /// Bytes captured across confirmed transitions.
    pub bytes_recovered: usize,
    pub distinct_blobs: usize,
    pub notes_by_level: BTreeMap<String, usize>,
    /// Target id -> number of times it fired.
    pub calls_by_target: BTreeMap<String, usize>,
}

/// A note from the payload, kept with its level so the renderer can decide how
/// to present it rather than receiving a pre-formatted string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportNote {
    pub level: NoteLevel,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub summary: Summary,
    pub events: Vec<UnpackEvent>,
    pub incomplete: Vec<IncompleteCall>,
    pub notes: Vec<ReportNote>,
}

/// What a rule predicted for one target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetExpectation {
    pub expect: Expect,
    /// Set when the transition spans two different buffers.
    pub compare: Option<Comparison>,
}

/// Expectation lookup: target id -> what its rule predicted. Passing this in
/// keeps `report` independent of the signature catalogue at replay time, so an
/// old trace can be re-read without the rules that produced it.
pub type Expectations = BTreeMap<String, TargetExpectation>;

/// Did this transition actually demonstrate what the rule predicted?
///
/// The input must have been opaque, by *either* measure: a raw entropy at or
/// above [`crate::entropy::Delta::is_unpack`]'s bar, or a classification that
/// says compressed/encrypted. The second clause matters for chained stages -
/// DEFLATE output feeding a decompressor often sits near 6.5, below the raw
/// threshold, but the chi-square corroborator has already identified it as
/// compressed rather than as ordinary data.
fn confirms(expect: Expect, delta: Delta, before: Class, after: Class) -> bool {
    const MIN_MOVE: f64 = 1.0;
    match expect {
        Expect::EntropyDrop => {
            (delta.is_unpack()) || (before.is_opaque() && delta.drop() >= MIN_MOVE)
        }
        // The mirror image: opaque on the way out, having not been on the way in.
        Expect::EntropyRise => {
            (delta.after >= 7.0 || after.is_opaque())
                && !before.is_opaque()
                && delta.drop() <= -MIN_MOVE
        }
        Expect::Any => delta.drop().abs() >= MIN_MOVE,
    }
}

/// Correlate a parsed trace.
pub fn build(records: &[Record], expectations: &Expectations) -> Report {
    let mut summary = Summary {
        records: records.len(),
        ..Default::default()
    };
    let mut notes = Vec::new();
    let mut calls: BTreeMap<u64, (Option<Event>, Option<Event>)> = BTreeMap::new();

    for record in records {
        match record {
            Record::Note(n) => {
                *summary
                    .notes_by_level
                    .entry(n.level.label().to_string())
                    .or_default() += 1;
                if n.level != NoteLevel::Info {
                    notes.push(ReportNote {
                        level: n.level,
                        message: n.message.clone(),
                    });
                }
            }
            Record::Event(e) => {
                let slot = calls.entry(e.call_id).or_insert((None, None));
                match e.phase {
                    Phase::Entry => slot.0 = Some(e.clone()),
                    Phase::Return => slot.1 = Some(e.clone()),
                }
            }
        }
    }

    summary.calls = calls.len();
    let mut events = Vec::new();
    let mut incomplete = Vec::new();
    let mut blob_hashes = std::collections::BTreeSet::new();

    for (call_id, (entry, ret)) in calls {
        let (entry, ret) = match (entry, ret) {
            (Some(a), Some(b)) => (a, b),
            (Some(a), None) => {
                incomplete.push(IncompleteCall {
                    call_id,
                    target_id: a.target_id.clone(),
                    symbol: a.symbol.clone(),
                    reason: "entered but never returned - the call did not complete, or the \
                             sample terminated inside it"
                        .into(),
                });
                *summary.calls_by_target.entry(a.target_id).or_default() += 1;
                continue;
            }
            (None, Some(b)) => {
                incomplete.push(IncompleteCall {
                    call_id,
                    target_id: b.target_id.clone(),
                    symbol: b.symbol.clone(),
                    reason: "returned without a matching entry record".into(),
                });
                *summary.calls_by_target.entry(b.target_id).or_default() += 1;
                continue;
            }
            (None, None) => continue,
        };

        summary.complete_calls += 1;
        *summary
            .calls_by_target
            .entry(entry.target_id.clone())
            .or_default() += 1;

        let expectation = expectations
            .get(&entry.target_id)
            .cloned()
            .unwrap_or_default();
        let expect = expectation.expect;

        let before_by_name: BTreeMap<&str, &Buffer> =
            entry.buffers.iter().map(|b| (b.name.as_str(), b)).collect();
        let after_by_name: BTreeMap<&str, &Buffer> =
            ret.buffers.iter().map(|b| (b.name.as_str(), b)).collect();

        // Either the rule names two different buffers, or every buffer present
        // on both sides is compared against itself.
        let pairs: Vec<(&Buffer, &Buffer, String)> = match &expectation.compare {
            Some(Comparison { from, to }) => {
                match (
                    before_by_name.get(from.as_str()),
                    after_by_name.get(to.as_str()),
                ) {
                    (Some(b), Some(a)) => vec![(*b, *a, format!("{from} -> {to}"))],
                    _ => Vec::new(),
                }
            }
            None => ret
                .buffers
                .iter()
                .filter_map(|a| {
                    before_by_name
                        .get(a.name.as_str())
                        .map(|b| (*b, a, a.name.clone()))
                })
                .collect(),
        };

        if pairs.is_empty() {
            incomplete.push(IncompleteCall {
                call_id,
                target_id: entry.target_id.clone(),
                symbol: entry.symbol.clone(),
                reason: match &expectation.compare {
                    Some(c) => format!(
                        "the rule compares {} on entry against {} on return, and at least one \
                         of them was not captured",
                        c.from, c.to
                    ),
                    None => "no buffer was captured on both entry and return".into(),
                },
            });
        }

        for (before, after, label) in pairs {
            let delta = Delta {
                before: before.stats.entropy,
                after: after.stats.entropy,
            };
            let met = match expect {
                Expect::EntropyDrop => delta.drop() > 0.0,
                Expect::EntropyRise => delta.drop() < 0.0,
                Expect::Any => true,
            };
            let confirmed = confirms(expect, delta, before.stats.class, after.stats.class);
            if confirmed {
                summary.confirmed_transitions += 1;
                summary.bytes_recovered += after.len;
            }
            blob_hashes.insert(after.sha256.clone());

            events.push(UnpackEvent {
                call_id,
                target_id: entry.target_id.clone(),
                symbol: entry.symbol.clone(),
                thread_id: entry.thread_id,
                buffer: label,
                delta,
                class_before: before.stats.class,
                class_after: after.stats.class,
                bytes: after.len,
                sha256_before: before.sha256.clone(),
                sha256_after: after.sha256.clone(),
                dump: after.dump.clone(),
                met_expectation: met,
                confirmed,
            });
        }
    }

    events.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.call_id.cmp(&b.call_id))
    });

    summary.transitions = events.len();
    summary.distinct_blobs = blob_hashes.len();

    Report {
        summary,
        events,
        incomplete,
        notes,
    }
}

/// Render a report as Markdown.
///
/// Deliberately plain: labelled lines and simple tables, no colour and no
/// box-drawing, so it reads the same in a terminal, a screen reader, and a
/// case-management system.
pub fn to_markdown(report: &Report) -> String {
    use std::fmt::Write;
    let mut s = String::new();

    let _ = writeln!(s, "# Frustracean trace report\n");
    let _ = writeln!(s, "## Summary\n");
    let _ = writeln!(s, "- Records: {}", report.summary.records);
    let _ = writeln!(
        s,
        "- Hijacked calls: {} ({} complete)",
        report.summary.calls, report.summary.complete_calls
    );
    let _ = writeln!(s, "- Buffer transitions: {}", report.summary.transitions);
    let _ = writeln!(
        s,
        "- Confirmed transitions: {}",
        report.summary.confirmed_transitions
    );
    let _ = writeln!(s, "- Bytes captured: {}", report.summary.bytes_recovered);
    let _ = writeln!(s, "- Distinct blobs: {}\n", report.summary.distinct_blobs);

    if !report.summary.calls_by_target.is_empty() {
        let _ = writeln!(s, "## Targets that fired\n");
        let _ = writeln!(s, "| Target | Calls |");
        let _ = writeln!(s, "| --- | --- |");
        for (target, count) in &report.summary.calls_by_target {
            let _ = writeln!(s, "| {target} | {count} |");
        }
        let _ = writeln!(s);
    }

    if report.events.is_empty() {
        let _ = writeln!(
            s,
            "No buffer was observed on both entry and return. Nothing was recovered.\n"
        );
    } else {
        let _ = writeln!(s, "## Entropy transitions\n");
        let _ = writeln!(
            s,
            "| Call | Target | Buffer | Bytes | Before | After | Change | Class | Direction | Confirmed | Dump |"
        );
        let _ = writeln!(
            s,
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
        );
        for e in &report.events {
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {:.2} | {:.2} | {:+.2} | {} -> {} | {} | {} | {} |",
                e.call_id,
                e.target_id,
                e.buffer,
                e.bytes,
                e.delta.before,
                e.delta.after,
                -e.delta.drop(),
                e.class_before.label(),
                e.class_after.label(),
                e.direction(),
                if e.confirmed { "yes" } else { "no" },
                e.dump.as_deref().unwrap_or("-")
            );
        }
        let _ = writeln!(s);
    }

    if !report.incomplete.is_empty() {
        let _ = writeln!(s, "## Incomplete calls\n");
        for c in &report.incomplete {
            let _ = writeln!(
                s,
                "- call {} ({}, {}): {}",
                c.call_id, c.target_id, c.symbol, c.reason
            );
        }
        let _ = writeln!(s);
    }

    if !report.notes.is_empty() {
        let _ = writeln!(s, "## Notes from the payload\n");
        for n in &report.notes {
            let _ = writeln!(s, "- {}: {}", n.level.label(), n.message);
        }
        let _ = writeln!(s);
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::Stats;
    use crate::trace::{Note, TRACE_VERSION};

    fn buf(name: &str, entropy: f64, class: Class, sha: &str, len: usize) -> Buffer {
        Buffer {
            name: name.into(),
            addr: 0x2000,
            len,
            reported_len: len,
            stats: Stats {
                len,
                entropy,
                chi_square: 255.0,
                printable_ratio: 0.0,
                distinct_bytes: 200,
                class,
            },
            sha256: sha.into(),
            dump: Some(format!("blobs/{sha}.bin")),
            truncated_reason: None,
        }
    }

    fn ev(call_id: u64, phase: Phase, buffers: Vec<Buffer>) -> Record {
        Record::Event(Event {
            version: TRACE_VERSION,
            seq: call_id * 2 + u64::from(phase == Phase::Return),
            call_id,
            elapsed_ns: 0,
            thread_id: 7,
            target_id: "rust.crypto.demo".into(),
            symbol: "demo::decrypt".into(),
            function_va: 0x1000,
            phase,
            return_address: 0x2000,
            scalars: Vec::new(),
            buffers,
        })
    }

    #[test]
    fn a_real_entropy_drop_is_confirmed() {
        let records = vec![
            ev(
                1,
                Phase::Entry,
                vec![buf("buffer", 7.95, Class::Encrypted, "aa", 4096)],
            ),
            ev(
                1,
                Phase::Return,
                vec![buf("buffer", 4.10, Class::Text, "bb", 4096)],
            ),
        ];
        let r = build(&records, &Expectations::new());
        assert_eq!(r.events.len(), 1);
        assert!(r.events[0].confirmed);
        assert!(r.events[0].met_expectation);
        assert_eq!(r.summary.confirmed_transitions, 1);
        assert_eq!(r.summary.bytes_recovered, 4096);
    }

    #[test]
    fn a_drop_from_an_unpacked_input_is_not_confirmed() {
        let records = vec![
            ev(
                1,
                Phase::Entry,
                vec![buf("buffer", 4.0, Class::Code, "aa", 64)],
            ),
            ev(
                1,
                Phase::Return,
                vec![buf("buffer", 1.0, Class::Structured, "bb", 64)],
            ),
        ];
        let r = build(&records, &Expectations::new());
        assert!(!r.events[0].confirmed, "input was never opaque");
        assert!(
            r.events[0].met_expectation,
            "entropy still moved the right way"
        );
        assert_eq!(r.summary.bytes_recovered, 0);
    }

    #[test]
    fn an_encrypt_rule_confirms_on_a_rise_instead() {
        let mut expect = Expectations::new();
        expect.insert(
            "rust.crypto.demo".into(),
            TargetExpectation {
                expect: Expect::EntropyRise,
                compare: None,
            },
        );
        let records = vec![
            ev(
                1,
                Phase::Entry,
                vec![buf("buffer", 4.0, Class::Text, "aa", 512)],
            ),
            ev(
                1,
                Phase::Return,
                vec![buf("buffer", 7.9, Class::Encrypted, "bb", 512)],
            ),
        ];
        let r = build(&records, &expect);
        assert!(r.events[0].confirmed);
        assert!(r.events[0].met_expectation);
    }

    #[test]
    fn a_call_that_never_returned_is_reported_not_dropped() {
        let records = vec![ev(
            1,
            Phase::Entry,
            vec![buf("buffer", 7.9, Class::Encrypted, "aa", 16)],
        )];
        let r = build(&records, &Expectations::new());
        assert!(r.events.is_empty());
        assert_eq!(r.incomplete.len(), 1);
        assert!(r.incomplete[0].reason.contains("never returned"));
        assert_eq!(r.summary.calls_by_target["rust.crypto.demo"], 1);
    }

    #[test]
    fn buffers_are_paired_by_name_not_position() {
        let records = vec![
            ev(
                1,
                Phase::Entry,
                vec![
                    buf("aad", 2.0, Class::Text, "a1", 8),
                    buf("buffer", 7.9, Class::Encrypted, "a2", 1024),
                ],
            ),
            ev(
                1,
                Phase::Return,
                // Reversed order on the way out.
                vec![buf("buffer", 3.2, Class::Text, "b2", 1024)],
            ),
        ];
        let r = build(&records, &Expectations::new());
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.events[0].buffer, "buffer");
        assert_eq!(r.events[0].sha256_before, "a2");
    }

    #[test]
    fn events_rank_by_drop_weighted_by_volume() {
        let records = vec![
            ev(
                1,
                Phase::Entry,
                vec![buf("buffer", 7.9, Class::Encrypted, "a", 32)],
            ),
            ev(
                1,
                Phase::Return,
                vec![buf("buffer", 6.9, Class::Code, "b", 32)],
            ),
            ev(
                2,
                Phase::Entry,
                vec![buf("buffer", 7.9, Class::Encrypted, "c", 65536)],
            ),
            ev(
                2,
                Phase::Return,
                vec![buf("buffer", 3.0, Class::Text, "d", 65536)],
            ),
        ];
        let r = build(&records, &Expectations::new());
        assert_eq!(
            r.events[0].call_id, 2,
            "the bigger, deeper drop ranks first"
        );
    }

    #[test]
    fn payload_warnings_surface_in_the_report() {
        let records = vec![Record::Note(Note {
            version: TRACE_VERSION,
            seq: 1,
            elapsed_ns: 0,
            level: NoteLevel::Warning,
            message: "target rva 0x1234 did not match its recorded prologue bytes".into(),
        })];
        let r = build(&records, &Expectations::new());
        assert_eq!(r.notes.len(), 1);
        // The level is carried as data, not baked into the message - otherwise
        // the renderer prefixes it a second time.
        assert_eq!(r.notes[0].level, NoteLevel::Warning);
        assert!(!r.notes[0].message.contains("WARNING"));
        assert_eq!(r.summary.notes_by_level["WARNING"], 1);
    }

    #[test]
    fn a_decompressor_is_measured_across_its_input_and_output_buffers() {
        // The output buffer is zero-filled on entry, so comparing it against
        // itself measures "zeroes became data" - true, and useless. The real
        // transition is compressed input against inflated output.
        let mut expect = Expectations::new();
        expect.insert(
            "rust.compression.demo".into(),
            TargetExpectation {
                expect: Expect::EntropyDrop,
                compare: Some(Comparison {
                    from: "input".into(),
                    to: "output".into(),
                }),
            },
        );
        let mut entry = match ev(1, Phase::Entry, vec![]) {
            Record::Event(e) => e,
            _ => unreachable!(),
        };
        entry.target_id = "rust.compression.demo".into();
        entry.buffers = vec![
            buf("input", 7.90, Class::Compressed, "in", 4096),
            buf("output", 0.0, Class::Padding, "zero", 65536),
        ];
        let mut ret = entry.clone();
        ret.phase = Phase::Return;
        ret.buffers = vec![buf("output", 5.10, Class::Code, "out", 65536)];

        let r = build(&[Record::Event(entry), Record::Event(ret)], &expect);
        assert_eq!(
            r.events.len(),
            1,
            "exactly one transition, not one per buffer"
        );
        let e = &r.events[0];
        assert_eq!(e.buffer, "input -> output");
        assert_eq!(e.delta.before, 7.90);
        assert_eq!(e.delta.after, 5.10);
        assert!(e.confirmed);
        assert_eq!(r.summary.bytes_recovered, 65536);
    }

    #[test]
    fn a_compressed_input_below_the_raw_threshold_still_confirms() {
        // Chained stages leave DEFLATE output around 6.5, under the 7.0 bar,
        // but the classifier has already called it compressed.
        let records = vec![
            ev(
                1,
                Phase::Entry,
                vec![buf("buffer", 6.45, Class::Compressed, "a", 2048)],
            ),
            ev(
                1,
                Phase::Return,
                vec![buf("buffer", 4.90, Class::Code, "b", 2048)],
            ),
        ];
        let r = build(&records, &Expectations::new());
        assert!(
            r.events[0].confirmed,
            "an opaque class must count as opaque"
        );
    }

    #[test]
    fn a_missing_half_of_a_cross_buffer_comparison_is_reported() {
        let mut expect = Expectations::new();
        expect.insert(
            "rust.compression.demo".into(),
            TargetExpectation {
                expect: Expect::EntropyDrop,
                compare: Some(Comparison {
                    from: "input".into(),
                    to: "output".into(),
                }),
            },
        );
        let mut entry = match ev(1, Phase::Entry, vec![]) {
            Record::Event(e) => e,
            _ => unreachable!(),
        };
        entry.target_id = "rust.compression.demo".into();
        entry.buffers = vec![buf("input", 7.9, Class::Compressed, "in", 4096)];
        let mut ret = entry.clone();
        ret.phase = Phase::Return;
        ret.buffers = vec![]; // output never captured

        let r = build(&[Record::Event(entry), Record::Event(ret)], &expect);
        assert!(r.events.is_empty());
        assert_eq!(r.incomplete.len(), 1);
        assert!(r.incomplete[0].reason.contains("was not captured"));
    }

    #[test]
    fn markdown_renders_without_panicking_on_an_empty_report() {
        let md = to_markdown(&build(&[], &Expectations::new()));
        assert!(md.contains("Nothing was recovered"));
    }
}
