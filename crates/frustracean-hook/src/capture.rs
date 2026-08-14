//! Reading buffers out of the target, measuring them, and writing the trace.
//!
//! Two rules shape this module, both learned from the way samples behave rather
//! than the way they are documented:
//!
//! * **Never trust a length.** A slice's length register is attacker-controlled
//!   the moment the sample notices it is being watched. Every read is clamped to
//!   the rule's `max_bytes` and the original figure is recorded separately, so a
//!   nonsense length shows up in the trace as evidence instead of as a fault.
//! * **Deduplicate by content.** A decrypt in a loop fires thousands of times on
//!   the same block. Hashing first and writing only new blobs keeps a capture
//!   directory usable.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use frustracean_core::entropy::Stats;
use frustracean_core::trace::{Buffer, Note, NoteLevel, Record, TRACE_VERSION};

/// Absolute ceiling on a single read, regardless of what a rule asks for.
pub const HARD_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Decide how many bytes to actually read.
///
/// Returns the clamped length and, when clamping happened, the reason to record
/// alongside the buffer.
pub fn clamp_len(reported: usize, rule_max: usize) -> (usize, Option<String>) {
    let ceiling = rule_max.clamp(1, HARD_MAX_BYTES);
    if reported == 0 {
        return (0, Some("the target reported a zero length".into()));
    }
    if reported > ceiling {
        return (
            ceiling,
            Some(format!(
                "the target reported {reported} bytes; clamped to {ceiling}"
            )),
        );
    }
    (reported, None)
}

/// Content-addressed storage for captured blobs.
pub struct BlobStore {
    dir: PathBuf,
    seen: BTreeSet<String>,
    written: usize,
    duplicates: usize,
}

impl BlobStore {
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<BlobStore> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(BlobStore {
            dir,
            seen: BTreeSet::new(),
            written: 0,
            duplicates: 0,
        })
    }

    /// Hash, store if new, and return `(sha256, path relative to the capture
    /// directory)`.
    ///
    /// The path is returned for duplicates too - the analyst wants to know
    /// *which* blob this call produced, not just that it was seen before.
    pub fn store(&mut self, bytes: &[u8]) -> std::io::Result<(String, Option<String>)> {
        if bytes.is_empty() {
            return Ok((frustracean_core::sha256_hex(bytes), None));
        }
        let sha = frustracean_core::sha256_hex(bytes);
        let rel = format!("blobs/{sha}.bin");
        if self.seen.contains(&sha) {
            self.duplicates += 1;
            return Ok((sha, Some(rel)));
        }
        let path = self.dir.join(format!("{sha}.bin"));
        std::fs::write(&path, bytes)?;
        self.seen.insert(sha.clone());
        self.written += 1;
        Ok((sha, Some(rel)))
    }

    pub fn written(&self) -> usize {
        self.written
    }

    pub fn duplicates(&self) -> usize {
        self.duplicates
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Build the trace record for one captured buffer.
pub fn describe_buffer(
    name: &str,
    addr: u64,
    reported_len: usize,
    bytes: &[u8],
    truncated_reason: Option<String>,
    sha256: String,
    dump: Option<String>,
) -> Buffer {
    Buffer {
        name: name.to_string(),
        addr,
        len: bytes.len(),
        reported_len,
        stats: Stats::of(bytes),
        sha256,
        dump,
        truncated_reason,
    }
}

/// The JSON Lines trace writer.
///
/// Every record is flushed as it is written. A sample that crashes, exits, or
/// deliberately kills its own process mid-unpack is the normal case, and a
/// buffered writer would lose exactly the records that mattered most.
pub struct Sink {
    file: std::fs::File,
    seq: u64,
    start: std::time::Instant,
    errors: usize,
}

impl Sink {
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Sink> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Sink {
            file: std::fs::File::create(path)?,
            seq: 0,
            start: std::time::Instant::now(),
            errors: 0,
        })
    }

    pub fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    pub fn elapsed_ns(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    pub fn write(&mut self, record: &Record) {
        let Ok(line) = record.to_line() else {
            self.errors += 1;
            return;
        };
        if writeln!(self.file, "{line}").is_err() || self.file.flush().is_err() {
            self.errors += 1;
        }
    }

    pub fn note(&mut self, level: NoteLevel, message: impl Into<String>) {
        let seq = self.next_seq();
        let elapsed_ns = self.elapsed_ns();
        self.write(&Record::Note(Note {
            version: TRACE_VERSION,
            seq,
            elapsed_ns,
            level,
            message: message.into(),
        }));
    }

    pub fn errors(&self) -> usize {
        self.errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("frustracean-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_ordinary_length_passes_through_unclamped() {
        assert_eq!(clamp_len(4096, 1 << 20), (4096, None));
    }

    #[test]
    fn an_oversized_length_is_clamped_and_explained() {
        let (len, reason) = clamp_len(1 << 30, 4096);
        assert_eq!(len, 4096);
        assert!(reason.unwrap().contains("clamped to 4096"));
    }

    #[test]
    fn the_hard_ceiling_overrides_a_permissive_rule() {
        let (len, reason) = clamp_len(usize::MAX, usize::MAX);
        assert_eq!(len, HARD_MAX_BYTES);
        assert!(reason.is_some());
    }

    #[test]
    fn a_zero_length_is_recorded_rather_than_read() {
        let (len, reason) = clamp_len(0, 4096);
        assert_eq!(len, 0);
        assert!(reason.unwrap().contains("zero length"));
    }

    #[test]
    fn identical_blobs_are_written_once_but_still_reported() {
        let dir = tempdir("blobs");
        let mut store = BlobStore::new(&dir).unwrap();
        let (sha1, path1) = store.store(b"hello world").unwrap();
        let (sha2, path2) = store.store(b"hello world").unwrap();
        assert_eq!(sha1, sha2);
        assert_eq!(path1, path2, "a duplicate still names its blob");
        assert_eq!(store.written(), 1);
        assert_eq!(store.duplicates(), 1);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn different_blobs_get_different_files() {
        let dir = tempdir("blobs2");
        let mut store = BlobStore::new(&dir).unwrap();
        store.store(b"one").unwrap();
        store.store(b"two").unwrap();
        assert_eq!(store.written(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_buffer_produces_no_file() {
        let dir = tempdir("blobs3");
        let mut store = BlobStore::new(&dir).unwrap();
        let (_, path) = store.store(b"").unwrap();
        assert!(path.is_none());
        assert_eq!(store.written(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_buffer_record_carries_both_the_read_and_the_reported_length() {
        let b = describe_buffer(
            "buffer",
            0x1000,
            1 << 30,
            b"plaintext",
            Some("clamped".into()),
            "aa".into(),
            Some("blobs/aa.bin".into()),
        );
        assert_eq!(b.len, 9);
        assert_eq!(b.reported_len, 1 << 30);
        assert!(b.truncated_reason.is_some());
        assert_eq!(b.stats.len, 9);
    }

    #[test]
    fn the_sink_writes_one_flushed_line_per_record() {
        let dir = tempdir("sink");
        let path = dir.join("trace.jsonl");
        let mut sink = Sink::create(&path).unwrap();
        sink.note(NoteLevel::Warning, "first");
        sink.note(NoteLevel::Info, "second");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        let (records, problems) = frustracean_core::trace::parse_lines(&text);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].seq(), 1);
        assert_eq!(records[1].seq(), 2);
        assert_eq!(sink.errors(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
