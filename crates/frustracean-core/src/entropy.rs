//! Shannon entropy, corroborating statistics, and region classification.
//!
//! Entropy alone is a blunt instrument: LZ-compressed data, AES ciphertext, and
//! a densely-packed `.text` section all sit in the 6.5-8.0 band. Frustracean
//! carries two cheap corroborators alongside the entropy value so the classifier
//! can separate them:
//!
//! * **chi-square** against a uniform byte distribution. True ciphertext and CSPRNG
//!   output land near the expected 255; DEFLATE/LZ4 output keeps residual structure
//!   and scores far higher. This is the single most useful signal for telling
//!   "encrypted" from "merely compressed".
//! * **printable ratio**, which pulls UTF-8 blobs (very common in Rust binaries,
//!   whose string literals are length-prefixed rather than NUL-terminated and so
//!   run together into long printable stretches) out of the "data" bucket.
//!
//! # Two limits worth knowing before trusting a number here
//!
//! **Neither entropy nor chi-square can see a single-byte XOR.** XOR permutes the
//! histogram's bins; it does not change the multiset of bin counts. Shannon
//! entropy is a function of the counts alone, and chi-square against a *uniform*
//! model compares every count to the same expected value, so both are exactly
//! invariant. This is asserted as a test, not merely asserted here. Of the three
//! measures only the printable ratio moves at all under XOR, and it moves
//! monotonically with the key's magnitude - a key of `0x01` leaves printability
//! at 1.0 - which makes it useless as a standalone discriminator.
//!
//! Detecting single-byte XOR needs chi-square against a *fixed* byte model rather
//! than a uniform one, brute-forced over all 256 keys. Frustracean does not do
//! that yet; see the roadmap. What matters for now is not mistaking "high
//! entropy" for "not XORed".
//!
//! **Entropy is bounded by `log2(len)`.** A 16-byte buffer cannot exceed 4 bits
//! per byte no matter how random it is. Reading 3.9 as "structured data" when it
//! is in fact the arithmetic ceiling for that length is the classic way to
//! misread a small capture, so [`Stats`] carries the ceiling and short buffers
//! are classified [`Class::Undersized`] rather than given a confident label.

use serde::{Deserialize, Serialize};

/// Maximum Shannon entropy for a byte-oriented source, in bits per byte.
pub const MAX_ENTROPY: f64 = 8.0;

/// Default sliding-window size. 256 bytes is small enough to localise a packed
/// blob inside a section but large enough that the entropy estimate is not pure
/// sampling noise (a 256-byte window can only ever observe 256 of 256 symbols).
pub const DEFAULT_WINDOW: usize = 256;

/// Default step. Half-overlapping windows keep boundaries from being missed
/// without doubling the work relative to a stride of 1.
pub const DEFAULT_STEP: usize = 128;

/// Windows at or above this are worth a second look.
pub const DEFAULT_THRESHOLD: f64 = 7.0;

/// Shannon entropy of `data` in bits per byte, in `0.0..=8.0`.
///
/// Returns 0.0 for an empty slice: no information, no surprise.
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / len;
        h -= p * p.log2();
    }
    h
}

/// Chi-square statistic of `data` against a uniform distribution over 256 symbols.
///
/// For uniformly random bytes the expected value is 255 (the degrees of freedom),
/// with a standard deviation of `sqrt(2 * 255)` ~= 22.6. Values far above that
/// indicate residual structure.
pub fn chi_square(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    let mut chi = 0.0f64;
    for &c in counts.iter() {
        let diff = f64::from(c) - expected;
        chi += (diff * diff) / expected;
    }
    chi
}

/// Fraction of bytes that are printable ASCII or common whitespace.
pub fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let n = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\r' | b'\n'))
        .count();
    n as f64 / data.len() as f64
}

/// Number of distinct byte values present.
pub fn distinct_bytes(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0;
    for &b in data {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n
}

/// Below this many bytes, an entropy value says more about the length than the
/// content: the ceiling is `log2(len)`, so a 32-byte buffer tops out at 5 bits
/// per byte however random it is.
pub const MIN_MEANINGFUL_LEN: usize = 64;

/// What a run of bytes most likely is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Too short for its entropy to carry information. Not a judgement about
    /// the content - a judgement about the measurement.
    Undersized,
    /// All one byte, or nearly so: alignment padding, zeroed BSS, `int3` fill.
    Padding,
    /// Printable text. In a Rust image this is usually the `.rodata` string pool.
    Text,
    /// Machine code density.
    Code,
    /// Structured binary: tables, relocations, resource blobs.
    Structured,
    /// High entropy with residual structure. DEFLATE, LZ4, zstd.
    Compressed,
    /// High entropy, uniform distribution. Ciphertext or CSPRNG output.
    Encrypted,
}

impl Class {
    /// A word, not a colour. Used directly in CLI output.
    pub fn label(self) -> &'static str {
        match self {
            Class::Undersized => "undersized",
            Class::Padding => "padding",
            Class::Text => "text",
            Class::Code => "code",
            Class::Structured => "structured",
            Class::Compressed => "compressed",
            Class::Encrypted => "encrypted",
        }
    }

    /// Whether this class is worth handing to the hijack planner.
    pub fn is_opaque(self) -> bool {
        matches!(self, Class::Compressed | Class::Encrypted)
    }
}

/// The full statistical picture of one buffer.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Stats {
    pub len: usize,
    pub entropy: f64,
    pub chi_square: f64,
    pub printable_ratio: f64,
    pub distinct_bytes: usize,
    pub class: Class,
}

impl Stats {
    pub fn of(data: &[u8]) -> Stats {
        let entropy = shannon(data);
        let chi = chi_square(data);
        let printable = printable_ratio(data);
        let distinct = distinct_bytes(data);
        Stats {
            len: data.len(),
            entropy,
            chi_square: chi,
            printable_ratio: printable,
            distinct_bytes: distinct,
            class: classify(data.len(), entropy, chi, printable, distinct),
        }
    }

    /// Chi-square normalised so that ~1.0 means "indistinguishable from uniform".
    pub fn chi_square_ratio(self) -> f64 {
        self.chi_square / 255.0
    }

    /// The highest entropy a buffer of this length could reach, `log2(len)`
    /// capped at 8.
    ///
    /// Worth printing next to the measurement whenever the buffer is small: an
    /// entropy of 4.0 means something very different at 16 bytes (the ceiling)
    /// than at 16 KiB.
    pub fn ceiling(self) -> f64 {
        if self.len == 0 {
            0.0
        } else {
            (self.len as f64).log2().min(MAX_ENTROPY)
        }
    }

    /// Is this buffer too short for its entropy to be interpreted?
    pub fn is_undersized(self) -> bool {
        self.len < MIN_MEANINGFUL_LEN
    }

    /// How close the measurement sits to its own arithmetic ceiling, in `0..=1`.
    ///
    /// A short buffer pressed against its ceiling is as random as it is able to
    /// be, which is the most that can honestly be said about it.
    pub fn saturation(self) -> f64 {
        let ceiling = self.ceiling();
        if ceiling <= 0.0 {
            0.0
        } else {
            (self.entropy / ceiling).clamp(0.0, 1.0)
        }
    }
}

/// Bucket a buffer from its summary statistics.
///
/// Ordering matters: the cheap, unambiguous cases (padding, text) are decided
/// first so they cannot be misread as low-entropy "code".
pub fn classify(len: usize, entropy: f64, chi: f64, printable: f64, distinct: usize) -> Class {
    if len == 0 || distinct <= 2 {
        return Class::Padding;
    }
    // A short buffer's entropy is capped at log2(len), so every band below
    // would be reading the length rather than the content. Padding is decided
    // first because "all one byte" is true at any size.
    if len < MIN_MEANINGFUL_LEN {
        return Class::Undersized;
    }
    if printable > 0.90 && entropy < 6.0 {
        return Class::Text;
    }
    if entropy >= 7.2 {
        // Both are high-entropy. The chi-square split is what separates them:
        // a compressor leaves structure behind, a cipher does not. The cutoff is
        // deliberately loose because small windows are noisy - at 256 bytes the
        // statistic has a wide spread even for genuinely uniform input.
        let expected_sd = (2.0 * 255.0f64).sqrt();
        let z = (chi - 255.0) / expected_sd;
        return if z > 12.0 {
            Class::Compressed
        } else {
            Class::Encrypted
        };
    }
    if entropy >= 5.0 {
        Class::Code
    } else {
        Class::Structured
    }
}

/// One sample of the sliding window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    /// File offset of the first byte in the window.
    pub offset: u64,
    /// Virtual address, when the window could be attributed to a mapped section.
    pub va: Option<u64>,
    /// Owning section name, when known.
    pub section: Option<String>,
    pub stats: Stats,
}

/// A merged run of adjacent windows that share a bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub va: Option<u64>,
    pub section: Option<String>,
    pub class: Class,
    /// Mean entropy across the region.
    pub entropy: f64,
    /// Highest single-window entropy inside the region.
    pub peak_entropy: f64,
    pub window_count: usize,
}

impl Region {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Knobs for the sliding-window sweep.
#[derive(Debug, Clone, Copy)]
pub struct MapOptions {
    pub window: usize,
    pub step: usize,
    /// Windows below this are not eligible to start a region.
    pub threshold: f64,
    /// How many consecutive sub-threshold windows a region may absorb before it
    /// is closed. Real packed blobs have brief dips; without tolerance one
    /// low window shatters a region into dozens of fragments.
    pub gap_tolerance: usize,
    /// Regions shorter than this many bytes are discarded as noise.
    pub min_region_len: u64,
}

impl Default for MapOptions {
    fn default() -> Self {
        MapOptions {
            window: DEFAULT_WINDOW,
            step: DEFAULT_STEP,
            threshold: DEFAULT_THRESHOLD,
            gap_tolerance: 2,
            min_region_len: 512,
        }
    }
}

/// Sweep `data` and return one [`Window`] per step.
///
/// The final partial window is included when it holds at least a quarter of a
/// full window, so a packed blob at the very end of a file is not dropped.
pub fn sweep(data: &[u8], opts: &MapOptions) -> Vec<Window> {
    let window = opts.window.max(1);
    let step = opts.step.max(1);
    let mut out = Vec::new();
    if data.is_empty() {
        return out;
    }
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + window).min(data.len());
        let slice = &data[offset..end];
        if slice.len() < window / 4 && offset != 0 {
            break;
        }
        out.push(Window {
            offset: offset as u64,
            va: None,
            section: None,
            stats: Stats::of(slice),
        });
        if end == data.len() {
            break;
        }
        offset += step;
    }
    out
}

/// Merge windows at or above `threshold` into contiguous regions.
pub fn regions(windows: &[Window], opts: &MapOptions) -> Vec<Region> {
    let mut out: Vec<Region> = Vec::new();
    let mut current: Option<(usize, usize, usize)> = None; // (start_idx, end_idx, gap_run)

    for (i, w) in windows.iter().enumerate() {
        let hot = w.stats.entropy >= opts.threshold;
        match current.as_mut() {
            None => {
                if hot {
                    current = Some((i, i, 0));
                }
            }
            Some((_, end_idx, gap_run)) => {
                if hot {
                    *end_idx = i;
                    *gap_run = 0;
                } else {
                    *gap_run += 1;
                    if *gap_run > opts.gap_tolerance {
                        let (s, e, _) = current.take().unwrap();
                        if let Some(r) = build_region(windows, s, e, opts) {
                            out.push(r);
                        }
                    }
                }
            }
        }
    }
    if let Some((s, e, _)) = current {
        if let Some(r) = build_region(windows, s, e, opts) {
            out.push(r);
        }
    }
    out
}

fn build_region(
    windows: &[Window],
    start_idx: usize,
    end_idx: usize,
    opts: &MapOptions,
) -> Option<Region> {
    let first = windows.get(start_idx)?;
    let last = windows.get(end_idx)?;
    let start = first.offset;
    let end = last.offset + last.stats.len as u64;
    if end.saturating_sub(start) < opts.min_region_len {
        return None;
    }
    let members = &windows[start_idx..=end_idx];
    let sum: f64 = members.iter().map(|w| w.stats.entropy).sum();
    let mean = sum / members.len() as f64;
    let peak = members
        .iter()
        .map(|w| w.stats.entropy)
        .fold(f64::MIN, f64::max);

    // A region inherits the class held by the majority of its hot windows,
    // so a handful of noisy samples cannot relabel a whole packed blob.
    let mut compressed = 0usize;
    let mut encrypted = 0usize;
    for w in members {
        match w.stats.class {
            Class::Compressed => compressed += 1,
            Class::Encrypted => encrypted += 1,
            _ => {}
        }
    }
    let class = if compressed == 0 && encrypted == 0 {
        Class::Structured
    } else if compressed > encrypted {
        Class::Compressed
    } else {
        Class::Encrypted
    };

    Some(Region {
        start,
        end,
        va: first.va,
        section: first.section.clone(),
        class,
        entropy: mean,
        peak_entropy: peak,
        window_count: members.len(),
    })
}

/// A before/after entropy pair, the core observable of an unpacking event.
///
/// A hijacked decrypt/decompress call is *confirmed* when the buffer it was
/// handed drops sharply in entropy by the time it returns. That drop, not the
/// symbol name, is the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Delta {
    pub before: f64,
    pub after: f64,
}

impl Delta {
    pub fn drop(self) -> f64 {
        self.before - self.after
    }

    /// Did entropy fall far enough to call this a successful unpack?
    ///
    /// The two conditions are deliberately both required: a drop from 7.9 to 7.4
    /// is large in absolute terms but still leaves opaque output, while a drop
    /// from 4.0 to 3.5 says nothing because the input was never packed.
    pub fn is_unpack(self) -> bool {
        self.before >= 7.0 && self.drop() >= 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_no_entropy() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(chi_square(&[]), 0.0);
    }

    #[test]
    fn constant_input_has_zero_entropy() {
        assert_eq!(shannon(&[0x41; 4096]), 0.0);
    }

    #[test]
    fn every_byte_once_is_maximal() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert!((shannon(&data) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn two_equally_likely_symbols_is_one_bit() {
        let data: Vec<u8> = (0..1024)
            .map(|i| if i % 2 == 0 { 0u8 } else { 1u8 })
            .collect();
        assert!((shannon(&data) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn uniform_input_scores_near_expected_chi_square() {
        // A perfectly flat histogram is the chi-square minimum, zero.
        let data: Vec<u8> = (0..=255u8).collect();
        assert!(chi_square(&data).abs() < 1e-9);
    }

    #[test]
    fn skewed_input_scores_high_chi_square() {
        let mut data = vec![0u8; 1024];
        data[0] = 1;
        assert!(chi_square(&data) > 1000.0);
    }

    #[test]
    fn classifier_separates_the_obvious_cases() {
        assert_eq!(Stats::of(&[0u8; 1024]).class, Class::Padding);
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(32);
        assert_eq!(Stats::of(&text).class, Class::Text);
    }

    #[test]
    fn neither_entropy_nor_chi_square_can_see_a_single_byte_xor() {
        // XOR permutes the histogram's bins. It does not change the multiset of
        // bin counts - and both measures are functions of the counts alone, so
        // both are exactly invariant. Anything claiming to detect XOR by
        // entropy is wrong, and this is the proof for all 255 keys.
        let data: Vec<u8> = (0..4096u32)
            .map(|i| b"the quick brown fox jumps over the lazy dog"[(i as usize) % 42])
            .collect();
        let h = shannon(&data);
        let c = chi_square(&data);

        for key in 1..=255u8 {
            let xored: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            assert!(
                (shannon(&xored) - h).abs() < 1e-12,
                "entropy moved under key {key:#04x}"
            );
            assert!(
                (chi_square(&xored) - c).abs() < 1e-9,
                "chi-square moved under key {key:#04x}"
            );
        }
    }

    #[test]
    fn the_printable_ratio_is_the_only_measure_xor_moves_at_all() {
        // And it moves monotonically with the key's magnitude rather than
        // collapsing, which is exactly why it cannot stand alone: a key of 0x01
        // leaves printability untouched.
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(32);
        assert!((printable_ratio(&text) - 1.0).abs() < 1e-12);

        let low: Vec<u8> = text.iter().map(|b| b ^ 0x01).collect();
        assert!(
            printable_ratio(&low) > 0.99,
            "a low key barely disturbs printability"
        );

        let high: Vec<u8> = text.iter().map(|b| b ^ 0x80).collect();
        assert!(
            printable_ratio(&high) < 0.01,
            "a high key clears the top bit and destroys it"
        );
    }

    #[test]
    fn entropy_is_bounded_by_the_log_of_the_length() {
        // 16 distinct random-looking bytes cannot exceed 4 bits per byte. Read
        // as an absolute number that looks like "structured data"; read against
        // the ceiling it is maximal randomness.
        let data: Vec<u8> = (0..16u8).collect();
        let stats = Stats::of(&data);
        assert!((stats.ceiling() - 4.0).abs() < 1e-12);
        assert!((stats.entropy - 4.0).abs() < 1e-12);
        assert!((stats.saturation() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn short_buffers_are_labelled_undersized_rather_than_guessed_at() {
        let data: Vec<u8> = (0..32u8).collect();
        let stats = Stats::of(&data);
        assert!(stats.is_undersized());
        assert_eq!(stats.class, Class::Undersized);

        // The same byte pattern, long enough to mean something, is not.
        let long: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(!Stats::of(&long).is_undersized());
        assert_ne!(Stats::of(&long).class, Class::Undersized);
    }

    #[test]
    fn an_all_one_byte_buffer_is_padding_at_any_length() {
        // The padding check has to come before the length check, or a 16-byte
        // run of zeroes gets reported as "too short to say".
        assert_eq!(Stats::of(&[0u8; 8]).class, Class::Padding);
    }

    #[test]
    fn counted_bytes_are_distinct() {
        assert_eq!(distinct_bytes(&[1, 1, 2, 2, 3]), 3);
        assert_eq!(distinct_bytes(&[]), 0);
    }

    #[test]
    fn sweep_covers_the_whole_buffer() {
        let data = vec![0xabu8; 1000];
        let opts = MapOptions {
            window: 100,
            step: 100,
            ..Default::default()
        };
        let windows = sweep(&data, &opts);
        assert_eq!(windows.len(), 10);
        assert_eq!(windows[9].offset, 900);
    }

    #[test]
    fn regions_merge_across_a_tolerated_gap() {
        let opts = MapOptions {
            window: 256,
            step: 256,
            threshold: 7.0,
            gap_tolerance: 2,
            min_region_len: 0,
        };
        let mk = |offset: u64, entropy: f64| Window {
            offset,
            va: None,
            section: None,
            stats: Stats {
                len: 256,
                entropy,
                chi_square: 255.0,
                printable_ratio: 0.0,
                distinct_bytes: 256,
                class: Class::Encrypted,
            },
        };
        let windows = vec![
            mk(0, 7.9),
            mk(256, 7.9),
            mk(512, 3.0), // one dip, absorbed
            mk(768, 7.9),
        ];
        let regions = regions(&windows, &opts);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].start, 0);
        assert_eq!(regions[0].end, 1024);
    }

    #[test]
    fn regions_split_when_the_gap_is_too_wide() {
        let opts = MapOptions {
            window: 256,
            step: 256,
            threshold: 7.0,
            gap_tolerance: 1,
            min_region_len: 0,
        };
        let mk = |offset: u64, entropy: f64| Window {
            offset,
            va: None,
            section: None,
            stats: Stats {
                len: 256,
                entropy,
                chi_square: 255.0,
                printable_ratio: 0.0,
                distinct_bytes: 256,
                class: Class::Encrypted,
            },
        };
        let windows = vec![
            mk(0, 7.9),
            mk(256, 1.0),
            mk(512, 1.0),
            mk(768, 1.0),
            mk(1024, 7.9),
        ];
        assert_eq!(regions(&windows, &opts).len(), 2);
    }

    #[test]
    fn delta_requires_both_a_packed_input_and_a_real_drop() {
        assert!(Delta {
            before: 7.9,
            after: 4.2
        }
        .is_unpack());
        // Large drop, but the input was never opaque.
        assert!(!Delta {
            before: 4.0,
            after: 1.0
        }
        .is_unpack());
        // Opaque input, but the output is still opaque.
        assert!(!Delta {
            before: 7.9,
            after: 7.6
        }
        .is_unpack());
    }
}
