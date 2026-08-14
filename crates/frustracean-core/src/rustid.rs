//! Rust fingerprinting: is this Rust, which rustc built it, and what did it pull in.
//!
//! This module is the reason Frustracean is Rust-specific rather than a generic
//! entropy tool. Rust images leak an unusual amount of build metadata even when
//! stripped, because the compiler embeds `file!()` for every panic site and
//! `panic_location` strings are plain UTF-8 in `.rodata`:
//!
//! * `/rustc/<40-hex commit>/library/core/src/...` pins the exact compiler.
//! * `.../registry/src/index.crates.io-<hash>/aes-gcm-0.10.3/src/lib.rs` names a
//!   dependency **and its exact version**. Recovering that list up front tells an
//!   analyst which crypto, which compression, and which HTTP stack to expect
//!   before any disassembly happens - and it is precisely what the hijack planner
//!   needs to pick rules.
//! * `C:\Users\<name>\...\src\main.rs` leaks the build machine's layout when the
//!   author did not pass `--remap-path-prefix`.
//!
//! One caveat drives the whole design: **a packed sample has none of this**. The
//! markers live in the compressed blob, not the stub. A low score plus a
//! high-entropy body is itself the finding, so [`Verdict`] reports that case
//! explicitly instead of concluding "not Rust".

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::binary::Image;
use crate::symbols;

/// Where a recovered crate reference came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrateSource {
    /// A cargo registry path in `.rodata`. Carries an exact version.
    Registry,
    /// A git checkout path. Version is usually absent.
    Git,
    /// The leading segment of a demangled symbol. No version.
    Symbol,
}

impl CrateSource {
    pub fn label(self) -> &'static str {
        match self {
            CrateSource::Registry => "registry",
            CrateSource::Git => "git",
            CrateSource::Symbol => "symbol",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrateRef {
    /// Normalised to underscores so it compares against symbol paths.
    pub name: String,
    /// As written in the path, hyphens intact.
    pub display_name: String,
    pub version: Option<String>,
    pub source: CrateSource,
    /// How many distinct references were seen. A crate referenced once may be a
    /// transitive dependency dragged in by a panic path; one referenced fifty
    /// times is load-bearing.
    pub hits: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustcInfo {
    pub version: Option<String>,
    pub commit: Option<String>,
    pub date: Option<String>,
}

impl RustcInfo {
    pub fn is_empty(&self) -> bool {
        self.version.is_none() && self.commit.is_none() && self.date.is_none()
    }
}

/// A source path recovered from an embedded panic location.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BuildPath {
    pub path: String,
    pub hits: usize,
}

/// A named indicator that fired, with the weight it contributed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub name: String,
    pub weight: u32,
    pub hits: usize,
}

/// The headline call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Rust markers are present and plentiful.
    Rust,
    /// Some markers, but not enough to be sure.
    LikelyRust,
    /// Few markers *and* a high-entropy body: the evidence is probably inside
    /// the packed blob. Not a "no".
    ObscuredByPacking,
    /// No markers and nothing to explain their absence.
    NotRust,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Rust => "rust",
            Verdict::LikelyRust => "likely-rust",
            Verdict::ObscuredByPacking => "obscured-by-packing",
            Verdict::NotRust => "not-rust",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustProfile {
    pub verdict: Verdict,
    /// 0-100. Not a probability, just a monotone confidence.
    pub score: u32,
    pub rustc: RustcInfo,
    /// True when std markers were found; false suggests `no_std`.
    pub std_present: bool,
    pub mangled_symbols: usize,
    pub crates: Vec<CrateRef>,
    pub build_paths: Vec<BuildPath>,
    pub markers: Vec<Marker>,
}

impl RustProfile {
    /// Dependencies with the toolchain's own crates filtered out.
    pub fn third_party_crates(&self) -> impl Iterator<Item = &CrateRef> {
        self.crates
            .iter()
            .filter(|c| !symbols::is_toolchain_crate(&c.name))
    }

    /// Look a crate up by either spelling.
    pub fn find_crate(&self, name: &str) -> Option<&CrateRef> {
        let target = symbols::normalize_crate_name(name);
        self.crates.iter().find(|c| c.name == target)
    }
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

// `(?-u)` keeps these byte-oriented: `.rodata` is not guaranteed to be valid
// UTF-8 around the edges of a literal, and a unicode-mode match would refuse to
// engage on the surrounding bytes.
static RE_RUSTC_COMMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)[/\\]rustc[/\\]([0-9a-f]{40})[/\\]library[/\\](core|std|alloc)[/\\]").unwrap()
});

static RE_RUSTC_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)rustc[ -](\d+\.\d+\.\d+)(?:[ -]\(([0-9a-f]{9}) (\d{4}-\d{2}-\d{2})\))?")
        .unwrap()
});

// Matches `.../registry/src/index.crates.io-<hash>/<name>-<semver>/`.
// The name is lazy so a hyphenated crate such as `curve25519-dalek-4.1.1`
// splits at the *last* hyphen-then-digit boundary rather than the first.
static RE_REGISTRY_CRATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?-u)[/\\]registry[/\\]src[/\\][^/\\]+[/\\]([A-Za-z0-9_][A-Za-z0-9_.-]*?)-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)[/\\]",
    )
    .unwrap()
});

static RE_GIT_CRATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)[/\\]git[/\\]checkouts[/\\]([A-Za-z0-9_][A-Za-z0-9_.-]*?)-[0-9a-f]{8,}[/\\]")
        .unwrap()
});

static RE_STD_LIBRARY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)library[/\\](core|std|alloc)[/\\]src[/\\]").unwrap());

/// Absolute or relative build paths ending in a `.rs` file, used to recover the
/// author's project layout. The path itself is capture group 1.
///
/// Two properties are doing the work here, and both exist because Rust pools
/// string literals with no terminator between them - `.rodata` routinely holds
/// `...src/main.rs/rustc/<hash>/library/core/src/mod.rs...` as one unbroken run,
/// and the literal before a path ends flush against it:
///
/// * **Lazy component quantifiers.** A greedy pattern swallows that whole run as
///   a single "path", which the toolchain filter then discards - silently losing
///   the author's real path.
/// * **A leading boundary.** Without one, the match starts inside the *previous*
///   literal, producing debris like `Classpaddingtextcode.../src/entropy.rs`. The
///   boundary must not itself be a separator or a word character, so an absolute
///   path keeps its leading slash. Rust's regex crate has no lookbehind, hence
///   the capture group.
static RE_BUILD_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?-u)(?:\A|[^A-Za-z0-9_/\\])((?:[A-Za-z]:[\\/]|[/\\])?(?:[A-Za-z0-9_][A-Za-z0-9_.+-]*[\\/]){0,12}?src[\\/](?:[A-Za-z0-9_][A-Za-z0-9_.+-]*[\\/]){0,8}?[A-Za-z0-9_][A-Za-z0-9_.+-]*\.rs)",
    )
    .unwrap()
});

/// Path fragments that mean "this came from the toolchain, not the author".
const NON_AUTHOR_PATH_MARKERS: &[&str] = &[
    "registry",
    "/rustc/",
    "\\rustc\\",
    "/rust/deps",
    "\\rust\\deps",
    "library/core",
    "library\\core",
    "library/std",
    "library\\std",
    "library/alloc",
    "library\\alloc",
    // Subtrees vendored into the standard library. Their paths are remapped
    // relative to `library/`, so a match that starts mid-path loses the
    // `/rustc/<hash>/library/` prefix that would otherwise identify them.
    "backtrace",
    "stdarch",
    "core_arch",
    "portable-simd",
];

/// Panic and runtime strings that only a Rust binary contains.
const PANIC_MARKERS: &[(&str, &str, u32)] = &[
    (
        "option_unwrap",
        "called `Option::unwrap()` on a `None` value",
        15,
    ),
    (
        "result_unwrap",
        "called `Result::unwrap()` on an `Err` value",
        15,
    ),
    ("index_oob", "index out of bounds: the len is ", 12),
    ("capacity_overflow", "capacity overflow", 8),
    ("arith_overflow", "attempt to add with overflow", 10),
    ("slice_range", "slice index starts at ", 10),
    ("backtrace_env", "RUST_BACKTRACE", 10),
    ("panic_msg", "panicked at ", 12),
    ("main_rs", "src/main.rs", 8),
    ("lib_rs", "src/lib.rs", 6),
    ("cargo_home", ".cargo", 6),
    ("alloc_fail", "memory allocation of ", 8),
    (
        "unwrap_failed",
        "internal error: entered unreachable code",
        6,
    ),
];

const STD_MARKERS: &[&str] = &[
    "library/std/src/",
    "library\\std\\src\\",
    "std::rt::lang_start",
    "RUST_BACKTRACE",
];

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Fingerprint an image.
///
/// `body_entropy` is the mean entropy of the image's non-executable data, used
/// only to decide between [`Verdict::NotRust`] and [`Verdict::ObscuredByPacking`].
pub fn detect(image: &Image, body_entropy: f64) -> RustProfile {
    let mut profile = detect_bytes(&image.data, body_entropy);

    // Symbols contribute both a marker and a crate source.
    let mut mangled = 0usize;
    let mut symbol_crates: BTreeMap<String, usize> = BTreeMap::new();
    for sym in &image.symbols {
        if sym.demangled.is_some() {
            mangled += 1;
        }
        if let Some(c) = &sym.crate_name {
            *symbol_crates.entry(c.clone()).or_default() += 1;
        }
    }
    profile.mangled_symbols = mangled;
    if mangled > 0 {
        profile.markers.push(Marker {
            name: "mangled_symbols".into(),
            weight: 40,
            hits: mangled,
        });
        profile.score = (profile.score + 40).min(100);
    }
    for (name, hits) in symbol_crates {
        // Do not overwrite a registry hit; that one carries a version.
        if profile.crates.iter().any(|c| c.name == name) {
            continue;
        }
        profile.crates.push(CrateRef {
            display_name: name.clone(),
            name,
            version: None,
            source: CrateSource::Symbol,
            hits,
        });
    }
    sort_crates(&mut profile.crates);
    profile.verdict = verdict_for(profile.score, body_entropy);
    profile
}

/// Fingerprint raw bytes, without a parsed image. Also used on memory dumps
/// captured by a hijack, where an unpacked payload's markers reappear.
pub fn detect_bytes(data: &[u8], body_entropy: f64) -> RustProfile {
    let mut score = 0u32;
    let mut markers: Vec<Marker> = Vec::new();
    let mut rustc = RustcInfo::default();

    let add = |markers: &mut Vec<Marker>, score: &mut u32, name: &str, weight: u32, hits: usize| {
        if hits == 0 {
            return;
        }
        markers.push(Marker {
            name: name.to_string(),
            weight,
            hits,
        });
        *score = (*score + weight).min(100);
    };

    // rustc commit hash and the library it came from.
    let commit_hits = RE_RUSTC_COMMIT.captures_iter(data).count();
    if let Some(caps) = RE_RUSTC_COMMIT.captures(data) {
        rustc.commit = caps
            .get(1)
            .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
    }
    add(
        &mut markers,
        &mut score,
        "rustc_commit_path",
        30,
        commit_hits,
    );

    if let Some(caps) = RE_RUSTC_VERSION.captures(data) {
        rustc.version = caps
            .get(1)
            .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
        rustc.date = caps
            .get(3)
            .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
        if rustc.commit.is_none() {
            rustc.commit = caps
                .get(2)
                .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
        }
        add(&mut markers, &mut score, "rustc_version_string", 20, 1);
    }

    let lib_hits = RE_STD_LIBRARY.find_iter(data).count();
    add(&mut markers, &mut score, "std_library_paths", 25, lib_hits);

    for (name, needle, weight) in PANIC_MARKERS {
        let hits = count_occurrences(data, needle.as_bytes());
        add(&mut markers, &mut score, name, *weight, hits);
    }

    let std_present = STD_MARKERS
        .iter()
        .any(|m| count_occurrences(data, m.as_bytes()) > 0);

    // Dependency inventory.
    let mut crates: BTreeMap<(String, Option<String>), (String, CrateSource, usize)> =
        BTreeMap::new();
    let mut registry_hits = 0usize;
    for caps in RE_REGISTRY_CRATE.captures_iter(data) {
        registry_hits += 1;
        let display = String::from_utf8_lossy(&caps[1]).into_owned();
        let version = String::from_utf8_lossy(&caps[2]).into_owned();
        let name = symbols::normalize_crate_name(&display);
        let entry =
            crates
                .entry((name, Some(version)))
                .or_insert((display, CrateSource::Registry, 0));
        entry.2 += 1;
    }
    add(
        &mut markers,
        &mut score,
        "cargo_registry_paths",
        25,
        registry_hits,
    );

    let mut git_hits = 0usize;
    for caps in RE_GIT_CRATE.captures_iter(data) {
        git_hits += 1;
        let display = String::from_utf8_lossy(&caps[1]).into_owned();
        let name = symbols::normalize_crate_name(&display);
        let entry = crates
            .entry((name, None))
            .or_insert((display, CrateSource::Git, 0));
        entry.2 += 1;
    }
    add(&mut markers, &mut score, "cargo_git_paths", 15, git_hits);

    let mut crate_refs: Vec<CrateRef> = crates
        .into_iter()
        .map(|((name, version), (display_name, source, hits))| CrateRef {
            name,
            display_name,
            version,
            source,
            hits,
        })
        .collect();
    sort_crates(&mut crate_refs);

    // Author build paths: everything that is not a toolchain or registry path.
    let mut path_hits: BTreeMap<String, usize> = BTreeMap::new();
    for caps in RE_BUILD_PATH.captures_iter(data) {
        let Some(m) = caps.get(1) else { continue };
        let raw = String::from_utf8_lossy(m.as_bytes()).into_owned();
        if NON_AUTHOR_PATH_MARKERS
            .iter()
            .any(|marker| raw.contains(marker))
        {
            continue;
        }
        if starts_with_version_fragment(&raw) {
            continue;
        }
        let trimmed = trim_leading_debris(&raw);
        if trimmed.is_empty() {
            continue;
        }
        *path_hits.entry(trimmed).or_default() += 1;
    }
    let mut build_paths: Vec<BuildPath> = path_hits
        .into_iter()
        .map(|(path, hits)| BuildPath { path, hits })
        .collect();
    build_paths.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.path.cmp(&b.path)));
    build_paths.truncate(64);

    RustProfile {
        verdict: verdict_for(score, body_entropy),
        score,
        rustc,
        std_present,
        mangled_symbols: 0,
        crates: crate_refs,
        build_paths,
        markers,
    }
}

/// Does this path begin with what looks like the tail of a crate version?
///
/// A pooled registry path such as `.../serde-1.0.203/src/lib.rs` offers the `-`
/// as a match boundary, so the extractor can start mid-version and produce
/// `1.0.203/src/lib.rs` - which passes the registry filter because the word
/// "registry" was left behind. Project directories starting with a digit are
/// rare enough that rejecting them is the right trade.
fn starts_with_version_fragment(path: &str) -> bool {
    let body = path
        .trim_start_matches(['/', '\\'])
        .split(['/', '\\'])
        .next()
        .unwrap_or("");
    // Skip a drive letter such as `C:`.
    let body = body.strip_suffix(':').map(|_| "").unwrap_or(body);
    body.starts_with(|c: char| c.is_ascii_digit())
}

/// Drop leading components of a *relative* path that cannot be directory names.
///
/// The boundary rule in [`RE_BUILD_PATH`] stops a match starting inside the
/// previous literal, but it cannot help when the debris happens to sit at the
/// start of the scanned buffer or right after a punctuation byte - leftmost
/// matching wins, and the run-together prefix comes along.
///
/// The signal used is capitalisation. Cargo emits workspace-relative paths, and
/// Rust project directories are lowercase by convention, whereas pooled debris
/// is made of type and variant names that are not. Absolute paths are left
/// alone: `C:\Users\...` is legitimately capitalised.
///
/// This is a heuristic and is documented as one. It trims noise; it does not
/// guarantee the leading component survived.
fn trim_leading_debris(path: &str) -> String {
    let absolute =
        path.starts_with('/') || path.starts_with('\\') || path.as_bytes().get(1) == Some(&b':');
    if absolute {
        return path.to_string();
    }
    let plausible = |c: &&str| -> bool {
        !c.is_empty() && c.len() <= 64 && !c.bytes().any(|b| b.is_ascii_uppercase())
    };
    let components: Vec<&str> = path.split(['/', '\\']).collect();
    let separator = if path.contains('\\') { '\\' } else { '/' };
    let first_good = components.iter().position(plausible);
    match first_good {
        Some(i) => components[i..].join(&separator.to_string()),
        None => String::new(),
    }
}

fn verdict_for(score: u32, body_entropy: f64) -> Verdict {
    match score {
        s if s >= 60 => Verdict::Rust,
        s if s >= 30 => Verdict::LikelyRust,
        // Almost no markers, but the body is opaque: the evidence is inside the
        // packed blob rather than absent.
        _ if body_entropy >= 7.2 => Verdict::ObscuredByPacking,
        _ => Verdict::NotRust,
    }
}

fn sort_crates(crates: &mut [CrateRef]) {
    crates.sort_by(|a, b| {
        symbols::is_toolchain_crate(&a.name)
            .cmp(&symbols::is_toolchain_crate(&b.name))
            .then_with(|| b.hits.cmp(&a.hits))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
pub fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > haystack.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

/// Extract printable runs of at least `min_len` bytes.
///
/// Rust string literals are *not* NUL-terminated - they are `(ptr, len)` slices
/// into a packed `.rodata` pool - so adjacent literals run together into long
/// stretches. That is expected; this is a scanning aid, not a literal recovery.
pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..=0x7e).contains(&b) || b == b'\t';
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len {
                    out.push((s as u64, String::from_utf8_lossy(&data[s..i]).into_owned()));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min_len {
            out.push((s as u64, String::from_utf8_lossy(&data[s..]).into_owned()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occurrences_are_counted_without_overlap() {
        assert_eq!(count_occurrences(b"aaaa", b"aa"), 2);
        assert_eq!(count_occurrences(b"abc", b"d"), 0);
        assert_eq!(count_occurrences(b"", b"a"), 0);
        assert_eq!(count_occurrences(b"a", b""), 0);
    }

    #[test]
    fn the_rustc_commit_and_version_are_recovered() {
        let data = b"/rustc/9b00956e56009bab2aa15d7bff10916599e3d6d6/library/core/src/panicking.rs\
                     rustc 1.79.0 (129f3b996 2024-06-10)";
        let p = detect_bytes(data, 5.0);
        assert_eq!(
            p.rustc.commit.as_deref(),
            Some("9b00956e56009bab2aa15d7bff10916599e3d6d6")
        );
        assert_eq!(p.rustc.version.as_deref(), Some("1.79.0"));
        assert_eq!(p.rustc.date.as_deref(), Some("2024-06-10"));
    }

    #[test]
    fn registry_paths_yield_crate_names_and_versions() {
        let data = b"/home/x/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aes-gcm-0.10.3/src/lib.rs";
        let p = detect_bytes(data, 5.0);
        let c = p
            .find_crate("aes_gcm")
            .expect("aes-gcm should be recovered");
        assert_eq!(c.version.as_deref(), Some("0.10.3"));
        assert_eq!(c.display_name, "aes-gcm");
        assert_eq!(c.source, CrateSource::Registry);
    }

    #[test]
    fn hyphenated_crate_names_split_at_the_version_not_the_first_hyphen() {
        let data = b"C:\\Users\\a\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\curve25519-dalek-4.1.1\\src\\lib.rs";
        let p = detect_bytes(data, 5.0);
        let c = p
            .find_crate("curve25519_dalek")
            .expect("curve25519-dalek should be recovered whole");
        assert_eq!(c.version.as_deref(), Some("4.1.1"));
    }

    #[test]
    fn windows_and_unix_separators_both_parse() {
        let unix = b"/x/registry/src/idx/serde-1.0.203/src/lib.rs";
        let win = b"C:\\x\\registry\\src\\idx\\serde-1.0.203\\src\\lib.rs";
        assert!(detect_bytes(unix, 5.0).find_crate("serde").is_some());
        assert!(detect_bytes(win, 5.0).find_crate("serde").is_some());
    }

    #[test]
    fn panic_markers_push_the_score_to_a_rust_verdict() {
        let data = b"called `Option::unwrap()` on a `None` value\
                     called `Result::unwrap()` on an `Err` value\
                     index out of bounds: the len is panicked at RUST_BACKTRACE\
                     library/std/src/io/mod.rs";
        let p = detect_bytes(data, 4.0);
        assert_eq!(p.verdict, Verdict::Rust);
        assert!(p.std_present);
    }

    #[test]
    fn a_packed_sample_reports_obscured_rather_than_not_rust() {
        // No markers at all, but the body is opaque.
        let p = detect_bytes(b"\x00\x01\x02", 7.9);
        assert_eq!(p.verdict, Verdict::ObscuredByPacking);
        // Same lack of markers, ordinary body: a real negative.
        let p = detect_bytes(b"\x00\x01\x02", 3.0);
        assert_eq!(p.verdict, Verdict::NotRust);
    }

    #[test]
    fn no_std_binaries_report_std_absent() {
        let data = b"/rustc/9b00956e56009bab2aa15d7bff10916599e3d6d6/library/core/src/panicking.rs";
        let p = detect_bytes(data, 5.0);
        assert!(!p.std_present, "core-only markers must not imply std");
    }

    #[test]
    fn author_build_paths_exclude_toolchain_and_registry_paths() {
        let data = b"/home/dev/loader/src/main.rs\
                     /rustc/9b00956e56009bab2aa15d7bff10916599e3d6d6/library/core/src/mod.rs\
                     /x/registry/src/idx/serde-1.0.203/src/lib.rs";
        let p = detect_bytes(data, 5.0);
        let paths: Vec<&str> = p.build_paths.iter().map(|b| b.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("loader/src/main.rs")));
        assert!(!paths.iter().any(|p| p.contains("registry")));
        assert!(!paths.iter().any(|p| p.contains("/rustc/")));
    }

    #[test]
    fn pooled_literals_do_not_run_together_into_one_path() {
        // Rust string literals are length-prefixed, not NUL-terminated, so
        // `.rodata` holds them back to back with nothing in between. A greedy
        // pattern reads this as a single path and loses the author's.
        let data =
            b"src/main.rs/rustc/9b00956e56009bab2aa15d7bff10916599e3d6d6/library/core/src/mod.rs";
        let p = detect_bytes(data, 5.0);
        let paths: Vec<&str> = p.build_paths.iter().map(|b| b.path.as_str()).collect();
        assert!(paths.contains(&"src/main.rs"), "got {paths:?}");
    }

    #[test]
    fn a_pooled_registry_path_does_not_leak_a_version_fragment() {
        // The `-` before the version is a valid match boundary, so without the
        // version-fragment filter this yields `1.0.203/src/lib.rs`, which no
        // longer contains the word "registry" and would pass as an author path.
        let data = b"x/registry/src/idx/serde-1.0.203/src/lib.rs";
        let p = detect_bytes(data, 5.0);
        let paths: Vec<&str> = p.build_paths.iter().map(|b| b.path.as_str()).collect();
        assert!(paths.is_empty(), "got {paths:?}");
    }

    #[test]
    fn debris_from_the_preceding_literal_is_not_prepended() {
        // `.rodata` packs literals flush against each other; a path must not
        // start inside the one before it.
        let data = b"ClasspaddingtextcodeDelta-crates\\loader\\src\\main.rs";
        let p = detect_bytes(data, 5.0);
        let paths: Vec<&str> = p.build_paths.iter().map(|b| b.path.as_str()).collect();
        // The fused first component is dropped. `crates` was swallowed into the
        // debris and cannot be recovered - what matters is that no garbage is
        // presented to the analyst as if it were a real directory.
        assert_eq!(paths, vec!["loader\\src\\main.rs"], "got {paths:?}");
    }

    #[test]
    fn lowercase_relative_paths_are_left_intact() {
        let data = b"\x00crates\\frustracean-core\\src\\binary.rs\x00";
        let p = detect_bytes(data, 5.0);
        let paths: Vec<&str> = p.build_paths.iter().map(|b| b.path.as_str()).collect();
        assert_eq!(paths, vec!["crates\\frustracean-core\\src\\binary.rs"]);
    }

    #[test]
    fn capitalised_absolute_paths_are_left_intact() {
        let data = b"\x00C:\\Users\\dev\\Projects\\Loader\\src\\main.rs\x00";
        let p = detect_bytes(data, 5.0);
        let paths: Vec<&str> = p.build_paths.iter().map(|b| b.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["C:\\Users\\dev\\Projects\\Loader\\src\\main.rs"]
        );
    }

    #[test]
    fn nested_source_paths_are_kept_whole() {
        let data = b"\x00/home/dev/proj/src/modules/loader.rs\x00";
        let p = detect_bytes(data, 5.0);
        let paths: Vec<&str> = p.build_paths.iter().map(|b| b.path.as_str()).collect();
        assert!(
            paths.contains(&"/home/dev/proj/src/modules/loader.rs"),
            "got {paths:?}"
        );
    }

    #[test]
    fn third_party_crates_exclude_the_toolchains_own() {
        let data = b"/x/registry/src/idx/reqwest-0.12.4/src/lib.rs\
                     /x/registry/src/idx/miniz_oxide-0.7.2/src/lib.rs";
        let p = detect_bytes(data, 5.0);
        let names: Vec<&str> = p.third_party_crates().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["reqwest"]);
    }

    #[test]
    fn strings_extraction_finds_runs_and_respects_the_minimum() {
        let data = b"\x00\x01hello world\x00ab\x00longer string here";
        let found = extract_strings(data, 6);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].1, "hello world");
        assert_eq!(found[0].0, 2);
        assert_eq!(found[1].1, "longer string here");
    }
}
