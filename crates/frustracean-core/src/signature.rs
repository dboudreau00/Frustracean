//! The rule catalogue: which functions are worth hijacking, and what to capture.
//!
//! A rule is deliberately two-sided. `match.demangled_regex` handles the easy
//! case - a sample that still has symbols - while `match.strings` handles the
//! realistic one, where the analyst has a stripped image and the only anchor is
//! a constant the crate is known to embed (an S-box, a magic header, a panic
//! message from inside the crate's own source tree). The planner will try the
//! symbol path first and fall back to string cross-references.
//!
//! Argument declarations describe *logical* Rust arguments, not registers. A
//! `slice` occupies two integer slots because `&[u8]` is a fat pointer; the ABI
//! mapping is applied later, in `plan`, where the target's calling convention
//! is known.

use serde::{Deserialize, Serialize};

#[cfg(feature = "analysis")]
use std::collections::BTreeSet;
#[cfg(feature = "analysis")]
use std::path::Path;

#[cfg(feature = "analysis")]
use regex::Regex;

#[cfg(feature = "analysis")]
use crate::binary::Symbol;
#[cfg(feature = "analysis")]
use crate::error::{Error, Result};

/// Catalogue format version.
pub const SIGNATURE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Crypto,
    Compression,
    Obfuscation,
    Loader,
    Network,
    #[serde(other)]
    Other,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::Crypto => "crypto",
            Family::Compression => "compression",
            Family::Obfuscation => "obfuscation",
            Family::Loader => "loader",
            Family::Network => "network",
            Family::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// How a logical Rust argument occupies the ABI's integer slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgKind {
    /// `&self` / `&mut self` / any thin pointer. One slot.
    Ptr,
    /// `&[u8]` - a fat pointer. **Two slots**: pointer then length.
    Slice,
    /// `&mut [u8]`. Two slots. The one worth dumping on return.
    SliceMut,
    /// A bare length or count. One slot.
    Len,
    /// Any other integer-class scalar. One slot.
    Int,
    /// Occupies a slot but is not worth recording.
    Skip,
}

impl ArgKind {
    /// Integer register/stack slots this argument consumes.
    pub fn slots(self) -> usize {
        match self {
            ArgKind::Slice | ArgKind::SliceMut => 2,
            _ => 1,
        }
    }

    pub fn is_buffer(self) -> bool {
        matches!(self, ArgKind::Slice | ArgKind::SliceMut)
    }

    pub fn label(self) -> &'static str {
        match self {
            ArgKind::Ptr => "ptr",
            ArgKind::Slice => "slice",
            ArgKind::SliceMut => "slice_mut",
            ArgKind::Len => "len",
            ArgKind::Int => "int",
            ArgKind::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    pub kind: ArgKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiSpec {
    /// Set when the function returns a type too large for a register, so the
    /// caller passes a hidden out-pointer that consumes the **first** slot
    /// before any declared argument. Getting this wrong shifts every argument.
    #[serde(default)]
    pub sret: bool,
    #[serde(default)]
    pub args: Vec<ArgSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum When {
    Entry,
    Return,
    #[default]
    Both,
}

impl When {
    pub fn captures_entry(self) -> bool {
        matches!(self, When::Entry | When::Both)
    }

    pub fn captures_return(self) -> bool {
        matches!(self, When::Return | When::Both)
    }

    pub fn label(self) -> &'static str {
        match self {
            When::Entry => "entry",
            When::Return => "return",
            When::Both => "both",
        }
    }
}

/// What the entropy of a dumped buffer is expected to do across the call.
/// Used to score whether a hijack actually caught an unpack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// Decrypt or decompress: opaque in, structured out.
    #[default]
    EntropyDrop,
    /// Encrypt or compress. Useful for catching exfil staging.
    EntropyRise,
    Any,
}

impl Expect {
    pub fn label(self) -> &'static str {
        match self {
            Expect::EntropyDrop => "entropy_drop",
            Expect::EntropyRise => "entropy_rise",
            Expect::Any => "any",
        }
    }
}

fn default_max_bytes() -> usize {
    1 << 20
}

/// Which two buffers to measure the entropy transition across.
///
/// The default - the same buffer on entry and on return - is right for an
/// in-place cipher, and wrong for anything that writes to a separate output.
/// A decompressor is handed an *empty* output buffer, so comparing it against
/// itself measures the difference between zeroes and data, which is not a
/// finding. What matters is the compressed `input` on the way in against the
/// inflated `output` on the way out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comparison {
    /// Buffer name to read on entry.
    pub from: String,
    /// Buffer name to read on return.
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSpec {
    #[serde(default)]
    pub when: When,
    /// Argument names to dump. Each must name a `slice` or `slice_mut` argument.
    #[serde(default)]
    pub dump: Vec<String>,
    #[serde(default)]
    pub expect: Expect,
    /// Cross-buffer comparison. Omit for an in-place transform.
    #[serde(default)]
    pub compare: Option<Comparison>,
    /// Upper bound on bytes read per buffer. A hostile length field is the
    /// obvious way to make a naive hook read a gigabyte or fault, so this is
    /// enforced by the payload, not merely advisory.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

impl Default for CaptureSpec {
    fn default() -> Self {
        CaptureSpec {
            when: When::default(),
            dump: Vec::new(),
            expect: Expect::default(),
            compare: None,
            max_bytes: default_max_bytes(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchSpec {
    /// Regex against the demangled symbol name.
    #[serde(default)]
    pub demangled_regex: Option<String>,
    /// Regex against the raw (still-mangled) symbol name.
    #[serde(default)]
    pub symbol_regex: Option<String>,
    /// Constants the crate is known to embed. Used to locate the function by
    /// cross-reference when the image is stripped.
    #[serde(default)]
    pub strings: Vec<String>,
    /// Hex byte patterns (whitespace ignored, `??` is a wildcard nibble pair).
    #[serde(default)]
    pub bytes: Vec<String>,
    /// How many of `strings` must be present before the string path is trusted.
    #[serde(default)]
    pub min_string_hits: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// Owning crate, hyphenated as on crates.io.
    #[serde(rename = "crate", default)]
    pub crate_name: Option<String>,
    #[serde(default)]
    pub family: Option<Family>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    #[serde(default)]
    pub abi: AbiSpec,
    #[serde(default)]
    pub capture: CaptureSpec,
}

impl Rule {
    /// Total integer slots the declared arguments consume, including `sret`.
    pub fn slot_count(&self) -> usize {
        let base = usize::from(self.abi.sret);
        base + self.abi.args.iter().map(|a| a.kind.slots()).sum::<usize>()
    }
}

#[cfg(feature = "analysis")]
impl Rule {
    /// Check the rule is internally consistent. Catching this at load time is
    /// the difference between a clear error and a hook that silently dumps the
    /// wrong register.
    pub fn validate(&self) -> Result<()> {
        let bad = |reason: String| Error::BadRule {
            id: self.id.clone(),
            reason,
        };
        if self.id.trim().is_empty() {
            return Err(bad("id must not be empty".into()));
        }
        if self.match_spec.demangled_regex.is_none()
            && self.match_spec.symbol_regex.is_none()
            && self.match_spec.strings.is_empty()
            && self.match_spec.bytes.is_empty()
        {
            return Err(bad(
                "match must specify at least one of demangled_regex, symbol_regex, strings, bytes"
                    .into(),
            ));
        }
        for pattern in [
            self.match_spec.demangled_regex.as_ref(),
            self.match_spec.symbol_regex.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            Regex::new(pattern).map_err(|e| bad(format!("bad regex {pattern:?}: {e}")))?;
        }
        for pattern in &self.match_spec.bytes {
            parse_byte_pattern(pattern)
                .map_err(|e| bad(format!("bad byte pattern {pattern:?}: {e}")))?;
        }

        let mut seen = BTreeSet::new();
        for arg in &self.abi.args {
            if !seen.insert(arg.name.as_str()) {
                return Err(bad(format!("duplicate argument name {:?}", arg.name)));
            }
        }
        for name in &self.capture.dump {
            match self.abi.args.iter().find(|a| &a.name == name) {
                None => {
                    return Err(bad(format!(
                        "capture.dump names {name:?}, which is not a declared argument"
                    )))
                }
                Some(arg) if !arg.kind.is_buffer() => {
                    return Err(bad(format!(
                        "capture.dump names {name:?}, which is a {} and carries no length",
                        arg.kind.label()
                    )))
                }
                Some(_) => {}
            }
        }
        if let Some(compare) = &self.capture.compare {
            for (field, name) in [("from", &compare.from), ("to", &compare.to)] {
                match self.abi.args.iter().find(|a| &a.name == name) {
                    None => {
                        return Err(bad(format!(
                            "capture.compare.{field} names {name:?}, which is not a declared argument"
                        )))
                    }
                    Some(arg) if !arg.kind.is_buffer() => {
                        return Err(bad(format!(
                            "capture.compare.{field} names {name:?}, which is a {} and carries no length",
                            arg.kind.label()
                        )))
                    }
                    Some(_) => {}
                }
                // A comparison is only observable if the buffer is captured.
                if !self.capture.dump.contains(name) {
                    return Err(bad(format!(
                        "capture.compare.{field} names {name:?}, which is not in capture.dump"
                    )));
                }
            }
            // `from` is read on entry and `to` on return, so both phases must
            // actually be captured.
            if self.capture.when != When::Both {
                return Err(bad(
                    "capture.compare needs capture.when: both, since it reads one buffer on \
                     entry and another on return"
                        .into(),
                ));
            }
        }
        if self.capture.max_bytes == 0 {
            return Err(bad("capture.max_bytes must be greater than zero".into()));
        }
        Ok(())
    }
}

/// One YAML file's worth of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFile {
    pub version: u32,
    #[serde(default)]
    pub family: Option<Family>,
    pub rules: Vec<Rule>,
}

/// A rule with its regexes compiled once.
#[cfg(feature = "analysis")]
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    demangled: Option<Regex>,
    symbol: Option<Regex>,
}

#[cfg(feature = "analysis")]
impl CompiledRule {
    pub fn new(rule: Rule) -> Result<CompiledRule> {
        rule.validate()?;
        let demangled = rule
            .match_spec
            .demangled_regex
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|e| Error::BadRule {
                id: rule.id.clone(),
                reason: e.to_string(),
            })?;
        let symbol = rule
            .match_spec
            .symbol_regex
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|e| Error::BadRule {
                id: rule.id.clone(),
                reason: e.to_string(),
            })?;
        Ok(CompiledRule {
            rule,
            demangled,
            symbol,
        })
    }

    /// Does this rule name the given symbol?
    pub fn matches_symbol(&self, sym: &Symbol) -> bool {
        if let (Some(re), Some(dem)) = (&self.demangled, sym.demangled.as_deref()) {
            if re.is_match(dem) {
                return true;
            }
        }
        if let Some(re) = &self.symbol {
            if re.is_match(&sym.name) {
                return true;
            }
        }
        false
    }

    /// Can this rule be resolved without symbols?
    pub fn has_string_anchors(&self) -> bool {
        !self.rule.match_spec.strings.is_empty()
    }

    /// How many string anchors must hit before the fallback path is trusted.
    pub fn required_string_hits(&self) -> usize {
        let declared = self.rule.match_spec.min_string_hits;
        if declared == 0 {
            1
        } else {
            declared.min(self.rule.match_spec.strings.len())
        }
    }
}

/// The loaded catalogue.
#[cfg(feature = "analysis")]
#[derive(Debug, Clone, Default)]
pub struct SignatureSet {
    pub rules: Vec<CompiledRule>,
}

#[cfg(feature = "analysis")]
impl SignatureSet {
    /// Parse one catalogue file's worth of YAML.
    ///
    /// Deliberately not `FromStr`: loading a catalogue validates every rule and
    /// reports which one failed, which is more than that trait's contract
    /// suggests.
    pub fn parse(text: &str) -> Result<SignatureSet> {
        let file: SignatureFile = serde_yaml::from_str(text)?;
        if file.version != SIGNATURE_VERSION {
            return Err(Error::plain(format!(
                "signature file version {} is not supported (expected {SIGNATURE_VERSION})",
                file.version
            )));
        }
        let mut rules = Vec::with_capacity(file.rules.len());
        for mut rule in file.rules {
            // A file-level family is the default for every rule in it.
            if rule.family.is_none() {
                rule.family = file.family;
            }
            rules.push(CompiledRule::new(rule)?);
        }
        Ok(SignatureSet { rules })
    }

    /// Load every `.yaml`/`.yml` file in a directory, non-recursively.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<SignatureSet> {
        let dir = dir.as_ref();
        let entries = std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))?;
        let mut paths: Vec<_> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|s| s.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        // Deterministic order so rule precedence does not depend on the filesystem.
        paths.sort();

        let mut set = SignatureSet::default();
        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
            let loaded = SignatureSet::parse(&text)
                .map_err(|e| Error::plain(format!("{}: {e}", path.display())))?;
            set.rules.extend(loaded.rules);
        }
        set.check_unique_ids()?;
        Ok(set)
    }

    fn check_unique_ids(&self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for r in &self.rules {
            if !seen.insert(r.rule.id.as_str()) {
                return Err(Error::plain(format!("duplicate rule id {:?}", r.rule.id)));
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Every rule that names this symbol. More than one can, and the planner
    /// keeps them all rather than guessing.
    pub fn match_symbol(&self, sym: &Symbol) -> Vec<&CompiledRule> {
        self.rules
            .iter()
            .filter(|r| r.matches_symbol(sym))
            .collect()
    }

    pub fn by_id(&self, id: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.rule.id == id)
    }

    /// Rules that can be resolved without symbols.
    pub fn string_anchored(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter().filter(|r| r.has_string_anchors())
    }
}

/// A byte pattern element: an exact byte or a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternByte {
    Exact(u8),
    Any,
}

/// Parse `"48 8b ?? c3"` into a matchable pattern.
pub fn parse_byte_pattern(pattern: &str) -> std::result::Result<Vec<PatternByte>, String> {
    let mut out = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "??" || token == "?" {
            out.push(PatternByte::Any);
            continue;
        }
        if token.len() != 2 {
            return Err(format!("token {token:?} is not two hex digits or ??"));
        }
        let b = u8::from_str_radix(token, 16)
            .map_err(|_| format!("token {token:?} is not valid hex"))?;
        out.push(PatternByte::Exact(b));
    }
    if out.is_empty() {
        return Err("pattern is empty".into());
    }
    Ok(out)
}

/// Find every offset in `haystack` where `pattern` matches.
pub fn find_byte_pattern(haystack: &[u8], pattern: &[PatternByte]) -> Vec<usize> {
    let mut out = Vec::new();
    if pattern.is_empty() || pattern.len() > haystack.len() {
        return out;
    }
    for i in 0..=haystack.len() - pattern.len() {
        let hit = pattern.iter().enumerate().all(|(j, p)| match p {
            PatternByte::Any => true,
            PatternByte::Exact(b) => haystack[i + j] == *b,
        });
        if hit {
            out.push(i);
        }
    }
    out
}

#[cfg(all(test, feature = "analysis"))]
mod tests {
    use super::*;
    use crate::binary::{Symbol, SymbolSource};

    const SAMPLE: &str = r#"
version: 1
family: crypto
rules:
  - id: rust.crypto.demo.decrypt
    description: demo
    crate: aes-gcm
    confidence: high
    tags: [aead, decrypt]
    match:
      demangled_regex: '^<aes_gcm::AesGcm<.+> as aead::AeadInPlace>::decrypt_in_place_detached'
      strings: ["aes-gcm-0.10"]
    abi:
      sret: false
      args:
        - {name: this, kind: ptr}
        - {name: nonce, kind: ptr}
        - {name: aad, kind: slice}
        - {name: buffer, kind: slice_mut}
    capture:
      when: both
      dump: [buffer]
      expect: entropy_drop
      max_bytes: 65536
"#;

    fn symbol(name: &str, demangled: Option<&str>) -> Symbol {
        Symbol {
            name: name.into(),
            demangled: demangled.map(str::to_string),
            crate_name: None,
            va: 0x1000,
            size: 0,
            source: SymbolSource::Export,
        }
    }

    #[test]
    fn a_well_formed_catalogue_loads() {
        let set = SignatureSet::parse(SAMPLE).unwrap();
        assert_eq!(set.len(), 1);
        let r = &set.rules[0].rule;
        assert_eq!(r.crate_name.as_deref(), Some("aes-gcm"));
        assert_eq!(
            r.family,
            Some(Family::Crypto),
            "file family should default down"
        );
        assert_eq!(r.confidence, Confidence::High);
        assert_eq!(r.capture.max_bytes, 65536);
    }

    #[test]
    fn slices_consume_two_slots() {
        let set = SignatureSet::parse(SAMPLE).unwrap();
        // ptr + ptr + slice(2) + slice_mut(2) = 6
        assert_eq!(set.rules[0].rule.slot_count(), 6);
    }

    #[test]
    fn sret_shifts_every_argument_by_one_slot() {
        let mut rule = SignatureSet::parse(SAMPLE).unwrap().rules[0].rule.clone();
        rule.abi.sret = true;
        assert_eq!(rule.slot_count(), 7);
    }

    #[test]
    fn symbol_matching_uses_the_demangled_name() {
        let set = SignatureSet::parse(SAMPLE).unwrap();
        let sym = symbol(
            "_ZN7aes_gcm4impl17h00E",
            Some("<aes_gcm::AesGcm<aes::Aes256, U12> as aead::AeadInPlace>::decrypt_in_place_detached"),
        );
        assert_eq!(set.match_symbol(&sym).len(), 1);
        assert!(set.match_symbol(&symbol("CreateFileW", None)).is_empty());
    }

    #[test]
    fn a_rule_with_no_match_criteria_is_rejected() {
        let bad = r#"
version: 1
rules:
  - id: broken
    match: {}
"#;
        let err = SignatureSet::parse(bad).unwrap_err().to_string();
        assert!(err.contains("at least one of"), "{err}");
    }

    #[test]
    fn dumping_a_non_buffer_argument_is_rejected() {
        let bad = r#"
version: 1
rules:
  - id: broken
    match: {demangled_regex: 'x'}
    abi:
      args:
        - {name: len, kind: len}
    capture:
      dump: [len]
"#;
        let err = SignatureSet::parse(bad).unwrap_err().to_string();
        assert!(err.contains("carries no length"), "{err}");
    }

    #[test]
    fn dumping_an_undeclared_argument_is_rejected() {
        let bad = r#"
version: 1
rules:
  - id: broken
    match: {demangled_regex: 'x'}
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture:
      dump: [nope]
"#;
        let err = SignatureSet::parse(bad).unwrap_err().to_string();
        assert!(err.contains("not a declared argument"), "{err}");
    }

    #[test]
    fn a_future_catalogue_version_is_refused() {
        let bad = "version: 99\nrules: []\n";
        assert!(SignatureSet::parse(bad)
            .unwrap_err()
            .to_string()
            .contains("not supported"));
    }

    #[test]
    fn byte_patterns_parse_and_match_with_wildcards() {
        let p = parse_byte_pattern("48 8b ?? c3").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p[2], PatternByte::Any);
        let hay = [0x00, 0x48, 0x8b, 0x05, 0xc3, 0x90];
        assert_eq!(find_byte_pattern(&hay, &p), vec![1]);
    }

    #[test]
    fn malformed_byte_patterns_are_rejected() {
        assert!(parse_byte_pattern("").is_err());
        assert!(parse_byte_pattern("4").is_err());
        assert!(parse_byte_pattern("zz").is_err());
    }

    #[test]
    fn a_comparison_across_two_dumped_buffers_is_accepted() {
        let yaml = r#"
version: 1
rules:
  - id: r
    match: {demangled_regex: 'x'}
    abi:
      args:
        - {name: input, kind: slice}
        - {name: output, kind: slice_mut}
    capture:
      when: both
      dump: [input, output]
      compare: {from: input, to: output}
"#;
        let set = SignatureSet::parse(yaml).unwrap();
        let compare = set.rules[0].rule.capture.compare.as_ref().unwrap();
        assert_eq!(compare.from, "input");
        assert_eq!(compare.to, "output");
    }

    #[test]
    fn a_comparison_naming_an_undumped_buffer_is_rejected() {
        // Comparing a buffer that is never captured yields nothing to compare.
        let yaml = r#"
version: 1
rules:
  - id: r
    match: {demangled_regex: 'x'}
    abi:
      args:
        - {name: input, kind: slice}
        - {name: output, kind: slice_mut}
    capture:
      when: both
      dump: [output]
      compare: {from: input, to: output}
"#;
        let err = SignatureSet::parse(yaml).unwrap_err().to_string();
        assert!(err.contains("not in capture.dump"), "{err}");
    }

    #[test]
    fn a_comparison_without_both_phases_is_rejected() {
        let yaml = r#"
version: 1
rules:
  - id: r
    match: {demangled_regex: 'x'}
    abi:
      args:
        - {name: input, kind: slice}
        - {name: output, kind: slice_mut}
    capture:
      when: entry
      dump: [input, output]
      compare: {from: input, to: output}
"#;
        let err = SignatureSet::parse(yaml).unwrap_err().to_string();
        assert!(err.contains("capture.when: both"), "{err}");
    }

    #[test]
    fn max_bytes_defaults_to_a_megabyte() {
        let yaml = r#"
version: 1
rules:
  - id: r
    match: {demangled_regex: 'x'}
"#;
        let set = SignatureSet::parse(yaml).unwrap();
        assert_eq!(set.rules[0].rule.capture.max_bytes, 1 << 20);
        assert_eq!(set.rules[0].rule.capture.when, When::Both);
    }
}
