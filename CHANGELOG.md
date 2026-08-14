# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

First public release. The static-analysis half is complete and exercised; the
detour stub that fires on each hooked call is designed, documented, and
deliberately unimplemented. See the build-status table in the README.

### Added

- **Rust fingerprinting** (`scan`, `deps`) — recovers the exact `rustc` commit,
  the dependency inventory *with versions* from embedded cargo registry paths,
  and the author's build paths, all from a stripped binary. Reports
  `obscured-by-packing` rather than "not Rust" when the markers are inside a
  packed blob.
- **Entropy mapping** (`map`, `stats`) — windowed Shannon entropy with
  chi-square and printable-ratio corroborators, so compressed data can be told
  from ciphertext rather than lumped together as "high entropy". Buffers under
  64 bytes are classified `undersized` rather than given a confident label,
  since entropy is bounded by `log2(len)` and a 16-byte buffer cannot exceed 4
  bits per byte however random it is; `Stats` carries the ceiling and its
  saturation.
- **Exact function boundaries from PE `.pdata`** — `strip` removes symbols but
  cannot remove unwind metadata, because the loader needs it. Parsing the
  `RUNTIME_FUNCTION` array gives precise start and end addresses for every
  function in a stripped x86-64 PE. On the bundled testbed this lifts recovery
  from 248 inferred function starts to 469, of which 413 are exact, and stops an
  address in inter-function padding being attributed to the function before it.
- **Hijack planning** (`plan`) — resolves signature rules against an image by
  symbol, or by RIP-relative string cross-reference when the image is stripped.
  Maps logical Rust arguments onto ABI slots, checks each site's prologue is
  safely patchable, and records every refusal.
- **Signature catalogue** (`rules`) — 19 validated rules across crypto,
  compression, obfuscation, and encoding, plus the bundled fixture.
- **Trace correlation** (`replay`) — pairs entry and return records, computes
  per-buffer entropy deltas, and ranks by what was actually recovered.
- **`frustracean-testbed`** — a benign, dependency-free sample that packs and
  unpacks itself in two stages. It is the target the detour stub is meant to be
  brought up against, and the subject of the CI end-to-end job.
- **Payload scaffolding** — plan rebasing for ASLR, prologue verification
  against the bytes the planner recorded, trampoline construction with
  instruction relocation, buffer clamping, content-addressed dumps, and the
  JSON Lines trace format. All unit tested.
- Hostile-input regression suite covering crafted PE and ELF images.
- Reproducible terminal screenshots generated from real output
  (`tools/screenshots.ps1`).

### Security

The following were found by an adversarial review of the pre-release code and
fixed before publication. Each has a regression test.

- Crafted `ImageBase` values overflowed section, entry, export, and COFF symbol
  address computations, panicking every static command on a malformed PE.
- `sh_size` of `u64::MAX` overflowed the section-offset lookups.
- A section whose `SizeOfRawData` exceeded its `VirtualSize` swallowed the next
  section's address range, so lookups returned the wrong bytes.
- Duplicate section headers over one file range made per-section sweeps do
  O(sections x file size) work — hundreds of gigabytes of hashing from an 8 MB
  file. Ranges are now deduplicated and counts capped.
- Symbol names and counts were bounded only by the sample's own string table.
- A string anchor near the top of the address space produced an inverted
  `BTreeMap::range`, which panics in release builds as well as debug.
- The code index could grow without bound on a crafted section table.
- A symbol pointing into `.rodata` could become a hook target, because constant
  data decodes into plausible-looking instructions.

### Documented

- **Neither Shannon entropy nor chi-square against a uniform model can detect a
  single-byte XOR.** XOR permutes the histogram's bins without changing the
  multiset of bin counts, and both measures are functions of those counts alone,
  so both are exactly invariant. This is now asserted as a test over all 255
  keys and stated in the README rather than left for a user to discover. Of the
  three measures only the printable ratio moves, and it moves monotonically with
  the key's magnitude, which is why it cannot stand alone.
- Every threshold in the entropy model is recorded as a hand-chosen guess rather
  than a fitted value, because none has been calibrated against a labelled
  corpus.

### Fixed

- PIE ELF images reported a load base derived from the lowest allocated
  section (typically `.interp`), making every RVA in a plan wrong by that
  offset.
- `min_string_hits` counted references rather than distinct anchors, so ten
  references to one string promoted a guess to medium confidence.
- Windows command-line arguments were quoted without backslash escaping, so a
  trailing separator swallowed the following argument.
- Two symbol tables naming one function produced a spurious "already hooked"
  entry that read like a coverage gap.
- Several catalogue rules had argument models that did not match the real crate
  APIs, including a missing `sret` on AES-GCM encryption and a trait path that
  never appears for provided methods such as `apply_keystream`.

[Unreleased]: https://github.com/dboudreau00/Frustracean/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dboudreau00/Frustracean/releases/tag/v0.1.0
