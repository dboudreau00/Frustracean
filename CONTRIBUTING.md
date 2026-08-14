# Contributing

Thanks for looking. This is a focused tool, and the fastest way to get a change
merged is to know what it is trying to be.

## The one principle

**Never claim more than you have verified.** A tool that tells an analyst
something false is worse than a tool that tells them nothing, because the
analyst will act on it. Concretely:

- A heuristic is labelled as one. String-cross-reference targets are low
  confidence *by construction*, and the code says so.
- Coverage gaps are recorded, never dropped. If the planner refuses a hook site,
  it goes in `plan.skipped` with a reason.
- If a capability is not finished, the README says it is not finished. The
  detour stub is the standing example: it is designed, documented, and
  deliberately unimplemented rather than approximated.

If a change would make the tool sound more capable than it is, it will not be
merged, however good the code.

## Setup

Stable Rust. No C toolchain — every dependency is pure Rust.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all
```

`tools/build.ps1` wraps build and test on Windows.

There is a good test subject in the repo: `crates/frustracean-testbed` is a
benign sample that packs and unpacks itself. Run the pipeline against it rather
than against real malware.

```bash
cargo run --bin frustracean -- scan target/debug/frustracean-testbed
```

## Before opening a pull request

- `cargo test --workspace` passes.
- `cargo clippy --workspace --all-targets` is clean. CI runs with
  `-D warnings`.
- `cargo fmt --all` has been run.
- If you touched console output, regenerate the screenshots:
  `powershell -File tools/screenshots.ps1`. They are produced from real output,
  so a stale one shows up as a text diff rather than going unnoticed.
- If you touched the signature catalogue, `cargo run --bin frustracean -- rules`
  loads and validates it.

## Things worth knowing before you start

These have each caused a real bug in this codebase.

**Rust string literals are not NUL-terminated.** They are length-prefixed slices
packed into `.rodata` with nothing between them, so a regex over that data needs
lazy quantifiers *and* an explicit leading boundary, or it will match across
literal edges. See `RE_BUILD_PATH` in `rustid.rs`.

**`&[u8]` is a fat pointer and consumes two ABI slots.** `sret` consumes one
more, before any declared argument, and whether a return value needs `sret` is
calling-convention dependent — a 12-byte return uses a hidden pointer on Win64
and registers on SysV64. Getting either wrong shifts every subsequent argument
silently. `plan::resolve_args` is small and heavily tested for this reason.

**Every header field is attacker-controlled.** Address arithmetic uses
`checked_`/`saturating_` throughout, and counts are capped, because a crafted
image must not panic the tool. Add to
`crates/frustracean-core/tests/hostile_images.rs` when you touch parsing.

**`BTreeMap::range` panics on an inverted range in release builds too.** Unlike
integer overflow, that one is not a debug-only failure.

## Contributing a signature rule

This is the highest-value contribution and the easiest to get subtly wrong.

A rule describes *logical Rust arguments*, not registers; the ABI mapping
happens in `plan`. Please include, in the rule's `description`:

- why `sret` is set or not, in terms of the real return type;
- what the string anchors are and why they survive into a compiled binary
  (an anchor that gets const-folded away is worse than no anchor, because a rule
  that never fires reads like evidence of absence);
- for anything writing to a separate output buffer, a `compare: {from, to}` —
  a decompressor's output is empty on entry, so comparing it against itself
  measures nothing.

Verify the argument model against a disassembly of the real crate before
submitting. "It looks right" is how the wrong register gets dumped.

Rules for crates that only exist at compile time — proc macros like `goldberg` —
cannot be matched by a registry-path anchor at all, because their code never
links into the sample. Say so in a comment instead of adding a rule that can
never fire.

## Reporting a crash on a real sample

Do not attach malware to a public issue. Reduce it to a minimal crafted file
that reproduces the behaviour, or report privately per `SECURITY.md`.

## Scope

In scope: Rust-specific analysis, the entropy pipeline, the rule catalogue, the
hook machinery, and anything that makes the output more honest.

Out of scope: becoming a general-purpose disassembler, unpacking non-Rust
binaries, and defeating commercial protectors. There are better tools for each.
