<!--
Thanks for contributing. CONTRIBUTING.md has the details; the short version is
that this tool must never claim more than it has verified.
-->

## What this changes

<!-- One or two sentences. -->

## Why

<!-- What was wrong, or what this makes possible. -->

## Checks

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets` is clean
- [ ] `cargo fmt --all` has been run
- [ ] Console output unchanged, or screenshots regenerated with
      `powershell -File tools/screenshots.ps1`
- [ ] Catalogue unchanged, or `cargo run --bin frustracean -- rules` validates

## If this touches parsing

- [ ] Address arithmetic is `checked_`/`saturating_`; any new count is capped
- [ ] A case was added to `crates/frustracean-core/tests/hostile_images.rs`

## If this touches the signature catalogue

- [ ] The argument model was checked against a disassembly, not just the source
- [ ] `sret` reflects the real return type, and the description says why
- [ ] Functions writing to a separate output buffer declare `compare: {from, to}`

## Honesty check

- [ ] Nothing here makes the tool sound more capable than it is
- [ ] New heuristics are labelled as heuristics
- [ ] Anything skipped or capped is recorded in the output, not silently dropped
