# Frustracean — working notes

Rust-aware entropy triage and call-hijack planning for Rust malware. Companion to the
Delphi tool `Delpheed` in the sibling directory; deliberately shares its conventions.

## Build and verify

Cargo is **not on PATH**. Invoke it by full path:

```powershell
& "C:\Program Files\Rust stable MSVC 1.96\bin\cargo.exe" test --workspace --offline
```

`--offline` matters: the sandbox has no network. Dependencies are already vendored in
`~/.cargo/registry`. If a new dependency is added, `cargo fetch` must run with the sandbox
disabled once before `--offline` builds will work again.

`tools/build.ps1` wraps build + test.

Before claiming anything works, run the workspace tests **and** exercise the CLI against a
real binary. `target/debug/frustracean.exe` is itself a Rust PE and makes a good subject:

```powershell
.\target\debug\frustracean.exe scan .\target\debug\frustracean.exe
```

## Layout

Four crates. The split is load-bearing, not cosmetic:

- `frustracean-core` — everything analytical. The `analysis` feature gates goblin, iced-x86,
  regex, serde_yaml, and rustc-demangle.
- `frustracean-cli` — the `frustracean` binary.
- `frustracean-hook` — the injected payload. Depends on core with
  **`default-features = false`**, so it does not pull core's binary parser, regex engine or
  YAML engine through that edge. It *does* take a direct `iced-x86` dependency, because the
  trampoline has to re-encode stolen bytes — the payload has a disassembler, just not core's
  analysis stack.
- `frustracean-testbed` — a benign, dependency-free self-unpacking sample; the target the
  detour stub is meant to be brought up against. `publish = false`.

If you add something to core that the payload needs, put the types outside the `analysis`
gate and the machinery inside it. `binary.rs`, `signature.rs`, and `plan.rs` are all split
this way already — types always compiled, parsers and matchers gated. CI checks the split
holds with `cargo check -p frustracean-core --no-default-features`.

## Conventions inherited from Delpheed

Console output is accessible by design, and this is not decorative:

- status in **words** (`OK:`, `ERROR:`, `WARNING:`, `INFO:`), never colour;
- labelled linear output (`Name: value`), no aligned columns;
- errors and warnings to **stderr**, results to stdout;
- exit codes: 0 ok, 1 usage, 2 bad input, 3 ran but failed.

Use the helpers in `cli/src/out.rs`; do not `println!` status directly.

## Things that bite

- **Rust string literals are not NUL-terminated.** They are length-prefixed slices packed
  into `.rodata` with nothing between them. Any regex over that data needs a lazy quantifier
  and an explicit leading boundary, or it will match across literal edges. This has already
  caused two real bugs; see `RE_BUILD_PATH` in `rustid.rs`.
- **`&[u8]` is a fat pointer** and consumes *two* ABI slots. `sret` consumes one before any
  declared argument. Both are handled in `plan::resolve_args`, which is small and heavily
  tested precisely because getting it wrong shifts every subsequent argument silently.
- **iced-x86's block encoder promotes unreachable branches.** A `jmp rel32` it cannot reach
  becomes a 14-byte `jmp [rip+N]` with the absolute target inline. Only the *patch* is
  constrained to ±2GB; the trampoline can live anywhere.
- **goblin's `CoffHeader::symbols`/`strings` return `Result<Option<..>>`**, not `Result<..>`.
- **`min_string_hits` counts distinct anchors, not references.** Ten references to one string
  is one piece of evidence repeated. Do not "fix" this back.
- A skipped hook site must always be **recorded** in `plan.skipped`, never dropped. A
  coverage gap nobody writes down is a coverage gap nobody notices.
- **Every header field is attacker-controlled.** Address arithmetic uses `checked_`/
  `saturating_`, and every count that comes from a header is capped (`binary::limits`,
  `disasm::limits`). `BTreeMap::range` panics on an inverted range in *release* builds too,
  unlike integer overflow. Add to `crates/frustracean-core/tests/hostile_images.rs` when
  touching parsing.
- **`sret` is calling-convention dependent.** A 12-byte return uses a hidden out-pointer on
  Win64 and registers on SysV64, so the same rule needs different `sret` values per target.
  The catalogue is written for Win64 and says so.
- Console output is screenshotted into the README by `tools/screenshots.ps1`, generated from
  real output. Change what the tool prints and the screenshots must be regenerated.

## The unfinished piece

`crates/frustracean-hook/src/detour.rs` documents a design and implements everything except
the stub itself. `install()` returns an explanatory error on purpose.

Do not write that stub speculatively. It is hand-written machine code running inside a
hostile process; it needs bring-up against a benign target under a debugger, with the
wrapped-call stack discipline, the TLS frame stack, and the re-entrancy guard each verified
separately. Shipping plausible-looking asm here is worse than shipping nothing, because the
failure mode is a corrupted sample halfway through unpacking.

## Signature catalogue

`signatures/*.yaml`, loaded in filename order so rule precedence is deterministic. Validated
at load time — run `frustracean rules` after editing.

Rules describe **logical Rust arguments**, not registers; the ABI mapping happens in `plan`.
Use `compare: {from: input, to: output}` for anything that writes to a separate buffer: a
decompressor's output is empty on entry, so comparing it against itself measures nothing.

Crate versions in the catalogue's `strings` anchors are load-bearing — they come from the
registry paths rustc embeds, and they are frequently the only anchor left in a stripped
sample.
