# Security policy

Frustracean is a malware-analysis tool. Two things follow from that, and both
shape what counts as a vulnerability here.

**It parses hostile input by design.** Every byte of a sample is chosen by
someone who would rather not be analysed, and who may well know this tool
exists. A crafted PE or ELF that crashes, hangs, or exhausts memory is a real
vulnerability: it denies an analyst their tool at the moment they need it.

**It executes malware on purpose.** The `trace` subcommand runs the sample so
that the sample's own code performs the unpacking. That is the entire technique,
not an oversight.

## Reporting

Report privately through **GitHub Security Advisories** — the *Security* tab,
then *Report a vulnerability*. Please do not open a public issue for anything in
scope below.

Include the affected version or commit, what you observed, and ideally a minimal
input that reproduces it. A crafted binary is far more useful than a
description; attach it as an archive.

Expect an acknowledgement within **7 days** and an assessment within **30 days**.
This is a personal project, not a funded programme, so those are honest targets
rather than a contractual commitment. If a fix will take longer, you will be told
why.

## In scope

- A malformed or crafted image that makes any static command (`scan`, `map`,
  `stats`, `deps`, `strings`, `plan`) panic, hang, or allocate without bound.
  Regression tests for this class live in
  `crates/frustracean-core/tests/hostile_images.rs`.
- Path traversal or arbitrary file write driven by attacker-controlled content —
  for example a captured buffer's name influencing where a dump is written.
- The injector writing to, or launching, anything other than the sample the
  analyst named.
- A signature rule whose argument model causes the payload to read memory the
  rule did not describe.
- Vulnerabilities in how this project uses `goblin`, `regex`, `iced-x86`,
  `serde_yaml`, or `windows-sys`. Report issues *inside* those crates upstream,
  but tell us too if this project's usage is what exposes them.

## Out of scope

- **`trace` running the sample.** It is documented, it refuses to start without
  an explicit `--sandboxed` acknowledgement, and running malware is the point.
  "The tool executed the malware I told it to execute" is not a vulnerability.
- **The sample escaping analysis.** A sample that detects the hook, refuses to
  unpack, or exits early is doing its job. That is an arms race, not a security
  bug — open a normal issue.
- **Anything requiring the attacker to already control the analyst's machine.**
- **The `detour` feature.** Hook installation is unimplemented and disabled by
  default; see `crates/frustracean-hook/src/detour.rs`. Bugs in code that
  refuses to run are not exploitable.

## Operating guidance

If you are running samples: use a disposable, network-isolated virtual machine
with a snapshot to revert to. Frustracean bounds the run with `--timeout` and
terminates the process afterwards, but a timeout is a convenience, not
containment. Nothing in this tool sandboxes anything.

The static commands never execute the sample and are safe to run on an ordinary
workstation.

## Supported versions

Pre-1.0. Only the latest release and `main` receive fixes. There are no
backports.
