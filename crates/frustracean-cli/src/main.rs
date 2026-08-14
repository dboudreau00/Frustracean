//! `frustracean` - Rust-aware entropy triage and call-hijack planning.

mod inject;
mod out;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use frustracean_core::binary::Image;
use frustracean_core::disasm::CodeIndex;
use frustracean_core::entropy::{self, MapOptions};
use frustracean_core::plan::{self, PlanOptions};
use frustracean_core::report::{self, Expectations};
use frustracean_core::rustid::{self, Verdict};
use frustracean_core::signature::SignatureSet;
use frustracean_core::trace;

use out::{exit, Out};

#[derive(Parser)]
#[command(
    name = "frustracean",
    version,
    about = "Rust-aware entropy triage and call-hijack planning for malware analysis",
    long_about = "Frustracean profiles a Rust binary, maps its entropy, recovers the crate \
                  inventory the compiler left behind, and plans inline hooks on the functions \
                  that are known to turn opaque bytes into readable ones.\n\n\
                  Static commands (scan, map, deps, strings, plan, rules, replay) never execute \
                  the sample. Only `trace` does, and it refuses to run without an explicit \
                  sandbox acknowledgement."
)]
struct Cli {
    /// Drop commentary; keep result lines only.
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Identify the image and say whether it is Rust.
    Scan(ScanArgs),
    /// Map entropy across the file and list the opaque regions.
    Map(MapArgs),
    /// Measure a raw blob: entropy, corroborating statistics, and hash.
    Stats(StatsArgs),
    /// Recover the crate dependency inventory from embedded build paths.
    Deps(DepsArgs),
    /// Extract printable strings.
    Strings(StringsArgs),
    /// Load and validate the signature catalogue.
    Rules(RulesArgs),
    /// Resolve signatures against the image and emit a hijack plan.
    Plan(PlanArgs),
    /// Run a sample under the hijack payload. Requires an isolated machine.
    Trace(TraceArgs),
    /// Turn a captured trace into a report.
    Replay(ReplayArgs),
}

#[derive(Args)]
struct ScanArgs {
    /// Path to the image.
    image: PathBuf,
    /// Emit JSON instead of labelled lines.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct MapArgs {
    image: PathBuf,
    /// Sliding window size in bytes.
    #[arg(long, default_value_t = entropy::DEFAULT_WINDOW)]
    window: usize,
    /// Step between windows in bytes.
    #[arg(long, default_value_t = entropy::DEFAULT_STEP)]
    step: usize,
    /// Entropy at or above which a window is considered opaque.
    #[arg(long, default_value_t = entropy::DEFAULT_THRESHOLD)]
    threshold: f64,
    /// Discard regions shorter than this many bytes.
    #[arg(long, default_value_t = 512)]
    min_region: u64,
    /// Also print a per-window listing, not just merged regions.
    #[arg(long)]
    windows: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct StatsArgs {
    /// Any file. Unlike the other commands this does not have to be an image -
    /// it is meant for the blobs a trace recovers.
    file: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DepsArgs {
    image: PathBuf,
    /// Include the toolchain's own crates, which are filtered out by default.
    #[arg(long)]
    all: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct StringsArgs {
    image: PathBuf,
    /// Minimum run length.
    #[arg(long, default_value_t = 6)]
    min: usize,
    /// Only strings that look like Rust build artefacts (source paths, panics).
    #[arg(long)]
    rust_only: bool,
}

#[derive(Args)]
struct RulesArgs {
    /// Directory of signature YAML files.
    #[arg(long)]
    signatures: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct PlanArgs {
    image: PathBuf,
    #[arg(long)]
    signatures: Option<PathBuf>,
    /// Write the plan JSON here. Defaults to stdout with --json.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Do not attempt string cross-reference resolution on stripped images.
    #[arg(long)]
    no_xrefs: bool,
    /// Emit targets whose prologue cannot be patched safely. Hooking one of
    /// these will corrupt the sample; it is for inspection only.
    #[arg(long)]
    include_unsafe: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct TraceArgs {
    /// Hijack plan produced by `frustracean plan`.
    plan: PathBuf,
    /// The sample to execute.
    #[arg(long)]
    sample: PathBuf,
    /// Directory for the trace and captured blobs.
    #[arg(long, default_value = "capture")]
    out: PathBuf,
    /// Path to frustracean_hook.dll. Defaults to one beside this executable.
    #[arg(long)]
    payload: Option<PathBuf>,
    /// Kill the sample after this many seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
    /// Arguments passed through to the sample.
    #[arg(last = true)]
    sample_args: Vec<String>,
    /// Required acknowledgement that this executes live malware on this machine.
    #[arg(long = "sandboxed")]
    sandboxed: bool,
}

#[derive(Args)]
struct ReplayArgs {
    /// A JSON Lines trace.
    trace: PathBuf,
    /// Plan the trace came from, used to recover each rule's expectation.
    #[arg(long)]
    plan: Option<PathBuf>,
    /// Write a Markdown report here.
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let o = Out::new(cli.quiet);
    let code = match cli.command {
        Command::Scan(a) => cmd_scan(&o, a),
        Command::Map(a) => cmd_map(&o, a),
        Command::Stats(a) => cmd_stats(&o, a),
        Command::Deps(a) => cmd_deps(&o, a),
        Command::Strings(a) => cmd_strings(&o, a),
        Command::Rules(a) => cmd_rules(&o, a),
        Command::Plan(a) => cmd_plan(&o, a),
        Command::Trace(a) => cmd_trace(&o, a),
        Command::Replay(a) => cmd_replay(&o, a),
    };
    ExitCode::from(code as u8)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn load_image(o: &Out, path: &Path) -> Result<Image, i32> {
    match Image::load(path) {
        Ok(img) => Ok(img),
        Err(e) => {
            o.error(format!("{}: {e}", path.display()));
            Err(exit::BAD_INPUT)
        }
    }
}

/// Mean entropy of the image's non-executable, on-disk data.
///
/// This is what decides whether a marker-free image is "not Rust" or "packed",
/// so it deliberately excludes code: dense `.text` alone should never make a
/// sample look packed.
fn body_entropy(image: &Image) -> f64 {
    let mut total = 0.0f64;
    let mut weight = 0u64;
    for section in image.data_sections() {
        let range = section.file_range();
        let Some(bytes) = image.data.get(range.start..range.end.min(image.data.len())) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        total += entropy::shannon(bytes) * bytes.len() as f64;
        weight += bytes.len() as u64;
    }
    if weight == 0 {
        entropy::shannon(&image.data)
    } else {
        total / weight as f64
    }
}

/// Find the signature catalogue: the flag, then `./signatures`, then a
/// `signatures` directory beside or above the executable (which is where it
/// lands in a `target/debug` build tree).
fn resolve_signatures(o: &Out, explicit: Option<PathBuf>) -> Result<PathBuf, i32> {
    if let Some(p) = explicit {
        if p.is_dir() {
            return Ok(p);
        }
        o.error(format!("{}: not a directory", p.display()));
        return Err(exit::USAGE);
    }
    let mut candidates = vec![PathBuf::from("signatures")];
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..4 {
            let Some(d) = dir else { break };
            candidates.push(d.join("signatures"));
            dir = d.parent().map(Path::to_path_buf);
        }
    }
    for c in &candidates {
        if c.is_dir() {
            return Ok(c.clone());
        }
    }
    o.error("could not find a signatures directory; pass --signatures");
    Err(exit::USAGE)
}

fn load_signatures(o: &Out, explicit: Option<PathBuf>) -> Result<(SignatureSet, PathBuf), i32> {
    let dir = resolve_signatures(o, explicit)?;
    match SignatureSet::load_dir(&dir) {
        Ok(set) => Ok((set, dir)),
        Err(e) => {
            o.error(format!("{}: {e}", dir.display()));
            Err(exit::BAD_INPUT)
        }
    }
}

fn write_out(o: &Out, path: &Path, contents: &str) -> Result<(), i32> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                o.error(format!("{}: {e}", parent.display()));
                return Err(exit::FAILED);
            }
        }
    }
    if let Err(e) = std::fs::write(path, contents) {
        o.error(format!("{}: {e}", path.display()));
        return Err(exit::FAILED);
    }
    Ok(())
}

fn emit_json<T: serde::Serialize>(o: &Out, value: &T) -> i32 {
    match serde_json::to_string_pretty(value) {
        Ok(s) => {
            o.line(s);
            exit::OK
        }
        Err(e) => {
            o.error(e.to_string());
            exit::FAILED
        }
    }
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

fn cmd_scan(o: &Out, a: ScanArgs) -> i32 {
    let image = match load_image(o, &a.image) {
        Ok(i) => i,
        Err(c) => return c,
    };
    let body = body_entropy(&image);
    let profile = rustid::detect(&image, body);

    if a.json {
        #[derive(serde::Serialize)]
        struct Json<'a> {
            path: String,
            sha256: &'a str,
            format: &'a str,
            arch: &'a str,
            bits: u32,
            abi: &'a str,
            image_base: u64,
            entry_va: u64,
            sections: usize,
            symbols: usize,
            body_entropy: f64,
            profile: &'a rustid::RustProfile,
        }
        return emit_json(
            o,
            &Json {
                path: image.path.display().to_string(),
                sha256: &image.sha256,
                format: image.format.label(),
                arch: image.arch.label(),
                bits: image.bits,
                abi: image.abi().label(),
                image_base: image.image_base,
                entry_va: image.entry_va,
                sections: image.sections.len(),
                symbols: image.symbols.len(),
                body_entropy: body,
                profile: &profile,
            },
        );
    }

    o.field("File", image.path.display());
    o.field("SHA256", &image.sha256);
    o.field("Size", out::bytes(image.data.len() as u64));
    o.field("Format", image.format.label());
    o.field(
        "Architecture",
        format!("{} ({}-bit)", image.arch.label(), image.bits),
    );
    o.field("Calling convention", image.abi().label());
    o.field("Image base", format!("{:#x}", image.image_base));
    o.field("Entry point", format!("{:#x}", image.entry_va));
    o.field("Sections", image.sections.len());
    o.field("Symbols", image.symbols.len());
    o.field("Mangled Rust symbols", profile.mangled_symbols);
    o.field("Data entropy", format!("{body:.2} bits/byte"));

    o.section("Rust identification");
    o.field("Verdict", profile.verdict.label());
    o.field("Score", format!("{} of 100", profile.score));
    if let Some(v) = &profile.rustc.version {
        o.field("rustc version", v);
    }
    if let Some(c) = &profile.rustc.commit {
        o.field("rustc commit", c);
    }
    if let Some(d) = &profile.rustc.date {
        o.field("rustc date", d);
    }
    o.field(
        "Standard library",
        if profile.std_present {
            "present"
        } else {
            "absent (no_std or packed)"
        },
    );

    if !profile.markers.is_empty() {
        o.section("Markers");
        for m in &profile.markers {
            o.field(&m.name, format!("{} hit(s), weight {}", m.hits, m.weight));
        }
    }

    let third_party: Vec<_> = profile.third_party_crates().collect();
    if !third_party.is_empty() {
        o.section("Dependencies (top 10; see `deps` for all)");
        for c in third_party.iter().take(10) {
            let version = c.version.as_deref().unwrap_or("version unknown");
            o.field(
                &c.display_name,
                format!("{version} ({}, {} refs)", c.source.label(), c.hits),
            );
        }
    }

    if !profile.build_paths.is_empty() {
        o.section("Build paths");
        for p in profile.build_paths.iter().take(10) {
            o.item(format!("{} ({} refs)", p.path, p.hits));
        }
    }

    o.section("Verdict");
    match profile.verdict {
        Verdict::Rust => o.ok("Rust binary with recoverable build metadata"),
        Verdict::LikelyRust => o.ok("probably Rust; markers are sparse"),
        Verdict::ObscuredByPacking => {
            o.warn(format!(
                "few Rust markers but data entropy is {body:.2} - the metadata is probably \
                 inside a packed blob. Run `frustracean map` to locate it."
            ));
            o.line("Result: obscured-by-packing");
        }
        Verdict::NotRust => {
            o.line("Result: not-rust");
            return exit::OK;
        }
    }
    exit::OK
}

// ---------------------------------------------------------------------------
// map
// ---------------------------------------------------------------------------

fn cmd_map(o: &Out, a: MapArgs) -> i32 {
    if a.window == 0 || a.step == 0 {
        o.error("--window and --step must be greater than zero");
        return exit::USAGE;
    }
    if !(0.0..=8.0).contains(&a.threshold) {
        o.error("--threshold must be between 0.0 and 8.0");
        return exit::USAGE;
    }
    let image = match load_image(o, &a.image) {
        Ok(i) => i,
        Err(c) => return c,
    };
    let opts = MapOptions {
        window: a.window,
        step: a.step,
        threshold: a.threshold,
        gap_tolerance: 2,
        min_region_len: a.min_region,
    };
    let mut windows = entropy::sweep(&image.data, &opts);
    image.annotate(&mut windows);
    let regions = entropy::regions(&windows, &opts);

    if a.json {
        #[derive(serde::Serialize)]
        struct Json<'a> {
            regions: &'a [entropy::Region],
            #[serde(skip_serializing_if = "Option::is_none")]
            windows: Option<&'a [entropy::Window]>,
        }
        return emit_json(
            o,
            &Json {
                regions: &regions,
                windows: if a.windows { Some(&windows) } else { None },
            },
        );
    }

    o.field("File", image.path.display());
    o.field("Window", format!("{} bytes, step {}", a.window, a.step));
    o.field("Threshold", format!("{:.2} bits/byte", a.threshold));

    o.section("Sections");
    for s in &image.sections {
        let range = s.file_range();
        let stats = image
            .data
            .get(range.start..range.end.min(image.data.len()))
            .filter(|b| !b.is_empty())
            .map(entropy::Stats::of);
        match stats {
            Some(st) => o.field(
                &s.name,
                format!(
                    // A whole-section class is a blunt summary of mixed content;
                    // the per-region classes below are the ones to act on.
                    "va {:#x}, {} on disk, entropy {:.2}, {}{}{}, density {}",
                    s.va,
                    out::bytes(s.file_size),
                    st.entropy,
                    if s.readable { "r" } else { "-" },
                    if s.writable { "w" } else { "-" },
                    if s.executable { "x" } else { "-" },
                    st.class.label()
                ),
            ),
            None => o.field(&s.name, format!("va {:#x}, no bytes on disk", s.va)),
        }
    }

    o.section("Opaque regions");
    if regions.is_empty() {
        o.line(format!(
            "None: no run of {} bytes or more reached {:.2} bits/byte.",
            a.min_region, a.threshold
        ));
    } else {
        for (i, r) in regions.iter().enumerate() {
            let where_ = match (&r.section, r.va) {
                (Some(name), Some(va)) => format!("{name} at va {va:#x}"),
                _ => "outside any mapped section".to_string(),
            };
            o.field(
                &format!("Region {}", i + 1),
                format!(
                    "offset {:#x}..{:#x}, {}, mean {:.2}, peak {:.2}, class {}, {}",
                    r.start,
                    r.end,
                    out::bytes(r.len()),
                    r.entropy,
                    r.peak_entropy,
                    r.class.label(),
                    where_
                ),
            );
        }
    }

    if a.windows {
        o.section("Windows");
        for w in &windows {
            o.field(
                &format!("{:#010x}", w.offset),
                format!(
                    "{:.2} bits/byte, chi-square {:.0}, class {}{}",
                    w.stats.entropy,
                    w.stats.chi_square,
                    w.stats.class.label(),
                    w.section
                        .as_deref()
                        .map(|s| format!(", {s}"))
                        .unwrap_or_default()
                ),
            );
        }
    }

    let opaque: u64 = regions
        .iter()
        .filter(|r| r.class.is_opaque())
        .map(|r| r.len())
        .sum();
    o.section("Summary");
    o.field("Regions", regions.len());
    o.field("Opaque bytes", out::bytes(opaque));
    if image.data.is_empty() {
        o.field("Share of file", "0.0%");
    } else {
        o.field(
            "Share of file",
            format!("{:.1}%", 100.0 * opaque as f64 / image.data.len() as f64),
        );
    }
    exit::OK
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

fn cmd_stats(o: &Out, a: StatsArgs) -> i32 {
    let data = match std::fs::read(&a.file) {
        Ok(d) => d,
        Err(e) => {
            o.error(format!("{}: {e}", a.file.display()));
            return exit::BAD_INPUT;
        }
    };
    if data.is_empty() {
        o.error(format!("{}: file is empty", a.file.display()));
        return exit::BAD_INPUT;
    }
    let stats = entropy::Stats::of(&data);
    let sha = frustracean_core::sha256_hex(&data);

    if a.json {
        #[derive(serde::Serialize)]
        struct Json<'a> {
            path: String,
            sha256: &'a str,
            stats: &'a entropy::Stats,
            chi_square_ratio: f64,
        }
        return emit_json(
            o,
            &Json {
                path: a.file.display().to_string(),
                sha256: &sha,
                stats: &stats,
                chi_square_ratio: stats.chi_square_ratio(),
            },
        );
    }

    o.field("File", a.file.display());
    o.field("SHA256", &sha);
    o.field("Size", out::bytes(data.len() as u64));
    o.field("Entropy", format!("{:.4} bits/byte", stats.entropy));
    o.field(
        "Chi-square",
        format!(
            "{:.1} ({:.2}x the uniform expectation of 255)",
            stats.chi_square,
            stats.chi_square_ratio()
        ),
    );
    o.field(
        "Printable",
        format!("{:.1}%", stats.printable_ratio * 100.0),
    );
    o.field("Distinct bytes", format!("{} of 256", stats.distinct_bytes));
    o.field("Class", stats.class.label());

    o.section("Reading");
    match stats.class {
        entropy::Class::Encrypted => o.item(
            "High entropy with a near-uniform byte distribution: ciphertext or CSPRNG output.",
        ),
        entropy::Class::Compressed => o.item(
            "High entropy but structurally non-uniform: a compressor's output, not a cipher's.",
        ),
        entropy::Class::Text => {
            o.item("Predominantly printable. Likely a string pool or a config.")
        }
        entropy::Class::Code => {
            o.item("Density consistent with machine code or dense binary data.")
        }
        entropy::Class::Structured => o.item("Low entropy: tables, relocations, or sparse data."),
        entropy::Class::Padding => o.item("One or two distinct byte values: alignment or fill."),
        entropy::Class::Undersized => {
            o.item("Too short for entropy to mean much on its own.");
            o.item(format!(
                "At {} bytes the ceiling is {:.2} bits/byte, and this sits at {:.0}% of it.",
                stats.len,
                stats.ceiling(),
                stats.saturation() * 100.0
            ));
        }
    }

    // Worth saying for any buffer whose length constrains the answer, not only
    // the ones short enough to be classified as undersized.
    if stats.is_undersized() || stats.ceiling() < entropy::MAX_ENTROPY {
        o.field(
            "Entropy ceiling",
            format!(
                "{:.2} bits/byte at this length ({:.0}% saturated)",
                stats.ceiling(),
                stats.saturation() * 100.0
            ),
        );
    }
    exit::OK
}

// ---------------------------------------------------------------------------
// deps
// ---------------------------------------------------------------------------

fn cmd_deps(o: &Out, a: DepsArgs) -> i32 {
    let image = match load_image(o, &a.image) {
        Ok(i) => i,
        Err(c) => return c,
    };
    let profile = rustid::detect(&image, body_entropy(&image));

    let listed: Vec<_> = if a.all {
        profile.crates.iter().collect()
    } else {
        profile.third_party_crates().collect()
    };

    if a.json {
        return emit_json(o, &listed);
    }

    o.field("File", image.path.display());
    o.field("Crates", listed.len());
    if listed.is_empty() {
        o.section("Result");
        if profile.verdict == Verdict::ObscuredByPacking {
            o.warn(
                "no crate paths found, and the body is high-entropy: the dependency list is \
                 probably inside the packed blob, not absent",
            );
            return exit::FAILED;
        }
        o.line("No crate references were recovered.");
        return exit::FAILED;
    }

    o.section("Recovered dependencies");
    for c in &listed {
        o.field(
            &c.display_name,
            format!(
                "{} ({}, {} reference(s))",
                c.version.as_deref().unwrap_or("version unknown"),
                c.source.label(),
                c.hits
            ),
        );
    }
    o.section("Summary");
    o.ok(format!("recovered {} crate reference(s)", listed.len()));
    exit::OK
}

// ---------------------------------------------------------------------------
// strings
// ---------------------------------------------------------------------------

fn cmd_strings(o: &Out, a: StringsArgs) -> i32 {
    if a.min == 0 {
        o.error("--min must be greater than zero");
        return exit::USAGE;
    }
    let image = match load_image(o, &a.image) {
        Ok(i) => i,
        Err(c) => return c,
    };
    let found = rustid::extract_strings(&image.data, a.min);
    let mut shown = 0usize;
    for (offset, text) in &found {
        if a.rust_only && !looks_rust(text) {
            continue;
        }
        let va = image
            .offset_to_va(*offset)
            .map(|v| format!("{v:#x}"))
            .unwrap_or_else(|| "-".into());
        o.line(format!("{offset:#010x} {va} {text}"));
        shown += 1;
    }
    if shown == 0 {
        o.error("no strings matched");
        return exit::FAILED;
    }
    exit::OK
}

fn looks_rust(text: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "src/",
        "src\\",
        ".rs",
        "registry",
        "rustc",
        "panicked at",
        "RUST_BACKTRACE",
        "Option::unwrap",
        "Result::unwrap",
        "cargo",
    ];
    NEEDLES.iter().any(|n| text.contains(n))
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

fn cmd_rules(o: &Out, a: RulesArgs) -> i32 {
    let (set, dir) = match load_signatures(o, a.signatures) {
        Ok(v) => v,
        Err(c) => return c,
    };

    if a.json {
        let rules: Vec<_> = set.rules.iter().map(|r| &r.rule).collect();
        return emit_json(o, &rules);
    }

    o.field("Catalogue", dir.display());
    o.field("Rules", set.len());
    o.section("Rules");
    for compiled in &set.rules {
        let r = &compiled.rule;
        o.field(
            &r.id,
            format!(
                "{} | crate {} | confidence {} | captures {} on {} | expects {}",
                r.family.map(|f| f.label()).unwrap_or("other"),
                r.crate_name.as_deref().unwrap_or("-"),
                r.confidence.label(),
                if r.capture.dump.is_empty() {
                    "nothing".to_string()
                } else {
                    r.capture.dump.join(", ")
                },
                r.capture.when.label(),
                r.capture.expect.label()
            ),
        );
        if !r.description.is_empty() {
            o.item(&r.description);
        }
        o.item(format!(
            "resolution: {}{}",
            if r.match_spec.demangled_regex.is_some() || r.match_spec.symbol_regex.is_some() {
                "symbol"
            } else {
                "none"
            },
            if compiled.has_string_anchors() {
                format!(
                    " + {} string anchor(s), {} required",
                    r.match_spec.strings.len(),
                    compiled.required_string_hits()
                )
            } else {
                String::new()
            }
        ));
    }
    o.section("Summary");
    o.ok(format!("{} rule(s) loaded and validated", set.len()));
    exit::OK
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

fn cmd_plan(o: &Out, a: PlanArgs) -> i32 {
    let image = match load_image(o, &a.image) {
        Ok(i) => i,
        Err(c) => return c,
    };
    let (signatures, dir) = match load_signatures(o, a.signatures) {
        Ok(v) => v,
        Err(c) => return c,
    };

    if image.arch.decoder_bitness().is_none() {
        o.error(format!(
            "no disassembler for {} - planning needs x86 or x86-64",
            image.arch.label()
        ));
        return exit::FAILED;
    }

    o.info(format!(
        "loaded {} rule(s) from {}",
        signatures.len(),
        dir.display()
    ));
    o.info("indexing code (linear sweep of executable sections)");
    let index = CodeIndex::build(&image);
    if index.decode_failures > 0 {
        o.warn(format!(
            "{} instruction(s) failed to decode during the sweep; function recovery in those \
             areas is unreliable",
            index.decode_failures
        ));
    }
    if let Some(reason) = &index.truncated {
        o.warn(format!(
            "code indexing was capped ({reason}); coverage is incomplete and targets may be missing"
        ));
    }

    let opts = PlanOptions {
        allow_string_xrefs: !a.no_xrefs,
        include_unsafe: a.include_unsafe,
        ..Default::default()
    };
    let built = plan::build(&image, &signatures, &index, &opts);

    if let Some(path) = &a.out {
        let json = match built.to_json() {
            Ok(j) => j,
            Err(e) => {
                o.error(e.to_string());
                return exit::FAILED;
            }
        };
        if let Err(c) = write_out(o, path, &json) {
            return c;
        }
        o.info(format!("plan written to {}", path.display()));
    }

    if a.json && a.out.is_none() {
        return emit_json(o, &built);
    }

    o.field("File", image.path.display());
    o.field("Functions indexed", index.function_starts.len());
    if index.exact_range_count() > 0 {
        o.field(
            "Exact extents",
            format!(
                "{} from unwind metadata (.pdata)",
                index.exact_range_count()
            ),
        );
    } else {
        o.field(
            "Exact extents",
            "none; boundaries inferred from call targets",
        );
    }
    o.field("Calling convention", built.abi.label());
    o.field("Targets", built.targets.len());
    o.field("Skipped", built.skipped.len());

    if built.targets.is_empty() {
        o.section("Result");
        o.warn("no hijack targets were resolved");
        o.item("If the sample is packed, the crate code is not in the image yet - unpack the");
        o.item("outer layer first, then plan against the dump.");
        o.item("If it is not packed, the catalogue may need a rule for the crate it uses;");
        o.item("run `frustracean deps` to see what it pulled in.");
        return exit::FAILED;
    }

    o.section("Targets");
    for t in &built.targets {
        o.field(
            &t.id,
            format!(
                "rva {:#x} (va {:#x}) | {} | confidence {} | steal {} bytes{}",
                t.rva,
                t.preferred_va,
                t.resolution.label(),
                t.confidence.label(),
                t.patch_len,
                if t.needs_relocation {
                    ", needs relocation"
                } else {
                    ""
                }
            ),
        );
        o.item(format!("symbol: {}", t.symbol));
        for arg in &t.args {
            let loc = match &arg.length {
                Some(len) => format!("{} + length in {}", arg.value.describe(), len.describe()),
                None => arg.value.describe(),
            };
            o.item(format!("arg {} ({}): {}", arg.name, arg.kind.label(), loc));
        }
        for e in &t.evidence {
            o.item(format!("evidence: {e}"));
        }
    }

    if !built.skipped.is_empty() {
        o.section("Skipped");
        for s in &built.skipped {
            o.field(
                &format!("{} at {:#x}", s.rule_id, s.preferred_va),
                s.reasons.join("; "),
            );
        }
    }

    o.section("Summary");
    o.ok(format!(
        "{} target(s) planned, {} skipped",
        built.targets.len(),
        built.skipped.len()
    ));
    exit::OK
}

// ---------------------------------------------------------------------------
// trace
// ---------------------------------------------------------------------------

fn cmd_trace(o: &Out, a: TraceArgs) -> i32 {
    let text = match std::fs::read_to_string(&a.plan) {
        Ok(t) => t,
        Err(e) => {
            o.error(format!("{}: {e}", a.plan.display()));
            return exit::BAD_INPUT;
        }
    };
    let loaded = match frustracean_core::plan::HijackPlan::from_json(&text) {
        Ok(p) => p,
        Err(e) => {
            o.error(format!("{}: {e}", a.plan.display()));
            return exit::BAD_INPUT;
        }
    };
    if loaded.targets.is_empty() {
        o.error("the plan contains no targets");
        return exit::USAGE;
    }
    if !a.sample.is_file() {
        o.error(format!("{}: not a file", a.sample.display()));
        return exit::BAD_INPUT;
    }

    // The safety gate comes before the correctness gate: an analyst who is not
    // on an isolated machine should be told that first, not after a hash
    // mismatch sends them off to rebuild the plan.
    if !a.sandboxed {
        o.error("refusing to execute the sample without --sandboxed");
        o.item("`trace` runs the sample so its own unpacking code produces the plaintext.");
        o.item("Use a disposable, network-isolated virtual machine with a snapshot to revert to.");
        o.item("Re-run with --sandboxed once you are on one.");
        return exit::USAGE;
    }

    // The plan is bound to a specific image by hash. Running it against a
    // different sample would hook whatever happens to sit at those offsets.
    match std::fs::read(&a.sample) {
        Ok(bytes) => {
            let sha = frustracean_core::sha256_hex(&bytes);
            if sha != loaded.image.sha256 {
                o.error(format!(
                    "the plan was built for SHA256 {} but --sample hashes to {sha}",
                    loaded.image.sha256
                ));
                return exit::USAGE;
            }
        }
        Err(e) => {
            o.error(format!("{}: {e}", a.sample.display()));
            return exit::BAD_INPUT;
        }
    }

    o.field("Plan", a.plan.display());
    o.field("Sample", a.sample.display());
    o.field("Targets", loaded.targets.len());
    o.field("Output", a.out.display());

    inject::run(
        o,
        &loaded,
        &a.plan,
        &a.sample,
        &a.out,
        a.payload.as_deref(),
        &a.sample_args,
        a.timeout,
    )
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

fn cmd_replay(o: &Out, a: ReplayArgs) -> i32 {
    let text = match std::fs::read_to_string(&a.trace) {
        Ok(t) => t,
        Err(e) => {
            o.error(format!("{}: {e}", a.trace.display()));
            return exit::BAD_INPUT;
        }
    };
    let (records, problems) = trace::parse_lines(&text);
    for p in &problems {
        o.warn(p);
    }
    if records.is_empty() {
        o.error("the trace contains no usable records");
        return exit::BAD_INPUT;
    }

    // Each rule predicted which way entropy would move; recover that from the
    // plan so an encrypt hook is not scored as a failed decrypt.
    let mut expectations: Expectations = BTreeMap::new();
    if let Some(plan_path) = &a.plan {
        match std::fs::read_to_string(plan_path)
            .map_err(|e| e.to_string())
            .and_then(|t| {
                frustracean_core::plan::HijackPlan::from_json(&t).map_err(|e| e.to_string())
            }) {
            Ok(p) => {
                for t in &p.targets {
                    expectations.insert(
                        t.id.clone(),
                        report::TargetExpectation {
                            expect: t.capture.expect,
                            compare: t.capture.compare.clone(),
                        },
                    );
                }
            }
            Err(e) => {
                o.warn(format!(
                    "{}: {e}; scoring every target as a decrypt",
                    plan_path.display()
                ));
            }
        }
    }

    let built = report::build(&records, &expectations);

    if let Some(path) = &a.out {
        let md = report::to_markdown(&built);
        if let Err(c) = write_out(o, path, &md) {
            return c;
        }
        o.info(format!("report written to {}", path.display()));
    }

    if a.json {
        return emit_json(o, &built);
    }

    o.field("Trace", a.trace.display());
    o.field("Records", built.summary.records);
    o.field("Hijacked calls", built.summary.calls);
    o.field("Complete calls", built.summary.complete_calls);
    o.field("Buffer transitions", built.summary.transitions);
    o.field("Confirmed transitions", built.summary.confirmed_transitions);
    o.field(
        "Bytes recovered",
        out::bytes(built.summary.bytes_recovered as u64),
    );
    o.field("Distinct blobs", built.summary.distinct_blobs);

    if !built.events.is_empty() {
        o.section("Entropy transitions (most significant first)");
        for e in &built.events {
            o.field(
                &format!("call {} {}", e.call_id, e.target_id),
                format!(
                    "{} {} bytes, {:.2} -> {:.2} ({:+.2}), {} -> {}, {}",
                    e.buffer,
                    e.bytes,
                    e.delta.before,
                    e.delta.after,
                    -e.delta.drop(),
                    e.class_before.label(),
                    e.class_after.label(),
                    if e.confirmed {
                        format!("confirmed {}", e.direction())
                    } else {
                        "not confirmed".to_string()
                    }
                ),
            );
            if let Some(d) = &e.dump {
                o.item(format!("dump: {d}"));
            }
        }
    }

    if !built.incomplete.is_empty() {
        o.section("Incomplete calls");
        for c in &built.incomplete {
            o.field(&format!("call {} {}", c.call_id, c.target_id), &c.reason);
        }
    }

    for n in &built.notes {
        match n.level {
            frustracean_core::trace::NoteLevel::Error => o.error(&n.message),
            _ => o.warn(&n.message),
        }
    }

    o.section("Summary");
    if built.summary.confirmed_transitions == 0 {
        o.warn("no confirmed transitions - no buffer moved far enough in entropy");
        return exit::FAILED;
    }
    o.ok(format!(
        "{} confirmed transition(s), {} captured",
        built.summary.confirmed_transitions,
        out::bytes(built.summary.bytes_recovered as u64)
    ));
    exit::OK
}
