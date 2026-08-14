//! Turning rules into a concrete, checkable hijack plan.
//!
//! The plan is the contract between the analyst-side tooling and the injected
//! payload. It is a plain JSON document on purpose: an analyst can read it,
//! delete a target they do not trust, and hand it back.
//!
//! Two resolution paths feed it:
//!
//! * **Symbol** - the rule's regex matched a demangled name. High confidence.
//! * **String cross-reference** - the image is stripped, so a constant the crate
//!   is known to embed was located in `.rodata`, its RIP-relative references
//!   were collected, and the enclosing functions became candidates. Lower
//!   confidence by construction, and labelled as such.
//!
//! Addresses are stored as **RVAs**, not absolute VAs. The payload rebases
//! against the module's real load address, so a plan stays valid under ASLR.

use serde::{Deserialize, Serialize};

use crate::binary::{Abi, Arch, Format};
use crate::error::Result;
use crate::signature::{ArgKind, CaptureSpec, Confidence};

#[cfg(feature = "analysis")]
use crate::binary::Image;
#[cfg(feature = "analysis")]
use crate::disasm::{self, CodeIndex, PrologueReport, JMP_REL32_LEN};
#[cfg(feature = "analysis")]
use crate::signature::SignatureSet;
#[cfg(feature = "analysis")]
use std::collections::{BTreeMap, BTreeSet};

pub const PLAN_VERSION: u32 = 1;

/// How many bytes past the function start we are willing to decode looking for
/// an instruction boundary. Well past any real prologue.
#[cfg(feature = "analysis")]
const PROLOGUE_SCAN_LEN: usize = 64;

/// How far back from a string hit to look for a reference. Rust pools string
/// literals without terminators, so a substring match can land inside a literal
/// whose reference points at an earlier address.
#[cfg(feature = "analysis")]
const XREF_BACKSCAN: u64 = 256;

/// Cap on the reference list recorded per target. Beyond a handful it is the
/// same fact repeated.
#[cfg(feature = "analysis")]
const MAX_EVIDENCE_REFS: usize = 6;

/// One referencing instruction and the constant it points at.
#[cfg(feature = "analysis")]
type Xref = (u64, u64);

/// What a candidate function accumulated during string-anchor resolution: the
/// set of distinct anchors that hit it, and the set of references that found it.
/// Both are sets - an anchor repeated in the string pool is one piece of
/// evidence, not several.
#[cfg(feature = "analysis")]
type AnchorEvidence = (BTreeSet<String>, BTreeSet<Xref>);

/// Where an argument lives at function entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArgLoc {
    Register {
        name: String,
    },
    /// Offset from `rsp` **as it stands at the function's first instruction**,
    /// i.e. with the return address already pushed.
    Stack {
        offset: u64,
    },
}

impl ArgLoc {
    pub fn describe(&self) -> String {
        match self {
            ArgLoc::Register { name } => name.clone(),
            ArgLoc::Stack { offset } => format!("[rsp+{offset:#x}]"),
        }
    }
}

/// A logical argument, mapped onto the target's ABI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedArg {
    pub name: String,
    pub kind: ArgKind,
    /// The pointer, or the scalar value itself for non-buffer kinds.
    pub value: ArgLoc,
    /// Present only for slices, whose length rides in the following slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<ArgLoc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Symbol,
    StringXref,
}

impl Resolution {
    pub fn label(self) -> &'static str {
        match self {
            Resolution::Symbol => "symbol",
            Resolution::StringXref => "string-xref",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HijackTarget {
    /// Unique within the plan: the rule id, suffixed when a rule resolves to
    /// more than one site.
    pub id: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crate_name: Option<String>,
    pub description: String,
    /// Name if known, else a synthesised `sub_<rva>`.
    pub symbol: String,
    /// Offset from the module base. Rebased by the payload at load time.
    pub rva: u64,
    /// Absolute address assuming the image's preferred base. For the analyst's
    /// disassembler, not for the payload.
    pub preferred_va: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    pub resolution: Resolution,
    pub confidence: Confidence,
    pub args: Vec<ResolvedArg>,
    pub capture: CaptureSpec,
    /// Instruction-aligned bytes the payload must relocate.
    pub patch_len: usize,
    pub needs_relocation: bool,
    /// The stolen bytes, so the payload can verify the image has not changed
    /// under it before patching.
    pub original_bytes: String,
    /// Why this target is believed to be what the rule says it is.
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedTarget {
    pub rule_id: String,
    pub symbol: String,
    pub preferred_va: u64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanImage {
    pub path: String,
    pub sha256: String,
    pub format: Format,
    pub arch: Arch,
    pub bits: u32,
    pub preferred_base: u64,
    pub entry_rva: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HijackPlan {
    pub version: u32,
    pub image: PlanImage,
    pub abi: Abi,
    pub targets: Vec<HijackTarget>,
    /// Sites a rule matched but that cannot be hooked safely. Kept in the plan
    /// so a silent gap in coverage is visible rather than invisible.
    pub skipped: Vec<SkippedTarget>,
}

impl HijackPlan {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(text: &str) -> Result<HijackPlan> {
        let plan: HijackPlan = serde_json::from_str(text)?;
        if plan.version != PLAN_VERSION {
            return Err(crate::Error::plain(format!(
                "plan version {} is not supported (expected {PLAN_VERSION})",
                plan.version
            )));
        }
        Ok(plan)
    }

    pub fn hookable_count(&self) -> usize {
        self.targets.len()
    }
}

/// Map a rule's logical arguments onto ABI slots.
///
/// `sret` consumes the first slot before anything declared, and each slice
/// consumes two - pointer then length. This is where a wrong `sret` flag or a
/// missed fat pointer turns into every subsequent argument reading the wrong
/// register, so it is kept in one small, tested function.
pub fn resolve_args(args: &[crate::signature::ArgSpec], sret: bool, abi: Abi) -> Vec<ResolvedArg> {
    let regs = abi.arg_registers();
    let ptr_size = abi.pointer_size();
    let shadow = abi.shadow_space();

    let loc_for = |slot: usize| -> ArgLoc {
        if slot < regs.len() {
            ArgLoc::Register {
                name: regs[slot].to_string(),
            }
        } else {
            let stack_index = (slot - regs.len()) as u64;
            ArgLoc::Stack {
                offset: ptr_size + shadow + stack_index * ptr_size,
            }
        }
    };

    let mut slot = usize::from(sret);
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let value = loc_for(slot);
        let length = if arg.kind.is_buffer() {
            Some(loc_for(slot + 1))
        } else {
            None
        };
        slot += arg.kind.slots();
        out.push(ResolvedArg {
            name: arg.name.clone(),
            kind: arg.kind,
            value,
            length,
        });
    }
    out
}

/// Options for plan construction.
#[cfg(feature = "analysis")]
#[derive(Debug, Clone, Copy)]
pub struct PlanOptions {
    /// Include targets resolved only by string cross-reference.
    pub allow_string_xrefs: bool,
    /// Emit targets whose prologue analysis found blockers. Off by default:
    /// hooking one of these corrupts the sample.
    pub include_unsafe: bool,
    /// Cap on candidate sites per rule from the string path, which can be noisy.
    pub max_xref_candidates: usize,
}

#[cfg(feature = "analysis")]
impl Default for PlanOptions {
    fn default() -> Self {
        PlanOptions {
            allow_string_xrefs: true,
            include_unsafe: false,
            max_xref_candidates: 8,
        }
    }
}

/// Build a hijack plan for `image` from `signatures`.
#[cfg(feature = "analysis")]
pub fn build(
    image: &Image,
    signatures: &SignatureSet,
    index: &CodeIndex,
    opts: &PlanOptions,
) -> HijackPlan {
    let abi = image.abi();
    let mut targets: Vec<HijackTarget> = Vec::new();
    let mut skipped: Vec<SkippedTarget> = Vec::new();
    // Rule id -> how many sites it has produced, for id suffixing.
    let mut site_counts: BTreeMap<String, usize> = BTreeMap::new();
    // Never hook the same address twice.
    let mut claimed: BTreeMap<u64, String> = BTreeMap::new();

    // --- Path 1: symbols -------------------------------------------------
    //
    // Deduplicated by (address, matched name) here rather than relying on the
    // parser, because symbols can also be supplied by a caller. An export table
    // and a COFF table routinely describe one function under a decorated and an
    // undecorated name; without this the planner resolves one and files the
    // other under "already hooked", which reads like a coverage gap when it is
    // really the same function twice.
    let mut seen_symbols: BTreeSet<(u64, &str)> = BTreeSet::new();
    for sym in &image.symbols {
        if !seen_symbols.insert((sym.va, sym.match_name())) {
            continue;
        }
        for compiled in signatures.match_symbol(sym) {
            let rule = &compiled.rule;
            let evidence = vec![format!(
                "symbol {:?} matched rule {}",
                sym.match_name(),
                rule.id
            )];
            add_candidate(
                image,
                index,
                abi,
                opts,
                rule,
                sym.va,
                sym.match_name().to_string(),
                Resolution::Symbol,
                rule.confidence,
                evidence,
                &mut targets,
                &mut skipped,
                &mut site_counts,
                &mut claimed,
            );
        }
    }

    // --- Path 2: string cross-references ---------------------------------
    if opts.allow_string_xrefs {
        for compiled in signatures.string_anchored() {
            let rule = &compiled.rule;
            // Per function: which distinct anchors hit, and every reference seen.
            // References are held in a set keyed by (referencing instruction,
            // target address). A single anchor that appears many times in the
            // string pool otherwise contributes the same instruction once per
            // occurrence, inflating both the evidence list and the ranking that
            // decides which candidates survive the cap.
            let mut per_function: BTreeMap<u64, AnchorEvidence> = BTreeMap::new();

            for needle in &rule.match_spec.strings {
                for hit_va in find_string_vas(image, needle.as_bytes()) {
                    let lo = hit_va.saturating_sub(XREF_BACKSCAN);
                    let hi = hit_va.saturating_add(needle.len() as u64);
                    // `BTreeMap::range` panics on an inverted range, and unlike
                    // an arithmetic overflow that one fires in release builds
                    // too. A crafted section VA can put a hit near u64::MAX.
                    if lo > hi {
                        continue;
                    }
                    for (&target_va, refs) in index.xrefs.range(lo..=hi) {
                        for &from in refs {
                            if let Some(func) = index.enclosing_function(from) {
                                let entry = per_function.entry(func).or_default();
                                entry.0.insert(needle.clone());
                                entry.1.insert((from, target_va));
                            }
                        }
                    }
                }
            }

            // `min_string_hits` counts *distinct anchors*, not references. Ten
            // references to one string is one piece of evidence repeated, not
            // ten pieces of evidence, and treating it as the latter is how a
            // low-confidence guess gets promoted into something an analyst
            // trusts.
            let required = compiled.required_string_hits();
            let mut candidates: Vec<(u64, BTreeSet<String>, BTreeSet<Xref>)> = per_function
                .into_iter()
                .filter(|(_, (anchors, _))| anchors.len() >= required)
                .map(|(va, (anchors, refs))| (va, anchors, refs))
                .collect();
            // Rank by distinct anchors first, then by weight of references.
            candidates.sort_by(|a, b| {
                b.1.len()
                    .cmp(&a.1.len())
                    .then_with(|| b.2.len().cmp(&a.2.len()))
                    .then_with(|| a.0.cmp(&b.0))
            });
            candidates.truncate(opts.max_xref_candidates);

            for (func_va, anchors, refs) in candidates {
                // Record rather than drop: two rules landing on one address is
                // a real observation about the catalogue, and a coverage gap
                // that is not written down is a coverage gap nobody notices.
                if let Some(owner) = claimed.get(&func_va) {
                    let rva = func_va.saturating_sub(image.image_base);
                    skipped.push(SkippedTarget {
                        rule_id: rule.id.clone(),
                        symbol: format!("sub_{rva:x}"),
                        preferred_va: func_va,
                        reasons: vec![format!("address already hooked by target {owner}")],
                    });
                    continue;
                }
                let mut evidence = vec![format!(
                    "no symbol; located by {} distinct anchor(s) across {} reference(s) for rule {}",
                    anchors.len(),
                    refs.len(),
                    rule.id
                )];
                // Long reference lists are repetition, not information.
                evidence.extend(refs.iter().take(MAX_EVIDENCE_REFS).map(|(from, target)| {
                    format!("{from:#x} references a constant at {target:#x}")
                }));
                if refs.len() > MAX_EVIDENCE_REFS {
                    evidence.push(format!(
                        "... and {} more reference(s)",
                        refs.len() - MAX_EVIDENCE_REFS
                    ));
                }
                // A string-located site is never better than medium confidence,
                // and only reaches it when independent anchors agree.
                let confidence = if anchors.len() >= 2 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };
                let rva = func_va.saturating_sub(image.image_base);
                add_candidate(
                    image,
                    index,
                    abi,
                    opts,
                    rule,
                    func_va,
                    format!("sub_{rva:x}"),
                    Resolution::StringXref,
                    confidence,
                    evidence,
                    &mut targets,
                    &mut skipped,
                    &mut site_counts,
                    &mut claimed,
                );
            }
        }
    }

    targets.sort_by_key(|t| t.rva);
    skipped.sort_by_key(|s| s.preferred_va);

    HijackPlan {
        version: PLAN_VERSION,
        image: PlanImage {
            path: image.path.display().to_string(),
            sha256: image.sha256.clone(),
            format: image.format,
            arch: image.arch,
            bits: image.bits,
            preferred_base: image.image_base,
            entry_rva: image.entry_va.saturating_sub(image.image_base),
        },
        abi,
        targets,
        skipped,
    }
}

#[cfg(feature = "analysis")]
#[allow(clippy::too_many_arguments)]
fn add_candidate(
    image: &Image,
    index: &CodeIndex,
    abi: Abi,
    opts: &PlanOptions,
    rule: &crate::signature::Rule,
    func_va: u64,
    symbol: String,
    resolution: Resolution,
    confidence: Confidence,
    evidence: Vec<String>,
    targets: &mut Vec<HijackTarget>,
    skipped: &mut Vec<SkippedTarget>,
    site_counts: &mut BTreeMap<String, usize>,
    claimed: &mut BTreeMap<u64, String>,
) {
    if let Some(owner) = claimed.get(&func_va) {
        skipped.push(SkippedTarget {
            rule_id: rule.id.clone(),
            symbol,
            preferred_va: func_va,
            reasons: vec![format!("address already hooked by target {owner}")],
        });
        return;
    }

    let report = inspect_site(image, index, func_va);
    let mut reasons = report.blockers.clone();
    if abi == Abi::Unknown {
        reasons.push("no ABI mapping for this format/architecture".into());
    }
    if !reasons.is_empty() && !opts.include_unsafe {
        skipped.push(SkippedTarget {
            rule_id: rule.id.clone(),
            symbol,
            preferred_va: func_va,
            reasons,
        });
        return;
    }

    let n = site_counts.entry(rule.id.clone()).or_insert(0);
    *n += 1;
    let id = if *n == 1 {
        rule.id.clone()
    } else {
        format!("{}#{}", rule.id, *n)
    };

    let rva = func_va.saturating_sub(image.image_base);
    let original_bytes = image
        .bytes_at_va(func_va, report.patch_len)
        .map(crate::hex)
        .unwrap_or_default();

    claimed.insert(func_va, id.clone());
    targets.push(HijackTarget {
        id,
        rule_id: rule.id.clone(),
        crate_name: rule.crate_name.clone(),
        description: rule.description.clone(),
        symbol,
        rva,
        preferred_va: func_va,
        file_offset: image.va_to_offset(func_va),
        resolution,
        confidence,
        args: resolve_args(&rule.abi.args, rule.abi.sret, abi),
        capture: rule.capture.clone(),
        patch_len: report.patch_len,
        needs_relocation: report.needs_relocation,
        original_bytes,
        evidence,
    });
}

/// Full safety check for one hook site: prologue decode plus a scan of the
/// function body for branches that land inside the bytes we would steal.
#[cfg(feature = "analysis")]
pub fn inspect_site(image: &Image, index: &CodeIndex, func_va: u64) -> PrologueReport {
    let bitness = image.arch.decoder_bitness().unwrap_or(64);
    let code = image.bytes_at_va(func_va, PROLOGUE_SCAN_LEN).unwrap_or(&[]);
    let mut report = disasm::analyze_prologue(code, func_va, bitness, JMP_REL32_LEN);

    // Before anything else: is this address even code?
    //
    // A symbol can point into `.rdata`, and constant data decodes into
    // plausible-looking instructions often enough that prologue analysis alone
    // will happily approve it. Patching there corrupts a constant and the
    // hook never fires, which is about the worst pair of outcomes available.
    match image.section_at_va(func_va) {
        None => report
            .blockers
            .push(format!("{func_va:#x} is not inside any mapped section")),
        Some(section) if !section.executable => report.blockers.push(format!(
            "{func_va:#x} is in {}, which is not executable",
            section.name
        )),
        Some(_) => {}
    }

    if !report.hookable() {
        return report;
    }

    // The function body, bounded by the next known function start.
    let end = index
        .function_end(func_va)
        .unwrap_or_else(|| func_va.saturating_add(PROLOGUE_SCAN_LEN as u64));
    let body_len = (end.saturating_sub(func_va)).min(64 * 1024) as usize;
    if let Some(body) = image.bytes_at_va(func_va, body_len) {
        let inbound =
            disasm::inbound_branch_targets(body, func_va, bitness, func_va, report.patch_len);
        for target in inbound {
            report.blockers.push(format!(
                "a branch inside the function targets {target:#x}, within the {} bytes that would be stolen",
                report.patch_len
            ));
        }
    }
    report
}

/// Every virtual address at which `needle` appears in a readable data section.
#[cfg(feature = "analysis")]
fn find_string_vas(image: &Image, needle: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    if needle.is_empty() {
        return out;
    }
    for section in image.data_sections() {
        let range = section.file_range();
        let Some(bytes) = image.data.get(range.start..range.end.min(image.data.len())) else {
            continue;
        };
        let mut i = 0usize;
        while i + needle.len() <= bytes.len() {
            if &bytes[i..i + needle.len()] == needle {
                if let Some(va) = section.va.checked_add(i as u64) {
                    out.push(va);
                }
                i += needle.len();
            } else {
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{ArgKind, ArgSpec};

    fn args() -> Vec<ArgSpec> {
        vec![
            ArgSpec {
                name: "this".into(),
                kind: ArgKind::Ptr,
            },
            ArgSpec {
                name: "buffer".into(),
                kind: ArgKind::SliceMut,
            },
            ArgSpec {
                name: "tag".into(),
                kind: ArgKind::Ptr,
            },
        ]
    }

    #[test]
    fn win64_maps_a_fat_pointer_across_two_registers() {
        let resolved = resolve_args(&args(), false, Abi::Win64);
        assert_eq!(resolved[0].value, ArgLoc::Register { name: "rcx".into() });
        // The slice takes rdx (pointer) and r8 (length)...
        assert_eq!(resolved[1].value, ArgLoc::Register { name: "rdx".into() });
        assert_eq!(
            resolved[1].length,
            Some(ArgLoc::Register { name: "r8".into() })
        );
        // ...so the next argument lands in r9, not r8.
        assert_eq!(resolved[2].value, ArgLoc::Register { name: "r9".into() });
    }

    #[test]
    fn sysv_uses_its_own_register_order() {
        let resolved = resolve_args(&args(), false, Abi::SysV64);
        assert_eq!(resolved[0].value, ArgLoc::Register { name: "rdi".into() });
        assert_eq!(resolved[1].value, ArgLoc::Register { name: "rsi".into() });
        assert_eq!(
            resolved[1].length,
            Some(ArgLoc::Register { name: "rdx".into() })
        );
        assert_eq!(resolved[2].value, ArgLoc::Register { name: "rcx".into() });
    }

    #[test]
    fn sret_shifts_everything_by_one_register() {
        let resolved = resolve_args(&args(), true, Abi::Win64);
        assert_eq!(resolved[0].value, ArgLoc::Register { name: "rdx".into() });
        assert_eq!(resolved[1].value, ArgLoc::Register { name: "r8".into() });
        assert_eq!(
            resolved[1].length,
            Some(ArgLoc::Register { name: "r9".into() })
        );
    }

    #[test]
    fn overflow_arguments_spill_past_the_shadow_space_on_win64() {
        // Five pointers: rcx, rdx, r8, r9, then the stack.
        let five: Vec<ArgSpec> = (0..5)
            .map(|i| ArgSpec {
                name: format!("a{i}"),
                kind: ArgKind::Ptr,
            })
            .collect();
        let resolved = resolve_args(&five, false, Abi::Win64);
        // 8 bytes of return address + 32 bytes of shadow space.
        assert_eq!(resolved[4].value, ArgLoc::Stack { offset: 40 });
    }

    #[test]
    fn overflow_arguments_spill_immediately_on_sysv() {
        let seven: Vec<ArgSpec> = (0..7)
            .map(|i| ArgSpec {
                name: format!("a{i}"),
                kind: ArgKind::Ptr,
            })
            .collect();
        let resolved = resolve_args(&seven, false, Abi::SysV64);
        // No shadow space: the first spilled argument sits just past the
        // return address.
        assert_eq!(resolved[6].value, ArgLoc::Stack { offset: 8 });
    }

    #[test]
    fn a_slice_split_across_the_register_boundary_keeps_its_length_on_the_stack() {
        // Win64: three pointers fill rcx/rdx/r8, so the slice takes r9 for its
        // pointer and must find its length on the stack.
        let spec = vec![
            ArgSpec {
                name: "a".into(),
                kind: ArgKind::Ptr,
            },
            ArgSpec {
                name: "b".into(),
                kind: ArgKind::Ptr,
            },
            ArgSpec {
                name: "c".into(),
                kind: ArgKind::Ptr,
            },
            ArgSpec {
                name: "buf".into(),
                kind: ArgKind::Slice,
            },
        ];
        let resolved = resolve_args(&spec, false, Abi::Win64);
        assert_eq!(resolved[3].value, ArgLoc::Register { name: "r9".into() });
        assert_eq!(resolved[3].length, Some(ArgLoc::Stack { offset: 40 }));
    }

    #[test]
    fn cdecl32_puts_everything_on_the_stack_at_pointer_width() {
        let resolved = resolve_args(&args(), false, Abi::Cdecl32);
        assert_eq!(resolved[0].value, ArgLoc::Stack { offset: 4 });
        assert_eq!(resolved[1].value, ArgLoc::Stack { offset: 8 });
        assert_eq!(resolved[1].length, Some(ArgLoc::Stack { offset: 12 }));
    }

    #[test]
    fn scalars_carry_no_length_slot() {
        let spec = vec![ArgSpec {
            name: "n".into(),
            kind: ArgKind::Len,
        }];
        let resolved = resolve_args(&spec, false, Abi::Win64);
        assert!(resolved[0].length.is_none());
    }

    #[test]
    fn a_plan_round_trips_through_json() {
        let plan = HijackPlan {
            version: PLAN_VERSION,
            image: PlanImage {
                path: "sample.exe".into(),
                sha256: "aa".into(),
                format: Format::Pe,
                arch: Arch::X86_64,
                bits: 64,
                preferred_base: 0x1_4000_0000,
                entry_rva: 0x1000,
            },
            abi: Abi::Win64,
            targets: Vec::new(),
            skipped: Vec::new(),
        };
        let json = plan.to_json().unwrap();
        assert_eq!(HijackPlan::from_json(&json).unwrap(), plan);
    }

    // ---------------------------------------------------------------------
    // End-to-end resolution against a hand-built image.
    //
    // A synthetic image is used rather than a compiled fixture so the
    // instruction bytes, the string addresses, and the RIP-relative
    // displacements are all visible in the test. If xref resolution breaks,
    // this says exactly where.
    // ---------------------------------------------------------------------
    #[cfg(feature = "analysis")]
    mod resolution {
        use super::*;
        use crate::binary::{Image, Section};
        use crate::disasm::CodeIndex;
        use crate::signature::SignatureSet;

        const TEXT_VA: u64 = 0x1000;
        const RDATA_VA: u64 = 0x2000;

        /// One function at 0x1000 that references two constants:
        ///
        /// ```text
        ///   0x1000: 48 8d 05 f9 0f 00 00   lea rax, [rip+0xff9]   -> 0x2000
        ///   0x1007: 48 8d 0d 02 10 00 00   lea rcx, [rip+0x1002]  -> 0x2010
        ///   0x100e: c3                     ret
        /// ```
        fn fixture() -> Image {
            let mut data = vec![0u8; 0x200];
            let code: &[u8] = &[
                0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x02, 0x10, 0x00, 0x00,
                0xc3,
            ];
            data[..code.len()].copy_from_slice(code);
            data[0x100..0x10a].copy_from_slice(b"ANCHOR_ONE");
            data[0x110..0x11a].copy_from_slice(b"ANCHOR_TWO");

            Image {
                path: std::path::PathBuf::from("fixture"),
                data,
                format: Format::Pe,
                arch: Arch::X86_64,
                bits: 64,
                image_base: 0,
                entry_va: TEXT_VA,
                sections: vec![
                    Section {
                        name: ".text".into(),
                        va: TEXT_VA,
                        virtual_size: 0x100,
                        file_offset: 0,
                        file_size: 0x100,
                        executable: true,
                        writable: false,
                        readable: true,
                    },
                    Section {
                        name: ".rdata".into(),
                        va: RDATA_VA,
                        virtual_size: 0x100,
                        file_offset: 0x100,
                        file_size: 0x100,
                        executable: false,
                        writable: false,
                        readable: true,
                    },
                ],
                symbols: Vec::new(),
                sha256: String::new(),
            }
        }

        fn plan_with(yaml: &str) -> HijackPlan {
            let image = fixture();
            let signatures = SignatureSet::parse(yaml).expect("catalogue should load");
            let index = CodeIndex::build(&image);
            build(&image, &signatures, &index, &PlanOptions::default())
        }

        #[test]
        fn the_fixture_disassembles_to_the_expected_references() {
            let image = fixture();
            let index = CodeIndex::build(&image);
            assert_eq!(index.references_to(RDATA_VA), &[TEXT_VA]);
            assert_eq!(index.references_to(RDATA_VA + 0x10), &[TEXT_VA + 7]);
            assert_eq!(index.enclosing_function(TEXT_VA + 7), Some(TEXT_VA));
        }

        #[test]
        fn a_stripped_function_is_located_through_its_string_references() {
            let plan = plan_with(
                r#"
version: 1
rules:
  - id: t.one
    match:
      strings: ["ANCHOR_ONE"]
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture: {dump: [buf]}
"#,
            );
            assert_eq!(plan.targets.len(), 1);
            let t = &plan.targets[0];
            assert_eq!(t.rva, TEXT_VA);
            assert_eq!(t.resolution, Resolution::StringXref);
            assert_eq!(t.symbol, "sub_1000");
            // The lea is 7 bytes, so a 5-byte jump has to steal all of it.
            assert_eq!(t.patch_len, 7);
            assert!(t.needs_relocation, "a RIP-relative lea must be flagged");
            assert_eq!(t.original_bytes, "488d05f90f0000");
        }

        #[test]
        fn one_anchor_is_low_confidence_however_often_it_is_referenced() {
            let plan = plan_with(
                r#"
version: 1
rules:
  - id: t.one
    match:
      strings: ["ANCHOR_ONE"]
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture: {dump: [buf]}
"#,
            );
            assert_eq!(plan.targets[0].confidence, Confidence::Low);
        }

        #[test]
        fn two_independent_anchors_raise_confidence_to_medium() {
            let plan = plan_with(
                r#"
version: 1
rules:
  - id: t.both
    match:
      strings: ["ANCHOR_ONE", "ANCHOR_TWO"]
      min_string_hits: 2
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture: {dump: [buf]}
"#,
            );
            assert_eq!(plan.targets.len(), 1);
            assert_eq!(plan.targets[0].confidence, Confidence::Medium);
            assert!(plan.targets[0].evidence[0].contains("2 distinct anchor(s)"));
        }

        #[test]
        fn a_rule_needing_two_anchors_is_not_satisfied_by_one() {
            let plan = plan_with(
                r#"
version: 1
rules:
  - id: t.missing
    match:
      strings: ["ANCHOR_ONE", "ANCHOR_ABSENT"]
      min_string_hits: 2
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture: {dump: [buf]}
"#,
            );
            assert!(
                plan.targets.is_empty(),
                "one anchor must not satisfy a two-anchor rule: {:?}",
                plan.targets
            );
        }

        #[test]
        fn disabling_xrefs_suppresses_the_whole_fallback_path() {
            let image = fixture();
            let signatures = SignatureSet::parse(
                r#"
version: 1
rules:
  - id: t.one
    match:
      strings: ["ANCHOR_ONE"]
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture: {dump: [buf]}
"#,
            )
            .unwrap();
            let index = CodeIndex::build(&image);
            let opts = PlanOptions {
                allow_string_xrefs: false,
                ..Default::default()
            };
            assert!(build(&image, &signatures, &index, &opts).targets.is_empty());
        }

        #[test]
        fn a_second_rule_hitting_the_same_address_is_skipped_not_double_hooked() {
            let plan = plan_with(
                r#"
version: 1
rules:
  - id: t.first
    match:
      strings: ["ANCHOR_ONE"]
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture: {dump: [buf]}
  - id: t.second
    match:
      strings: ["ANCHOR_TWO"]
    abi:
      args: [{name: buf, kind: slice_mut}]
    capture: {dump: [buf]}
"#,
            );
            assert_eq!(plan.targets.len(), 1, "one address, one hook");
            assert_eq!(plan.skipped.len(), 1);
            assert!(plan.skipped[0].reasons[0].contains("already hooked"));
        }
    }

    #[test]
    fn a_future_plan_version_is_refused() {
        let json = r#"{"version":99,"image":{"path":"a","sha256":"b","format":"pe","arch":"x86_64","bits":64,"preferred_base":0,"entry_rva":0},"abi":"win64","targets":[],"skipped":[]}"#;
        assert!(HijackPlan::from_json(json)
            .unwrap_err()
            .to_string()
            .contains("not supported"));
    }
}
