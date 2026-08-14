//! Just enough disassembly to place a hook safely and to find functions in a
//! stripped image.
//!
//! Two jobs:
//!
//! 1. **Prologue analysis.** An inline hook overwrites the first bytes of a
//!    function with a jump. Overwriting a partial instruction corrupts the
//!    target; jumping into the middle of the stolen bytes from elsewhere in the
//!    function corrupts it differently and much later. [`analyze_prologue`]
//!    reports the exact instruction-aligned patch length and every reason the
//!    site might be unsafe, so the planner can refuse rather than crash a sample
//!    halfway through unpacking.
//!
//! 2. **Code indexing.** Malware is usually stripped, so function starts are
//!    recovered from `call rel32` targets, and constants are located through
//!    RIP-relative references. Together these turn "this crate embeds the string
//!    `chacha20`" into "the function at 0x1400123f0 uses it".

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use serde::{Deserialize, Serialize};

use crate::binary::Image;

/// Bytes a near `jmp rel32` needs. The trampoline is allocated within +/-2GB of
/// the target so the short form is always sufficient; a 14-byte absolute
/// `jmp [rip+0]` would need far more of the prologue and fails more often.
pub const JMP_REL32_LEN: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstrInfo {
    pub va: u64,
    pub len: usize,
    pub text: String,
    /// Uses a RIP-relative memory operand, so it must be re-encoded if moved.
    pub rip_relative: bool,
    /// A relative branch, so its displacement must be recomputed if moved.
    pub relative_branch: bool,
}

/// The verdict on one hook site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrologueReport {
    pub va: u64,
    /// Instruction-aligned bytes that must be stolen, always >= [`JMP_REL32_LEN`]
    /// when `hookable` is true.
    pub patch_len: usize,
    pub instructions: Vec<InstrInfo>,
    /// The stolen bytes contain something that changes meaning when relocated.
    /// Not fatal - the trampoline builder re-encodes them - but worth surfacing.
    pub needs_relocation: bool,
    /// Reasons this site must not be hooked. Empty means it is safe.
    pub blockers: Vec<String>,
}

impl PrologueReport {
    pub fn hookable(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Decode forward from `va` until at least `min_len` bytes are covered, and
/// report whether those bytes can be safely stolen.
pub fn analyze_prologue(code: &[u8], va: u64, bitness: u32, min_len: usize) -> PrologueReport {
    let mut report = PrologueReport {
        va,
        patch_len: 0,
        instructions: Vec::new(),
        needs_relocation: false,
        blockers: Vec::new(),
    };

    if code.is_empty() {
        report
            .blockers
            .push("no bytes available at the function start".into());
        return report;
    }

    let mut decoder = Decoder::with_ip(bitness, code, va, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instr = Instruction::default();
    let mut covered = 0usize;

    while covered < min_len {
        if !decoder.can_decode() {
            report
                .blockers
                .push(format!("ran out of bytes after {covered} of {min_len}"));
            break;
        }
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            report
                .blockers
                .push(format!("undecodable byte at {:#x}", instr.ip()));
            break;
        }

        let mut text = String::new();
        formatter.format(&instr, &mut text);

        let rip_relative = instr.is_ip_rel_memory_operand();
        let relative_branch = matches!(
            instr.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call
        ) && instr.near_branch_target() != 0;

        // A `ret` inside the stolen bytes means the whole function is shorter
        // than the patch - stealing past it would clobber whatever follows.
        if matches!(instr.flow_control(), FlowControl::Return) {
            report.blockers.push(format!(
                "function returns at {:#x}, before {min_len} bytes are available",
                instr.ip()
            ));
        }

        if rip_relative || relative_branch {
            report.needs_relocation = true;
        }

        covered += instr.len();
        report.instructions.push(InstrInfo {
            va: instr.ip(),
            len: instr.len(),
            text,
            rip_relative,
            relative_branch,
        });
    }

    report.patch_len = covered;
    if covered < min_len && report.blockers.is_empty() {
        report.blockers.push(format!(
            "only {covered} of {min_len} bytes could be decoded"
        ));
    }
    report
}

/// Find branch targets inside a function that land within `[start, start+len)`.
///
/// This is the failure mode that inline hooking gets wrong most often: a loop
/// or a `jcc` further down the function jumps back into the bytes we replaced
/// with a jump, and the target executes garbage. `body` is scanned linearly,
/// which is imprecise for hand-written or obfuscated code but catches the
/// ordinary compiler-generated cases that matter.
pub fn inbound_branch_targets(
    body: &[u8],
    body_va: u64,
    bitness: u32,
    start: u64,
    len: usize,
) -> BTreeSet<u64> {
    let mut hits = BTreeSet::new();
    let end = start.saturating_add(len as u64);
    let mut decoder = Decoder::with_ip(bitness, body, body_va, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            continue;
        }
        if !matches!(
            instr.flow_control(),
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) {
            continue;
        }
        let target = instr.near_branch_target();
        // The first byte is fine - that is where our jump goes.
        if target > start && target < end {
            hits.insert(target);
        }
    }
    hits
}

/// Ceilings on the linear sweep.
///
/// The sweep is driven entirely by section headers, so its cost is whatever the
/// sample's author says it is. These bounds are far above any real image - a
/// 10 MB Rust binary decodes a few megabytes of `.text` and yields tens of
/// thousands of call targets - and exist so a crafted one cannot turn
/// `frustracean plan` into an out-of-memory kill.
pub mod limits {
    /// Total instruction bytes decoded across all executable sections.
    pub const MAX_DECODED_BYTES: usize = 128 * 1024 * 1024;
    /// Distinct RIP-relative targets recorded.
    pub const MAX_XREF_TARGETS: usize = 2_000_000;
    /// Recovered function starts.
    pub const MAX_FUNCTION_STARTS: usize = 2_000_000;
}

/// Recovered code structure for a whole image.
pub struct CodeIndex {
    /// Sorted, deduplicated function start addresses.
    pub function_starts: Vec<u64>,
    /// Target address -> addresses of instructions that reference it via a
    /// RIP-relative operand.
    pub xrefs: BTreeMap<u64, Vec<u64>>,
    /// Instructions that could not be decoded, by section. High counts mean the
    /// linear sweep desynchronised, usually because of embedded data or
    /// obfuscation - a signal worth reporting rather than hiding.
    pub decode_failures: usize,
    /// Set when a [`limits`] ceiling stopped the sweep early, so the caller can
    /// say that coverage was capped instead of implying it was complete.
    pub truncated: Option<String>,
    /// Exact function extents from unwind metadata, keyed by start address.
    ///
    /// When this is populated the index is not guessing. `.pdata` survives
    /// `strip`, because the loader needs it, so a binary with no symbols at all
    /// can still yield precise boundaries - and precision here is what stops a
    /// string cross-reference being attributed to the wrong function.
    pub exact_ranges: BTreeMap<u64, u64>,
}

impl CodeIndex {
    /// Linear-sweep every executable section.
    ///
    /// Linear sweep is the wrong algorithm for adversarial code and the right
    /// one for compiler output. Rust binaries are overwhelmingly the latter, and
    /// the results feed heuristics that are checked before use.
    pub fn build(image: &Image) -> CodeIndex {
        let mut function_starts: BTreeSet<u64> = BTreeSet::new();
        let mut xrefs: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut decode_failures = 0usize;

        let mut truncated: Option<String> = None;

        // Unwind metadata first: these are exact, and they survive stripping.
        let mut exact_ranges: BTreeMap<u64, u64> = BTreeMap::new();
        for range in image.pdata_functions() {
            exact_ranges.insert(range.start_va, range.end_va);
            function_starts.insert(range.start_va);
        }

        let Some(bitness) = image.arch.decoder_bitness() else {
            return CodeIndex {
                function_starts: function_starts.into_iter().collect(),
                xrefs,
                decode_failures: 0,
                truncated: None,
                exact_ranges,
            };
        };

        function_starts.insert(image.entry_va);
        for sym in &image.symbols {
            function_starts.insert(sym.va);
        }

        let mut decoded_bytes = 0usize;
        'sections: for section in image.executable_sections() {
            let range = section.file_range();
            let Some(bytes) = image.data.get(range.start..range.end.min(image.data.len())) else {
                continue;
            };
            if decoded_bytes >= limits::MAX_DECODED_BYTES {
                truncated = Some(format!(
                    "stopped after {} MiB of decoding",
                    limits::MAX_DECODED_BYTES / (1024 * 1024)
                ));
                break;
            }
            decoded_bytes = decoded_bytes.saturating_add(bytes.len());

            let mut decoder = Decoder::with_ip(bitness, bytes, section.va, DecoderOptions::NONE);
            let mut instr = Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut instr);
                if instr.is_invalid() {
                    decode_failures += 1;
                    continue;
                }
                if matches!(instr.flow_control(), FlowControl::Call) {
                    let target = instr.near_branch_target();
                    if target != 0 && function_starts.len() < limits::MAX_FUNCTION_STARTS {
                        function_starts.insert(target);
                    }
                }
                if instr.is_ip_rel_memory_operand() {
                    let target = instr.ip_rel_memory_address();
                    if target != 0 && xrefs.len() < limits::MAX_XREF_TARGETS {
                        xrefs.entry(target).or_default().push(instr.ip());
                    }
                }
                if xrefs.len() >= limits::MAX_XREF_TARGETS
                    || function_starts.len() >= limits::MAX_FUNCTION_STARTS
                {
                    truncated =
                        Some("reached the cross-reference or function-start ceiling".to_string());
                    break 'sections;
                }
            }
        }

        // Keep only starts that land in executable memory.
        let function_starts: Vec<u64> = function_starts
            .into_iter()
            .filter(|&va| {
                image
                    .section_at_va(va)
                    .map(|s| s.executable)
                    .unwrap_or(false)
            })
            .collect();

        CodeIndex {
            function_starts,
            xrefs,
            decode_failures,
            truncated,
            exact_ranges,
        }
    }

    /// The function containing `va`: the greatest known start at or below it.
    ///
    /// When an exact extent is known for that start, the address must actually
    /// fall inside it. Without that check an address in the padding between two
    /// functions is silently attributed to the one before it, which is how a
    /// string cross-reference ends up naming the wrong function.
    pub fn enclosing_function(&self, va: u64) -> Option<u64> {
        let start = match self.function_starts.binary_search(&va) {
            Ok(i) => self.function_starts[i],
            Err(0) => return None,
            Err(i) => self.function_starts[i - 1],
        };
        match self.exact_ranges.get(&start) {
            Some(&end) if va >= end => None,
            _ => Some(start),
        }
    }

    /// Where the function starting at `start` ends.
    ///
    /// Exact when unwind metadata covers it; otherwise the next known start,
    /// which over-estimates. Over-estimating is safe for the uses here - it
    /// widens the scan for branches into the patch region - but knowing which
    /// answer you got matters, so [`CodeIndex::has_exact_range`] reports it.
    pub fn function_end(&self, start: u64) -> Option<u64> {
        if let Some(&end) = self.exact_ranges.get(&start) {
            return Some(end);
        }
        let i = self.function_starts.binary_search(&start).ok()?;
        self.function_starts.get(i + 1).copied()
    }

    /// Whether this function's extent came from unwind metadata rather than
    /// from the address of the next thing along.
    pub fn has_exact_range(&self, start: u64) -> bool {
        self.exact_ranges.contains_key(&start)
    }

    /// How many function extents are exact rather than inferred.
    pub fn exact_range_count(&self) -> usize {
        self.exact_ranges.len()
    }

    /// Addresses that reference `target` through a RIP-relative operand.
    pub fn references_to(&self, target: u64) -> &[u64] {
        self.xrefs.get(&target).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 48 89 5c 24 08    mov [rsp+8], rbx
    // 57                push rdi
    // 48 83 ec 20       sub rsp, 0x20
    const TYPICAL_MSVC_PROLOGUE: &[u8] =
        &[0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20];

    #[test]
    fn a_normal_prologue_is_hookable_at_an_instruction_boundary() {
        let r = analyze_prologue(TYPICAL_MSVC_PROLOGUE, 0x1000, 64, JMP_REL32_LEN);
        assert!(r.hookable(), "{:?}", r.blockers);
        // First instruction is exactly 5 bytes, so no over-steal is needed.
        assert_eq!(r.patch_len, 5);
        assert_eq!(r.instructions.len(), 1);
        assert!(!r.needs_relocation);
    }

    #[test]
    fn patch_length_rounds_up_to_whole_instructions() {
        // 55                push rbp        (1)
        // 48 89 e5          mov rbp, rsp    (3)
        // 48 83 ec 20       sub rsp, 0x20   (4)  -> 5 bytes needs 3 instructions, 8 total
        let code = &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20];
        let r = analyze_prologue(code, 0x1000, 64, JMP_REL32_LEN);
        assert!(r.hookable(), "{:?}", r.blockers);
        assert_eq!(r.patch_len, 8, "must never split an instruction");
        assert_eq!(r.instructions.len(), 3);
    }

    #[test]
    fn a_rip_relative_prologue_is_flagged_for_relocation() {
        // 48 8d 05 00 00 00 00   lea rax, [rip+0]
        let code = &[0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let r = analyze_prologue(code, 0x1000, 64, JMP_REL32_LEN);
        assert!(r.needs_relocation);
        assert!(r.instructions[0].rip_relative);
    }

    #[test]
    fn a_function_shorter_than_the_patch_is_refused() {
        // 31 c0    xor eax, eax
        // c3       ret            -> only 3 bytes before the function ends
        let code = &[0x31, 0xc0, 0xc3, 0x90, 0x90];
        let r = analyze_prologue(code, 0x1000, 64, JMP_REL32_LEN);
        assert!(!r.hookable());
        assert!(r.blockers[0].contains("returns"), "{:?}", r.blockers);
    }

    #[test]
    fn truncated_code_is_refused_rather_than_half_patched() {
        let r = analyze_prologue(&[0x48], 0x1000, 64, JMP_REL32_LEN);
        assert!(!r.hookable());
    }

    #[test]
    fn empty_code_is_refused() {
        let r = analyze_prologue(&[], 0x1000, 64, JMP_REL32_LEN);
        assert!(!r.hookable());
        assert_eq!(r.patch_len, 0);
    }

    #[test]
    fn a_branch_back_into_the_stolen_bytes_is_detected() {
        // 90                   nop            @0x1000
        // 90                   nop            @0x1001
        // 90                   nop            @0x1002
        // 90                   nop            @0x1003
        // 90                   nop            @0x1004
        // eb fa                jmp 0x1001     @0x1005  -> lands inside the patch
        let body = &[0x90, 0x90, 0x90, 0x90, 0x90, 0xeb, 0xfa];
        let hits = inbound_branch_targets(body, 0x1000, 64, 0x1000, JMP_REL32_LEN);
        assert_eq!(hits.iter().copied().collect::<Vec<_>>(), vec![0x1001]);
    }

    #[test]
    fn a_branch_past_the_stolen_bytes_is_not_flagged() {
        // jmp +0 lands at 0x1007, outside the 5-byte patch at 0x1000.
        let body = &[0x90, 0x90, 0x90, 0x90, 0x90, 0xeb, 0x00];
        let hits = inbound_branch_targets(body, 0x1000, 64, 0x1000, JMP_REL32_LEN);
        assert!(hits.is_empty());
    }

    #[test]
    fn the_entry_byte_itself_is_not_an_inbound_target() {
        // A branch to the function's first byte is fine: that is where our jump
        // sits, so control still reaches the hook.
        let body = &[0xeb, 0xfe]; // jmp $
        let hits = inbound_branch_targets(body, 0x1000, 64, 0x1000, JMP_REL32_LEN);
        assert!(hits.is_empty());
    }

    #[test]
    fn an_exact_extent_stops_padding_being_attributed_to_the_function_before_it() {
        // 0x1000 is known to end at 0x1080. Address 0x1100 sits in the gap
        // before 0x2000 - it belongs to no function, and saying otherwise is
        // how a cross-reference gets pinned on the wrong one.
        let mut exact = BTreeMap::new();
        exact.insert(0x1000u64, 0x1080u64);
        let idx = CodeIndex {
            function_starts: vec![0x1000, 0x2000],
            xrefs: BTreeMap::new(),
            decode_failures: 0,
            truncated: None,
            exact_ranges: exact,
        };
        assert_eq!(idx.enclosing_function(0x1040), Some(0x1000));
        assert_eq!(idx.enclosing_function(0x1100), None);
        assert_eq!(
            idx.function_end(0x1000),
            Some(0x1080),
            "exact, not the next start"
        );
        assert!(idx.has_exact_range(0x1000));
        assert!(!idx.has_exact_range(0x2000));
    }

    #[test]
    fn without_an_exact_extent_the_next_start_is_used() {
        let idx = CodeIndex {
            function_starts: vec![0x1000, 0x2000],
            xrefs: BTreeMap::new(),
            decode_failures: 0,
            truncated: None,
            exact_ranges: BTreeMap::new(),
        };
        assert_eq!(idx.enclosing_function(0x1900), Some(0x1000));
        assert_eq!(idx.function_end(0x1000), Some(0x2000));
    }

    #[test]
    fn enclosing_function_picks_the_greatest_start_at_or_below() {
        let idx = CodeIndex {
            function_starts: vec![0x1000, 0x2000, 0x3000],
            xrefs: BTreeMap::new(),
            decode_failures: 0,
            truncated: None,
            exact_ranges: BTreeMap::new(),
        };
        assert_eq!(idx.enclosing_function(0x2000), Some(0x2000));
        assert_eq!(idx.enclosing_function(0x2abc), Some(0x2000));
        assert_eq!(idx.enclosing_function(0x0fff), None);
        assert_eq!(idx.function_end(0x2000), Some(0x3000));
        assert_eq!(idx.function_end(0x3000), None);
    }
}
