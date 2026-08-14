//! The detour stub: the one piece of Frustracean that is designed but not yet
//! validated against a running target.
//!
//! Everything else in this crate is pure byte manipulation that can be checked
//! on the host. The stub cannot: it is hand-written machine code that runs
//! inside a hostile process, and the only honest way to bring it up is against a
//! benign target under a debugger. It is therefore behind the off-by-default
//! `detour` feature, and [`install`] refuses rather than pretending.
//!
//! # The design it is waiting on
//!
//! The obvious shape - patch the prologue, log, jump back - only sees arguments
//! on the way *in*. That is not enough: an in-place `decrypt_in_place` shows
//! ciphertext on entry and plaintext on return, and the entropy *drop between
//! the two* is the whole finding. So the detour has to wrap the call:
//!
//! ```text
//!   caller --call--> function
//!                    | jmp detour            (the 5-byte patch)
//!                    v
//!                  detour: save context
//!                          capture arguments          <- entry record
//!                          call trampoline  ----------> stolen bytes, then
//!                                                       jmp function+patch_len
//!                                                       ...function body...
//!                                                       ret  -----------.
//!                          capture the same buffers   <- return record  |
//!                          jmp caller's return address <----------------'
//! ```
//!
//! Three details make this harder than it looks, and each is the reason the
//! stub is not simply written inline here:
//!
//! 1. **Stack discipline.** The detour is reached by `jmp`, so at its first
//!    instruction `rsp` holds exactly what the function expected: the caller's
//!    return address at `[rsp]`, and stack arguments above it. Before calling
//!    the trampoline the stub must pop that return address away and re-establish
//!    `rsp` so the `call` pushes into the same slot - otherwise every stack
//!    argument the function reads is off by one slot. Win64 additionally
//!    requires 32 bytes of shadow space and 16-byte alignment at each call.
//!
//! 2. **The saved context cannot live on the stack.** Once the trampoline is
//!    called, the function owns everything below the original `rsp`, including
//!    any frame the stub built there. The entry context has to be parked in
//!    thread-local storage - which also makes the design naturally reentrant and
//!    thread-safe, since two threads can be inside the same hooked function at
//!    once, and a recursive decrypt can be inside it twice on one thread. That
//!    makes the parking structure a per-thread *stack* of frames, not a slot.
//!
//! 3. **Reentrancy into our own code.** The capture path allocates, hashes, and
//!    writes to disk. If the sample has hooked or replaced the allocator - or if
//!    the hooked function is itself called from inside the allocator - the stub
//!    must detect re-entry on the same thread and skip capture rather than
//!    recurse. A per-thread "in capture" flag, checked before anything else.
//!
//! # What is already done
//!
//! [`crate::trampoline`] builds and verifies the relocated stolen bytes and the
//! patch, with tests; [`crate::capture`] does the measurement, deduplication,
//! and trace writing, with tests; [`PlannedHook`] below resolves a plan against
//! the loaded module and checks the prologue still matches what the planner saw.
//! What remains is the stub itself and its TLS frame stack.

use frustracean_core::plan::{HijackPlan, HijackTarget};

/// A plan target resolved against the module as it is actually loaded.
#[derive(Debug, Clone)]
pub struct PlannedHook {
    pub target_id: String,
    pub symbol: String,
    /// Absolute address in this process, after rebasing for ASLR.
    pub address: u64,
    /// Bytes the patch will displace.
    pub patch_len: usize,
    /// What the planner recorded at this address.
    pub expected_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    BadOriginalBytes { target_id: String },
    PatchTooShort { target_id: String, patch_len: usize },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::BadOriginalBytes { target_id } => write!(
                f,
                "target {target_id} has malformed original_bytes in the plan"
            ),
            ResolveError::PatchTooShort {
                target_id,
                patch_len,
            } => write!(
                f,
                "target {target_id} has patch_len {patch_len}, shorter than a near jump"
            ),
        }
    }
}

/// Rebase one target against the module's real load address.
///
/// Plans store RVAs precisely so this can happen: the analyst's static base is
/// almost never where the image lands under ASLR.
pub fn resolve(target: &HijackTarget, module_base: u64) -> Result<PlannedHook, ResolveError> {
    if target.patch_len < crate::trampoline::JMP_LEN {
        return Err(ResolveError::PatchTooShort {
            target_id: target.id.clone(),
            patch_len: target.patch_len,
        });
    }
    let expected_bytes =
        decode_hex(&target.original_bytes).ok_or(ResolveError::BadOriginalBytes {
            target_id: target.id.clone(),
        })?;
    Ok(PlannedHook {
        target_id: target.id.clone(),
        symbol: target.symbol.clone(),
        address: module_base.wrapping_add(target.rva),
        patch_len: target.patch_len,
        expected_bytes,
    })
}

/// Resolve every target, collecting the failures instead of stopping at the first.
pub fn resolve_all(plan: &HijackPlan, module_base: u64) -> (Vec<PlannedHook>, Vec<ResolveError>) {
    let mut hooks = Vec::new();
    let mut errors = Vec::new();
    for target in &plan.targets {
        match resolve(target, module_base) {
            Ok(h) => hooks.push(h),
            Err(e) => errors.push(e),
        }
    }
    (hooks, errors)
}

/// Does memory still hold what the planner saw?
///
/// This is the guard against the plan being stale, against the sample having
/// already self-modified, and against a rule resolving to the wrong address in a
/// packed image where the planner read the *stub's* bytes rather than the
/// unpacked function's. Patching without this check corrupts the target
/// silently; failing it is a finding worth recording in the trace.
pub fn prologue_matches(hook: &PlannedHook, actual: &[u8]) -> bool {
    if hook.expected_bytes.is_empty() {
        // The planner could not read the bytes, so there is nothing to verify
        // against. Treated as a match, and reported by the caller.
        return true;
    }
    let n = hook.expected_bytes.len().min(actual.len());
    n == hook.expected_bytes.len() && actual[..n] == hook.expected_bytes[..]
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Install the detour stubs.
///
/// Returns an explanatory error while the stub is unimplemented, so a caller
/// that tries gets a clear answer rather than a process that looks hooked and
/// captures nothing.
pub fn install(_hooks: &[PlannedHook]) -> Result<usize, String> {
    if cfg!(feature = "detour") {
        Err(
            "the `detour` feature is enabled but the stub is not implemented yet; \
             see the module documentation in detour.rs for the remaining design"
                .to_string(),
        )
    } else {
        Err(
            "hook installation is disabled: build frustracean-hook with --features detour \
             once the stub has been brought up against a benign target"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frustracean_core::binary::{Abi, Arch, Format};
    use frustracean_core::plan::{PlanImage, Resolution, PLAN_VERSION};
    use frustracean_core::signature::{CaptureSpec, Confidence};

    fn target(id: &str, rva: u64, patch_len: usize, bytes: &str) -> HijackTarget {
        HijackTarget {
            id: id.into(),
            rule_id: id.into(),
            crate_name: None,
            description: String::new(),
            symbol: "demo".into(),
            rva,
            preferred_va: 0x1_4000_0000 + rva,
            file_offset: None,
            resolution: Resolution::Symbol,
            confidence: Confidence::High,
            args: Vec::new(),
            capture: CaptureSpec::default(),
            patch_len,
            needs_relocation: false,
            original_bytes: bytes.into(),
            evidence: Vec::new(),
        }
    }

    fn plan(targets: Vec<HijackTarget>) -> HijackPlan {
        HijackPlan {
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
            targets,
            skipped: Vec::new(),
        }
    }

    #[test]
    fn a_target_is_rebased_onto_the_real_module_base() {
        let h = resolve(&target("t", 0x2340, 5, "48895c2408"), 0x7ff6_0000_0000).unwrap();
        assert_eq!(h.address, 0x7ff6_0000_2340);
        assert_eq!(h.expected_bytes, vec![0x48, 0x89, 0x5c, 0x24, 0x08]);
    }

    #[test]
    fn a_patch_shorter_than_a_jump_is_refused() {
        let err = resolve(&target("t", 0x10, 4, "48895c24"), 0x1000).unwrap_err();
        assert_eq!(
            err,
            ResolveError::PatchTooShort {
                target_id: "t".into(),
                patch_len: 4
            }
        );
    }

    #[test]
    fn malformed_original_bytes_are_refused() {
        assert!(matches!(
            resolve(&target("t", 0x10, 5, "zzz"), 0x1000).unwrap_err(),
            ResolveError::BadOriginalBytes { .. }
        ));
        assert!(matches!(
            resolve(&target("t", 0x10, 5, "abc"), 0x1000).unwrap_err(),
            ResolveError::BadOriginalBytes { .. }
        ));
    }

    #[test]
    fn resolving_collects_failures_instead_of_stopping() {
        let p = plan(vec![
            target("good", 0x100, 5, "9090909090"),
            target("bad", 0x200, 4, "90909090"),
            target("also_good", 0x300, 5, "9090909090"),
        ]);
        let (hooks, errors) = resolve_all(&p, 0x1000);
        assert_eq!(hooks.len(), 2);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn a_changed_prologue_fails_verification() {
        let h = resolve(&target("t", 0, 5, "48895c2408"), 0).unwrap();
        assert!(prologue_matches(&h, &[0x48, 0x89, 0x5c, 0x24, 0x08, 0x57]));
        assert!(!prologue_matches(&h, &[0xe9, 0x00, 0x00, 0x00, 0x00]));
        assert!(
            !prologue_matches(&h, &[0x48, 0x89]),
            "a short read must not pass"
        );
    }

    #[test]
    fn installation_refuses_clearly_rather_than_silently_doing_nothing() {
        let err = install(&[]).unwrap_err();
        assert!(
            err.contains("not implemented") || err.contains("disabled"),
            "{err}"
        );
    }
}
