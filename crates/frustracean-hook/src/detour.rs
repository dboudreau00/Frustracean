//! The inline detour runtime: resolves a hijack plan against the loaded image,
//! builds per-hook executable trampolines and wrapped-call stubs within
//! `+/-2 GiB` of each target, and captures buffer/scalar arguments across entry
//! and return on a per-thread TLS frame stack.

use frustracean_core::plan::{HijackPlan, HijackTarget};

#[cfg(windows)]
use crate::capture::{BlobStore, Sink};
#[cfg(windows)]
use frustracean_core::trace::NoteLevel;

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
pub fn prologue_matches(hook: &PlannedHook, actual: &[u8]) -> bool {
    if hook.expected_bytes.is_empty() {
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

/// Verify and install every hook described by `plan` relative to `module_base`,
/// wiring buffer capture into `sink` and `store`.
#[cfg(windows)]
pub fn install_plan(
    plan: &HijackPlan,
    module_base: u64,
    sink: &mut Sink,
    store: Option<BlobStore>,
) -> Result<usize, String> {
    if plan.image.bits != 64 {
        return Err(format!(
            "the payload is 64-bit but the plan targets a {}-bit image",
            plan.image.bits
        ));
    }

    let (hooks, errors) = resolve_all(plan, module_base);
    for e in &errors {
        sink.note(NoteLevel::Warning, e.to_string());
    }

    let meta_by_id: std::collections::BTreeMap<&str, &HijackTarget> =
        plan.targets.iter().map(|t| (t.id.as_str(), t)).collect();

    let mut verified = Vec::new();
    for hook in hooks {
        let probe_len = hook.patch_len.max(hook.expected_bytes.len()).max(1);
        match crate::probe::read_exact(hook.address, probe_len) {
            None => sink.note(
                NoteLevel::Warning,
                format!(
                    "target {} at {:#x} is not mapped or not readable; skipping",
                    hook.target_id, hook.address
                ),
            ),
            Some(actual) => {
                if prologue_matches(&hook, &actual) {
                    let meta = meta_by_id.get(hook.target_id.as_str()).copied().cloned();
                    verified.push((hook, actual, meta));
                } else {
                    sink.note(
                        NoteLevel::Warning,
                        format!(
                            "target {} at {:#x} does not match the bytes the planner recorded; \
                             the plan is stale, or the sample has already rewritten this code",
                            hook.target_id, hook.address
                        ),
                    );
                }
            }
        }
    }

    sink.note(
        NoteLevel::Info,
        format!("{} target(s) verified against the plan", verified.len()),
    );

    #[cfg(all(target_arch = "x86_64", feature = "detour"))]
    {
        win64::install_verified(verified, sink, store)
    }

    #[cfg(not(all(target_arch = "x86_64", feature = "detour")))]
    {
        let _ = (verified, store);
        if cfg!(feature = "detour") {
            Err("inline detour hooking is implemented for Windows x86-64 only".to_string())
        } else {
            Err(
                "hook installation is disabled: rebuild frustracean-hook with the default `detour` feature"
                    .to_string(),
            )
        }
    }
}

/// Install detour stubs for raw [`PlannedHook`] targets without plan metadata.
pub fn install(hooks: &[PlannedHook]) -> Result<usize, String> {
    #[cfg(all(windows, target_arch = "x86_64", feature = "detour"))]
    {
        win64::install_bare(hooks)
    }

    #[cfg(not(all(windows, target_arch = "x86_64", feature = "detour")))]
    {
        let _ = hooks;
        if cfg!(feature = "detour") {
            Err("inline detour hooking is implemented for Windows x86-64 only".to_string())
        } else {
            Err(
                "hook installation is disabled: build frustracean-hook with --features detour"
                    .to_string(),
            )
        }
    }
}

/// Flush the final trace summary on process exit / DLL detach.
pub fn finish_session() {
    #[cfg(all(windows, target_arch = "x86_64", feature = "detour"))]
    win64::finish_session();
}

// ---------------------------------------------------------------------------
// Win64 wrapped-call detour engine
// ---------------------------------------------------------------------------

#[cfg(all(windows, target_arch = "x86_64", feature = "detour"))]
mod win64 {
    use crate::capture::{clamp_len, describe_buffer};
    use std::collections::BTreeSet;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;

    use frustracean_core::plan::{ArgLoc, HijackTarget};
    use frustracean_core::signature::{ArgKind, CaptureSpec};
    use frustracean_core::trace::{Buffer, Event, NoteLevel, Phase, Record, Scalar, TRACE_VERSION};
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION,
        MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_READWRITE,
    };
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThreadId, TlsGetValue, TlsSetValue, TLS_OUT_OF_INDEXES,
    };

    use super::{capture_guard_tls_slot, PlannedHook};
    use crate::capture::{BlobStore, Sink};
    use crate::trampoline;

    const MAX_HOOKS: usize = 512;
    const SLAB_BYTES: usize = 64 * 1024;
    const SENTINEL_INITING: usize = 1;

    static TRAMPOLINES: [AtomicU64; MAX_HOOKS] = {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        [ZERO; MAX_HOOKS]
    };
    static DETACHED: AtomicBool = AtomicBool::new(false);

    struct RuntimeState {
        hooks: Vec<InstalledHook>,
        slabs: Vec<ExecSlab>,
        sink: Option<Sink>,
        store: Option<BlobStore>,
        next_call_id: u64,
        calls_captured: usize,
    }

    static RUNTIME: Mutex<Option<RuntimeState>> = Mutex::new(None);

    #[derive(Clone)]
    struct InstalledHook {
        target_id: String,
        symbol: String,
        address: u64,
        #[cfg(test)]
        original_bytes: Vec<u8>,
        args: Vec<frustracean_core::plan::ResolvedArg>,
        dump_names: BTreeSet<String>,
        capture: CaptureSpec,
    }

    struct ExecSlab {
        base: u64,
        cap: usize,
        used: usize,
        sealed: bool,
    }

    impl ExecSlab {
        fn cursor(&self) -> u64 {
            self.base + self.used as u64
        }

        fn remaining(&self) -> usize {
            self.cap.saturating_sub(self.used)
        }

        fn align_to(&mut self, align: usize) {
            let rem = self.used % align;
            if rem != 0 {
                self.used = self.used.saturating_add(align - rem).min(self.cap);
            }
        }

        fn write(&mut self, bytes: &[u8]) -> Option<u64> {
            if self.sealed || self.remaining() < bytes.len() {
                return None;
            }
            let addr = self.cursor();
            // SAFETY: `self.base .. self.base + self.cap` is an owned
            // `VirtualAlloc` RW allocation not yet flipped to RX; `used + bytes.len() <= cap`.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
            }
            self.used += bytes.len();
            Some(addr)
        }

        fn seal(&mut self) -> Result<(), String> {
            if self.sealed {
                return Ok(());
            }
            let mut old = 0u32;
            // SAFETY: `self.base` and `self.cap` name the exact allocation from
            // `VirtualAlloc`; changing it to `PAGE_EXECUTE_READ` stops stubs
            // and trampolines from remaining writable while executing.
            let ok = unsafe {
                VirtualProtect(
                    self.base as *const c_void,
                    self.cap,
                    PAGE_EXECUTE_READ,
                    &mut old,
                )
            };
            if ok == 0 {
                // SAFETY: `GetLastError` reads only TEB state with no preconditions.
                let err = unsafe { GetLastError() };
                return Err(format!(
                    "VirtualProtect(PAGE_EXECUTE_READ) on stub slab failed with error {err}"
                ));
            }
            // SAFETY: flushes the instruction cache on the newly populated code
            // slab before any control transfers into it.
            unsafe {
                FlushInstructionCache(GetCurrentProcess(), self.base as *const c_void, self.cap);
            }
            self.sealed = true;
            Ok(())
        }
    }

    impl Drop for ExecSlab {
        fn drop(&mut self) {
            // Only explicitly freed when tests tear down an InstallGuard;
            // live injected sessions detach and let process teardown reclaim pages.
            if self.base != 0 {
                // SAFETY: `self.base` came from `VirtualAlloc(MEM_RESERVE | MEM_COMMIT)`
                // and size `0` is required for `MEM_RELEASE`.
                unsafe {
                    VirtualFree(self.base as *mut c_void, 0, MEM_RELEASE);
                }
            }
        }
    }

    #[repr(C)]
    struct EntryRegs {
        rcx: u64,
        rdx: u64,
        r8: u64,
        r9: u64,
        rax: u64,
        r10: u64,
        r11: u64,
        _pad: u64,
        xmm0: [u8; 16],
        xmm1: [u8; 16],
        xmm2: [u8; 16],
        xmm3: [u8; 16],
    }

    #[repr(C)]
    struct EntryDecision {
        trampoline: u64,
        captured: u64,
    }

    #[repr(C)]
    struct ReturnRegs {
        rax: u64,
        rdx: u64,
        xmm0: [u8; 16],
        xmm1: [u8; 16],
    }

    struct SavedBufferArg {
        name: String,
        addr: u64,
        reported_len: usize,
    }

    struct ActiveFrame {
        hook_idx: usize,
        call_id: u64,
        caller_ret: u64,
        orig_rsp: u64,
        thread_id: u64,
        saved_buffers: Vec<SavedBufferArg>,
    }

    struct ThreadCtx {
        in_capture: u32,
        frames: Vec<ActiveFrame>,
    }

    extern "C" {
        fn frustracean_detour_dispatch();
    }

    // Wrapped-call assembly dispatcher and return epilogue.
    //
    // At `frustracean_detour_dispatch`:
    //   [rsp + 0]  = hook_idx (pushed by per-hook pre-stub)
    //   [rsp + 8]  = caller_ret (pushed by original `call target`)
    //
    // Using `push rbx; mov rbx, rsp; sub rsp, ...; and rsp, -16` guarantees a
    // 16-byte aligned stack regardless of caller alignment while preserving all
    // integer argument/return registers (`rax, rcx, rdx, r8, r9, r10, r11`),
    // callee-saved `rbx`, and `xmm0..xmm3` untouched across the trampoline call
    // and keeping `[orig_rsp + 8..]` stack arguments at their exact ABI offsets.
    std::arch::global_asm!(
        ".globl frustracean_detour_dispatch",
        "frustracean_detour_dispatch:",
        "push rbx",
        "mov rbx, rsp",
        "sub rsp, 0xe0",
        "and rsp, -16",
        "mov qword ptr [rsp + 0x30], rcx",
        "mov qword ptr [rsp + 0x38], rdx",
        "mov qword ptr [rsp + 0x40], r8",
        "mov qword ptr [rsp + 0x48], r9",
        "mov qword ptr [rsp + 0x50], rax",
        "mov qword ptr [rsp + 0x58], r10",
        "mov qword ptr [rsp + 0x60], r11",
        "movdqu xmmword ptr [rsp + 0x70], xmm0",
        "movdqu xmmword ptr [rsp + 0x80], xmm1",
        "movdqu xmmword ptr [rsp + 0x90], xmm2",
        "movdqu xmmword ptr [rsp + 0xa0], xmm3",
        "mov rcx, qword ptr [rbx + 8]",
        "mov rdx, qword ptr [rbx + 16]",
        "lea r8, [rbx + 16]",
        "lea r9, [rsp + 0x30]",
        "lea rax, [rsp + 0xb0]",
        "mov qword ptr [rsp + 0x20], rax",
        "call frustracean_hook_entry",
        "mov rax, qword ptr [rsp + 0xb0]",
        "mov qword ptr [rbx + 8], rax",
        "cmp qword ptr [rsp + 0xb8], 0",
        "je 2f",
        "lea rax, [rip + frustracean_detour_return]",
        "mov qword ptr [rbx + 16], rax",
        "2:",
        "mov rcx, qword ptr [rsp + 0x30]",
        "mov rdx, qword ptr [rsp + 0x38]",
        "mov r8, qword ptr [rsp + 0x40]",
        "mov r9, qword ptr [rsp + 0x48]",
        "mov rax, qword ptr [rsp + 0x50]",
        "mov r10, qword ptr [rsp + 0x58]",
        "mov r11, qword ptr [rsp + 0x60]",
        "movdqu xmm0, xmmword ptr [rsp + 0x70]",
        "movdqu xmm1, xmmword ptr [rsp + 0x80]",
        "movdqu xmm2, xmmword ptr [rsp + 0x90]",
        "movdqu xmm3, xmmword ptr [rsp + 0xa0]",
        "mov rsp, rbx",
        "pop rbx",
        "ret",
        ".globl frustracean_detour_return",
        "frustracean_detour_return:",
        "push rax",
        "push rbx",
        "mov rbx, rsp",
        "sub rsp, 0x80",
        "and rsp, -16",
        "mov qword ptr [rsp + 0x20], rax",
        "mov qword ptr [rsp + 0x28], rdx",
        "movdqu xmmword ptr [rsp + 0x30], xmm0",
        "movdqu xmmword ptr [rsp + 0x40], xmm1",
        "lea rcx, [rsp + 0x20]",
        "lea rdx, [rbx + 16]",
        "call frustracean_hook_return",
        "mov qword ptr [rbx + 8], rax",
        "mov rax, qword ptr [rsp + 0x20]",
        "mov rdx, qword ptr [rsp + 0x28]",
        "movdqu xmm0, xmmword ptr [rsp + 0x30]",
        "movdqu xmm1, xmmword ptr [rsp + 0x40]",
        "mov rsp, rbx",
        "pop rbx",
        "ret",
    );

    struct LastErrorGuard(u32);
    impl LastErrorGuard {
        fn save() -> Self {
            // SAFETY: `GetLastError` reads only TEB state and has no side effects.
            LastErrorGuard(unsafe { GetLastError() })
        }
    }
    impl Drop for LastErrorGuard {
        fn drop(&mut self) {
            // SAFETY: restores the hooked thread's Win32 last-error value so our
            // file/TLS calls remain invisible to error checks in the sample.
            unsafe { SetLastError(self.0) };
        }
    }

    struct CaptureDepthGuard(*mut ThreadCtx);
    impl Drop for CaptureDepthGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` was entered on the current thread and remains valid
            // across this synchronous hook callback.
            unsafe {
                (*self.0).in_capture = (*self.0).in_capture.saturating_sub(1);
            }
        }
    }

    /// Acquire the current thread's hook context and mark `in_capture` depth.
    /// Returns `None` if already re-entering capture on this thread.
    unsafe fn enter_thread_capture() -> Option<CaptureDepthGuard> {
        let slot = capture_guard_tls_slot();
        if slot == TLS_OUT_OF_INDEXES {
            return None;
        }
        // SAFETY: `slot` was allocated via `TlsAlloc` before any hook patch was written.
        let raw = unsafe { TlsGetValue(slot) } as usize;
        if raw == SENTINEL_INITING {
            return None;
        }
        let ctx_ptr = if raw == 0 {
            // Mark initializing in TLS before allocating so any allocator recursion
            // skips hook capture cleanly.
            // SAFETY: setting sentinel pointer into our TLS slot.
            if unsafe { TlsSetValue(slot, SENTINEL_INITING as *const c_void) } == 0 {
                return None;
            }
            let boxed = Box::into_raw(Box::new(ThreadCtx {
                in_capture: 1,
                frames: Vec::with_capacity(8),
            }));
            // SAFETY: storing newly allocated per-thread `ThreadCtx` pointer in TLS.
            if unsafe { TlsSetValue(slot, boxed as *const c_void) } == 0 {
                // SAFETY: restore slot and free boxed context on failed TlsSetValue.
                unsafe {
                    TlsSetValue(slot, std::ptr::null());
                    drop(Box::from_raw(boxed));
                }
                return None;
            }
            return Some(CaptureDepthGuard(boxed));
        } else {
            raw as *mut ThreadCtx
        };

        // SAFETY: `ctx_ptr` belongs exclusively to this OS thread and is valid.
        let ctx = unsafe { &mut *ctx_ptr };
        if ctx.in_capture > 0 {
            return None;
        }
        ctx.in_capture = 1;
        Some(CaptureDepthGuard(ctx_ptr))
    }

    fn read_arg_loc(loc: &ArgLoc, regs: &EntryRegs, orig_rsp: u64) -> Option<u64> {
        match loc {
            ArgLoc::Register { name } => match name.as_str() {
                "rcx" => Some(regs.rcx),
                "rdx" => Some(regs.rdx),
                "r8" => Some(regs.r8),
                "r9" => Some(regs.r9),
                "rax" => Some(regs.rax),
                "r10" => Some(regs.r10),
                "r11" => Some(regs.r11),
                _ => None,
            },
            ArgLoc::Stack { offset } => {
                let addr = orig_rsp.checked_add(*offset)?;
                let bytes = crate::probe::read_exact(addr, 8)?;
                Some(u64::from_le_bytes(bytes.try_into().ok()?))
            }
        }
    }

    fn capture_buffer_now(
        name: &str,
        addr: u64,
        reported_len: usize,
        rule_max: usize,
        store: &mut Option<BlobStore>,
    ) -> Buffer {
        let (read_len, mut trunc) = clamp_len(reported_len, rule_max);
        let (bytes, mem_err) = crate::probe::read_checked(addr, read_len);
        if mem_err.is_some() && trunc.is_none() {
            trunc = mem_err;
        }
        let (sha, dump) = match store.as_mut() {
            Some(st) => match st.store(&bytes) {
                Ok(v) => v,
                Err(_) => (frustracean_core::sha256_hex(&bytes), None),
            },
            None => (frustracean_core::sha256_hex(&bytes), None),
        };
        describe_buffer(name, addr, reported_len, &bytes, trunc, sha, dump)
    }

    #[no_mangle]
    unsafe extern "C" fn frustracean_hook_entry(
        hook_idx: u64,
        caller_ret: u64,
        orig_rsp: u64,
        regs: *const EntryRegs,
        out: *mut EntryDecision,
    ) {
        let _err_guard = LastErrorGuard::save();
        let idx = hook_idx as usize;
        let tramp = if idx < MAX_HOOKS {
            TRAMPOLINES[idx].load(Ordering::Acquire)
        } else {
            0
        };
        // Default: execute original trampoline transparently without wrapping return.
        // SAFETY: `out` points to stack-allocated `EntryDecision` inside our assembly frame.
        unsafe {
            (*out).trampoline = tramp;
            (*out).captured = 0;
        }
        if tramp == 0 || regs.is_null() || DETACHED.load(Ordering::Acquire) {
            return;
        }

        // SAFETY: `enter_thread_capture` checks this thread's raw TLS slot first.
        let Some(depth_guard) = (unsafe { enter_thread_capture() }) else {
            return;
        };

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: `regs` points to saved volatile registers in the assembly frame.
            let regs = unsafe { &*regs };
            // SAFETY: `GetCurrentThreadId` has no preconditions.
            let thread_id = u64::from(unsafe { GetCurrentThreadId() });

            let Ok(mut guard) = RUNTIME.lock() else {
                return;
            };
            let Some(rt) = guard.as_mut() else {
                return;
            };
            let Some(hook) = rt.hooks.get(idx).cloned() else {
                return;
            };

            rt.next_call_id += 1;
            let call_id = rt.next_call_id;
            rt.calls_captured += 1;

            let mut scalars = Vec::new();
            let mut buffers = Vec::new();
            let mut saved_buffers = Vec::new();

            for arg in &hook.args {
                match arg.kind {
                    ArgKind::Ptr | ArgKind::Len | ArgKind::Int => {
                        if hook.capture.when.captures_entry() {
                            if let Some(val) = read_arg_loc(&arg.value, regs, orig_rsp) {
                                scalars.push(Scalar {
                                    name: arg.name.clone(),
                                    value: val,
                                });
                            }
                        }
                    }
                    ArgKind::Slice | ArgKind::SliceMut => {
                        if hook.dump_names.contains(&arg.name) {
                            let Some(ptr_val) = read_arg_loc(&arg.value, regs, orig_rsp) else {
                                continue;
                            };
                            let Some(len_val) = arg
                                .length
                                .as_ref()
                                .and_then(|l| read_arg_loc(l, regs, orig_rsp))
                            else {
                                continue;
                            };
                            let reported_len = usize::try_from(len_val).unwrap_or(usize::MAX);
                            if hook.capture.when.captures_return() {
                                saved_buffers.push(SavedBufferArg {
                                    name: arg.name.clone(),
                                    addr: ptr_val,
                                    reported_len,
                                });
                            }
                            if hook.capture.when.captures_entry() {
                                buffers.push(capture_buffer_now(
                                    &arg.name,
                                    ptr_val,
                                    reported_len,
                                    hook.capture.max_bytes,
                                    &mut rt.store,
                                ));
                            }
                        }
                    }
                    ArgKind::Skip => {}
                }
            }

            if hook.capture.when.captures_entry() {
                if let Some(sink) = rt.sink.as_mut() {
                    let seq = sink.next_seq();
                    let elapsed_ns = sink.elapsed_ns();
                    sink.write(&Record::Event(Event {
                        version: TRACE_VERSION,
                        seq,
                        call_id,
                        elapsed_ns,
                        thread_id,
                        target_id: hook.target_id.clone(),
                        symbol: hook.symbol.clone(),
                        function_va: hook.address,
                        phase: Phase::Entry,
                        return_address: caller_ret,
                        scalars,
                        buffers,
                    }));
                }
            }

            if hook.capture.when.captures_return() {
                // SAFETY: `depth_guard.0` points to this thread's live `ThreadCtx`.
                let frames = unsafe { &mut (*depth_guard.0).frames };
                // Drop any frames belonging to deeper calls that unwound past us
                // (e.g. via SEH/panic unwind) before pushing this call frame.
                while let Some(top) = frames.last() {
                    if top.orig_rsp < orig_rsp {
                        frames.pop();
                    } else {
                        break;
                    }
                }
                frames.push(ActiveFrame {
                    hook_idx: idx,
                    call_id,
                    caller_ret,
                    orig_rsp,
                    thread_id,
                    saved_buffers,
                });
                // SAFETY: `out` points into assembly stack frame.
                unsafe {
                    (*out).captured = 1;
                }
            }
        }));
    }

    #[no_mangle]
    unsafe extern "C" fn frustracean_hook_return(regs: *const ReturnRegs, return_rsp: u64) -> u64 {
        let _err_guard = LastErrorGuard::save();
        let slot = capture_guard_tls_slot();
        if slot == TLS_OUT_OF_INDEXES {
            return 0;
        }
        // SAFETY: reading raw TLS pointer for this OS thread.
        let raw = unsafe { TlsGetValue(slot) } as usize;
        if raw <= SENTINEL_INITING {
            return 0;
        }
        let ctx_ptr = raw as *mut ThreadCtx;
        // SAFETY: `ctx_ptr` is owned by the current OS thread.
        let ctx = unsafe { &mut *ctx_ptr };

        // Pop matching frame first so `caller_ret` is always returned safely
        // even if `Runtime` cannot be acquired.
        while let Some(top) = ctx.frames.last() {
            let expected_ret_rsp = top.orig_rsp.wrapping_add(8);
            if expected_ret_rsp < return_rsp {
                ctx.frames.pop();
            } else {
                break;
            }
        }
        let Some(frame) = ctx.frames.pop() else {
            return 0;
        };
        let caller_ret = frame.caller_ret;

        if ctx.in_capture > 0 || DETACHED.load(Ordering::Acquire) {
            return caller_ret;
        }
        ctx.in_capture = 1;
        let _depth_guard = CaptureDepthGuard(ctx_ptr);

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ret_val = if regs.is_null() {
                0
            } else {
                // SAFETY: `regs` points to saved `ReturnRegs` inside the assembly stub.
                unsafe { (*regs).rax }
            };
            let Ok(mut guard) = RUNTIME.lock() else {
                return;
            };
            let Some(rt) = guard.as_mut() else {
                return;
            };
            let Some(hook) = rt.hooks.get(frame.hook_idx).cloned() else {
                return;
            };

            let mut buffers = Vec::with_capacity(frame.saved_buffers.len());
            for saved in &frame.saved_buffers {
                buffers.push(capture_buffer_now(
                    &saved.name,
                    saved.addr,
                    saved.reported_len,
                    hook.capture.max_bytes,
                    &mut rt.store,
                ));
            }

            if let Some(sink) = rt.sink.as_mut() {
                let seq = sink.next_seq();
                let elapsed_ns = sink.elapsed_ns();
                sink.write(&Record::Event(Event {
                    version: TRACE_VERSION,
                    seq,
                    call_id: frame.call_id,
                    elapsed_ns,
                    thread_id: frame.thread_id,
                    target_id: hook.target_id.clone(),
                    symbol: hook.symbol.clone(),
                    function_va: hook.address,
                    phase: Phase::Return,
                    return_address: frame.caller_ret,
                    scalars: vec![Scalar {
                        name: "returned".into(),
                        value: ret_val,
                    }],
                    buffers,
                }));
            }
        }));

        caller_ret
    }

    fn alloc_near(target: u64, size: usize) -> Result<ExecSlab, String> {
        // SAFETY: `SYSTEM_INFO` is a plain Win32 struct populated by `GetSystemInfo`.
        let mut sys: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: `sys` is a valid mutable stack struct.
        unsafe { GetSystemInfo(&mut sys) };
        let gran = (sys.dwAllocationGranularity as u64).max(0x10000);
        let min_app = sys.lpMinimumApplicationAddress as u64;
        let max_app = (sys.lpMaximumApplicationAddress as u64).max(min_app);

        // Leave a 2 MiB margin inside the +/-2 GiB signed rel32 boundary so
        // any offset within the slab can reach back and forth with `jmp rel32`.
        let reach = (i32::MAX as u64).saturating_sub(0x20_0000);
        let search_lo = target.saturating_sub(reach).max(min_app);
        let search_hi = target.saturating_add(reach).min(max_app);
        let alloc_size = size.max(gran as usize);

        let try_reserve_at = |addr: u64| -> Option<ExecSlab> {
            // SAFETY: reserving and committing RW pages at explicit address inside
            // free virtual memory; returned address is checked non-null and verified
            // to be within `trampoline::in_near_reach`.
            let ptr = unsafe {
                VirtualAlloc(
                    addr as *const c_void,
                    alloc_size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE,
                )
            };
            if ptr.is_null() {
                None
            } else {
                Some(ExecSlab {
                    base: ptr as u64,
                    cap: alloc_size,
                    used: 0,
                    sealed: false,
                })
            }
        };

        let align_up = |v: u64| -> u64 { (v.saturating_add(gran - 1)) / gran * gran };
        let align_down = |v: u64| -> u64 { (v / gran) * gran };

        // Probe upward from `target`, then downward toward `search_lo`, choosing
        // free memory closest to the target to maximize +/-2 GiB headroom across
        // adjacent functions.
        let mut cursor = align_up(target).max(search_lo);
        while cursor < search_hi {
            // SAFETY: `MEMORY_BASIC_INFORMATION` initialized on stack and inspected via `VirtualQuery`.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: `VirtualQuery` reads page table state without dereferencing.
            let got = unsafe {
                VirtualQuery(
                    cursor as *const c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if got == 0 {
                break;
            }
            let r_base = mbi.BaseAddress as u64;
            let r_end = r_base.saturating_add(mbi.RegionSize as u64);
            if mbi.State == MEM_FREE {
                let cand = align_up(cursor.max(r_base));
                let cand_end = cand.saturating_add(alloc_size as u64);
                if cand_end <= r_end
                    && cand_end <= search_hi
                    && trampoline::in_near_reach(target, cand)
                    && trampoline::in_near_reach(target, cand_end - 1)
                {
                    if let Some(slab) = try_reserve_at(cand) {
                        return Ok(slab);
                    }
                }
            }
            if r_end <= cursor {
                break;
            }
            cursor = align_up(r_end);
        }

        let mut down_cursor = align_down(target);
        while down_cursor > search_lo {
            // SAFETY: `MEMORY_BASIC_INFORMATION` initialized on stack for `VirtualQuery`.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: inspecting free range below `target`.
            let got = unsafe {
                VirtualQuery(
                    down_cursor as *const c_void,
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if got == 0 {
                break;
            }
            let r_base = mbi.BaseAddress as u64;
            let r_end = r_base.saturating_add(mbi.RegionSize as u64);
            if mbi.State == MEM_FREE && r_end >= alloc_size as u64 {
                let top_cand = align_down(r_end - alloc_size as u64);
                if top_cand >= r_base
                    && top_cand >= search_lo
                    && trampoline::in_near_reach(target, top_cand)
                    && trampoline::in_near_reach(target, top_cand + alloc_size as u64 - 1)
                {
                    if let Some(slab) = try_reserve_at(top_cand) {
                        return Ok(slab);
                    }
                }
            }
            if r_base <= search_lo || r_base == 0 {
                break;
            }
            down_cursor = r_base.saturating_sub(gran);
        }

        Err(format!(
            "could not allocate executable memory within +/-2 GiB of {target:#x}"
        ))
    }

    fn build_pre_stub(hook_idx: u32, dispatch_va: u64) -> [u8; 19] {
        let mut buf = [0u8; 19];
        // push imm32 (hook_idx as i32; caller enforces hook_idx < MAX_HOOKS < i32::MAX)
        buf[0] = 0x68;
        buf[1..5].copy_from_slice(&hook_idx.to_le_bytes());
        // jmp qword ptr [rip + 0]
        buf[5..11].copy_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
        // target 64-bit pointer stored inline immediately after `jmp [rip+0]`
        buf[11..19].copy_from_slice(&dispatch_va.to_le_bytes());
        buf
    }

    fn write_code_patch(address: u64, patch: &[u8]) -> Result<(), String> {
        let mut old = 0u32;
        // SAFETY: `address .. address + patch.len()` was verified readable and in a
        // code page by `read_exact`. Temporarily adding write permission lets us
        // install the 5-byte `jmp` + `int3` tail before restoring original protection.
        let ok = unsafe {
            VirtualProtect(
                address as *const c_void,
                patch.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
        };
        if ok == 0 {
            // SAFETY: `GetLastError` reads only TEB state with no preconditions.
            let err = unsafe { GetLastError() };
            return Err(format!(
                "VirtualProtect(PAGE_EXECUTE_READWRITE) at {address:#x} failed with error {err}"
            ));
        }
        // SAFETY: memory is now writable for `patch.len()` bytes; no other thread
        // in suspended startup or test setup is concurrently modifying this prologue.
        unsafe {
            std::ptr::copy_nonoverlapping(patch.as_ptr(), address as *mut u8, patch.len());
            FlushInstructionCache(GetCurrentProcess(), address as *const c_void, patch.len());
        }
        let mut ignored = 0u32;
        // SAFETY: restores the code page's original protection after patching.
        unsafe {
            VirtualProtect(address as *const c_void, patch.len(), old, &mut ignored);
        }
        Ok(())
    }

    pub fn install_verified(
        verified: Vec<(PlannedHook, Vec<u8>, Option<HijackTarget>)>,
        sink: &mut Sink,
        store: Option<BlobStore>,
    ) -> Result<usize, String> {
        let slot = capture_guard_tls_slot();
        if slot == TLS_OUT_OF_INDEXES {
            return Err("TlsAlloc failed: could not initialize per-thread frame stack".to_string());
        }
        DETACHED.store(false, Ordering::Release);

        let mut slabs: Vec<ExecSlab> = Vec::new();
        let mut patches: Vec<(u64, Vec<u8>, usize, u64)> = Vec::new();
        let mut installed_hooks: Vec<InstalledHook> = Vec::new();
        let mut patched_ranges: Vec<(u64, u64)> = Vec::new();
        let dispatch_va = frustracean_detour_dispatch as *const () as usize as u64;

        for (hook, actual, meta) in verified {
            if installed_hooks.len() >= MAX_HOOKS {
                sink.note(
                    NoteLevel::Warning,
                    format!(
                        "hook table limit ({MAX_HOOKS}) reached; skipping {}",
                        hook.target_id
                    ),
                );
                break;
            }
            let h_start = hook.address;
            let h_end = hook.address.saturating_add(hook.patch_len as u64);
            if patched_ranges
                .iter()
                .any(|&(s, e)| h_start < e && s < h_end)
            {
                sink.note(
                    NoteLevel::Warning,
                    format!(
                        "target {} at {h_start:#x} overlaps an earlier hook site; skipping",
                        hook.target_id
                    ),
                );
                continue;
            }

            // Pick an existing writable slab with room and within +/-2 GiB, or allocate one.
            let slab_idx = slabs.iter().position(|sl| {
                !sl.sealed
                    && sl.remaining() >= 256
                    && trampoline::in_near_reach(hook.address, sl.cursor())
                    && trampoline::in_near_reach(hook.address, sl.cursor() + 255)
            });
            let slab_idx = match slab_idx {
                Some(idx) => idx,
                None => {
                    slabs.push(alloc_near(hook.address, SLAB_BYTES)?);
                    slabs.len() - 1
                }
            };

            let slot_idx = installed_hooks.len();
            let slab = &mut slabs[slab_idx];
            slab.align_to(16);
            let pre_stub = build_pre_stub(slot_idx as u32, dispatch_va);
            let Some(stub_va) = slab.write(&pre_stub) else {
                sink.note(
                    NoteLevel::Warning,
                    format!("stub slab full before {}", hook.target_id),
                );
                continue;
            };
            slab.align_to(16);
            let tramp_va = slab.cursor();
            let resume_ip = hook.address.wrapping_add(hook.patch_len as u64);
            let stolen = &actual[..hook.patch_len];
            let tramp_bytes =
                match trampoline::build_trampoline(stolen, hook.address, tramp_va, resume_ip, 64) {
                    Ok(b) => b,
                    Err(e) => {
                        sink.note(
                            NoteLevel::Warning,
                            format!("could not build trampoline for {}: {e}", hook.target_id),
                        );
                        continue;
                    }
                };
            if slab.write(&tramp_bytes).is_none() {
                sink.note(
                    NoteLevel::Warning,
                    format!(
                        "stub slab ran out of space for trampoline {}",
                        hook.target_id
                    ),
                );
                continue;
            }

            let patch_bytes = match trampoline::build_patch(hook.address, stub_va, hook.patch_len) {
                Ok(b) => b,
                Err(e) => {
                    sink.note(
                        NoteLevel::Warning,
                        format!("could not build patch for {}: {e}", hook.target_id),
                    );
                    continue;
                }
            };

            let (args, capture) = match meta {
                Some(t) => (t.args, t.capture),
                None => (Vec::new(), CaptureSpec::default()),
            };
            let dump_names: BTreeSet<String> = capture.dump.iter().cloned().collect();

            patches.push((hook.address, patch_bytes, slot_idx, tramp_va));
            patched_ranges.push((h_start, h_end));
            installed_hooks.push(InstalledHook {
                target_id: hook.target_id,
                symbol: hook.symbol,
                address: hook.address,
                #[cfg(test)]
                original_bytes: stolen.to_vec(),
                args,
                dump_names,
                capture,
            });
        }

        // Flip every executable slab RW -> RX before publishing runtime or patching code.
        for slab in &mut slabs {
            slab.seal()?;
        }

        // Populate lock-free trampolines & runtime state BEFORE modifying any target prologue.
        for &(_, _, slot_idx, tramp_va) in &patches {
            TRAMPOLINES[slot_idx].store(tramp_va, Ordering::Release);
        }

        let installed_count = installed_hooks.len();
        sink.note(
            NoteLevel::Info,
            format!("{installed_count} hook(s) installed"),
        );

        let moved_sink = std::mem::replace(sink, Sink::discard());

        if let Ok(mut rt_guard) = RUNTIME.lock() {
            *rt_guard = Some(RuntimeState {
                hooks: installed_hooks,
                slabs,
                sink: Some(moved_sink),
                store,
                next_call_id: 0,
                calls_captured: 0,
            });
        }

        // Actually write the 5-byte `jmp` + `int3` patches into the process's prologues.
        for (addr, patch, _, _) in &patches {
            if let Err(e) = write_code_patch(*addr, patch) {
                if let Ok(mut rt_guard) = RUNTIME.lock() {
                    if let Some(rt) = rt_guard.as_mut() {
                        if let Some(s) = rt.sink.as_mut() {
                            s.note(NoteLevel::Error, e);
                        }
                    }
                }
                return Err(format!("failed writing hook patch at {addr:#x}"));
            }
        }

        Ok(installed_count)
    }

    pub fn install_bare(hooks: &[PlannedHook]) -> Result<usize, String> {
        let mut verified = Vec::with_capacity(hooks.len());
        for hook in hooks {
            let probe_len = hook.patch_len.max(hook.expected_bytes.len()).max(1);
            let actual = crate::probe::read_exact(hook.address, probe_len).ok_or_else(|| {
                format!(
                    "target {} at {:#x} is not mapped or not readable",
                    hook.target_id, hook.address
                )
            })?;
            if !super::prologue_matches(hook, &actual) {
                return Err(format!(
                    "target {} at {:#x} prologue bytes do not match plan",
                    hook.target_id, hook.address
                ));
            }
            verified.push((hook.clone(), actual, None));
        }
        let mut sink = Sink::discard();
        install_verified(verified, &mut sink, None)
    }

    pub fn finish_session() {
        DETACHED.store(true, Ordering::Release);
        // Use try_lock inside DLL_PROCESS_DETACH: during process termination other
        // threads may have been frozen while holding locks, and blocking could deadlock.
        if let Ok(mut guard) = RUNTIME.try_lock() {
            if let Some(rt) = guard.as_mut() {
                let calls = rt.calls_captured;
                let blobs = rt.store.as_ref().map(|s| s.written()).unwrap_or(0);
                if let Some(sink) = rt.sink.as_mut() {
                    sink.note(
                        NoteLevel::Info,
                        format!("sample exited; {calls} call(s) captured, {blobs} blob(s) written"),
                    );
                }
                // Drop sink & store while detached; leak slabs into process teardown
                // so any final OS exit callback cannot execute freed slab memory.
                rt.sink = None;
                rt.store = None;
                std::mem::forget(std::mem::take(&mut rt.slabs));
            }
            *guard = None;
        }
    }

    /// Tear down installed hooks and restore original prologue bytes (for tests).
    #[cfg(test)]
    pub fn uninstall_for_tests() {
        DETACHED.store(true, Ordering::Release);
        let mut to_restore = Vec::new();
        let mut slabs = Vec::new();
        if let Ok(mut guard) = RUNTIME.lock() {
            if let Some(mut rt) = guard.take() {
                for (i, h) in rt.hooks.iter().enumerate() {
                    TRAMPOLINES[i].store(0, Ordering::Release);
                    to_restore.push((h.address, h.original_bytes.clone()));
                }
                slabs = std::mem::take(&mut rt.slabs);
            }
        }
        for (addr, orig) in to_restore {
            let _ = write_code_patch(addr, &orig);
        }
        drop(slabs);
    }
}

#[cfg(all(windows, target_arch = "x86_64", feature = "detour"))]
static CAPTURE_TLS_SLOT: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(windows_sys::Win32::System::Threading::TLS_OUT_OF_INDEXES);

#[cfg(all(windows, target_arch = "x86_64", feature = "detour"))]
fn capture_guard_tls_slot() -> u32 {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Threading::{TlsAlloc, TLS_OUT_OF_INDEXES};

    let current = CAPTURE_TLS_SLOT.load(Ordering::Acquire);
    if current != TLS_OUT_OF_INDEXES {
        return current;
    }
    // SAFETY: `TlsAlloc` allocates a process-wide TLS index safely from any thread.
    let allocated = unsafe { TlsAlloc() };
    if allocated == TLS_OUT_OF_INDEXES {
        return TLS_OUT_OF_INDEXES;
    }
    match CAPTURE_TLS_SLOT.compare_exchange(
        TLS_OUT_OF_INDEXES,
        allocated,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => allocated,
        Err(existing) => {
            // SAFETY: another thread initialized `CAPTURE_TLS_SLOT` concurrently;
            // free our redundant slot so we do not leak a TLS index.
            unsafe { windows_sys::Win32::System::Threading::TlsFree(allocated) };
            existing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frustracean_core::binary::{Abi, Arch, Format};
    use frustracean_core::plan::{PlanImage, Resolution, PLAN_VERSION};
    use frustracean_core::signature::Confidence;

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
            capture: frustracean_core::signature::CaptureSpec::default(),
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

    #[cfg(not(all(windows, target_arch = "x86_64", feature = "detour")))]
    #[test]
    fn installation_refuses_clearly_rather_than_silently_doing_nothing() {
        let err = install(&[]).unwrap_err();
        assert!(
            err.contains("Windows x86-64") || err.contains("disabled"),
            "{err}"
        );
    }

    #[cfg(all(windows, target_arch = "x86_64", feature = "detour"))]
    mod live_win64_tests {
        use super::*;
        use frustracean_core::plan::{ArgLoc, ResolvedArg};
        use frustracean_core::signature::{ArgKind, CaptureSpec, Comparison, Expect, When};
        use frustracean_core::trace::{parse_lines, Phase, Record};
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;
        use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

        static LIVE_TEST_LOCK: Mutex<()> = Mutex::new(());
        static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

        struct HookCleanup;
        impl Drop for HookCleanup {
            fn drop(&mut self) {
                super::super::win64::uninstall_for_tests();
            }
        }

        struct TempCaptureDir {
            root: PathBuf,
        }

        impl TempCaptureDir {
            fn new(tag: &str) -> Self {
                let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "frustracean-detour-{tag}-{}-{seq}",
                    std::process::id()
                ));
                let _ = std::fs::remove_dir_all(&root);
                std::fs::create_dir_all(root.join("blobs")).unwrap();
                TempCaptureDir { root }
            }

            fn trace_path(&self) -> PathBuf {
                self.root.join("trace.jsonl")
            }

            fn blobs_dir(&self) -> PathBuf {
                self.root.join("blobs")
            }

            fn read_blob(&self, rel: &str) -> Vec<u8> {
                std::fs::read(self.root.join(rel)).unwrap()
            }
        }

        impl Drop for TempCaptureDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }

        fn exe_module_base() -> u64 {
            // SAFETY: null requests the handle (load base) of the main executable module.
            let h = unsafe { GetModuleHandleW(std::ptr::null()) };
            assert!(!h.is_null(), "GetModuleHandleW(NULL) returned null");
            h as u64
        }

        fn hex_encode(bytes: &[u8]) -> String {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(bytes.len() * 2);
            for &b in bytes {
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
            out
        }

        fn live_target(
            id: &str,
            module_base: u64,
            fn_va: u64,
            args: Vec<ResolvedArg>,
            capture: CaptureSpec,
        ) -> HijackTarget {
            let probe = crate::probe::read_exact(fn_va, 64)
                .expect("test target function code must be readable");
            let mut decoder =
                iced_x86::Decoder::with_ip(64, &probe, fn_va, iced_x86::DecoderOptions::NONE);
            let mut patch_len = 0usize;
            while decoder.can_decode() && patch_len < crate::trampoline::JMP_LEN {
                let instr = decoder.decode();
                assert!(
                    !instr.is_invalid(),
                    "invalid prologue instruction at {fn_va:#x}"
                );
                patch_len += instr.len();
            }
            assert!(
                patch_len >= crate::trampoline::JMP_LEN,
                "prologue shorter than near jump at {fn_va:#x}"
            );
            let mut t = super::target(
                id,
                fn_va.wrapping_sub(module_base),
                patch_len,
                &hex_encode(&probe[..patch_len]),
            );
            t.preferred_va = fn_va;
            t.args = args;
            t.capture = capture;
            t
        }

        fn reg_arg(name: &str, kind: ArgKind, ptr_reg: &str, len_reg: Option<&str>) -> ResolvedArg {
            ResolvedArg {
                name: name.into(),
                kind,
                value: ArgLoc::Register {
                    name: ptr_reg.into(),
                },
                length: len_reg.map(|r| ArgLoc::Register { name: r.into() }),
            }
        }

        fn install_live(
            targets: Vec<HijackTarget>,
            cap_dir: &TempCaptureDir,
        ) -> (usize, HookCleanup) {
            let base = exe_module_base();
            let mut p = super::plan(targets);
            p.image.preferred_base = base;
            let mut sink = Sink::create(cap_dir.trace_path()).unwrap();
            let store = BlobStore::new(cap_dir.blobs_dir()).unwrap();
            let count = install_plan(&p, base, &mut sink, Some(store)).unwrap();
            (count, HookCleanup)
        }

        fn read_trace_events(trace_path: &Path) -> Vec<frustracean_core::trace::Event> {
            let text = std::fs::read_to_string(trace_path).unwrap();
            let (records, errors) = parse_lines(&text);
            assert!(errors.is_empty(), "trace parse errors: {errors:?}");
            records
                .into_iter()
                .filter_map(|r| match r {
                    Record::Event(e) => Some(e),
                    Record::Note(_) => None,
                })
                .collect()
        }

        #[inline(never)]
        unsafe extern "C" fn target_inplace_xor(
            key_ptr: *const u8,
            key_len: usize,
            buf_ptr: *mut u8,
            buf_len: usize,
        ) -> usize {
            // SAFETY: caller guarantees `key_ptr..key_len` and `buf_ptr..buf_len`
            // are valid in-bounds slices for the duration of the call.
            let (key, buf) = unsafe {
                (
                    std::slice::from_raw_parts(key_ptr, key_len),
                    std::slice::from_raw_parts_mut(buf_ptr, buf_len),
                )
            };
            if key.is_empty() {
                return 0;
            }
            let mut checksum = 0usize;
            for (i, b) in buf.iter_mut().enumerate() {
                *b ^= key[i % key.len()];
                checksum = checksum.wrapping_add(*b as usize);
            }
            std::hint::black_box(checksum)
        }

        #[inline(never)]
        unsafe extern "C" fn target_separate_expand(
            in_ptr: *const u8,
            in_len: usize,
            out_ptr: *mut u8,
            out_len: usize,
        ) -> u64 {
            // SAFETY: caller guarantees both slices are valid and disjoint.
            let (input, output) = unsafe {
                (
                    std::slice::from_raw_parts(in_ptr, in_len),
                    std::slice::from_raw_parts_mut(out_ptr, out_len),
                )
            };
            for (i, slot) in output.iter_mut().enumerate() {
                *slot = input[i % input.len()].wrapping_add(1);
            }
            std::hint::black_box(0xDEAD_BEEF_CAFE_1234u64)
        }

        #[inline(never)]
        unsafe extern "C" fn target_stack_args(
            a: usize,
            b: usize,
            c: usize,
            d: usize,
            ptr5: *const u8,
            len6: usize,
        ) -> usize {
            // SAFETY: caller provides a valid slice for slots 5 and 6.
            let s = unsafe { std::slice::from_raw_parts(ptr5, len6) };
            let mut acc = a.wrapping_add(b).wrapping_add(c).wrapping_add(d);
            for &x in s {
                acc = acc.wrapping_add(x as usize);
            }
            std::hint::black_box(acc)
        }

        #[repr(C)]
        #[derive(Debug, PartialEq, Eq)]
        struct BigRet {
            words: [u64; 4],
        }

        #[inline(never)]
        unsafe extern "C" fn target_sret_stack(
            a: usize,
            b: usize,
            c: usize,
            ptr4: *const u8,
            len5: usize,
        ) -> BigRet {
            // SAFETY: caller provides a valid slice shifted behind hidden `sret`.
            let s = unsafe { std::slice::from_raw_parts(ptr4, len5) };
            let sum: u64 = s.iter().map(|&x| x as u64).sum();
            std::hint::black_box(BigRet {
                words: [a as u64, b as u64, c as u64, sum],
            })
        }

        #[inline(never)]
        unsafe extern "C" fn target_recursive_xor(
            depth: usize,
            buf_ptr: *mut u8,
            buf_len: usize,
        ) -> usize {
            // SAFETY: `GetLastError` reads TEB state with no preconditions.
            assert_eq!(unsafe { GetLastError() }, 0x1337_BEEF);
            // SAFETY: caller ensures `buf_ptr..buf_len` is mutable for the call.
            let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_len) };
            for b in buf.iter_mut() {
                *b ^= (depth as u8).wrapping_add(0x11);
            }
            if depth > 0 {
                // SAFETY: recursive call on the same live buffer at `depth - 1`.
                let sub = unsafe { target_recursive_xor(depth - 1, buf.as_mut_ptr(), buf.len()) };
                depth + sub
            } else {
                0
            }
        }

        #[test]
        fn live_win64_inplace_xor_captures_entry_and_return_blobs() {
            let _lock = LIVE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir = TempCaptureDir::new("inplace-xor");
            let base = exe_module_base();
            let t = live_target(
                "test.xor",
                base,
                target_inplace_xor as *const () as usize as u64,
                vec![
                    reg_arg("key", ArgKind::Slice, "rcx", Some("rdx")),
                    reg_arg("data", ArgKind::SliceMut, "r8", Some("r9")),
                ],
                CaptureSpec {
                    when: When::Both,
                    dump: vec!["data".into()],
                    expect: Expect::EntropyDrop,
                    compare: None,
                    max_bytes: 1 << 20,
                },
            );
            let (count, _guard) = install_live(vec![t], &dir);
            assert_eq!(count, 1);

            let key = b"K0Y7-SECRET-KEY!";
            let plaintext = b"Frustracean testbed recoverable ASCII plaintext payload\n".repeat(8);
            let mut work: Vec<u8> = plaintext
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ key[i % key.len()])
                .collect();

            // SAFETY: hooked target decrypts `work` in-place via trampoline and returns.
            let _sum = unsafe {
                std::hint::black_box(target_inplace_xor(
                    key.as_ptr(),
                    key.len(),
                    work.as_mut_ptr(),
                    work.len(),
                ))
            };
            assert_eq!(work, plaintext);
            super::super::finish_session();

            let events = read_trace_events(&dir.trace_path());
            assert_eq!(
                events.len(),
                2,
                "expected Entry and Return events: {events:?}"
            );
            assert_eq!(events[0].phase, Phase::Entry);
            assert_eq!(events[1].phase, Phase::Return);
            assert_eq!(events[0].call_id, events[1].call_id);
            let entry_buf = &events[0].buffers[0];
            let ret_buf = &events[1].buffers[0];
            assert_ne!(entry_buf.sha256, ret_buf.sha256);
            assert!(
                ret_buf.stats.entropy < entry_buf.stats.entropy,
                "expected entropy drop: entry={} return={}",
                entry_buf.stats.entropy,
                ret_buf.stats.entropy
            );
            let ret_dump = ret_buf
                .dump
                .as_deref()
                .expect("return blob must be written");
            assert_eq!(dir.read_blob(ret_dump), plaintext);
        }

        #[test]
        fn live_win64_separate_output_preserves_return_scalar_and_compares() {
            let _lock = LIVE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir = TempCaptureDir::new("separate-out");
            let base = exe_module_base();
            let t = live_target(
                "test.expand",
                base,
                target_separate_expand as *const () as usize as u64,
                vec![
                    reg_arg("input", ArgKind::Slice, "rcx", Some("rdx")),
                    reg_arg("output", ArgKind::SliceMut, "r8", Some("r9")),
                ],
                CaptureSpec {
                    when: When::Both,
                    dump: vec!["input".into(), "output".into()],
                    expect: Expect::EntropyDrop,
                    compare: Some(Comparison {
                        from: "input".into(),
                        to: "output".into(),
                    }),
                    max_bytes: 1 << 20,
                },
            );
            let (count, _guard) = install_live(vec![t], &dir);
            assert_eq!(count, 1);

            let input = b"ABCD".to_vec();
            let mut output = vec![0u8; 64];
            // SAFETY: hooked function populates `output` and returns sentinel u64 in rax.
            let ret = unsafe {
                std::hint::black_box(target_separate_expand(
                    input.as_ptr(),
                    input.len(),
                    output.as_mut_ptr(),
                    output.len(),
                ))
            };
            assert_eq!(ret, 0xDEAD_BEEF_CAFE_1234u64);
            super::super::finish_session();

            let events = read_trace_events(&dir.trace_path());
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].phase, Phase::Entry);
            assert_eq!(events[1].phase, Phase::Return);
            assert_eq!(events[0].buffers[0].name, "input");
            let out_rec = events[1]
                .buffers
                .iter()
                .find(|b| b.name == "output")
                .expect("Return record must contain output buffer");
            assert_eq!(
                dir.read_blob(events[0].buffers[0].dump.as_deref().unwrap()),
                input
            );
            assert_eq!(dir.read_blob(out_rec.dump.as_deref().unwrap()), output);
        }

        #[test]
        fn live_win64_stack_spilled_args_and_sret_preserve_stack_and_rax() {
            let _lock = LIVE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir = TempCaptureDir::new("stack-sret");
            let base = exe_module_base();
            let t_stack = live_target(
                "test.stack6",
                base,
                target_stack_args as *const () as usize as u64,
                vec![
                    reg_arg("a", ArgKind::Int, "rcx", None),
                    reg_arg("b", ArgKind::Int, "rdx", None),
                    reg_arg("c", ArgKind::Int, "r8", None),
                    reg_arg("d", ArgKind::Int, "r9", None),
                    ResolvedArg {
                        name: "payload".into(),
                        kind: ArgKind::Slice,
                        value: ArgLoc::Stack { offset: 0x28 },
                        length: Some(ArgLoc::Stack { offset: 0x30 }),
                    },
                ],
                CaptureSpec {
                    when: When::Entry,
                    dump: vec!["payload".into()],
                    expect: Expect::Any,
                    compare: None,
                    max_bytes: 1 << 20,
                },
            );
            let t_sret = live_target(
                "test.sret",
                base,
                target_sret_stack as *const () as usize as u64,
                vec![
                    reg_arg("a", ArgKind::Int, "rdx", None),
                    reg_arg("b", ArgKind::Int, "r8", None),
                    reg_arg("c", ArgKind::Int, "r9", None),
                    ResolvedArg {
                        name: "payload".into(),
                        kind: ArgKind::Slice,
                        value: ArgLoc::Stack { offset: 0x28 },
                        length: Some(ArgLoc::Stack { offset: 0x30 }),
                    },
                ],
                CaptureSpec {
                    when: When::Entry,
                    dump: vec!["payload".into()],
                    expect: Expect::Any,
                    compare: None,
                    max_bytes: 1 << 20,
                },
            );
            let (count, _guard) = install_live(vec![t_stack, t_sret], &dir);
            assert_eq!(count, 2);

            let bytes = b"STACK-ARG-SLICE!";
            // SAFETY: passes 6 Win64 arguments (slots 5 and 6 spilled at [rsp+0x28..0x30]).
            let sum = unsafe {
                std::hint::black_box(target_stack_args(
                    11,
                    22,
                    33,
                    44,
                    bytes.as_ptr(),
                    bytes.len(),
                ))
            };
            let expected_bytes_sum: usize = bytes.iter().map(|&x| x as usize).sum();
            assert_eq!(sum, 11 + 22 + 33 + 44 + expected_bytes_sum);

            // SAFETY: `BigRet` (32 bytes) uses hidden Win64 `sret` pointer in `rcx`,
            // shifting `bytes` onto [rsp+0x28]/[rsp+0x30] behind `a,b,c`.
            let big = unsafe {
                std::hint::black_box(target_sret_stack(
                    101,
                    202,
                    303,
                    bytes.as_ptr(),
                    bytes.len(),
                ))
            };
            assert_eq!(
                big,
                BigRet {
                    words: [101, 202, 303, expected_bytes_sum as u64],
                }
            );
            super::super::finish_session();

            let events = read_trace_events(&dir.trace_path());
            assert_eq!(events.len(), 2);
            for ev in &events {
                assert_eq!(ev.phase, Phase::Entry);
                let buf = &ev.buffers[0];
                assert_eq!(buf.name, "payload");
                assert_eq!(buf.len, bytes.len());
                assert_eq!(dir.read_blob(buf.dump.as_deref().unwrap()), bytes);
            }
            assert_eq!(events[0].scalars.len(), 4);
            assert_eq!(events[1].scalars.len(), 3);
            assert_eq!(events[1].scalars[0].value, 101);
        }

        #[test]
        fn live_win64_recursive_calls_and_last_error_preservation() {
            let _lock = LIVE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir = TempCaptureDir::new("recursive");
            let base = exe_module_base();
            let t = live_target(
                "test.recurse",
                base,
                target_recursive_xor as *const () as usize as u64,
                vec![
                    reg_arg("depth", ArgKind::Int, "rcx", None),
                    reg_arg("data", ArgKind::SliceMut, "rdx", Some("r8")),
                ],
                CaptureSpec {
                    when: When::Both,
                    dump: vec!["data".into()],
                    expect: Expect::Any,
                    compare: None,
                    max_bytes: 1 << 20,
                },
            );
            let (count, _guard) = install_live(vec![t], &dir);
            assert_eq!(count, 1);

            let mut buf = vec![0xAAu8; 32];
            // SAFETY: sets thread last-error sentinel checked inside `target_recursive_xor`.
            unsafe { SetLastError(0x1337_BEEF) };
            // SAFETY: runs 3 nested hooked invocations (`depth` = 2 -> 1 -> 0).
            let res = unsafe {
                std::hint::black_box(target_recursive_xor(2, buf.as_mut_ptr(), buf.len()))
            };
            // SAFETY: `GetLastError` reads TEB state with no preconditions.
            let after_err = unsafe { GetLastError() };
            assert_eq!(after_err, 0x1337_BEEF);
            assert_eq!(res, 2 + 1);
            // XOR mask applied for depth 2 (0x13), depth 1 (0x12), depth 0 (0x11) -> 0x13^0x12^0x11 = 0x10.
            assert_eq!(buf, vec![0xAA ^ 0x10; 32]);
            super::super::finish_session();

            let events = read_trace_events(&dir.trace_path());
            assert_eq!(events.len(), 6);
            assert_eq!(
                events
                    .iter()
                    .map(|e| (e.phase, e.call_id))
                    .collect::<Vec<_>>(),
                vec![
                    (Phase::Entry, 1),
                    (Phase::Entry, 2),
                    (Phase::Entry, 3),
                    (Phase::Return, 3),
                    (Phase::Return, 2),
                    (Phase::Return, 1),
                ]
            );
        }
    }
}
