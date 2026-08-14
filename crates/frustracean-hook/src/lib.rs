//! The injected payload.
//!
//! Loaded into a suspended sample before its entry point runs, so hooks are in
//! place before the unpacking stub executes. On attach it reads the hijack plan
//! named by `FRUSTRACEAN_PLAN`, rebases every target onto the module's real load
//! address, verifies that the bytes at each site still match what the planner
//! saw, and writes a JSON Lines trace into `FRUSTRACEAN_OUT`.
//!
//! Build status, stated plainly: plan loading, rebasing, prologue verification,
//! trampoline construction, buffer measurement, and trace writing are
//! implemented and unit tested. The detour stub that fires on each hooked call
//! is **not** - see [`detour`] for the design and what remains. Attaching today
//! produces a trace that records exactly what was resolved and why nothing was
//! hooked, which is honest and diagnosable, but it does not yet capture calls.

pub mod capture;
pub mod detour;
pub mod trampoline;

#[cfg(windows)]
mod attach {
    use std::path::PathBuf;

    use frustracean_core::plan::HijackPlan;
    use frustracean_core::trace::NoteLevel;

    use crate::capture::{BlobStore, Sink};
    use crate::detour;

    /// Environment variables the analyst-side launcher sets before creating the
    /// process. Kept in sync with `frustracean-cli/src/inject.rs`.
    const ENV_PLAN: &str = "FRUSTRACEAN_PLAN";
    const ENV_OUT: &str = "FRUSTRACEAN_OUT";

    /// Read `len` bytes at `addr` in this process, first asking the memory
    /// manager whether the range is committed and readable.
    ///
    /// Reading a hook site blind is a fault waiting to happen: a plan can name
    /// an address that the loader never mapped, and in a packed sample a section
    /// may not be committed until the stub gets to it.
    fn read_probe(addr: u64, len: usize) -> Option<Vec<u8>> {
        use windows_sys::Win32::System::Memory::{
            VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
            PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        };

        if len == 0 {
            return Some(Vec::new());
        }
        // SAFETY: `MEMORY_BASIC_INFORMATION` is a plain C struct that
        // `VirtualQuery` fills in entirely; zeroing is the documented way to
        // initialise it before the call.
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `VirtualQuery` only *inspects* the address - it does not
        // dereference it - so an unmapped or wild `addr` is answered rather
        // than faulted on. `info` is a live local of exactly the size passed.
        let written = unsafe {
            VirtualQuery(
                addr as *const std::ffi::c_void,
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 || info.State != MEM_COMMIT {
            return None;
        }
        if info.Protect & PAGE_GUARD != 0 || info.Protect & PAGE_NOACCESS != 0 {
            return None;
        }
        let readable = PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY;
        if info.Protect & readable == 0 {
            return None;
        }
        // Do not read past the end of this region, which may be followed by an
        // unmapped guard.
        let region_end = info.BaseAddress as u64 + info.RegionSize as u64;
        let avail = region_end.saturating_sub(addr) as usize;
        let n = len.min(avail);
        if n == 0 {
            return None;
        }
        // SAFETY: every condition for a valid read has just been established by
        // VirtualQuery - the range is committed, not a guard page, and carries
        // a readable protection - and `n` is clamped to the end of that one
        // region, so the slice cannot run into an unmapped neighbour. The bytes
        // are copied out immediately, so no reference outlives the query.
        Some(unsafe { std::slice::from_raw_parts(addr as *const u8, n) }.to_vec())
    }

    fn module_base() -> u64 {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        // SAFETY: a null module name asks for the handle of the process's own
        // executable, which is always loaded. The handle is an HMODULE, which
        // on Windows *is* the module's base address; it is used as a number and
        // never dereferenced, and needs no release.
        unsafe { GetModuleHandleW(std::ptr::null()) as u64 }
    }

    /// Everything the payload does on attach.
    ///
    /// This runs directly on the loader's thread rather than on a worker.
    /// The launcher waits for `LoadLibraryW` to return before resuming the
    /// sample, so doing the work here is what guarantees the hooks are in place
    /// before the sample's first instruction - a worker thread would race it.
    pub fn run() {
        let Ok(plan_path) = std::env::var(ENV_PLAN) else {
            return;
        };
        let out_dir = PathBuf::from(std::env::var(ENV_OUT).unwrap_or_else(|_| ".".to_string()));

        let Ok(mut sink) = Sink::create(out_dir.join("trace.jsonl")) else {
            return;
        };

        let text = match std::fs::read_to_string(&plan_path) {
            Ok(t) => t,
            Err(e) => {
                sink.note(NoteLevel::Error, format!("could not read {plan_path}: {e}"));
                return;
            }
        };
        let plan = match HijackPlan::from_json(&text) {
            Ok(p) => p,
            Err(e) => {
                sink.note(
                    NoteLevel::Error,
                    format!("could not parse {plan_path}: {e}"),
                );
                return;
            }
        };

        let base = module_base();
        sink.note(
            NoteLevel::Info,
            format!(
                "attached to module base {base:#x} (plan assumed {:#x}); {} target(s)",
                plan.image.preferred_base,
                plan.targets.len()
            ),
        );

        match BlobStore::new(out_dir.join("blobs")) {
            Ok(_store) => {}
            Err(e) => {
                sink.note(
                    NoteLevel::Warning,
                    format!("could not create the blob directory: {e}; buffers will not be dumped"),
                );
            }
        }

        let (hooks, errors) = detour::resolve_all(&plan, base);
        for e in &errors {
            sink.note(NoteLevel::Warning, e.to_string());
        }

        let mut verified = Vec::new();
        for hook in hooks {
            match read_probe(hook.address, hook.expected_bytes.len().max(1)) {
                None => sink.note(
                    NoteLevel::Warning,
                    format!(
                        "target {} at {:#x} is not mapped or not readable; skipping",
                        hook.target_id, hook.address
                    ),
                ),
                Some(actual) => {
                    if detour::prologue_matches(&hook, &actual) {
                        verified.push(hook);
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

        match detour::install(&verified) {
            Ok(n) => sink.note(NoteLevel::Info, format!("{n} hook(s) installed")),
            Err(e) => sink.note(NoteLevel::Error, e),
        }
    }
}

#[cfg(windows)]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _module: *mut std::ffi::c_void,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        // A panic must never unwind into the sample's loader.
        let _ = std::panic::catch_unwind(attach::run);
    }
    1
}
