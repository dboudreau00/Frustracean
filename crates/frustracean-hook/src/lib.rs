//! The injected payload.
//!
//! Loaded into a suspended sample before its entry point runs, so hooks are in
//! place before the unpacking stub executes. On attach it reads the hijack plan
//! named by `FRUSTRACEAN_PLAN`, rebases every target onto the module's real load
//! address, verifies that the bytes at each site still match what the planner
//! saw, installs wrapped-call detours, and writes a JSON Lines trace plus
//! content-addressed buffer dumps into `FRUSTRACEAN_OUT`.

pub mod capture;
pub mod detour;
pub mod trampoline;

#[cfg(windows)]
pub(crate) mod probe {
    use windows_sys::Win32::System::Memory::{
        VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY,
        PAGE_READWRITE, PAGE_WRITECOPY,
    };

    fn is_readable_region(info: &MEMORY_BASIC_INFORMATION) -> bool {
        if info.State != MEM_COMMIT {
            return false;
        }
        if info.Protect & PAGE_GUARD != 0 || info.Protect & PAGE_NOACCESS != 0 {
            return false;
        }
        let readable = PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY;
        info.Protect & readable != 0
    }

    /// Read up to `len` contiguous bytes at `addr`, checking every virtual
    /// memory region spanned rather than trusting the target's pointer/length.
    pub fn read_checked(addr: u64, len: usize) -> (Vec<u8>, Option<String>) {
        if len == 0 {
            return (Vec::new(), None);
        }
        if addr == 0 {
            return (Vec::new(), Some("null buffer pointer".into()));
        }

        let mut out = Vec::new();
        let mut cursor = addr;
        while out.len() < len {
            // SAFETY: `MEMORY_BASIC_INFORMATION` is a plain C struct that
            // `VirtualQuery` fills in entirely.
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: `VirtualQuery` inspects virtual memory metadata without
            // dereferencing `cursor`, and `info` has exact struct size.
            let written = unsafe {
                VirtualQuery(
                    cursor as *const std::ffi::c_void,
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 || !is_readable_region(&info) {
                let msg = if out.is_empty() {
                    format!("pointer {addr:#x} is not mapped or not readable")
                } else {
                    format!(
                        "buffer unreadable past {cursor:#x} (read {} of {len} bytes)",
                        out.len()
                    )
                };
                return (out, Some(msg));
            }
            let region_end = (info.BaseAddress as u64).saturating_add(info.RegionSize as u64);
            let avail = region_end.saturating_sub(cursor) as usize;
            let take = (len - out.len()).min(avail);
            if take == 0 {
                let msg = format!(
                    "zero-byte stride at {cursor:#x} (read {} of {len} bytes)",
                    out.len()
                );
                return (out, Some(msg));
            }
            // SAFETY: `cursor .. cursor + take` lies entirely inside one
            // committed, non-guard, non-noaccess readable region verified by
            // `VirtualQuery` above, and we copy the bytes immediately.
            let slice = unsafe { std::slice::from_raw_parts(cursor as *const u8, take) };
            out.extend_from_slice(slice);
            let Some(next) = cursor.checked_add(take as u64) else {
                break;
            };
            cursor = next;
        }
        (out, None)
    }

    /// Read exact `len` contiguous bytes at `addr`, returning `None` unless the
    /// full range is readable.
    pub fn read_exact(addr: u64, len: usize) -> Option<Vec<u8>> {
        let (bytes, err) = read_checked(addr, len);
        if err.is_some() || bytes.len() != len {
            None
        } else {
            Some(bytes)
        }
    }
}

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

        let store = match BlobStore::new(out_dir.join("blobs")) {
            Ok(store) => Some(store),
            Err(e) => {
                sink.note(
                    NoteLevel::Warning,
                    format!("could not create the blob directory: {e}; buffers will not be dumped"),
                );
                None
            }
        };

        if let Err(e) = detour::install_plan(&plan, base, &mut sink, store) {
            sink.note(NoteLevel::Error, e);
        }
    }

    pub fn detach() {
        detour::finish_session();
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
    const DLL_PROCESS_DETACH: u32 = 0;
    const DLL_PROCESS_ATTACH: u32 = 1;
    match reason {
        DLL_PROCESS_ATTACH => {
            // A panic must never unwind into the sample's loader.
            let _ = std::panic::catch_unwind(attach::run);
        }
        DLL_PROCESS_DETACH => {
            let _ = std::panic::catch_unwind(attach::detach);
        }
        _ => {}
    }
    1
}
