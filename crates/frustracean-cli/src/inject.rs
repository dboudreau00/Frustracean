//! Launching a sample with the hijack payload attached.
//!
//! The mechanism is the ordinary one: create the process suspended, write the
//! payload's path into it, run `LoadLibraryW` on that path via a remote thread,
//! then resume.
//!
//! # What "before the sample runs" does and does not mean
//!
//! `CREATE_SUSPENDED` stops the initial thread before the **entry point**, not
//! before everything. By the time `LoadLibraryW` runs in the target, the loader
//! has already mapped the image and its static imports. And loading the payload
//! is itself what triggers the remaining initialisation: `LoadLibraryW` runs the
//! loader, which executes the `DllMain` of every statically imported DLL and
//! then the sample's own **TLS callbacks** - a well-known anti-analysis hiding
//! place - before our `DllMain` is reached.
//!
//! So the guarantee is: hooks are installed before the entry point, and before
//! any code the sample runs from `main`. A sample that does its unpacking from a
//! TLS callback will have finished before the first hook exists. Catching that
//! needs a debugger attach (`DEBUG_ONLY_THIS_PROCESS`) and injection at the
//! initial breakpoint instead; see the roadmap.
//!
//! # Structure
//!
//! Everything Win32 lives in the [`win`] module as small owning wrappers, so the
//! logic below reads as ordinary safe Rust and each `unsafe` block has exactly
//! one thing to justify. That is not tidiness for its own sake: this module
//! creates processes and writes to their memory, and it is the part of the tool
//! most likely to be read closely by someone deciding whether to trust it.
//!
//! Handles are owned by [`win::Child`] and released on drop, so the many early
//! returns below cannot leak one.

use std::path::Path;

use frustracean_core::plan::HijackPlan;

use crate::out::{exit, Out};

// Everything from here to `run` exists only to serve the Windows
// implementation. On other platforms it is genuinely dead, and CI builds with
// `-D warnings`, so it is gated rather than left to rot behind an `allow`.
//
// The string helpers are `any(windows, test)`: their behaviour is pure logic
// worth testing everywhere, even though only Windows calls them.

/// Environment variables the payload reads on attach.
#[cfg(windows)]
pub const ENV_PLAN: &str = "FRUSTRACEAN_PLAN";
#[cfg(windows)]
pub const ENV_OUT: &str = "FRUSTRACEAN_OUT";

/// How long to wait for the payload's `DllMain` to finish attaching.
#[cfg(windows)]
const ATTACH_TIMEOUT_MS: u32 = 30_000;

/// Quote one argument for a Windows command line.
///
/// Windows has no argv; it hands the child a single string and the C runtime
/// splits it. Wrapping an argument in quotes is not sufficient, because
/// backslashes are only special immediately before a quote: `C:\dir\` inside
/// quotes ends up escaping the closing quote and swallowing the next argument.
///
/// The rule the CRT actually implements, and the one below: double every
/// backslash in a run that precedes a quote (including the closing one), and
/// escape embedded quotes as `\"`.
///
/// This matters here beyond tidiness. The arguments after `--` are analyst input
/// aimed at a malware sample, and an argument that silently merges with the next
/// one changes what the sample is asked to do.
#[cfg(any(windows, test))]
fn quote_argument(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"', '\\']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                // Each backslash in the run is doubled, and then one more is
                // added to escape the quote itself: N backslashes before a
                // quote become 2N+1. Emitting N+1 instead - the tempting
                // off-by-one - leaves the quote escaped but the backslashes
                // halved, so the child sees a different argument.
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // A trailing run precedes the closing quote, so it is doubled too.
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Build the full command line for the sample and its pass-through arguments.
#[cfg(any(windows, test))]
fn build_command_line(sample: &Path, args: &[String]) -> String {
    let mut line = quote_argument(&sample.display().to_string());
    for arg in args {
        line.push(' ');
        line.push_str(&quote_argument(arg));
    }
    line
}

/// Locate `frustracean_hook.dll`: the flag, then beside this executable.
#[cfg(windows)]
pub fn resolve_payload(explicit: Option<&Path>) -> Option<std::path::PathBuf> {
    if let Some(p) = explicit {
        return p.is_file().then(|| p.to_path_buf());
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    for name in ["frustracean_hook.dll", "libfrustracean_hook.so"] {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Win32
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    //! Owning wrappers over the handful of Win32 calls the injector needs.
    //!
    //! Each wrapper contains one `unsafe` block with one thing to justify, and
    //! the resource types release themselves on drop so no error path can leak
    //! a process handle or a remote allocation.

    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows_sys::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, CreateRemoteThread, GetExitCodeProcess, ResumeThread, TerminateProcess,
        WaitForSingleObject, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    };

    pub type Handle = *mut c_void;
    pub type StartRoutine = unsafe extern "system" fn(*mut c_void) -> u32;

    /// NUL-terminated UTF-16, as every `...W` entry point expects.
    pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
        s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn last_error() -> u32 {
        // SAFETY: `GetLastError` takes no arguments, reads only thread-local
        // state, and is sound to call at any time.
        unsafe { GetLastError() }
    }

    /// The address of `LoadLibraryW` in this process.
    ///
    /// It is valid in the child too: `kernel32.dll` is mapped at the same base
    /// in every process for a given boot, which is what makes the whole
    /// `CreateRemoteThread(LoadLibraryW)` technique work.
    pub fn load_library_w() -> Option<StartRoutine> {
        // SAFETY: the argument is a NUL-terminated UTF-16 string that outlives
        // the call. `GetModuleHandleW` does not take a reference on the module,
        // so the returned handle needs no release, and kernel32 is loaded into
        // every Win32 process for its lifetime.
        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
        if kernel32.is_null() {
            return None;
        }
        // SAFETY: `kernel32` is a live module handle from the call above, and
        // the name is a NUL-terminated byte string literal.
        let proc = unsafe { GetProcAddress(kernel32, c"LoadLibraryW".as_ptr().cast()) }?;
        // SAFETY: `LoadLibraryW` really has the signature
        // `extern "system" fn(*const u16) -> HMODULE`. Both the parameter and
        // the return are pointer-sized, which is what `LPTHREAD_START_ROUTINE`
        // requires, so this transmute reinterprets a function pointer as a
        // compatible function pointer rather than changing its ABI.
        Some(unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, StartRoutine>(proc)
        })
    }

    /// A page-aligned allocation inside another process, freed on drop.
    pub struct RemoteBuffer<'a> {
        process: Handle,
        address: *mut c_void,
        _child: std::marker::PhantomData<&'a Child>,
    }

    impl RemoteBuffer<'_> {
        pub fn address(&self) -> *mut c_void {
            self.address
        }
    }

    impl Drop for RemoteBuffer<'_> {
        fn drop(&mut self) {
            // SAFETY: `address` came from `VirtualAllocEx` on this same process
            // handle and has not been freed; `MEM_RELEASE` requires a size of
            // zero, which is what is passed. The handle outlives this buffer,
            // enforced by the lifetime parameter.
            unsafe { VirtualFreeEx(self.process, self.address, 0, MEM_RELEASE) };
        }
    }

    /// A suspended child process. Both handles are closed on drop.
    pub struct Child {
        process: Handle,
        thread: Handle,
        pub pid: u32,
    }

    impl Child {
        /// Create the process suspended. `command_line` must already be quoted.
        pub fn spawn_suspended(application: &Path, command_line: &str) -> Result<Child, u32> {
            let application = wide(application);
            let mut command_line = wide(command_line);

            // SAFETY: `STARTUPINFOW` and `PROCESS_INFORMATION` are plain C
            // structs whose all-zero bit pattern is the documented "unset"
            // state, so zeroing them is the initialisation the API expects.
            let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
            startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            // SAFETY: as above.
            let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

            // SAFETY: `application` and `command_line` are NUL-terminated and
            // live for the duration of the call. `command_line` is passed as a
            // mutable pointer because CreateProcessW may write to it in place,
            // and it is an owned local, not a shared buffer. The null
            // attribute/environment/directory pointers select the documented
            // defaults, so the child inherits this process's environment -
            // which is how the payload receives FRUSTRACEAN_PLAN.
            let created = unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    CREATE_SUSPENDED,
                    std::ptr::null(),
                    std::ptr::null(),
                    &startup,
                    &mut info,
                )
            };
            if created == 0 {
                return Err(last_error());
            }
            Ok(Child {
                process: info.hProcess,
                thread: info.hThread,
                pid: info.dwProcessId,
            })
        }

        /// Reserve and commit read/write memory in the child.
        pub fn alloc(&self, len: usize) -> Option<RemoteBuffer<'_>> {
            // SAFETY: `self.process` is a live handle owned by this struct. A
            // null base address asks the kernel to choose one, which is always
            // valid, and the returned pointer is only ever handed back to
            // Win32 calls on this same process - never dereferenced here.
            let address = unsafe {
                VirtualAllocEx(
                    self.process,
                    std::ptr::null(),
                    len,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if address.is_null() {
                return None;
            }
            Some(RemoteBuffer {
                process: self.process,
                address,
                _child: std::marker::PhantomData,
            })
        }

        /// Copy bytes into a buffer previously returned by [`Child::alloc`].
        pub fn write(&self, target: &RemoteBuffer<'_>, bytes: &[u8]) -> bool {
            // SAFETY: `self.process` is live, and `target.address` was returned
            // by `VirtualAllocEx` on it. The source is a Rust slice, so it is
            // valid for `bytes.len()` bytes; the caller is responsible for the
            // allocation being at least that large, which the one call site
            // guarantees by allocating exactly this length.
            let ok = unsafe {
                WriteProcessMemory(
                    self.process,
                    target.address(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    std::ptr::null_mut(),
                )
            };
            ok != 0
        }

        /// Run `start(argument)` on a new thread in the child and wait for it.
        pub fn run_remote(
            &self,
            start: StartRoutine,
            argument: *mut c_void,
            timeout_ms: u32,
        ) -> Result<(), String> {
            // SAFETY: `self.process` is live. `start` is the address of
            // `LoadLibraryW`, valid in the child for the reason documented on
            // `load_library_w`. `argument` points at memory allocated in the
            // child, which is where the callee expects its parameter to live.
            let thread = unsafe {
                CreateRemoteThread(
                    self.process,
                    std::ptr::null(),
                    0,
                    Some(start),
                    argument,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if thread.is_null() {
                return Err(format!(
                    "CreateRemoteThread failed with error {}",
                    last_error()
                ));
            }
            // SAFETY: `thread` is a live handle from the call above.
            let waited = unsafe { WaitForSingleObject(thread, timeout_ms) };
            // SAFETY: same handle, not yet closed, and not used afterwards.
            unsafe { CloseHandle(thread) };
            if waited != WAIT_OBJECT_0 {
                return Err(format!(
                    "the remote thread did not finish within {} seconds",
                    timeout_ms / 1000
                ));
            }
            Ok(())
        }

        /// Release the initial thread so the sample starts executing.
        pub fn resume(&self) {
            // SAFETY: `self.thread` is the live initial-thread handle from
            // CreateProcessW, suspended exactly once by CREATE_SUSPENDED.
            unsafe { ResumeThread(self.thread) };
        }

        /// Wait for the process to exit. Returns false on timeout.
        pub fn wait(&self, timeout_ms: u32) -> bool {
            // SAFETY: `self.process` is a live handle owned by this struct.
            unsafe { WaitForSingleObject(self.process, timeout_ms) == WAIT_OBJECT_0 }
        }

        pub fn exit_code(&self) -> u32 {
            let mut code = 0u32;
            // SAFETY: `self.process` is live and `code` is a local u32 that
            // outlives the call.
            unsafe { GetExitCodeProcess(self.process, &mut code) };
            code
        }

        pub fn terminate(&self) {
            // SAFETY: `self.process` is live. Terminating an already-exited
            // process is a no-op that returns an error, which is ignored here
            // because there is nothing useful to do about it.
            unsafe { TerminateProcess(self.process, 1) };
        }
    }

    impl Drop for Child {
        fn drop(&mut self) {
            // SAFETY: both handles came from CreateProcessW, are closed exactly
            // once here, and are not used afterwards.
            unsafe {
                CloseHandle(self.thread);
                CloseHandle(self.process);
            }
        }
    }

    use std::path::Path;
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
pub fn run(
    o: &Out,
    plan: &HijackPlan,
    plan_path: &Path,
    sample: &Path,
    out_dir: &Path,
    payload: Option<&Path>,
    sample_args: &[String],
    timeout_secs: u64,
) -> i32 {
    if plan.image.bits != 64 {
        o.error(format!(
            "the payload is 64-bit but the plan targets a {}-bit image; bitness must match",
            plan.image.bits
        ));
        return exit::FAILED;
    }

    let Some(payload_path) = resolve_payload(payload) else {
        o.error("could not find frustracean_hook.dll; pass --payload");
        return exit::USAGE;
    };

    if let Err(e) = std::fs::create_dir_all(out_dir) {
        o.error(format!("{}: {e}", out_dir.display()));
        return exit::FAILED;
    }

    // Absolute paths: the child's working directory is its own.
    let plan_abs = plan_path
        .canonicalize()
        .unwrap_or_else(|_| plan_path.to_path_buf());
    let out_abs = out_dir
        .canonicalize()
        .unwrap_or_else(|_| out_dir.to_path_buf());
    let payload_abs = payload_path
        .canonicalize()
        .unwrap_or_else(|_| payload_path.clone());

    // The child inherits our environment, so this is how the payload is told
    // what to do. Set before spawning.
    std::env::set_var(ENV_PLAN, &plan_abs);
    std::env::set_var(ENV_OUT, &out_abs);

    o.info(format!("payload: {}", payload_abs.display()));
    o.info("creating the process suspended so hooks land before the entry point runs");
    o.info("note: the sample's TLS callbacks run during payload load, ahead of the first hook");

    let command_line = build_command_line(sample, sample_args);
    let child = match win::Child::spawn_suspended(sample, &command_line) {
        Ok(c) => c,
        Err(code) => {
            o.error(format!("CreateProcessW failed with error {code}"));
            return exit::FAILED;
        }
    };
    o.field("Process id", child.pid);

    // 1. Write the payload's path into the target.
    let payload_wide = win::wide(&payload_abs);
    let payload_bytes: &[u8] = {
        let ptr = payload_wide.as_ptr().cast::<u8>();
        let len = std::mem::size_of_val(payload_wide.as_slice());
        // SAFETY: reinterpreting a `[u16]` as `[u8]` of twice the length. u8
        // has weaker alignment than u16 and no padding or invalid bit patterns,
        // and the borrow is tied to `payload_wide`, which outlives this slice.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    };

    let Some(remote) = child.alloc(payload_bytes.len()) else {
        o.error(format!(
            "VirtualAllocEx failed with error {}",
            win::last_error()
        ));
        child.terminate();
        return exit::FAILED;
    };
    if !child.write(&remote, payload_bytes) {
        o.error(format!(
            "WriteProcessMemory failed with error {}",
            win::last_error()
        ));
        child.terminate();
        return exit::FAILED;
    }

    // 2. Call LoadLibraryW in the target, and wait for the payload to finish
    //    attaching before letting the sample run.
    let Some(load_library) = win::load_library_w() else {
        o.error("could not resolve LoadLibraryW in kernel32.dll");
        child.terminate();
        return exit::FAILED;
    };
    if let Err(e) = child.run_remote(load_library, remote.address(), ATTACH_TIMEOUT_MS) {
        o.error(e);
        child.terminate();
        return exit::FAILED;
    }
    o.info("payload attached; resuming the sample");

    // 3. Let it run, bounded.
    child.resume();
    let timeout_ms = u32::try_from(timeout_secs.saturating_mul(1000)).unwrap_or(u32::MAX);
    if child.wait(timeout_ms) {
        o.field("Sample exit code", child.exit_code());
    } else {
        o.warn(format!(
            "the sample was still running after {timeout_secs} seconds; terminating it"
        ));
        child.terminate();
    }

    let trace_path = out_abs.join("trace.jsonl");
    if !trace_path.is_file() {
        o.error(format!(
            "no trace was produced at {}; the payload may not have attached",
            trace_path.display()
        ));
        return exit::FAILED;
    }
    o.section("Summary");
    o.ok(format!("trace written to {}", trace_path.display()));
    o.item(format!(
        "next: frustracean replay {} --plan {}",
        trace_path.display(),
        plan_abs.display()
    ));
    exit::OK
}

#[cfg(not(windows))]
#[allow(clippy::too_many_arguments)]
pub fn run(
    o: &Out,
    _plan: &HijackPlan,
    _plan_path: &Path,
    _sample: &Path,
    _out_dir: &Path,
    _payload: Option<&Path>,
    _sample_args: &[String],
    _timeout_secs: u64,
) -> i32 {
    o.error("dynamic tracing is implemented for Windows only");
    o.item("The static commands (scan, map, stats, deps, strings, plan, rules, replay) work everywhere.");
    exit::FAILED
}

#[cfg(test)]
mod tests {
    use super::{build_command_line, quote_argument};
    use std::path::Path;

    #[test]
    fn a_plain_argument_is_not_quoted_at_all() {
        assert_eq!(quote_argument("--verbose"), "--verbose");
    }

    #[test]
    fn an_argument_with_spaces_is_quoted() {
        assert_eq!(quote_argument("two words"), "\"two words\"");
    }

    #[test]
    fn a_trailing_backslash_is_doubled_so_it_cannot_escape_the_closing_quote() {
        // The bug this guards: `"C:\dir\"` escapes its own closing quote, and
        // the next argument is swallowed into this one.
        assert_eq!(quote_argument(r"C:\dir\"), r#""C:\dir\\""#);
    }

    #[test]
    fn interior_backslashes_are_left_alone() {
        // Backslashes are only special immediately before a quote.
        assert_eq!(quote_argument(r"C:\a b\c"), "\"C:\\a b\\c\"");
    }

    #[test]
    fn embedded_quotes_are_escaped() {
        assert_eq!(quote_argument(r#"say "hi""#), r#""say \"hi\"""#);
    }

    #[test]
    fn a_backslash_run_before_a_quote_is_doubled() {
        assert_eq!(quote_argument(r#"a\\"b"#), r#""a\\\\\"b""#);
    }

    #[test]
    fn an_empty_argument_survives_as_an_empty_pair_of_quotes() {
        assert_eq!(quote_argument(""), "\"\"");
    }

    #[test]
    fn the_command_line_quotes_the_program_and_every_argument() {
        let line = build_command_line(
            Path::new(r"C:\samples\evil one.exe"),
            &["--flag".to_string(), r"C:\out\".to_string()],
        );
        assert_eq!(line, r#""C:\samples\evil one.exe" --flag "C:\out\\""#);
    }
}
