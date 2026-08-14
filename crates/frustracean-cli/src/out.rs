//! Accessible console output.
//!
//! The conventions here are the same ones Delpheed uses, and they are load-bearing
//! rather than cosmetic:
//!
//! * status is carried by **words** (`OK:`, `ERROR:`, `WARNING:`, `INFO:`), never
//!   by colour;
//! * output is **linear and labelled** (`Name: value`), not aligned columns;
//! * no box drawing, spinners, or cursor tricks;
//! * **errors and warnings go to stderr**, results go to stdout, so a pipeline
//!   gets clean data;
//! * quiet mode drops the commentary but keeps the result lines.

use std::io::Write;

/// Process exit codes, shared with Delpheed so the two tools script the same way.
pub mod exit {
    /// Everything worked.
    pub const OK: i32 = 0;
    /// Bad or missing arguments.
    pub const USAGE: i32 = 1;
    /// The input could not be read, or was not a valid image.
    pub const BAD_INPUT: i32 = 2;
    /// The tool ran, but the operation did not succeed.
    pub const FAILED: i32 = 3;
}

#[derive(Debug, Clone, Copy)]
pub struct Out {
    pub quiet: bool,
}

impl Out {
    pub fn new(quiet: bool) -> Out {
        Out { quiet }
    }

    /// A result line. Always printed, even when quiet.
    pub fn line(&self, text: impl AsRef<str>) {
        println!("{}", text.as_ref());
    }

    /// A labelled value. Always printed.
    pub fn field(&self, name: &str, value: impl std::fmt::Display) {
        println!("{name}: {value}");
    }

    /// An indented sub-item beneath the preceding field.
    pub fn item(&self, text: impl AsRef<str>) {
        println!("  {}", text.as_ref());
    }

    /// A section heading. Suppressed when quiet.
    pub fn section(&self, title: &str) {
        if self.quiet {
            return;
        }
        println!();
        println!("{title}");
    }

    /// Commentary. Suppressed when quiet.
    pub fn info(&self, text: impl AsRef<str>) {
        if self.quiet {
            return;
        }
        println!("INFO: {}", text.as_ref());
    }

    /// A successful outcome. Always printed.
    pub fn ok(&self, text: impl AsRef<str>) {
        println!("OK: {}", text.as_ref());
    }

    /// Something the analyst should know but that did not stop the run.
    /// Always printed, to stderr.
    pub fn warn(&self, text: impl AsRef<str>) {
        let _ = writeln!(std::io::stderr(), "WARNING: {}", text.as_ref());
    }

    /// A failure. Always printed, to stderr.
    pub fn error(&self, text: impl AsRef<str>) {
        let _ = writeln!(std::io::stderr(), "ERROR: {}", text.as_ref());
    }
}

/// Format a byte count with a plain unit suffix. No alignment padding, because
/// padded columns read badly aloud.
pub fn bytes(n: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("bytes", 1),
    ];
    for (unit, scale) in UNITS {
        if n >= scale {
            if scale == 1 {
                return format!("{n} bytes");
            }
            return format!("{:.2} {unit} ({n} bytes)", n as f64 / scale as f64);
        }
    }
    format!("{n} bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_carry_both_a_readable_and_an_exact_form() {
        assert_eq!(bytes(512), "512 bytes");
        assert!(bytes(2048).starts_with("2.00 KiB"));
        assert!(bytes(2048).ends_with("(2048 bytes)"));
        assert_eq!(bytes(0), "0 bytes");
    }
}
