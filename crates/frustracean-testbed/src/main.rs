//! Run the testbed's unpacking chain and report what each stage produced.
//!
//! Output follows the project's console conventions: labelled linear lines, no
//! colour, results on stdout.
//!
//! Under `frustracean trace`, this is the process the payload attaches to. Its
//! correct output is known in advance, which is the whole reason it exists - a
//! hook that fires and captures the right bytes and a hook that quietly corrupts
//! the process look identical when the target is real malware.

use frustracean_testbed_payload as testbed;

/// `--dump <dir>` writes each stage's buffer to disk.
///
/// This is the ground truth for detour bring-up: when a hook finally fires, the
/// bytes it captures must be identical to these files. Without a known-good
/// reference there is no way to tell a working capture from a plausible-looking
/// one.
fn dump_dir() -> Option<std::path::PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--dump" {
            return args.next().map(std::path::PathBuf::from);
        }
    }
    None
}

fn write_stage(dir: &std::path::Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    match std::fs::write(&path, bytes) {
        Ok(()) => println!("Dumped: {} ({} bytes)", path.display(), bytes.len()),
        Err(e) => eprintln!("WARNING: could not write {}: {e}", path.display()),
    }
}

fn main() {
    let dump = dump_dir();
    if let Some(dir) = &dump {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("ERROR: could not create {}: {e}", dir.display());
            std::process::exit(3);
        }
    }

    println!("Fixture: frustracean-testbed (benign; every recovered value is invalid by design)");
    println!("Packed blob: {} bytes", testbed::STAGE1_BLOB.len());
    println!(
        "Packed entropy: {:.2} bits/byte",
        testbed::entropy(&testbed::STAGE1_BLOB)
    );

    if let Some(dir) = &dump {
        write_stage(dir, "stage0-packed.bin", &testbed::STAGE1_BLOB);
    }

    let mut staged = testbed::STAGE1_BLOB.to_vec();
    testbed::stage1_decrypt(&testbed::STAGE1_KEY, &mut staged);
    println!("Stage 1: decrypted in place, {} bytes", staged.len());
    println!(
        "Stage 1 entropy: {:.2} bits/byte",
        testbed::entropy(&staged)
    );
    if let Some(dir) = &dump {
        write_stage(dir, "stage1-decrypted.bin", &staged);
    }

    let mut expanded = vec![0u8; testbed::EXPANDED_LEN];
    let written = testbed::stage2_expand(&staged, &mut expanded);
    expanded.truncate(written);
    println!("Stage 2: expanded to {} bytes", expanded.len());
    println!(
        "Stage 2 entropy: {:.2} bits/byte",
        testbed::entropy(&expanded)
    );
    if let Some(dir) = &dump {
        write_stage(dir, "stage2-expanded.bin", &expanded);
    }

    match String::from_utf8(expanded) {
        Ok(text) => {
            println!();
            println!("Recovered configuration");
            for line in text.lines().take(12) {
                println!("  {line}");
            }
            let total = text.lines().count();
            if total > 12 {
                println!("  ... {} more line(s)", total - 12);
            }
            println!();
            println!("OK: chain completed, {} bytes recovered", text.len());
        }
        Err(_) => {
            eprintln!("ERROR: the recovered payload was not valid UTF-8");
            std::process::exit(3);
        }
    }
}
