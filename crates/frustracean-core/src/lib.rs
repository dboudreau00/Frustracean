//! Frustracean core: Rust-aware static triage and call-hijack planning.
//!
//! The crate is split so the injected payload can reuse the wire types and the
//! entropy math without dragging in a binary parser or a disassembler. Anything
//! that needs to *read a file on disk* lives behind the `analysis` feature.
//!
//! Pipeline, in the order the CLI drives it:
//!
//! ```text
//!   image -> [binary]  parse sections/symbols, VA<->offset
//!         -> [rustid]  is this Rust? which rustc? which crates?
//!         -> [entropy] windowed map, regions, classification
//!         -> [plan]    signatures x symbols x prologues = HijackPlan
//!         -> [trace]   (runtime) hook fires, buffers captured
//!         -> [report]  entropy deltas -> recovered blobs
//! ```

// Always available, including to the injected payload: the wire types, the
// entropy math, and the correlation that reads them back.
pub mod binary;
pub mod entropy;
pub mod error;
pub mod plan;
pub mod report;
pub mod signature;
pub mod trace;

// Static analysis only. These pull in a binary parser, a disassembler, and a
// regex engine, none of which belong in a DLL loaded into a live sample.
#[cfg(feature = "analysis")]
pub mod disasm;
#[cfg(feature = "analysis")]
pub mod rustid;
#[cfg(feature = "analysis")]
pub mod symbols;

pub use error::{Error, Result};

/// Hex-encode without pulling in a dependency for it.
pub fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0f) as usize] as char);
    }
    s
}

/// SHA-256 of a buffer, hex-encoded. Analysts pivot on these, so they are
/// recorded for every dumped blob.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_low_and_high_nibbles() {
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
    }

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256 of the empty string.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
