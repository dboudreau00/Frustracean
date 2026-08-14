//! A benign sample that unpacks itself, for exercising Frustracean end to end.
//!
//! **This is a test fixture, not malware.** It carries an encrypted blob and
//! decrypts it in two stages, printing the result. It opens no files, makes no
//! network connections, spawns nothing, and touches no persistence. Every value
//! in the recovered configuration is deliberately invalid.
//!
//! It exists because the one unfinished piece of Frustracean - the detour stub -
//! cannot be brought up against real malware. You need a target whose correct
//! output you already know, so that when a hook fires you can tell the
//! difference between "captured the buffer" and "corrupted the process".
//!
//! # The chain
//!
//! ```text
//!   STAGE1_BLOB (~7.99 bits/byte, encrypted)
//!        |  stage1_decrypt(key, buffer)          <- in place
//!        v
//!   RLE-compressed bytes (~6 bits/byte)
//!        |  stage2_expand(input, output)         <- separate output buffer
//!        v
//!   plaintext configuration (~4.5 bits/byte)
//! ```
//!
//! Those two steps are deliberately different shapes, because they exercise
//! different halves of the report: stage 1 is an in-place transform whose
//! before/after is the *same* buffer, and stage 2 writes to a separate output,
//! which is the case that needs a rule-declared `compare: {from, to}`.
//!
//! # Two builds, two resolution paths
//!
//! The crate builds as both a `cdylib` and a binary. The DLL exports the
//! `testbed_*` shims below, so the planner resolves them by `symbol_regex`. The
//! executable is MSVC-linked and carries no symbol table whatsoever, so it can
//! only be resolved through the string anchors - which is the realistic case for
//! a stripped sample, and the path most worth testing.

/// Keystream generation and run-length coding, shared verbatim with `build.rs`.
///
/// The file is `include!`d by the build script rather than depended on, so the
/// bytes baked in at compile time and the bytes produced at runtime cannot drift
/// apart.
pub mod keystream;

pub use keystream::{rle_compress, rle_expand, Keystream};

// The payload, baked in at compile time. See build.rs.
include!(concat!(env!("OUT_DIR"), "/payload.rs"));

/// Domain-separating tags, and the string anchors the catalogue keys on.
///
/// `STAGE1_TAG` must match `build.rs` byte for byte: the blob is encrypted with
/// it there and decrypted with it here.
///
/// # Why these are passed through `black_box`
///
/// The first version of this fixture simply used the tags, and they did not
/// survive into the binary at all. With LTO on, rustc const-evaluated the entire
/// key schedule over a constant string and folded it into immediates - so the
/// anchors the catalogue keys on had been erased before the linker ran.
///
/// That is not an artefact of the fixture; it is the real limitation of
/// string-anchored resolution, and it is worth knowing. Anchors survive in real
/// samples because their references are *incidental* - a registry path embedded
/// in a panic `Location`, a message the formatter must be able to print - and
/// the compiler cannot fold away a value it has to be able to produce.
/// [`std::hint::black_box`] reproduces that property deliberately: it makes the
/// tag opaque to the optimiser, forcing a real RIP-relative reference from
/// inside the function that uses it. Which is exactly the cross-reference the
/// planner follows when there are no symbols.
pub const STAGE1_TAG: &str = "FRUSTRACEAN_TESTBED::stage1/keystream-xor";
pub const STAGE2_TAG: &str = "FRUSTRACEAN_TESTBED::stage2/rle-expand";

/// Stage 1: decrypt in place.
///
/// Signature chosen to mirror the shape Frustracean's rules describe for a real
/// in-place cipher: two `&[u8]`-class arguments, each a fat pointer occupying
/// two integer slots. Under the Win64 mapping that is
/// `key.ptr=rcx, key.len=rdx, buffer.ptr=r8, buffer.len=r9`.
#[inline(never)]
pub fn stage1_decrypt(key: &[u8], buffer: &mut [u8]) {
    // See STAGE1_TAG's documentation for why this goes through black_box.
    let tag = std::hint::black_box(STAGE1_TAG.as_bytes());
    let mut stream = Keystream::new(key, tag);
    stream.apply(buffer);
}

/// Stage 2: expand into a separate output buffer.
///
/// Returns the number of bytes written. The output buffer is *empty on entry*,
/// which is precisely why a rule for this function needs
/// `compare: {from: input, to: output}` - comparing `output` against itself
/// would measure the difference between zeroes and data, which is not a finding.
#[inline(never)]
pub fn stage2_expand(input: &[u8], output: &mut [u8]) -> usize {
    // Anchor the tag inside this function. See STAGE1_TAG's documentation.
    let tag = std::hint::black_box(STAGE2_TAG.as_bytes());
    std::hint::black_box(keystream::seed(tag, &[input.len() as u8]));

    rle_expand(input, output).unwrap_or(0)
}

/// Run the whole chain and return the recovered plaintext.
#[inline(never)]
pub fn unpack() -> Vec<u8> {
    let mut staged = STAGE1_BLOB.to_vec();
    stage1_decrypt(&STAGE1_KEY, &mut staged);

    let mut expanded = vec![0u8; EXPANDED_LEN];
    let written = stage2_expand(&staged, &mut expanded);
    expanded.truncate(written);
    expanded
}

/// Shannon entropy in bits per byte. Duplicated here rather than depended on, so
/// the testbed stays free of Frustracean itself and can be built and run
/// independently of the tool that measures it.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / len;
        h -= p * p.log2();
    }
    h
}

// ---------------------------------------------------------------------------
// C-ABI shims.
//
// These exist so the cdylib exports named symbols, giving the planner something
// to resolve by `symbol_regex`. The register layout matches the Rust functions
// above exactly - a `&[u8]` is a pointer and a length in adjacent slots either
// way - so a rule written against one describes the other.
// ---------------------------------------------------------------------------

/// # Safety
/// `key` must be valid for `key_len` bytes and `buffer` for `buffer_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn testbed_stage1_decrypt(
    key: *const u8,
    key_len: usize,
    buffer: *mut u8,
    buffer_len: usize,
) {
    if key.is_null() || buffer.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `key` is valid for `key_len` bytes and
    // `buffer` for `buffer_len` bytes, and the null cases are rejected above.
    // The two slices are handed to `stage1_decrypt`, which does not retain
    // them past the call, so no aliasing outlives this function.
    let (key, buffer) = unsafe {
        (
            std::slice::from_raw_parts(key, key_len),
            std::slice::from_raw_parts_mut(buffer, buffer_len),
        )
    };
    stage1_decrypt(key, buffer);
}

/// # Safety
/// `input` must be valid for `input_len` bytes and `output` for `output_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn testbed_stage2_expand(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> usize {
    if input.is_null() || output.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees `input` is valid for `input_len` bytes and
    // `output` for `output_len` bytes, and the null cases are rejected above.
    // The caller is also responsible for the two ranges not overlapping, which
    // is the contract of any decompress-into-a-separate-buffer function.
    let (input, output) = unsafe {
        (
            std::slice::from_raw_parts(input, input_len),
            std::slice::from_raw_parts_mut(output, output_len),
        )
    };
    stage2_expand(input, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chain_recovers_the_original_configuration() {
        let out = unpack();
        let text = String::from_utf8(out).expect("the fixture is UTF-8");
        assert!(text.contains("BENIGN FIXTURE"));
        assert!(text.contains("campaign      = \"testbed-demo\""));
        assert!(text.contains("example.invalid"));
        assert_eq!(text.len(), EXPANDED_LEN);
    }

    #[test]
    fn the_embedded_blob_is_genuinely_opaque() {
        // If this drops, the testbed has stopped being a useful subject: the
        // whole point is that the packed form is indistinguishable from noise.
        let h = entropy(&STAGE1_BLOB);
        assert!(h > 7.5, "embedded blob entropy was only {h:.2} bits/byte");
    }

    #[test]
    fn each_stage_lowers_the_entropy() {
        let mut staged = STAGE1_BLOB.to_vec();
        let packed = entropy(&staged);

        stage1_decrypt(&STAGE1_KEY, &mut staged);
        let compressed = entropy(&staged);

        let mut expanded = vec![0u8; EXPANDED_LEN];
        let written = stage2_expand(&staged, &mut expanded);
        expanded.truncate(written);
        let plain = entropy(&expanded);

        assert!(
            packed > compressed && compressed > plain,
            "expected a monotone entropy chain, got {packed:.2} -> {compressed:.2} -> {plain:.2}"
        );
        // Stage 1 must clear the bar `frustracean replay` uses to confirm a
        // transition: an input that was genuinely opaque, and at least a full
        // bit of drop. If a change to the fixture's filler quietly stops it
        // confirming, the testbed has stopped demonstrating what it exists for,
        // and this is where that is caught.
        assert!(packed >= 7.0, "stage 1 input was not opaque: {packed:.2}");
        assert!(
            packed - compressed >= 1.0,
            "stage 1 drop was only {:.2}; the report would not confirm it",
            packed - compressed
        );

        // Stage 2 is the opposite case, and deliberately so. Its entropy drops
        // by more than a bit, but its *input* was already readable text - the
        // plaintext was recoverable the moment stage 1 returned. The report
        // therefore reports the transition and declines to call it a confirmed
        // unpack, which is the behaviour worth having: a tool that counted this
        // as a recovery would inflate every chained sample's findings.
        assert!(
            compressed - plain >= 1.0,
            "stage 2 drop was only {:.2}",
            compressed - plain
        );
        assert!(
            compressed < 7.0,
            "stage 2's input became opaque ({compressed:.2}); the fixture no longer demonstrates \
             the unconfirmed case"
        );
    }

    #[test]
    fn the_packed_blob_is_large_enough_to_map_as_a_region() {
        // `frustracean map` discards runs shorter than its default minimum, so a
        // fixture whose blob shrank below that would silently stop appearing in
        // the entropy map.
        const DEFAULT_MIN_REGION: usize = 512;
        assert!(
            STAGE1_BLOB.len() > DEFAULT_MIN_REGION * 4,
            "packed blob is only {} bytes",
            STAGE1_BLOB.len()
        );
    }

    #[test]
    fn the_plaintext_appears_nowhere_in_the_packed_blob() {
        let needle = b"example.invalid";
        assert!(
            !STAGE1_BLOB.windows(needle.len()).any(|w| w == needle),
            "the packed blob leaks plaintext, which would defeat the fixture"
        );
    }

    #[test]
    fn the_keystream_is_symmetric() {
        let original = b"the same call encrypts and decrypts".to_vec();
        let mut buffer = original.clone();
        stage1_decrypt(b"k", &mut buffer);
        assert_ne!(buffer, original);
        stage1_decrypt(b"k", &mut buffer);
        assert_eq!(buffer, original);
    }

    #[test]
    fn expansion_refuses_to_overrun_a_short_output_buffer() {
        let compressed = rle_compress(&[0x41u8; 64]);
        let mut tiny = [0u8; 8];
        assert_eq!(rle_expand(&compressed, &mut tiny), None);
    }

    #[test]
    fn expansion_rejects_a_truncated_stream() {
        // A run header with no count or value following it.
        assert_eq!(rle_expand(&[0x00], &mut [0u8; 16]), None);
        assert_eq!(rle_expand(&[0x00, 0x05], &mut [0u8; 16]), None);
    }

    #[test]
    fn literal_zero_bytes_survive_the_round_trip() {
        let input = [0x00u8, 0x41, 0x00, 0x00, 0x42];
        let compressed = rle_compress(&input);
        let mut output = [0u8; 16];
        let n = rle_expand(&compressed, &mut output).unwrap();
        assert_eq!(&output[..n], &input);
    }

    #[test]
    fn the_c_shims_reject_null_pointers_instead_of_faulting() {
        // SAFETY: null pointers with zero lengths are exactly the case these
        // shims are documented to reject before dereferencing anything, which
        // is what this test exists to pin.
        unsafe {
            testbed_stage1_decrypt(std::ptr::null(), 0, std::ptr::null_mut(), 0);
            assert_eq!(
                testbed_stage2_expand(std::ptr::null(), 0, std::ptr::null_mut(), 0),
                0
            );
        }
    }
}
