// A tiny keystream generator, shared verbatim between `build.rs` and the crate.
//
// `build.rs` includes this file directly rather than depending on the crate, so
// the bytes baked into the binary at compile time and the bytes produced at
// runtime cannot drift apart. If they ever did, the testbed would silently
// "unpack" to garbage and every entropy measurement taken from it would be a lie.
//
// This is xorshift64* keyed by a seed. It is *not* cryptography and is not
// pretending to be: the point is to produce output that is statistically flat
// enough to sit at ~7.99 bits/byte, so the tool under test sees a genuinely
// opaque blob rather than a synthetic one.
//
// Note the comment style. Inner doc comments (`//!`) are illegal at the point
// where `build.rs` includes this file, so the header has to be plain comments;
// the module-level documentation lives on the `mod` declaration in lib.rs.

/// Fold a key and a domain-separating tag into a 64-bit seed.
///
/// The tag matters for more than domain separation. Mixing it in forces the
/// compiler to emit a real reference to the tag constant from inside the calling
/// function, which is exactly the RIP-relative cross-reference the planner
/// follows when it has no symbols to work with. A tag that were merely compared
/// or unused could be constant-folded away, and the string-anchor path would
/// have nothing to find.
pub fn seed(key: &[u8], tag: &[u8]) -> u64 {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for &b in key {
        state ^= u64::from(b);
        state = state.wrapping_mul(0x0100_0000_01b3);
        state = state.rotate_left(17);
    }
    for &b in tag {
        state ^= u64::from(b).wrapping_shl(8);
        state = state.wrapping_mul(0x0100_0000_01b3);
        state = state.rotate_left(29);
    }
    // xorshift64* jams on a zero state.
    if state == 0 {
        0xdead_beef_cafe_f00d
    } else {
        state
    }
}

pub struct Keystream {
    state: u64,
}

impl Keystream {
    pub fn new(key: &[u8], tag: &[u8]) -> Keystream {
        Keystream {
            state: seed(key, tag),
        }
    }

    pub fn next_byte(&mut self) -> u8 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8
    }

    /// XOR the keystream over a buffer. Symmetric: the same call encrypts and
    /// decrypts, which is why the testbed only needs one implementation.
    pub fn apply(&mut self, buffer: &mut [u8]) {
        for byte in buffer.iter_mut() {
            *byte ^= self.next_byte();
        }
    }
}

/// Run-length encoding, byte oriented.
///
/// Format: `0x00 <count> <byte>` encodes a run of `count` (2..=255) copies of
/// `byte`; any other byte is a literal; a literal `0x00` is escaped as
/// `0x00 0x00`. Chosen because it is small enough to read in one sitting and
/// because it produces the middling entropy of a real compressor's output,
/// which is what makes the chi-square corroborator worth testing against.
pub fn rle_compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        let mut run = 1usize;
        while i + run < input.len() && input[i + run] == b && run < 255 {
            run += 1;
        }
        if run >= 3 {
            out.push(0x00);
            out.push(run as u8);
            out.push(b);
            i += run;
        } else {
            for _ in 0..run {
                out.push(b);
                if b == 0x00 {
                    out.push(0x00);
                }
            }
            i += run;
        }
    }
    out
}

/// Decode the format above. Returns the number of bytes written, or `None` if
/// the stream is malformed or the output buffer is too small.
///
/// Written to be total rather than convenient: this is the function Frustracean
/// hooks, so it must behave predictably when handed the wrong bytes.
pub fn rle_expand(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut written = 0usize;
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        if b != 0x00 {
            *output.get_mut(written)? = b;
            written += 1;
            i += 1;
            continue;
        }
        let count = *input.get(i + 1)?;
        if count == 0x00 {
            // An escaped literal zero.
            *output.get_mut(written)? = 0x00;
            written += 1;
            i += 2;
            continue;
        }
        let value = *input.get(i + 2)?;
        for _ in 0..count {
            *output.get_mut(written)? = value;
            written += 1;
        }
        i += 3;
    }
    Some(written)
}
