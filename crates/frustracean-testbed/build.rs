//! Bake the testbed's payload in at compile time.
//!
//! The plaintext lives here in source, readable. What ends up in the binary is
//! `encrypt(rle_compress(plaintext))` - a high-entropy blob with no readable
//! strings in it at all. That asymmetry is the entire point: an analyst looking
//! at the built binary sees only the opaque form, and has to make the program
//! decrypt it for them.

use std::io::Write;
use std::path::PathBuf;

// Shared verbatim with the crate so the compile-time and runtime halves cannot
// drift. See the module docs in keystream.rs.
include!("src/keystream.rs");

/// The stage 1 domain-separating tag. This is also the string anchor the
/// signature catalogue keys on, and it must match `src/lib.rs` byte for byte -
/// the blob is encrypted with it here and decrypted with it there.
///
/// Stage 2's tag has no compile-time role, so it lives only in `src/lib.rs`.
const STAGE1_TAG: &str = "FRUSTRACEAN_TESTBED::stage1/keystream-xor";

const KEY: &[u8] = b"frustracean-testbed-key-v1";

/// A deliberately fake configuration blob.
///
/// It is shaped like the sort of thing a loader carries - hosts, an interval, a
/// mutex name - so the recovered plaintext looks like a real finding in a report
/// and the entropy drop is representative. Every value is invalid on purpose:
/// the hosts are in RFC 2606 reserved domains and RFC 5737 documentation address
/// ranges, so nothing here can resolve or connect to anything.
fn plaintext() -> Vec<u8> {
    let mut s = String::new();
    s.push_str("################################################################\n");
    s.push_str("# FRUSTRACEAN TESTBED - BENIGN FIXTURE, NOT MALWARE            #\n");
    s.push_str("# Every value below is deliberately invalid. The hosts are in   #\n");
    s.push_str("# RFC 2606 reserved domains and RFC 5737 documentation ranges,  #\n");
    s.push_str("# so none of them resolve or route anywhere.                    #\n");
    s.push_str("################################################################\n\n");
    s.push_str("campaign      = \"testbed-demo\"\n");
    s.push_str("build         = \"0.1.0\"\n");
    s.push_str("mutex         = \"Global\\\\FrustraceanTestbedFixture\"\n");
    s.push_str("interval_secs = 900\n");
    s.push_str("jitter_pct    = 20\n\n");
    s.push_str("[endpoints]\n");
    for i in 1..=6 {
        s.push_str(&format!(
            "  primary_{i:02} = \"https://c2-{i:02}.example.invalid/gate.php\"\n"
        ));
    }
    for i in 1..=6 {
        s.push_str(&format!("  fallback_{i:02} = \"203.0.113.{i}:8443\"\n"));
    }
    s.push_str("\n[tasks]\n");
    for name in [
        "collect_host_info",
        "enumerate_processes",
        "screenshot",
        "keylog",
        "exfil_staged",
        "self_delete",
    ] {
        s.push_str(&format!("  {name} = false\n"));
    }
    // Long runs, so the RLE stage has real work to do. The two fillers below are
    // balanced against each other deliberately:
    //
    //   - the runs compress hard, which drags the *expanded* entropy down and
    //     gives stage 2 a drop large enough for the report to confirm it;
    //   - the base64 block does not compress at all, which keeps the *packed*
    //     blob large enough for `frustracean map` to resolve as a region rather
    //     than discard as noise.
    //
    // Remove either one and the fixture stops demonstrating half of what it is
    // for. The chain is asserted in the crate's tests so this cannot silently rot.
    s.push_str("\n[padding]\n");
    const FILL: &[u8] = b"=-_.#*+~^";
    for i in 0..520 {
        let ch = FILL[i % FILL.len()] as char;
        s.push_str("  ");
        for _ in 0..64 {
            s.push(ch);
        }
        s.push_str(&format!(" {i:04}\n"));
    }

    // A block of incompressible-looking base64. It is deterministic nonsense,
    // not a key of any kind, and it is here for a measurement reason: RLE cannot
    // shrink it, so it keeps the packed blob large enough that `frustracean map`
    // resolves it as a region rather than discarding it as noise.
    s.push_str("\n[signing]\n");
    s.push_str("  # Not a key. Deterministic filler, present so the packed blob\n");
    s.push_str("  # is large enough to show up as an entropy region.\n");
    s.push_str("  operator_blob = \"\"\"\n");
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state: u64 = 0x5eed_1234_9abc_def0;
    for _ in 0..96 {
        s.push_str("    ");
        for _ in 0..64 {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let idx = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 58) as usize;
            s.push(B64[idx & 63] as char);
        }
        s.push('\n');
    }
    s.push_str("  \"\"\"\n");

    s.push_str("\n# end of configuration\n");
    s.into_bytes()
}

fn emit_array(out: &mut String, name: &str, bytes: &[u8]) {
    out.push_str(&format!("pub const {name}: [u8; {}] = [\n", bytes.len()));
    for chunk in bytes.chunks(16) {
        out.push_str("    ");
        for b in chunk {
            out.push_str(&format!("0x{b:02x}, "));
        }
        out.push('\n');
    }
    out.push_str("];\n\n");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/keystream.rs");

    let plain = plaintext();
    let compressed = rle_compress(&plain);

    // Sanity-check the round trip at build time. A testbed that does not
    // actually round-trip would produce entropy measurements for a chain that
    // does not exist.
    let mut check = vec![0u8; plain.len()];
    let written = rle_expand(&compressed, &mut check)
        .expect("the testbed payload must round-trip through RLE");
    assert_eq!(written, plain.len(), "RLE round trip changed the length");
    assert_eq!(
        &check[..written],
        &plain[..],
        "RLE round trip changed the bytes"
    );

    let mut encrypted = compressed.clone();
    Keystream::new(KEY, STAGE1_TAG.as_bytes()).apply(&mut encrypted);

    let mut out = String::new();
    out.push_str("// Generated by build.rs. Do not edit.\n");
    out.push_str("//\n");
    out.push_str("// STAGE1_BLOB is encrypt(rle_compress(plaintext)); the plaintext itself\n");
    out.push_str("// appears nowhere in the compiled binary.\n\n");
    emit_array(&mut out, "STAGE1_BLOB", &encrypted);
    emit_array(&mut out, "STAGE1_KEY", KEY);
    out.push_str(&format!(
        "/// Length of the fully expanded plaintext.\npub const EXPANDED_LEN: usize = {};\n\n",
        plain.len()
    ));
    out.push_str(&format!(
        "/// Length of the intermediate, RLE-compressed stage.\npub const COMPRESSED_LEN: usize = {};\n",
        compressed.len()
    ));

    let dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let path = dir.join("payload.rs");
    let mut file = std::fs::File::create(&path).expect("could not create payload.rs");
    file.write_all(out.as_bytes())
        .expect("could not write payload.rs");
}
