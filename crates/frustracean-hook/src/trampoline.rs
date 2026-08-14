//! Building the trampoline that lets a hooked function still run.
//!
//! Inline hooking replaces the first instructions of a function with a jump.
//! Those displaced ("stolen") instructions have to execute somewhere, and they
//! cannot simply be memcpy'd: a `lea rax, [rip+0x1234]` or a `jz +0x40` means
//! something different at a new address. So they are decoded, re-encoded at
//! their new home with iced-x86's block encoder - which recomputes every
//! relative displacement - and followed by a jump back into the middle of the
//! original function.
//!
//! ```text
//!   original                        trampoline (new allocation)
//!   +----------------------+        +--------------------------+
//!   | jmp detour  (5 B)    | -----> | stolen bytes, re-encoded |
//!   | ...stolen tail...    |        | jmp original+patch_len   | --+
//!   | rest of function     | <---------------------------------- -+
//!   +----------------------+        +--------------------------+
//! ```
//!
//! Everything in this module is pure byte manipulation and is unit tested on
//! the host; nothing here touches another process.

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction, InstructionBlock,
};

/// Length of a near `jmp rel32`.
pub const JMP_LEN: usize = 5;

/// x86-64 near jumps reach +/-2GB.
///
/// This constrains the **patch**, which is hand-encoded as a 5-byte `jmp rel32`
/// so it fits in a prologue: the detour has to be allocated within this window
/// of the hooked function. It does not constrain the trampoline's jump back -
/// that one goes through the block encoder, which promotes an unreachable
/// branch to a 14-byte `jmp [rip+N]` with the absolute target stored inline.
pub const NEAR_REACH: i64 = i32::MAX as i64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrampolineError {
    Decode(String),
    Encode(String),
    OutOfReach { from: u64, to: u64, delta: i64 },
    Empty,
}

impl std::fmt::Display for TrampolineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrampolineError::Decode(m) => write!(f, "could not decode the stolen bytes: {m}"),
            TrampolineError::Encode(m) => write!(f, "could not re-encode the stolen bytes: {m}"),
            TrampolineError::OutOfReach { from, to, delta } => write!(
                f,
                "a near jump from {from:#x} to {to:#x} needs a {delta} byte displacement, \
                 which does not fit in 32 bits"
            ),
            TrampolineError::Empty => write!(f, "no bytes to relocate"),
        }
    }
}

impl std::error::Error for TrampolineError {}

/// Encode a 5-byte near `jmp` from `from` to `to`.
///
/// The displacement is measured from the *end* of the jump instruction, which
/// is the single most commonly fumbled detail in hand-written patching.
pub fn encode_jmp_rel32(from: u64, to: u64) -> Result<[u8; JMP_LEN], TrampolineError> {
    let next = from.wrapping_add(JMP_LEN as u64);
    let delta = (to as i64).wrapping_sub(next as i64);
    // The conversion is the reach check: a displacement that does not fit in
    // 32 bits has no valid near encoding, and truncating it would produce a
    // jump to a plausible-looking wrong address.
    let Ok(rel) = i32::try_from(delta) else {
        return Err(TrampolineError::OutOfReach { from, to, delta });
    };
    let mut out = [0u8; JMP_LEN];
    out[0] = 0xe9;
    out[1..].copy_from_slice(&rel.to_le_bytes());
    Ok(out)
}

/// Decode `stolen` (read from `original_ip`) and re-encode it to run at
/// `new_ip`, followed by a jump back to `resume_ip`.
///
/// `new_ip` must be within near-jump reach of `resume_ip`.
pub fn build_trampoline(
    stolen: &[u8],
    original_ip: u64,
    new_ip: u64,
    resume_ip: u64,
    bitness: u32,
) -> Result<Vec<u8>, TrampolineError> {
    if stolen.is_empty() {
        return Err(TrampolineError::Empty);
    }

    let mut decoder = Decoder::with_ip(bitness, stolen, original_ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut consumed = 0usize;
    while decoder.can_decode() && consumed < stolen.len() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            return Err(TrampolineError::Decode(format!(
                "undecodable byte at {:#x}",
                instr.ip()
            )));
        }
        consumed += instr.len();
        instructions.push(instr);
    }
    if consumed != stolen.len() {
        return Err(TrampolineError::Decode(format!(
            "the stolen range does not end on an instruction boundary \
             ({consumed} decoded, {} given)",
            stolen.len()
        )));
    }

    // The jump back. `with_branch` records the absolute target; the block
    // encoder turns it into the right displacement for wherever the block lands.
    let jmp_back = Instruction::with_branch(
        if bitness == 64 {
            Code::Jmp_rel32_64
        } else {
            Code::Jmp_rel32_32
        },
        resume_ip,
    )
    .map_err(|e| TrampolineError::Encode(e.to_string()))?;
    instructions.push(jmp_back);

    let block = InstructionBlock::new(&instructions, new_ip);
    let encoded = BlockEncoder::encode(bitness, block, BlockEncoderOptions::NONE)
        .map_err(|e| TrampolineError::Encode(e.to_string()))?;
    Ok(encoded.code_buffer)
}

/// Is `to` reachable from `from` with a 5-byte near jump?
pub fn in_near_reach(from: u64, to: u64) -> bool {
    encode_jmp_rel32(from, to).is_ok()
}

/// The patch bytes to write over a function's prologue: a jump to the detour,
/// then `int3` fill for any stolen tail.
///
/// The fill matters. If the patch is 5 bytes but 8 were stolen, leaving the
/// original 3 bytes in place means a stray branch into them executes an
/// instruction fragment. `int3` turns that silent corruption into an immediate,
/// diagnosable fault.
pub fn build_patch(
    function_ip: u64,
    detour_ip: u64,
    patch_len: usize,
) -> Result<Vec<u8>, TrampolineError> {
    if patch_len < JMP_LEN {
        return Err(TrampolineError::Decode(format!(
            "patch_len {patch_len} is shorter than the {JMP_LEN} bytes a near jump needs"
        )));
    }
    let jmp = encode_jmp_rel32(function_ip, detour_ip)?;
    let mut out = Vec::with_capacity(patch_len);
    out.extend_from_slice(&jmp);
    out.resize(patch_len, 0xcc);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forward_jump_encodes_its_displacement_from_the_end_of_the_instruction() {
        // 0x1000 -> 0x1010: the instruction ends at 0x1005, so rel32 = 0x0b.
        let bytes = encode_jmp_rel32(0x1000, 0x1010).unwrap();
        assert_eq!(bytes, [0xe9, 0x0b, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn a_jump_to_the_next_instruction_encodes_as_zero() {
        assert_eq!(
            encode_jmp_rel32(0x1000, 0x1005).unwrap(),
            [0xe9, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_backward_jump_encodes_negative() {
        let bytes = encode_jmp_rel32(0x1005, 0x1000).unwrap();
        assert_eq!(bytes[0], 0xe9);
        assert_eq!(i32::from_le_bytes(bytes[1..].try_into().unwrap()), -10);
    }

    #[test]
    fn a_target_beyond_two_gigabytes_is_refused_rather_than_truncated() {
        let err = encode_jmp_rel32(0x1000, 0x1000 + 0x9000_0000).unwrap_err();
        assert!(matches!(err, TrampolineError::OutOfReach { .. }));
        assert!(!in_near_reach(0x1000, 0x1000 + 0x9000_0000));
        assert!(in_near_reach(0x1000, 0x1000 + 0x7000_0000));
    }

    #[test]
    fn the_reach_boundary_is_measured_from_the_end_of_the_jump() {
        // The displacement is (to - (from + 5)), so the furthest reachable
        // target is 5 bytes past what a naive (to - from) check would allow.
        // Getting this off by one is how a hook silently lands out of range.
        let from = 0x1000u64;
        assert!(in_near_reach(from, from + 5 + i32::MAX as u64));
        assert!(!in_near_reach(from, from + 6 + i32::MAX as u64));
    }

    #[test]
    fn stolen_bytes_without_displacements_are_copied_verbatim() {
        // 48 89 5c 24 08   mov [rsp+8], rbx
        let stolen = &[0x48, 0x89, 0x5c, 0x24, 0x08];
        let out = build_trampoline(stolen, 0x1000, 0x5000, 0x1005, 64).unwrap();
        assert_eq!(&out[..5], stolen, "no displacement, so nothing to change");
        // ...followed by a jump back to 0x1005 from 0x5005.
        assert_eq!(out[5], 0xe9);
        let rel = i32::from_le_bytes(out[6..10].try_into().unwrap());
        assert_eq!(0x5005i64 + 5 + i64::from(rel), 0x1005);
    }

    #[test]
    fn a_rip_relative_instruction_is_re_encoded_to_keep_its_target() {
        // 48 8d 05 f9 0f 00 00   lea rax, [rip+0xff9]  at 0x1000 -> targets 0x2000
        let stolen = &[0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00];
        let out = build_trampoline(stolen, 0x1000, 0x5000, 0x1007, 64).unwrap();

        // Decode what we produced and confirm it still points at 0x2000.
        let mut decoder = Decoder::with_ip(64, &out, 0x5000, DecoderOptions::NONE);
        let instr = decoder.decode();
        assert!(instr.is_ip_rel_memory_operand());
        assert_eq!(
            instr.ip_rel_memory_address(),
            0x2000,
            "the relocated lea must still reference the original address"
        );
    }

    #[test]
    fn a_relative_branch_is_re_encoded_to_keep_its_target() {
        // eb 08   jmp +8   at 0x1000 -> targets 0x100a
        // 90 90 90
        let stolen = &[0xeb, 0x08, 0x90, 0x90, 0x90];
        let out = build_trampoline(stolen, 0x1000, 0x5000, 0x1005, 64).unwrap();
        let mut decoder = Decoder::with_ip(64, &out, 0x5000, DecoderOptions::NONE);
        let instr = decoder.decode();
        assert_eq!(
            instr.near_branch_target(),
            0x100a,
            "the relocated branch must still reach into the original function"
        );
    }

    #[test]
    fn a_range_that_splits_an_instruction_is_refused() {
        // The `lea` is 7 bytes; handing over 5 of them must fail loudly.
        let stolen = &[0x48, 0x8d, 0x05, 0xf9, 0x0f];
        let err = build_trampoline(stolen, 0x1000, 0x5000, 0x1005, 64).unwrap_err();
        assert!(matches!(err, TrampolineError::Decode(_)), "{err}");
    }

    #[test]
    fn empty_stolen_bytes_are_refused() {
        assert_eq!(
            build_trampoline(&[], 0x1000, 0x5000, 0x1000, 64).unwrap_err(),
            TrampolineError::Empty
        );
    }

    #[test]
    fn an_unreachable_jump_back_is_promoted_to_an_absolute_indirect_jump() {
        // The jump back out of the trampoline is emitted by the block encoder,
        // which rewrites a `jmp rel32` it cannot reach into `jmp [rip+N]` with
        // the 64-bit target stored inline. That is why only the *patch* is
        // constrained to +/-2GB; the trampoline itself can live anywhere.
        let bytes = build_trampoline(&[0x90], 0x1000, 0x1000, 0x9000_0000_0000, 64)
            .expect("the encoder should promote rather than fail");
        assert!(
            bytes.windows(2).any(|w| w == [0xff, 0x25]),
            "expected an indirect jump, got {bytes:02x?}"
        );
        let target = 0x9000_0000_0000u64.to_le_bytes();
        assert!(
            bytes.windows(8).any(|w| w == target),
            "the absolute target must be stored verbatim, got {bytes:02x?}"
        );
    }

    #[test]
    fn a_reachable_jump_back_stays_a_five_byte_rel32() {
        let bytes = build_trampoline(&[0x90], 0x1000, 0x5000, 0x1001, 64).unwrap();
        assert_eq!(
            bytes.len(),
            6,
            "nop + jmp rel32, no promotion: {bytes:02x?}"
        );
        assert_eq!(bytes[1], 0xe9);
    }

    #[test]
    fn the_patch_pads_the_stolen_tail_with_int3() {
        let patch = build_patch(0x1000, 0x1010, 8).unwrap();
        assert_eq!(patch.len(), 8);
        assert_eq!(patch[0], 0xe9);
        assert_eq!(
            &patch[5..],
            &[0xcc, 0xcc, 0xcc],
            "the tail must trap, not drift"
        );
    }

    #[test]
    fn a_patch_shorter_than_a_jump_is_refused() {
        assert!(build_patch(0x1000, 0x1010, 4).is_err());
    }
}
