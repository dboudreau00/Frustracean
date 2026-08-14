//! Crafted images that must not crash the tool.
//!
//! The threat model is specific: an analyst runs Frustracean on a sample built
//! by someone who knows Frustracean exists. Every header field is therefore
//! attacker-controlled, and a panic on a malformed image is a denial of service
//! against the analyst at exactly the moment they need the tool.
//!
//! Every fixture here is a real, structurally valid PE or ELF that goblin
//! accepts - the interesting failures are in what Frustracean does *after*
//! parsing succeeds, not in the parser.
//!
//! Each test corresponds to a defect that was live in this code and is now
//! fixed. They are regression tests, not hypotheticals.

use frustracean_core::binary::Image;
use frustracean_core::entropy::{self, MapOptions};

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

fn w16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn w32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn w64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// One 64-byte ELF section header.
#[allow(clippy::too_many_arguments)]
fn shdr(name: u32, typ: u32, flags: u64, addr: u64, off: u64, size: u64, align: u64) -> Vec<u8> {
    let mut v = Vec::new();
    w32(&mut v, name);
    w32(&mut v, typ);
    w64(&mut v, flags);
    w64(&mut v, addr);
    w64(&mut v, off);
    w64(&mut v, size);
    w32(&mut v, 0); // link
    w32(&mut v, 0); // info
    w64(&mut v, align);
    w64(&mut v, 0); // entsize
    assert_eq!(v.len(), 64);
    v
}

/// One 56-byte ELF program header.
fn phdr(
    typ: u32,
    flags: u32,
    off: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
) -> Vec<u8> {
    let mut v = Vec::new();
    w32(&mut v, typ);
    w32(&mut v, flags);
    w64(&mut v, off);
    w64(&mut v, vaddr);
    w64(&mut v, vaddr); // paddr
    w64(&mut v, filesz);
    w64(&mut v, memsz);
    w64(&mut v, align);
    assert_eq!(v.len(), 56);
    v
}

/// ELF64 whose one allocated section declares `sh_size == u64::MAX`.
fn elf_with_absurd_section_size() -> Vec<u8> {
    let strtab: &[u8] = b"\0.shstrtab\0.text\0";
    let shoff = 64u64;
    let stroff = shoff + 3 * 64;

    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    w16(&mut f, 2); // ET_EXEC
    w16(&mut f, 0x3e); // x86-64
    w32(&mut f, 1);
    w64(&mut f, 0x1000); // entry
    w64(&mut f, 0); // phoff
    w64(&mut f, shoff);
    w32(&mut f, 0);
    w16(&mut f, 64); // ehsize
    w16(&mut f, 56); // phentsize
    w16(&mut f, 0); // phnum
    w16(&mut f, 64); // shentsize
    w16(&mut f, 3); // shnum
    w16(&mut f, 1); // shstrndx
    assert_eq!(f.len(), 64);

    f.extend(shdr(0, 0, 0, 0, 0, 0, 0));
    f.extend(shdr(1, 3, 0, 0, stroff, strtab.len() as u64, 1));
    f.extend(shdr(11, 1, 0x2 | 0x4, 0x1000, 0x40, u64::MAX, 1));
    f.extend_from_slice(strtab);
    while f.len() < 0x800 {
        f.push(0x41);
    }
    f
}

/// A position-independent ELF: load base 0, `.interp` well above it.
fn pie_elf() -> Vec<u8> {
    let strtab: &[u8] = b"\0.shstrtab\0.interp\0.text\0";
    let phoff = 64u64;
    let shoff = phoff + 56;
    let stroff = shoff + 4 * 64;

    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    w16(&mut f, 3); // ET_DYN
    w16(&mut f, 0x3e);
    w32(&mut f, 1);
    w64(&mut f, 0x1000); // entry
    w64(&mut f, phoff);
    w64(&mut f, shoff);
    w32(&mut f, 0);
    w16(&mut f, 64);
    w16(&mut f, 56);
    w16(&mut f, 1); // one PT_LOAD
    w16(&mut f, 64);
    w16(&mut f, 4);
    w16(&mut f, 1);
    assert_eq!(f.len(), 64);

    // PT_LOAD covering the image from vaddr 0.
    f.extend(phdr(1, 5, 0, 0, 0x1100, 0x1100, 0x1000));
    f.extend(shdr(0, 0, 0, 0, 0, 0, 0));
    f.extend(shdr(1, 3, 0, 0, stroff, strtab.len() as u64, 1));
    f.extend(shdr(11, 1, 0x2, 0x318, 0x318, 0x1c, 1)); // .interp
    f.extend(shdr(19, 1, 0x2 | 0x4, 0x1000, 0x1000, 0x100, 16)); // .text
    f.extend_from_slice(strtab);
    while f.len() < 0x1100 {
        f.push(0x90);
    }
    f
}

/// One PE section header, as the builder below takes it:
/// `(name, virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data, characteristics)`.
type SectionSpec<'a> = (&'a [u8; 8], u32, u32, u32, u32, u32);

/// Minimal PE32+ skeleton around the given section headers.
fn pe(sections: &[SectionSpec<'_>], image_base: u64, size: usize) -> Vec<u8> {
    let mut f = vec![0u8; size];
    f[0] = b'M';
    f[1] = b'Z';
    f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe_off = 0x80usize;
    f[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_off + 4;
    f[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    f[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    f[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
    f[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
    let opt = coff + 20;
    f[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    f[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry rva
    f[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
    f[opt + 32..opt + 36].copy_from_slice(&0x200u32.to_le_bytes()); // section align
    f[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
    f[opt + 56..opt + 60].copy_from_slice(&0x8000u32.to_le_bytes()); // size of image
    f[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
    f[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem
    f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    let mut cur = opt + 240;
    for (name, vsize, vaddr, raw_size, raw_ptr, chars) in sections {
        f[cur..cur + 8].copy_from_slice(*name);
        f[cur + 8..cur + 12].copy_from_slice(&vsize.to_le_bytes());
        f[cur + 12..cur + 16].copy_from_slice(&vaddr.to_le_bytes());
        f[cur + 16..cur + 20].copy_from_slice(&raw_size.to_le_bytes());
        f[cur + 20..cur + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        f[cur + 36..cur + 40].copy_from_slice(&chars.to_le_bytes());
        cur += 40;
    }
    f
}

const EXEC_READ: u32 = 0x6000_0020;
const DATA_READ: u32 = 0x4000_0040;

// ---------------------------------------------------------------------------
// Regressions
// ---------------------------------------------------------------------------

#[test]
fn a_section_size_of_u64_max_does_not_overflow_offset_lookups() {
    let img = Image::parse(elf_with_absurd_section_size(), "evil.elf").expect("valid ELF");

    // Each of these used to compute `file_offset + file_size` and panic.
    assert!(img.section_at_offset(0x40).is_some());
    assert!(img.va_to_offset(0x1000).is_some());
    assert!(img.bytes_at_va(0x1000, 32).is_some());

    // And the whole entropy pipeline must survive it.
    let mut windows = entropy::sweep(&img.data, &MapOptions::default());
    img.annotate(&mut windows);
    assert!(!windows.is_empty());
}

#[test]
fn an_image_base_near_the_top_of_the_address_space_does_not_overflow() {
    // ImageBase 0xffff_ffff_ffff_f000 plus a section RVA of 0x2000 wraps.
    let data = pe(
        &[(b".text\0\0\0", 0x200, 0x2000, 0x200, 0x200, EXEC_READ)],
        0xffff_ffff_ffff_f000,
        0x400,
    );
    let img = Image::parse(data, "evil.exe").expect("valid PE");
    assert_eq!(img.image_base, 0xffff_ffff_ffff_f000);
    // Saturated rather than wrapped: the address is nonsense either way, but it
    // must not be a *small* nonsense address that looks legitimate.
    assert_eq!(img.sections[0].va, u64::MAX);
    assert_eq!(img.entry_va, u64::MAX);
    assert!(img.va_to_offset(0).is_none());
}

#[test]
fn a_raw_size_larger_than_the_virtual_size_does_not_swallow_the_next_section() {
    // `.text` declares VirtualSize 0x100 but SizeOfRawData 0x400. Treating the
    // larger of the two as its address-space span made it cover `.rdata`, so
    // every lookup in `.rdata` resolved to the wrong file offset and returned
    // the wrong bytes.
    let mut data = pe(
        &[
            (b".text\0\0\0", 0x100, 0x200, 0x400, 0x200, EXEC_READ),
            (b".rdata\0\0", 0x200, 0x400, 0x200, 0x600, DATA_READ),
        ],
        0x0040_0000,
        0x800,
    );
    data[0x200..0x600].fill(0xcc);
    data[0x600..0x800].fill(0xaa);

    let img = Image::parse(data, "overlap.exe").expect("valid PE");
    let rdata_va = 0x0040_0400u64;

    assert_eq!(
        img.section_at_va(rdata_va).map(|s| s.name.as_str()),
        Some(".rdata"),
        "the address belongs to .rdata, whatever .text's raw size says"
    );
    assert_eq!(img.va_to_offset(rdata_va), Some(0x600));
    assert_eq!(
        img.bytes_at_va(rdata_va, 4),
        Some(&[0xaa, 0xaa, 0xaa, 0xaa][..])
    );
}

#[test]
fn a_section_with_no_virtual_size_falls_back_to_its_raw_size() {
    // Packers routinely leave VirtualSize at zero. Such a section still owns
    // address space, and must still be found.
    let data = pe(
        &[(b".packed\0", 0, 0x200, 0x400, 0x200, EXEC_READ)],
        0x0040_0000,
        0x800,
    );
    let img = Image::parse(data, "packed.exe").expect("valid PE");
    assert_eq!(
        img.section_at_va(0x0040_0300).map(|s| s.name.as_str()),
        Some(".packed")
    );
}

#[test]
fn a_pie_elf_reports_a_load_base_of_zero() {
    // Taking the lowest allocated *section* address gives 0x318 (`.interp`),
    // which makes every RVA in a plan off by that much - and the payload then
    // rebases every hook to the wrong address at runtime.
    let img = Image::parse(pie_elf(), "pie.elf").expect("valid ELF");
    assert_eq!(img.image_base, 0, "a PIE binary loads at base 0");
    assert_eq!(img.entry_va, 0x1000);
    assert_eq!(
        img.entry_va.saturating_sub(img.image_base),
        0x1000,
        "the entry RVA a plan would record"
    );
}

#[test]
fn a_symbol_pointing_into_read_only_data_is_never_hooked() {
    use frustracean_core::disasm::CodeIndex;
    use frustracean_core::plan::{self, PlanOptions};
    use frustracean_core::signature::SignatureSet;

    // `.rdata` holding bytes that happen to decode as a textbook prologue:
    //   mov [rsp+8], rbx ; push rdi ; sub rsp, 0x20
    // Prologue analysis alone approves this, because constant data decodes into
    // plausible instructions more often than is comfortable.
    let mut data = pe(
        &[
            (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, EXEC_READ),
            (b".rdata\0\0", 0x200, 0x2000, 0x200, 0x400, DATA_READ),
        ],
        0,
        0x800,
    );
    data[0x400..0x40a]
        .copy_from_slice(&[0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20]);

    let mut img = Image::parse(data, "rdata-symbol.exe").expect("valid PE");
    img.symbols.push(frustracean_core::binary::Symbol {
        name: "decrypt_me".into(),
        demangled: Some("evil::decrypt".into()),
        crate_name: None,
        va: 0x2000,
        size: 0,
        source: frustracean_core::binary::SymbolSource::ElfDynsym,
    });

    let sigs = SignatureSet::parse(
        "version: 1\nrules:\n  - id: t.sym\n    match: {demangled_regex: 'evil::decrypt'}\n\
         \n    abi:\n      args: [{name: buf, kind: slice_mut}]\n    capture: {dump: [buf]}\n",
    )
    .expect("catalogue should load");
    let index = CodeIndex::build(&img);
    let p = plan::build(&img, &sigs, &index, &PlanOptions::default());

    assert!(
        p.targets.is_empty(),
        "a data address must not become a hook site"
    );
    assert_eq!(p.skipped.len(), 1, "and the refusal must be recorded");
    assert!(
        p.skipped[0]
            .reasons
            .iter()
            .any(|r| r.contains("not executable")),
        "got {:?}",
        p.skipped[0].reasons
    );
}

#[test]
fn one_function_named_by_two_symbol_tables_is_planned_once() {
    use frustracean_core::binary::{Symbol, SymbolSource};
    use frustracean_core::disasm::CodeIndex;
    use frustracean_core::plan::{self, PlanOptions};
    use frustracean_core::signature::SignatureSet;

    let mut data = pe(
        &[(b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, EXEC_READ)],
        0,
        0x400,
    );
    data[0x200..0x20a]
        .copy_from_slice(&[0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20]);

    let mut img = Image::parse(data, "twonames.exe").expect("valid PE");
    // What an export table plus a COFF table produce for a single function.
    for (name, source) in [
        ("decrypt", SymbolSource::Export),
        ("_decrypt", SymbolSource::CoffTable),
    ] {
        img.symbols.push(Symbol {
            name: name.into(),
            demangled: Some("evil::decrypt".into()),
            crate_name: None,
            va: 0x1000,
            size: 0,
            source,
        });
    }

    let sigs = SignatureSet::parse(
        "version: 1\nrules:\n  - id: t.sym\n    match: {demangled_regex: 'evil::decrypt'}\n\
         \n    abi:\n      args: [{name: buf, kind: slice_mut}]\n    capture: {dump: [buf]}\n",
    )
    .expect("catalogue should load");
    let index = CodeIndex::build(&img);
    let p = plan::build(&img, &sigs, &index, &PlanOptions::default());

    assert_eq!(p.targets.len(), 1);
    assert!(
        p.skipped.is_empty(),
        "the same function under two names is not a coverage gap: {:?}",
        p.skipped
    );
}

#[test]
fn thousands_of_sections_mapping_one_range_collapse_to_one() {
    // Nothing in either format forbids duplicate headers over the same bytes.
    // Left alone, every per-section sweep in the tool repeats its work once per
    // header, so a few hundred headers over an 8 MB file becomes gigabytes of
    // hashing and the tool appears to hang.
    let count = 400usize;
    let mut headers = Vec::new();
    for _ in 0..count {
        headers.push((
            b".dup\0\0\0\0",
            0x200u32,
            0x1000u32,
            0x200u32,
            0x200u32,
            DATA_READ,
        ));
    }
    let refs: Vec<SectionSpec<'_>> = headers
        .iter()
        .map(|(n, a, b, c, d, e)| (*n, *a, *b, *c, *d, *e))
        .collect();
    let data = pe(&refs, 0x0040_0000, 0x8000);
    let img = Image::parse(data, "dup.exe").expect("valid PE");
    assert_eq!(
        img.sections.len(),
        1,
        "identical file ranges must collapse, got {}",
        img.sections.len()
    );
}

#[test]
fn a_section_count_beyond_the_cap_is_truncated_rather_than_ingested() {
    // Distinct ranges cannot be deduplicated, so the count itself is capped.
    let mut headers = Vec::new();
    for i in 0..700u32 {
        headers.push((
            b"s\0\0\0\0\0\0\0",
            0x10u32,
            0x1000 + i * 0x10,
            0x10u32,
            0x200 + i * 0x10,
            DATA_READ,
        ));
    }
    let refs: Vec<SectionSpec<'_>> = headers
        .iter()
        .map(|(n, a, b, c, d, e)| (*n, *a, *b, *c, *d, *e))
        .collect();
    let data = pe(&refs, 0x0040_0000, 0x8000);
    let img = Image::parse(data, "many.exe").expect("valid PE");
    assert!(
        img.sections.len() <= frustracean_core::binary::limits::MAX_SECTIONS,
        "got {} sections",
        img.sections.len()
    );
}

#[test]
fn a_string_anchor_near_the_top_of_the_address_space_does_not_invert_a_range() {
    // `hit_va + needle.len()` wrapping produces `lo > hi`, and BTreeMap::range
    // panics on an inverted range in *release* builds too - unlike an
    // arithmetic overflow, which only aborts in debug.
    use frustracean_core::disasm::CodeIndex;
    use frustracean_core::plan::{self, PlanOptions};
    use frustracean_core::signature::SignatureSet;

    let mut data = pe(
        &[
            (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, EXEC_READ),
            (b".rdata\0\0", 0x200, 0x2000, 0x200, 0x400, DATA_READ),
        ],
        // Places .rdata's contents within a few bytes of u64::MAX.
        0xffff_ffff_ffff_e000,
        0x800,
    );
    data[0x400..0x40a].copy_from_slice(b"ANCHOR_XYZ");

    let img = Image::parse(data, "wrap.exe").expect("valid PE");
    let sigs = SignatureSet::parse(
        "version: 1\nrules:\n  - id: t.s\n    match:\n      strings: [\"ANCHOR_XYZ\"]\n\
         \n    abi:\n      args: [{name: buf, kind: slice_mut}]\n    capture: {dump: [buf]}\n",
    )
    .expect("catalogue should load");
    let index = CodeIndex::build(&img);
    // The assertion is simply that this returns at all.
    let _ = plan::build(&img, &sigs, &index, &PlanOptions::default());
}

#[test]
fn an_empty_file_is_rejected_rather_than_parsed() {
    assert!(Image::parse(Vec::new(), "empty").is_err());
}

#[test]
fn a_truncated_pe_header_is_rejected_rather_than_parsed() {
    let mut data = vec![0u8; 0x40];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3c..0x40].copy_from_slice(&0x1000u32.to_le_bytes());
    assert!(Image::parse(data, "truncated.exe").is_err());
}
