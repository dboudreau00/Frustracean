//! Format-agnostic image model: sections, symbols, and address translation.
//!
//! Only what the rest of the pipeline needs. Frustracean is not a linker and
//! does not try to be a complete PE/ELF library; it needs to map addresses both
//! ways, know which bytes are executable, and enumerate whatever symbols the
//! sample was careless enough to leave behind.
//!
//! The descriptive types ([`Format`], [`Arch`], [`Abi`], [`Section`], [`Symbol`])
//! are always available because the hijack plan is written in terms of them.
//! [`Image`] and the parsers behind it need the `analysis` feature.

use serde::{Deserialize, Serialize};

#[cfg(feature = "analysis")]
use std::path::{Path, PathBuf};

#[cfg(feature = "analysis")]
use crate::error::{Error, Result};
#[cfg(feature = "analysis")]
use crate::symbols;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pe,
    Elf,
    MachO,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Pe => "PE",
            Format::Elf => "ELF",
            Format::MachO => "Mach-O",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X86_64,
    Aarch64,
    Other,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86-64",
            Arch::Aarch64 => "aarch64",
            Arch::Other => "other",
        }
    }

    /// Bitness for the disassembler, or `None` where we have no decoder.
    pub fn decoder_bitness(self) -> Option<u32> {
        match self {
            Arch::X86 => Some(32),
            Arch::X86_64 => Some(64),
            _ => None,
        }
    }
}

/// The calling convention a hijack plan must assume.
///
/// Rust's own `extern "Rust"` ABI is explicitly unstable, but in practice rustc
/// lowers integer and pointer arguments through the platform C ABI's integer
/// register sequence. Frustracean plans against that and records the assumption
/// so a wrong recovery is diagnosable rather than mysterious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Abi {
    Win64,
    SysV64,
    Cdecl32,
    Unknown,
}

impl Abi {
    pub fn label(self) -> &'static str {
        match self {
            Abi::Win64 => "win64",
            Abi::SysV64 => "sysv64",
            Abi::Cdecl32 => "cdecl32",
            Abi::Unknown => "unknown",
        }
    }

    /// Integer/pointer argument registers, in order. Empty means stack-only.
    pub fn arg_registers(self) -> &'static [&'static str] {
        match self {
            Abi::Win64 => &["rcx", "rdx", "r8", "r9"],
            Abi::SysV64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            _ => &[],
        }
    }

    /// Bytes of shadow space the caller reserves above the return address.
    pub fn shadow_space(self) -> u64 {
        match self {
            Abi::Win64 => 32,
            _ => 0,
        }
    }

    /// Width of one stack slot, which is also the width of the pushed return
    /// address that stack arguments are measured from.
    pub fn pointer_size(self) -> u64 {
        match self {
            Abi::Cdecl32 => 4,
            _ => 8,
        }
    }

    pub fn for_target(format: Format, arch: Arch) -> Abi {
        match (format, arch) {
            (Format::Pe, Arch::X86_64) => Abi::Win64,
            (Format::Pe, Arch::X86) => Abi::Cdecl32,
            (Format::Elf, Arch::X86_64) | (Format::MachO, Arch::X86_64) => Abi::SysV64,
            (Format::Elf, Arch::X86) => Abi::Cdecl32,
            _ => Abi::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub va: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub executable: bool,
    pub writable: bool,
    pub readable: bool,
}

impl Section {
    /// Bytes actually present in the file for this section.
    ///
    /// A section's virtual size routinely exceeds its raw size (BSS-like tails
    /// are zero-filled at load). Callers must not assume the two match.
    pub fn file_range(&self) -> std::ops::Range<usize> {
        // `try_from` rather than `as`: a hostile header can carry a 64-bit
        // offset that `as usize` would silently truncate into a valid-looking
        // small one, and reading the wrong bytes is worse than reading none.
        let start = usize::try_from(self.file_offset).unwrap_or(usize::MAX);
        let size = usize::try_from(self.file_size).unwrap_or(usize::MAX);
        start..start.saturating_add(size)
    }

    /// How many bytes of address space this section occupies once loaded.
    ///
    /// Virtual size wins when it is set. Some linkers - and most packers -
    /// leave `VirtualSize` at zero and rely on `SizeOfRawData`, so that is the
    /// fallback, but it must not be used as an *extension* of a section that
    /// declared its virtual size: a `.text` with `VirtualSize` 0x100 and
    /// `SizeOfRawData` 0x400 does not own the 0x300 bytes of address space
    /// belonging to whatever section follows it.
    pub fn virtual_span(&self) -> u64 {
        if self.virtual_size > 0 {
            self.virtual_size
        } else {
            self.file_size
        }
    }

    pub fn contains_va(&self, va: u64) -> bool {
        // Subtract rather than add: `self.va + span` overflows for a crafted
        // header, and the comparison below is exact either way.
        va >= self.va && va - self.va < self.virtual_span()
    }
}

/// Caps that bound the work a hostile image can demand.
///
/// None of these constrain a real binary: a large Rust executable has on the
/// order of tens of sections and tens of thousands of symbols, and no symbol
/// name approaches the length limit. They exist because every one of these
/// counts is a field in a header the sample's author controls, and unbounded
/// work driven by an attacker-controlled count is a denial of service against
/// the analyst.
pub mod limits {
    /// A PE's section count is a `u16` and an ELF's is bounded only by file
    /// size. Anything past this is a deliberately malformed image.
    pub const MAX_SECTIONS: usize = 512;
    /// Symbols are ingested into owned `String`s, so the count is a memory bound.
    pub const MAX_SYMBOLS: usize = 200_000;
    /// A symbol name is bounded only by the string table it points into.
    pub const MAX_SYMBOL_NAME: usize = 4096;
}

/// An exact function extent, recovered from unwind metadata rather than guessed.
///
/// This is the most valuable thing a stripped PE still carries. `strip` removes
/// symbols; it does not remove `.pdata`, because the loader needs it to unwind
/// exceptions. So a binary with no symbol table at all still tells you where
/// every function begins and ends - including the one that does the unpacking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRange {
    pub start_va: u64,
    pub end_va: u64,
}

impl FunctionRange {
    pub fn contains(&self, va: u64) -> bool {
        va >= self.start_va && va < self.end_va
    }

    pub fn len(&self) -> u64 {
        self.end_va.saturating_sub(self.start_va)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolSource {
    Export,
    CoffTable,
    ElfSymtab,
    ElfDynsym,
    /// Not a real symbol: a function start recovered from call-target analysis.
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    /// Demangled form when the name was Rust-mangled, else `None`.
    pub demangled: Option<String>,
    /// Owning crate, recovered from the demangled path.
    pub crate_name: Option<String>,
    pub va: u64,
    pub size: u64,
    pub source: SymbolSource,
}

impl Symbol {
    /// The name a signature rule should be matched against.
    pub fn match_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

/// A parsed executable image plus its raw bytes.
#[cfg(feature = "analysis")]
pub struct Image {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub format: Format,
    pub arch: Arch,
    pub bits: u32,
    pub image_base: u64,
    pub entry_va: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub sha256: String,
}

#[cfg(feature = "analysis")]
impl Image {
    pub fn load(path: impl AsRef<Path>) -> Result<Image> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
        Image::parse(data, path)
    }

    pub fn parse(data: Vec<u8>, path: impl AsRef<Path>) -> Result<Image> {
        let path = path.as_ref().to_path_buf();
        let sha256 = crate::sha256_hex(&data);
        let object = goblin::Object::parse(&data)?;
        match object {
            goblin::Object::PE(pe) => Ok(Self::from_pe(&pe, &data, path, sha256)),
            goblin::Object::Elf(elf) => Ok(Self::from_elf(&elf, &data, path, sha256)),
            goblin::Object::Mach(_) => Err(Error::UnsupportedFormat(
                "Mach-O is recognised but not yet supported".into(),
            )),
            goblin::Object::Archive(_) => Err(Error::UnsupportedFormat(
                "static archive, not an image".into(),
            )),
            other => Err(Error::UnsupportedFormat(format!("{other:?}"))),
        }
    }

    fn from_pe(pe: &goblin::pe::PE<'_>, data: &[u8], path: PathBuf, sha256: String) -> Image {
        use goblin::pe::section_table::{
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
        };

        let image_base = pe.image_base as u64;
        let arch = match pe.header.coff_header.machine {
            0x014c => Arch::X86,
            0x8664 => Arch::X86_64,
            0xaa64 => Arch::Aarch64,
            _ => Arch::Other,
        };

        let sections = pe
            .sections
            .iter()
            .take(limits::MAX_SECTIONS)
            .map(|s| {
                let name = s.name().map(str::to_string).unwrap_or_else(|_| {
                    String::from_utf8_lossy(&s.name)
                        .trim_end_matches('\0')
                        .to_string()
                });
                Section {
                    name,
                    // Saturating: a crafted `ImageBase` near u64::MAX plus a
                    // section RVA overflows, and an overflow panic on a
                    // malicious sample is a denial of service against the
                    // analyst.
                    va: image_base.saturating_add(u64::from(s.virtual_address)),
                    virtual_size: u64::from(s.virtual_size),
                    file_offset: u64::from(s.pointer_to_raw_data),
                    file_size: u64::from(s.size_of_raw_data),
                    executable: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                    writable: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    readable: s.characteristics & IMAGE_SCN_MEM_READ != 0,
                }
            })
            .collect::<Vec<_>>();
        let sections = dedupe_sections(sections);

        let mut symbols: Vec<Symbol> = pe
            .exports
            .iter()
            .take(limits::MAX_SYMBOLS)
            .filter_map(|e| {
                let name = e.name?;
                if name.len() > limits::MAX_SYMBOL_NAME {
                    return None;
                }
                Some(make_symbol(
                    name,
                    // Saturating for the same reason as the section VAs above:
                    // `ImageBase` is attacker-controlled and its sum with an
                    // export RVA overflows for a crafted header.
                    image_base.saturating_add(e.rva as u64),
                    e.size as u64,
                    SymbolSource::Export,
                ))
            })
            .collect();

        symbols.extend(pe_coff_symbols(pe, data, image_base));
        dedupe_symbols(&mut symbols);

        Image {
            path,
            data: data.to_vec(),
            format: Format::Pe,
            arch,
            bits: if pe.is_64 { 64 } else { 32 },
            image_base,
            entry_va: image_base.saturating_add(pe.entry as u64),
            sections,
            symbols,
            sha256,
        }
    }

    fn from_elf(elf: &goblin::elf::Elf<'_>, data: &[u8], path: PathBuf, sha256: String) -> Image {
        use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};

        let arch = match elf.header.e_machine {
            0x03 => Arch::X86,
            0x3e => Arch::X86_64,
            0xb7 => Arch::Aarch64,
            _ => Arch::Other,
        };

        let sections: Vec<Section> = elf
            .section_headers
            .iter()
            .filter(|sh| sh.sh_flags as u32 & SHF_ALLOC != 0)
            .take(limits::MAX_SECTIONS)
            .map(|sh| {
                let name = elf
                    .shdr_strtab
                    .get_at(sh.sh_name)
                    .unwrap_or("<unnamed>")
                    .to_string();
                let has_bits = sh.sh_type != SHT_NOBITS;
                Section {
                    name,
                    va: sh.sh_addr,
                    virtual_size: sh.sh_size,
                    file_offset: if has_bits { sh.sh_offset } else { 0 },
                    file_size: if has_bits { sh.sh_size } else { 0 },
                    executable: sh.sh_flags as u32 & SHF_EXECINSTR != 0,
                    writable: sh.sh_flags as u32 & SHF_WRITE != 0,
                    readable: true,
                }
            })
            .collect();

        // The load base comes from the program headers, not the sections.
        //
        // Using the lowest section address is wrong in the case that matters
        // most: a PIE binary loads at base 0, but its lowest *allocated section*
        // is typically `.interp` at something like 0x318. Deriving a base from
        // that makes every RVA in the plan off by 0x318, and the payload then
        // rebases every hook to the wrong address.
        //
        // The first PT_LOAD's `p_vaddr`, rounded down to its alignment, is the
        // definition the loader itself uses.
        let image_base = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|ph| {
                let align = ph.p_align.max(1);
                ph.p_vaddr - (ph.p_vaddr % align)
            })
            .min()
            .unwrap_or(0);

        let sections = dedupe_sections(sections);

        let mut symbols: Vec<Symbol> = Vec::new();
        for (table, source) in [
            (&elf.syms, SymbolSource::ElfSymtab),
            (&elf.dynsyms, SymbolSource::ElfDynsym),
        ] {
            let strtab = match source {
                SymbolSource::ElfDynsym => &elf.dynstrtab,
                _ => &elf.strtab,
            };
            for sym in table.iter() {
                if !sym.is_function() || sym.st_value == 0 {
                    continue;
                }
                let Some(name) = strtab.get_at(sym.st_name) else {
                    continue;
                };
                // Each symbol becomes an owned `String`, and both the count and
                // the name length are bounded only by the string table - which
                // is to say, by whatever the sample's author put there.
                if name.is_empty() || name.len() > limits::MAX_SYMBOL_NAME {
                    continue;
                }
                if symbols.len() >= limits::MAX_SYMBOLS {
                    break;
                }
                symbols.push(make_symbol(name, sym.st_value, sym.st_size, source));
            }
        }
        dedupe_symbols(&mut symbols);

        Image {
            path,
            data: data.to_vec(),
            format: Format::Elf,
            arch,
            bits: if elf.is_64 { 64 } else { 32 },
            image_base,
            entry_va: elf.entry,
            sections,
            symbols,
            sha256,
        }
    }

    pub fn abi(&self) -> Abi {
        Abi::for_target(self.format, self.arch)
    }

    pub fn section_at_va(&self, va: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_va(va))
    }

    pub fn section_at_offset(&self, offset: u64) -> Option<&Section> {
        self.sections.iter().find(|s| {
            s.file_size > 0 && offset >= s.file_offset && offset - s.file_offset < s.file_size
        })
    }

    /// Translate a virtual address to a file offset.
    ///
    /// Returns `None` for addresses inside a section's virtual tail, which has
    /// no bytes in the file - the caller must handle that rather than reading
    /// whatever happens to follow on disk.
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        let s = self.section_at_va(va)?;
        let delta = va.checked_sub(s.va)?;
        if delta >= s.file_size {
            return None;
        }
        s.file_offset.checked_add(delta)
    }

    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        let s = self.section_at_offset(offset)?;
        s.va.checked_add(offset.checked_sub(s.file_offset)?)
    }

    /// Read `len` bytes starting at a virtual address, clamped to what the file
    /// actually contains within that one section.
    pub fn bytes_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        let s = self.section_at_va(va)?;
        let delta = va.checked_sub(s.va)?;
        if delta >= s.file_size {
            return None;
        }
        let start = usize::try_from(s.file_offset.checked_add(delta)?).ok()?;
        let avail = usize::try_from(s.file_size - delta).unwrap_or(usize::MAX);
        let end = start.saturating_add(len.min(avail)).min(self.data.len());
        if start > end {
            return None;
        }
        self.data.get(start..end)
    }

    pub fn executable_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections
            .iter()
            .filter(|s| s.executable && s.file_size > 0)
    }

    /// Sections that hold constants. Rust string literals and embedded blobs
    /// live here, so this is where the entropy map earns its keep.
    pub fn data_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections
            .iter()
            .filter(|s| !s.executable && s.readable && s.file_size > 0)
    }

    /// Exact function extents from PE `.pdata`, if this image has any.
    ///
    /// `.pdata` on x86-64 is an array of `RUNTIME_FUNCTION`:
    /// `{ u32 BeginAddress; u32 EndAddress; u32 UnwindInfoAddress; }`, all RVAs,
    /// sorted ascending by `BeginAddress`.
    ///
    /// Records are validated as they are read, and the parse **stops** at the
    /// first one that fails rather than skipping it. A packer that stuffs junk
    /// into `.pdata` should yield a short honest list, not a long wrong one -
    /// and since these ranges are treated as authoritative downstream, a wrong
    /// entry is worse than a missing one.
    ///
    /// Returns empty for ELF, for 32-bit PE (where the record layout differs),
    /// and for any image without the section.
    pub fn pdata_functions(&self) -> Vec<FunctionRange> {
        const RECORD_LEN: usize = 12;

        if self.format != Format::Pe || self.arch != Arch::X86_64 {
            return Vec::new();
        }
        let Some(section) = self.sections.iter().find(|s| s.name == ".pdata") else {
            return Vec::new();
        };
        let range = section.file_range();
        let Some(raw) = self.data.get(range.start..range.end.min(self.data.len())) else {
            return Vec::new();
        };

        let mut out = Vec::with_capacity(raw.len() / RECORD_LEN);
        let mut last_begin = 0u32;
        for record in raw.chunks_exact(RECORD_LEN) {
            let begin = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
            let end = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);

            // The conventional terminator, and also what zero padding looks like.
            if begin == 0 && end == 0 {
                break;
            }
            // An empty or inverted range, or a break in the ascending order,
            // means this is no longer a real table.
            if end <= begin || begin < last_begin {
                break;
            }
            last_begin = begin;

            let (Some(start_va), Some(end_va)) = (
                self.image_base.checked_add(u64::from(begin)),
                self.image_base.checked_add(u64::from(end)),
            ) else {
                break;
            };
            out.push(FunctionRange { start_va, end_va });
        }
        out
    }

    /// Attribute each window of an entropy sweep to its owning section.
    pub fn annotate(&self, windows: &mut [crate::entropy::Window]) {
        for w in windows.iter_mut() {
            if let Some(s) = self.section_at_offset(w.offset) {
                w.section = Some(s.name.clone());
                w.va = w
                    .offset
                    .checked_sub(s.file_offset)
                    .and_then(|d| s.va.checked_add(d));
            }
        }
    }
}

#[cfg(feature = "analysis")]
fn make_symbol(raw: &str, va: u64, size: u64, source: SymbolSource) -> Symbol {
    // Both toolchains prepend an underscore on some targets; strip it before
    // asking the demangler, which expects the bare `_ZN`/`_R` form.
    let candidate = raw
        .strip_prefix('_')
        .filter(|s| s.starts_with("_Z") || s.starts_with("R"))
        .unwrap_or(raw);
    let demangled = symbols::demangle(candidate);
    let crate_name = demangled.as_deref().and_then(symbols::crate_of);
    Symbol {
        name: raw.to_string(),
        demangled,
        crate_name,
        va,
        size,
        source,
    }
}

/// Collapse sections that describe the same bytes.
///
/// Nothing in either format forbids two headers pointing at one file range, and
/// a sample can ship thousands that all map the whole file. Every per-section
/// sweep in the tool - `body_entropy`, the code index, the string search - then
/// does that much redundant work, which turns an 8 MB file into hundreds of
/// gigabytes of hashing. Deduplicating by file range at parse time bounds all of
/// them at once, and costs a real image nothing: its sections do not overlap.
///
/// Sections with no bytes on disk are kept regardless, since they carry address
/// space rather than content and cost nothing to sweep.
#[cfg(feature = "analysis")]
fn dedupe_sections(sections: Vec<Section>) -> Vec<Section> {
    let mut seen: std::collections::BTreeSet<(u64, u64)> = std::collections::BTreeSet::new();
    sections
        .into_iter()
        .filter(|s| s.file_size == 0 || seen.insert((s.file_offset, s.file_size)))
        .collect()
}

/// Keep one symbol per address, preferring the source that carries the most
/// information. Exports and symbol tables routinely name the same function.
#[cfg(feature = "analysis")]
fn dedupe_symbols(symbols: &mut Vec<Symbol>) {
    symbols.sort_by(|a, b| {
        a.va.cmp(&b.va)
            .then_with(|| b.demangled.is_some().cmp(&a.demangled.is_some()))
            .then_with(|| b.size.cmp(&a.size))
    });
    // Collapse an address that two tables named identically once demangled. An
    // export table and a COFF table routinely describe the same function with
    // decorated and undecorated names; keeping both makes the planner resolve
    // one and record the other as "already hooked", which reads like a coverage
    // gap when it is really the same function twice.
    symbols.dedup_by(|a, b| {
        a.va == b.va && (a.name == b.name || (a.demangled.is_some() && a.demangled == b.demangled))
    });
}

/// COFF symbol tables survive in PEs produced by the GNU toolchain
/// (`x86_64-pc-windows-gnu`), which is common enough in Rust malware to be
/// worth reading. MSVC-linked release builds will have none.
#[cfg(feature = "analysis")]
fn pe_coff_symbols(pe: &goblin::pe::PE<'_>, data: &[u8], image_base: u64) -> Vec<Symbol> {
    let header = &pe.header.coff_header;
    if header.pointer_to_symbol_table == 0 || header.number_of_symbol_table == 0 {
        return Vec::new();
    }
    // Both accessors return `Ok(None)` when the table is simply absent, which is
    // the norm for MSVC-linked images.
    let Ok(Some(table)) = header.symbols(data) else {
        return Vec::new();
    };
    let Ok(Some(strings)) = header.strings(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (_, inline_name, sym) in table.iter() {
        if !sym.is_function_definition() || sym.value == 0 {
            continue;
        }
        let name = match sym.name(&strings) {
            Ok(n) => n,
            Err(_) => match inline_name {
                Some(n) => n,
                None => continue,
            },
        };
        if name.is_empty() {
            continue;
        }
        // `section_number` is 1-based into the section table.
        let idx = sym.section_number as usize;
        let Some(section) = idx.checked_sub(1).and_then(|i| pe.sections.get(i)) else {
            continue;
        };
        if name.len() > limits::MAX_SYMBOL_NAME || out.len() >= limits::MAX_SYMBOLS {
            continue;
        }
        let va = image_base
            .saturating_add(u64::from(section.virtual_address))
            .saturating_add(u64::from(sym.value));
        out.push(make_symbol(name, va, 0, SymbolSource::CoffTable));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_follows_format_and_arch() {
        assert_eq!(Abi::for_target(Format::Pe, Arch::X86_64), Abi::Win64);
        assert_eq!(Abi::for_target(Format::Elf, Arch::X86_64), Abi::SysV64);
        assert_eq!(Abi::for_target(Format::Pe, Arch::Aarch64), Abi::Unknown);
    }

    #[test]
    fn win64_reserves_shadow_space_and_sysv_does_not() {
        assert_eq!(Abi::Win64.shadow_space(), 32);
        assert_eq!(Abi::SysV64.shadow_space(), 0);
        assert_eq!(Abi::Win64.arg_registers()[0], "rcx");
        assert_eq!(Abi::SysV64.arg_registers()[0], "rdi");
    }

    #[cfg(feature = "analysis")]
    fn section(name: &str, va: u64, vsize: u64, off: u64, fsize: u64) -> Section {
        Section {
            name: name.into(),
            va,
            virtual_size: vsize,
            file_offset: off,
            file_size: fsize,
            executable: false,
            writable: false,
            readable: true,
        }
    }

    #[cfg(feature = "analysis")]
    fn image_with(sections: Vec<Section>, data: Vec<u8>) -> Image {
        Image {
            path: std::path::PathBuf::from("test"),
            data,
            format: Format::Pe,
            arch: Arch::X86_64,
            bits: 64,
            image_base: 0x1_4000_0000,
            entry_va: 0x1_4000_1000,
            sections,
            symbols: Vec::new(),
            sha256: String::new(),
        }
    }

    #[cfg(feature = "analysis")]
    #[test]
    fn addresses_translate_both_ways() {
        let img = image_with(
            vec![section(".text", 0x1000, 0x200, 0x400, 0x200)],
            vec![0u8; 0x600],
        );
        assert_eq!(img.va_to_offset(0x1000), Some(0x400));
        assert_eq!(img.va_to_offset(0x10ff), Some(0x4ff));
        assert_eq!(img.offset_to_va(0x400), Some(0x1000));
        assert_eq!(img.va_to_offset(0x2000), None);
    }

    #[cfg(feature = "analysis")]
    #[test]
    fn a_virtual_tail_has_no_file_offset() {
        // 0x200 bytes of virtual size but only 0x100 on disk: the upper half is
        // zero-filled at load time and must not resolve to file bytes.
        let img = image_with(
            vec![section(".data", 0x1000, 0x200, 0x400, 0x100)],
            vec![0u8; 0x600],
        );
        assert_eq!(img.va_to_offset(0x1080), Some(0x480));
        assert_eq!(
            img.va_to_offset(0x1180),
            None,
            "virtual tail must not map to disk"
        );
    }

    #[cfg(feature = "analysis")]
    #[test]
    fn reads_are_clamped_to_the_owning_section() {
        let mut data = vec![0u8; 0x600];
        data[0x400..0x500].fill(0xaa);
        let img = image_with(vec![section(".rdata", 0x1000, 0x100, 0x400, 0x100)], data);
        let bytes = img.bytes_at_va(0x10f0, 0x100).unwrap();
        assert_eq!(
            bytes.len(),
            0x10,
            "must not read past the section into the next"
        );
        assert!(bytes.iter().all(|&b| b == 0xaa));
    }

    #[cfg(feature = "analysis")]
    #[test]
    fn windows_are_attributed_to_sections() {
        use crate::entropy::{sweep, MapOptions};
        let img = image_with(
            vec![section(".rdata", 0x2000, 0x400, 0x0, 0x400)],
            vec![0x41u8; 0x400],
        );
        let mut windows = sweep(
            &img.data,
            &MapOptions {
                window: 256,
                step: 256,
                ..Default::default()
            },
        );
        img.annotate(&mut windows);
        assert_eq!(windows[0].section.as_deref(), Some(".rdata"));
        assert_eq!(windows[1].va, Some(0x2100));
    }
}
