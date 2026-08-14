//! Rust symbol demangling and crate attribution.
//!
//! Two mangling schemes are in play. The legacy scheme wraps an Itanium-style
//! `_ZN...E` path and appends a `17h<16 hex digits>` disambiguator; the v0
//! scheme starts with `_R` and encodes generics properly. `rustc-demangle`
//! handles both, and the alternate formatter (`{:#}`) drops the trailing hash
//! so rules can be written against a stable name.

/// Demangle a Rust symbol, or `None` if it was not Rust-mangled.
pub fn demangle(name: &str) -> Option<String> {
    let d = rustc_demangle::try_demangle(name).ok()?;
    // `{:#}` suppresses the `::h<hash>` suffix on legacy symbols.
    let out = format!("{d:#}");
    if out == name {
        return None;
    }
    Some(out)
}

/// Which mangling scheme a symbol uses, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Legacy,
    V0,
    NotRust,
}

pub fn scheme_of(name: &str) -> Scheme {
    if rustc_demangle::try_demangle(name).is_err() {
        return Scheme::NotRust;
    }
    // Both schemes may carry an extra leading underscore on some targets.
    if name.starts_with("_R") || name.starts_with("__R") {
        Scheme::V0
    } else if name.starts_with("_ZN") || name.starts_with("__ZN") {
        Scheme::Legacy
    } else {
        Scheme::NotRust
    }
}

/// Recover the owning crate from a demangled path.
///
/// Handles the two shapes rustc emits:
///
/// * plain paths - `aes_gcm::AesGcm::decrypt` -> `aes_gcm`
/// * trait impls - `<aes_gcm::AesGcm<A> as aead::AeadInPlace>::decrypt` -> `aes_gcm`,
///   because the *implementing* type's crate is the one that owns the code, not
///   the crate that declared the trait.
///
/// Returns `None` when the leading type is primitive (`<[u8] as ...>`,
/// `<&str as ...>`), since no crate owns those.
pub fn crate_of(demangled: &str) -> Option<String> {
    let s = demangled.trim_start_matches('<').trim_start();

    // Reject primitives and references outright: they carry no crate.
    if s.starts_with('[') || s.starts_with('&') || s.starts_with('*') || s.starts_with('(') {
        return None;
    }

    let mut end = 0;
    for (i, c) in s.char_indices() {
        if c.is_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let head = &s[..end];

    // A bare identifier with no path separator after it is a local item, not a
    // crate-qualified one.
    let rest = &s[end..];
    if !rest.starts_with("::") && !rest.starts_with('<') {
        return None;
    }
    if is_primitive(head) {
        return None;
    }
    Some(head.to_string())
}

fn is_primitive(name: &str) -> bool {
    matches!(
        name,
        "bool"
            | "char"
            | "str"
            | "f32"
            | "f64"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "never"
    )
}

/// Crate names are written with hyphens in `Cargo.toml` and on crates.io but
/// with underscores in symbol paths. Compare through this.
pub fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

/// Crates that are part of the toolchain rather than something the author chose.
/// Filtering these out makes a dependency inventory readable.
pub fn is_toolchain_crate(name: &str) -> bool {
    matches!(
        normalize_crate_name(name).as_str(),
        "core"
            | "std"
            | "alloc"
            | "proc_macro"
            | "test"
            | "panic_unwind"
            | "panic_abort"
            | "unwind"
            | "compiler_builtins"
            | "rustc_std_workspace_core"
            | "rustc_std_workspace_alloc"
            | "rustc_std_workspace_std"
            | "std_detect"
            | "addr2line"
            | "gimli"
            | "object"
            | "miniz_oxide"
            | "hashbrown"
            | "rustc_demangle"
            | "adler"
            | "adler2"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_symbols_demangle_without_the_hash() {
        // core::ptr::drop_in_place, legacy scheme.
        let sym = "_ZN4core3ptr13drop_in_place17h0123456789abcdefE";
        let out = demangle(sym).expect("should demangle");
        assert_eq!(out, "core::ptr::drop_in_place");
        assert!(!out.contains("17h"), "the disambiguator must be suppressed");
    }

    #[test]
    fn non_rust_names_are_left_alone() {
        assert_eq!(demangle("CreateFileW"), None);
        assert_eq!(demangle("main"), None);
    }

    #[test]
    fn schemes_are_identified() {
        assert_eq!(
            scheme_of("_ZN4core3ptr13drop_in_place17h0123456789abcdefE"),
            Scheme::Legacy
        );
        assert_eq!(scheme_of("CreateFileW"), Scheme::NotRust);
    }

    #[test]
    fn plain_paths_yield_their_first_segment() {
        assert_eq!(
            crate_of("aes_gcm::AesGcm::decrypt").as_deref(),
            Some("aes_gcm")
        );
        assert_eq!(
            crate_of("miniz_oxide::inflate::core::decompress").as_deref(),
            Some("miniz_oxide")
        );
    }

    #[test]
    fn trait_impls_attribute_to_the_implementing_crate() {
        let s =
            "<aes_gcm::AesGcm<aes::Aes256, U12> as aead::AeadInPlace>::decrypt_in_place_detached";
        assert_eq!(crate_of(s).as_deref(), Some("aes_gcm"));
    }

    #[test]
    fn primitives_own_no_crate() {
        assert_eq!(crate_of("<[u8] as core::fmt::Debug>::fmt"), None);
        assert_eq!(crate_of("<&str as core::convert::From>::from"), None);
        assert_eq!(crate_of("u32::wrapping_add"), None);
    }

    #[test]
    fn a_bare_identifier_is_not_a_crate() {
        assert_eq!(crate_of("main"), None);
    }

    #[test]
    fn crate_names_normalise_across_hyphen_and_underscore() {
        assert_eq!(normalize_crate_name("aes-gcm"), "aes_gcm");
        assert!(is_toolchain_crate("std"));
        assert!(is_toolchain_crate("miniz-oxide"));
        assert!(!is_toolchain_crate("reqwest"));
    }
}
