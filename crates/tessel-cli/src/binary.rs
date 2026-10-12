//! Static classification of binaries by header (PE, ELF, Mach-O, DEX, Wasm, ...).
//!
//! Only reads bytes: never loads, maps as executable or runs the file. Every access
//! to the buffer is checked (`get`), so a truncated or malicious header yields at
//! most `partial = true`, never a panic or an out-of-bounds read.

use crate::util::open_regular;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::Path;

/// Maximum number of bytes read from the start of each candidate file.
pub const HEAD_BYTES: usize = 64 * 1024;

/// Analysis finding: something that deserves the attention of whoever is evaluating the project.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub path: Option<String>,
    pub code: String,
    pub message: String,
}

impl Finding {
    pub fn new(path: Option<&str>, code: &str, message: impl Into<String>) -> Self {
        Finding {
            path: path.map(str::to_string),
            code: code.to_string(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pe,
    /// Starts with `MZ` but has no valid PE signature (DOS/NE/LE or a corrupted file).
    DosMz,
    Elf,
    MachO,
    MachOFat,
    JavaClass,
    Dex,
    Wasm,
    /// Generic ZIP (APK, AAB, JAR...). The contents are not opened.
    Zip,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Pe => "pe",
            Format::DosMz => "dos_mz",
            Format::Elf => "elf",
            Format::MachO => "mach_o",
            Format::MachOFat => "mach_o_fat",
            Format::JavaClass => "java_class",
            Format::Dex => "dex",
            Format::Wasm => "wasm",
            Format::Zip => "zip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub format: Format,
    pub arch: Option<String>,
    pub bits: Option<u8>,
    /// executable, shared_library, object, core, bundle...
    pub kind: Option<String>,
    /// PE with a CLR directory: managed .NET assembly (decompilable as IL).
    pub managed_dotnet: Option<bool>,
    /// Architectures of a universal Mach-O.
    pub archs: Vec<String>,
    pub version: Option<String>,
    /// The header ended earlier than expected; fields may be incomplete.
    pub partial: bool,
}

impl Header {
    fn new(format: Format) -> Self {
        Header {
            format,
            arch: None,
            bits: None,
            kind: None,
            managed_dotnet: None,
            archs: Vec::new(),
            version: None,
            partial: false,
        }
    }
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u16be(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u32be(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Does the start of the file look like one of the recognized formats? Decides whether to read more bytes.
pub fn is_candidate(head: &[u8]) -> bool {
    head.starts_with(b"MZ")
        || head.starts_with(b"\x7fELF")
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || macho_magic(head).is_some()
        || head.starts_with(b"dex\n")
        || head.starts_with(b"\0asm")
        || head.starts_with(b"PK\x03\x04")
}

/// Reads enough of the start of the file to classify it. Opens without following symlinks.
pub fn read_probe(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = open_regular(path)?;
    let mut head = Vec::with_capacity(8);
    (&mut f).take(8).read_to_end(&mut head)?;
    if is_candidate(&head) {
        (&mut f)
            .take((HEAD_BYTES - head.len()) as u64)
            .read_to_end(&mut head)?;
    }
    Ok(head)
}

pub fn classify(b: &[u8]) -> Option<Header> {
    if b.starts_with(b"MZ") {
        return Some(pe(b));
    }
    if b.starts_with(b"\x7fELF") {
        return Some(elf(b));
    }
    if b.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        return Some(fat_or_class(b));
    }
    if macho_magic(b).is_some() {
        return Some(macho(b));
    }
    if b.starts_with(b"dex\n") {
        return Some(dex(b));
    }
    if b.starts_with(b"\0asm") {
        let mut h = Header::new(Format::Wasm);
        h.version = u32le(b, 4).map(|v| v.to_string());
        h.partial = h.version.is_none();
        return Some(h);
    }
    if b.starts_with(b"PK\x03\x04") {
        return Some(Header::new(Format::Zip));
    }
    None
}

fn pe_machine(m: u16) -> String {
    match m {
        0x014c => "x86".into(),
        0x8664 => "x86_64".into(),
        0x01c0 | 0x01c4 => "arm".into(),
        0xaa64 => "arm64".into(),
        0x0200 => "ia64".into(),
        other => format!("unknown(0x{other:04x})"),
    }
}

fn pe(b: &[u8]) -> Header {
    let mut h = Header::new(Format::Pe);
    let Some(lfanew) = u32le(b, 0x3c).map(|v| v as usize) else {
        h.format = Format::DosMz;
        h.partial = true;
        return h;
    };
    if b.get(lfanew..lfanew.saturating_add(4)) != Some(b"PE\0\0") {
        // May be mere truncation (e_lfanew beyond the buffer) or a file that is not a PE.
        h.partial = lfanew >= b.len();
        h.format = Format::DosMz;
        return h;
    }
    h.arch = u16le(b, lfanew + 4).map(pe_machine);
    let characteristics = u16le(b, lfanew + 22);
    let opt = lfanew + 24;
    let magic = u16le(b, opt);
    h.bits = match magic {
        Some(0x10b) => Some(32),
        Some(0x20b) => Some(64),
        _ => None,
    };
    h.kind = characteristics.map(|c| {
        if c & 0x2000 != 0 {
            "shared_library".to_string()
        } else if c & 0x0002 != 0 {
            "executable".to_string()
        } else {
            "object".to_string()
        }
    });
    let (count_off, dirs_off) = match magic {
        Some(0x10b) => (opt + 92, opt + 96),
        Some(0x20b) => (opt + 108, opt + 112),
        _ => {
            h.partial = true;
            return h;
        }
    };
    match u32le(b, count_off) {
        Some(n) if n > 14 => match u32le(b, dirs_off + 14 * 8) {
            Some(rva) => h.managed_dotnet = Some(rva != 0),
            None => h.partial = true,
        },
        Some(_) => h.managed_dotnet = Some(false),
        None => h.partial = true,
    }
    h
}

fn elf(b: &[u8]) -> Header {
    let mut h = Header::new(Format::Elf);
    h.bits = match b.get(4) {
        Some(1) => Some(32),
        Some(2) => Some(64),
        _ => None,
    };
    let rd = |o| match b.get(5) {
        Some(2) => u16be(b, o),
        _ => u16le(b, o),
    };
    h.kind = rd(16).map(|t| {
        match t {
            1 => "object",
            2 => "executable",
            3 => "shared_library_or_pie",
            4 => "core",
            _ => "other",
        }
        .to_string()
    });
    h.arch = rd(18).map(|m| match m {
        3 => "x86".into(),
        8 => "mips".into(),
        20 => "ppc".into(),
        21 => "ppc64".into(),
        40 => "arm".into(),
        62 => "x86_64".into(),
        183 => "arm64".into(),
        243 => "riscv".into(),
        other => format!("unknown({other})"),
    });
    h.partial = h.bits.is_none() || h.kind.is_none() || h.arch.is_none();
    h
}

/// Returns (little_endian, 64 bits) if the first 4 bytes are a thin Mach-O magic.
fn macho_magic(b: &[u8]) -> Option<(bool, bool)> {
    match b.get(0..4)? {
        [0xfe, 0xed, 0xfa, 0xce] => Some((false, false)),
        [0xfe, 0xed, 0xfa, 0xcf] => Some((false, true)),
        [0xce, 0xfa, 0xed, 0xfe] => Some((true, false)),
        [0xcf, 0xfa, 0xed, 0xfe] => Some((true, true)),
        _ => None,
    }
}

fn macho_cpu(t: u32) -> String {
    match t {
        7 => "x86".into(),
        0x0100_0007 => "x86_64".into(),
        12 => "arm".into(),
        0x0100_000c => "arm64".into(),
        18 => "ppc".into(),
        0x0100_0012 => "ppc64".into(),
        other => format!("unknown(0x{other:x})"),
    }
}

fn macho(b: &[u8]) -> Header {
    let mut h = Header::new(Format::MachO);
    let Some((le, is64)) = macho_magic(b) else {
        h.partial = true;
        return h;
    };
    h.bits = Some(if is64 { 64 } else { 32 });
    let rd = |o| if le { u32le(b, o) } else { u32be(b, o) };
    h.arch = rd(4).map(macho_cpu);
    h.kind = rd(12).map(|t| {
        match t {
            1 => "object",
            2 => "executable",
            6 => "shared_library",
            8 => "bundle",
            10 => "debug_symbols",
            _ => "other",
        }
        .to_string()
    });
    h.partial = h.arch.is_none() || h.kind.is_none();
    h
}

/// `CAFEBABE` is the magic of both universal Mach-O and Java `.class`. The architecture
/// count of the former is small; the latter carries minor/major (major ≥ 45).
fn fat_or_class(b: &[u8]) -> Header {
    let Some(second) = u32be(b, 4) else {
        let mut h = Header::new(Format::MachOFat);
        h.partial = true;
        return h;
    };
    if second >= 45 {
        let mut h = Header::new(Format::JavaClass);
        h.version = u16be(b, 6).map(|major| format!("major {major}"));
        return h;
    }
    let mut h = Header::new(Format::MachOFat);
    let n = second as usize;
    for i in 0..n.min(16) {
        match u32be(b, 8 + i * 20) {
            Some(cpu) => h.archs.push(macho_cpu(cpu)),
            None => {
                h.partial = true;
                break;
            }
        }
    }
    h.kind = Some("universal".into());
    h
}

fn dex(b: &[u8]) -> Header {
    let mut h = Header::new(Format::Dex);
    match b.get(4..7) {
        Some(v) if v.iter().all(u8::is_ascii_digit) => {
            h.version = Some(String::from_utf8_lossy(v).into_owned());
        }
        _ => h.partial = true,
    }
    h
}

/// Formats promised by the file extension. `None` = no expectation for the extension.
pub fn expected_by_extension(path: &str) -> Option<&'static [Format]> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if name.ends_with(".dll") || name.ends_with(".exe") {
        Some(&[Format::Pe])
    } else if name.ends_with(".so") || name.contains(".so.") {
        Some(&[Format::Elf])
    } else if name.ends_with(".dylib") {
        Some(&[Format::MachO, Format::MachOFat])
    } else if name.ends_with(".dex") {
        Some(&[Format::Dex])
    } else if name.ends_with(".wasm") {
        Some(&[Format::Wasm])
    } else if name.ends_with(".class") {
        Some(&[Format::JavaClass])
    } else {
        None
    }
}

/// Symbol/debug files that accompany the binary `path` (by name only, in the inventory).
pub fn companion_symbols(path: &str, all: &BTreeSet<String>) -> Vec<String> {
    let (dir, name) = match path.rsplit_once('/') {
        Some((d, n)) => (format!("{d}/"), n),
        None => (String::new(), path),
    };
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    let exact = [
        format!("{dir}{stem}.pdb"),
        format!("{path}.mdb"),
        format!("{path}.debug"),
        format!("{dir}{stem}.debug"),
        format!("{dir}{stem}.sym"),
    ];
    let mut out: BTreeSet<String> = exact.into_iter().filter(|p| all.contains(p)).collect();
    for dsym in [format!("{path}.dSYM/"), format!("{dir}{stem}.dSYM/")] {
        if let Some(first) = all.range(dsym.clone()..).next()
            && first.starts_with(&dsym)
        {
            out.insert(dsym.trim_end_matches('/').to_string());
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_bytes(machine: u16, chars: u16, magic: u16, clr_rva: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        b[0x80 + 22..0x80 + 24].copy_from_slice(&chars.to_le_bytes());
        let opt = 0x80 + 24;
        b[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        let (count, dirs) = if magic == 0x20b {
            (opt + 108, opt + 112)
        } else {
            (opt + 92, opt + 96)
        };
        b[count..count + 4].copy_from_slice(&16u32.to_le_bytes());
        b[dirs + 14 * 8..dirs + 14 * 8 + 4].copy_from_slice(&clr_rva.to_le_bytes());
        b
    }

    #[test]
    fn classifies_pe_managed_dll_x64() {
        let h = classify(&pe_bytes(0x8664, 0x2022, 0x20b, 0x2000)).unwrap();
        assert_eq!(h.format, Format::Pe);
        assert_eq!(h.arch.as_deref(), Some("x86_64"));
        assert_eq!(h.bits, Some(64));
        assert_eq!(h.kind.as_deref(), Some("shared_library"));
        assert_eq!(h.managed_dotnet, Some(true));
        assert!(!h.partial);
    }

    #[test]
    fn classifies_pe_native_exe_x86() {
        let h = classify(&pe_bytes(0x014c, 0x0102, 0x10b, 0)).unwrap();
        assert_eq!(h.arch.as_deref(), Some("x86"));
        assert_eq!(h.bits, Some(32));
        assert_eq!(h.kind.as_deref(), Some("executable"));
        assert_eq!(h.managed_dotnet, Some(false));
    }

    #[test]
    fn mz_without_pe_signature_is_dos() {
        let mut b = pe_bytes(0x8664, 0x2022, 0x20b, 0);
        b[0x80] = b'X';
        assert_eq!(classify(&b).unwrap().format, Format::DosMz);
        assert!(!classify(&b).unwrap().partial);
    }

    #[test]
    fn truncated_pe_is_partial_not_panic() {
        let b = pe_bytes(0x8664, 0x2022, 0x20b, 1);
        for n in 0..b.len() {
            let _ = classify(&b[..n]); // no truncation may cause a panic
        }
        let h = classify(&b[..0x90]).unwrap();
        assert_eq!(h.format, Format::Pe);
        assert!(h.partial);
    }

    #[test]
    fn hostile_lfanew_does_not_overflow() {
        let mut b = vec![0u8; 64];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        let h = classify(&b).unwrap();
        assert_eq!(h.format, Format::DosMz);
    }

    #[test]
    fn classifies_elf() {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        let h = classify(&b).unwrap();
        assert_eq!(h.format, Format::Elf);
        assert_eq!(h.arch.as_deref(), Some("x86_64"));
        assert_eq!(h.bits, Some(64));
        assert_eq!(h.kind.as_deref(), Some("shared_library_or_pie"));
    }

    #[test]
    fn classifies_macho_thin_and_fat() {
        let mut b = vec![0u8; 32];
        b[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        b[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        b[12..16].copy_from_slice(&6u32.to_le_bytes());
        let h = classify(&b).unwrap();
        assert_eq!(h.format, Format::MachO);
        assert_eq!(h.arch.as_deref(), Some("arm64"));
        assert_eq!(h.kind.as_deref(), Some("shared_library"));

        let mut f = vec![0u8; 48];
        f[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        f[4..8].copy_from_slice(&2u32.to_be_bytes());
        f[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
        f[28..32].copy_from_slice(&0x0100_000cu32.to_be_bytes());
        let h = classify(&f).unwrap();
        assert_eq!(h.format, Format::MachOFat);
        assert_eq!(h.archs, vec!["x86_64", "arm64"]);
    }

    #[test]
    fn cafebabe_with_java_version_is_class() {
        let mut b = vec![0u8; 16];
        b[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        b[6..8].copy_from_slice(&61u16.to_be_bytes());
        let h = classify(&b).unwrap();
        assert_eq!(h.format, Format::JavaClass);
        assert_eq!(h.version.as_deref(), Some("major 61"));
    }

    #[test]
    fn classifies_dex_wasm_zip_and_unknown() {
        assert_eq!(classify(b"dex\n035\0rest").unwrap().format, Format::Dex);
        assert_eq!(
            classify(b"dex\n035\0rest").unwrap().version.as_deref(),
            Some("035")
        );
        let w = classify(b"\0asm\x01\0\0\0").unwrap();
        assert_eq!(w.format, Format::Wasm);
        assert_eq!(w.version.as_deref(), Some("1"));
        assert_eq!(classify(b"PK\x03\x04....").unwrap().format, Format::Zip);
        assert!(classify(b"hello world").is_none());
        assert!(classify(b"").is_none());
    }

    #[test]
    fn extension_expectations() {
        assert_eq!(expected_by_extension("a/Game.EXE"), Some(&[Format::Pe][..]));
        assert_eq!(
            expected_by_extension("lib/libx.so.1"),
            Some(&[Format::Elf][..])
        );
        assert_eq!(expected_by_extension("a/readme.txt"), None);
    }

    #[test]
    fn finds_companion_symbols() {
        let all: BTreeSet<String> = [
            "Game_Data/Managed/Assembly-CSharp.dll",
            "Game_Data/Managed/Assembly-CSharp.dll.mdb",
            "Game.exe",
            "Game.pdb",
            "Lib.dylib",
            "Lib.dSYM/Contents/Info.plist",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            companion_symbols("Game_Data/Managed/Assembly-CSharp.dll", &all),
            vec!["Game_Data/Managed/Assembly-CSharp.dll.mdb"]
        );
        assert_eq!(companion_symbols("Game.exe", &all), vec!["Game.pdb"]);
        assert_eq!(companion_symbols("Lib.dylib", &all), vec!["Lib.dSYM"]);
        assert!(companion_symbols("Other.dll", &all).is_empty());
    }
}
