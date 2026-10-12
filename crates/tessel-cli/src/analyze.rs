//! `tessel analyze`: static analysis of a build or directory (binaries and Unity build).
//!
//! Read-only: small headers are read to classify binaries, and only the identified
//! binaries get their SHA-256 computed. Nothing is loaded or executed.

use crate::binary::{self, Finding, Format, Header};
use crate::inventory::{self, FileEntry, ScanError, ScanOptions, Skipped};
use crate::unity;
use crate::unity_build::{self, SourceComparison, UnityBuild};
use crate::util::{hash_reader, open_regular};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub struct AnalyzeOptions<'a> {
    pub excludes: &'a [String],
    /// Source Unity project, to compare against the build.
    pub source: Option<&'a Path>,
}

#[derive(Debug, Serialize)]
pub struct BinaryInfo {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub format: Format,
    pub arch: Option<String>,
    pub bits: Option<u8>,
    pub kind: Option<String>,
    pub managed_dotnet: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub archs: Vec<String>,
    pub version: Option<String>,
    /// Incomplete header: fields may be missing.
    pub partial: bool,
    /// Symbol files present in the same inventory (.pdb, .mdb, .dSYM, .debug).
    pub symbols: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Analysis {
    pub analysis_version: u32,
    pub generator: String,
    pub root_name: String,
    pub files: u64,
    pub total_bytes: u64,
    pub by_format: BTreeMap<String, u64>,
    pub binaries: Vec<BinaryInfo>,
    pub unity_build: Option<UnityBuild>,
    pub source_comparison: Option<SourceComparison>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
    pub errors: Vec<ScanError>,
    pub unmatched_excludes: Vec<String>,
    pub limitations: Vec<&'static str>,
}

impl Analysis {
    /// Is there anything that needs attention (read error or finding)?
    pub fn has_findings(&self) -> bool {
        !self.errors.is_empty() || !self.findings.is_empty()
    }
}

fn root_name(root: &Path) -> String {
    fs::canonicalize(root)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

pub fn analyze(root: &Path, opts: &AnalyzeOptions) -> Result<Analysis> {
    let inv = inventory::scan_with(
        root,
        &ScanOptions {
            excludes: opts.excludes,
            skip_paths: &[],
        },
        false,
    )?;
    let canon =
        fs::canonicalize(root).with_context(|| format!("could not access {}", root.display()))?;
    let all_paths: BTreeSet<String> = inv.files.iter().map(|f| f.path.clone()).collect();

    let mut errors = inv.errors.clone();
    let mut findings: Vec<Finding> = Vec::new();
    let mut binaries: Vec<BinaryInfo> = Vec::new();
    let mut by_format: BTreeMap<String, u64> = BTreeMap::new();

    for f in &inv.files {
        let path = canon.join(&f.path);
        let head = match binary::read_probe(&path) {
            Ok(h) => h,
            Err(e) => {
                errors.push(ScanError {
                    path: f.path.clone(),
                    error: format!("read failure: {e}"),
                });
                continue;
            }
        };
        let header: Option<Header> = binary::classify(&head);
        let expected = binary::expected_by_extension(&f.path);
        match (&header, expected) {
            (Some(h), Some(exp)) if !exp.contains(&h.format) => findings.push(Finding::new(
                Some(&f.path),
                "extension_mismatch",
                format!(
                    "the extension suggests {} but the header is {}",
                    exp.iter().map(|x| x.as_str()).collect::<Vec<_>>().join("/"),
                    h.format.as_str()
                ),
            )),
            (None, Some(exp)) => findings.push(Finding::new(
                Some(&f.path),
                "extension_mismatch",
                format!(
                    "the extension suggests {} but the header is not recognized (empty, encrypted, packed or corrupted file)",
                    exp.iter().map(|x| x.as_str()).collect::<Vec<_>>().join("/")
                ),
            )),
            _ => {}
        }
        let Some(h) = header else {
            *by_format.entry("other".into()).or_default() += 1;
            continue;
        };
        *by_format.entry(h.format.as_str().into()).or_default() += 1;
        if h.partial {
            findings.push(Finding::new(
                Some(&f.path),
                "truncated_header",
                "incomplete or inconsistent header: partial classification",
            ));
        }
        let sha256 = match open_regular(&path).and_then(hash_reader) {
            Ok((s, _)) => Some(s),
            Err(e) => {
                errors.push(ScanError {
                    path: f.path.clone(),
                    error: format!("read failure: {e}"),
                });
                None
            }
        };
        binaries.push(BinaryInfo {
            symbols: binary::companion_symbols(&f.path, &all_paths),
            path: f.path.clone(),
            size: f.size,
            sha256,
            format: h.format,
            arch: h.arch,
            bits: h.bits,
            kind: h.kind,
            managed_dotnet: h.managed_dotnet,
            archs: h.archs,
            version: h.version,
            partial: h.partial,
        });
    }
    binaries.sort_by(|a, b| a.path.cmp(&b.path));

    let unity_build = unity_build::detect(&canon, &inv.files);
    if let Some(b) = &unity_build {
        findings.extend(b.findings.iter().cloned());
    }

    let mut source_comparison = None;
    if let Some(src) = opts.source {
        match &unity_build {
            None => findings.push(Finding::new(
                None,
                "no_unity_build",
                "--source was given, but the analysed directory does not look like a Unity build",
            )),
            Some(build) => {
                let src_canon = fs::canonicalize(src)
                    .with_context(|| format!("could not access {}", src.display()))?;
                let src_inv = inventory::scan_with(
                    &src_canon,
                    &ScanOptions {
                        excludes: &[],
                        skip_paths: &[],
                    },
                    false,
                )?;
                errors.extend(src_inv.errors.iter().map(|e| ScanError {
                    path: format!("source:{}", e.path),
                    error: e.error.clone(),
                }));
                let declared = unity::detect(&src_canon).and_then(|u| u.editor_version);
                let cmp = unity_build::compare(&src_canon, &src_inv.files, declared, build);
                if cmp.unity_version.status == "mismatch" {
                    findings.push(Finding::new(
                        None,
                        "unity_version_mismatch",
                        format!(
                            "the project declares {} but the build contains {}",
                            cmp.unity_version
                                .declared_by_project
                                .as_deref()
                                .unwrap_or("?"),
                            cmp.unity_version.found_in_build.as_deref().unwrap_or("?")
                        ),
                    ));
                }
                source_comparison = Some(cmp);
            }
        }
    }

    errors.sort_by(|a, b| a.path.cmp(&b.path));
    findings.sort_by(|a, b| (&a.path, &a.code).cmp(&(&b.path, &b.code)));

    let total_bytes = inv.files.iter().map(|f: &FileEntry| f.size).sum();
    Ok(Analysis {
        analysis_version: 1,
        generator: format!("tessel {}", env!("CARGO_PKG_VERSION")),
        root_name: root_name(root),
        files: inv.files.len() as u64,
        total_bytes,
        by_format,
        binaries,
        unity_build,
        source_comparison,
        findings,
        skipped: inv.skipped,
        errors,
        unmatched_excludes: inv.unmatched_excludes,
        limitations: vec![
            "Static analysis by headers and names: no binary was loaded or executed.",
            "A recognized format does not mean the file is intact or safe; nothing was disassembled.",
            "APK/AAB/ZIP packages are not opened; their contents are not analysed.",
            "The Editor version comes from build headers and may be absent in encrypted or customized builds.",
            "Comparison with the source is by assembly name and declared version; it does not prove correspondence.",
            "IL2CPP backend: managed code was compiled to native; there are no DLLs to compare.",
        ],
    })
}
