//! Readable (JSON) report for a TSP package: verification + manifest summary.

use crate::model::*;
use crate::util::hash_reader;
use crate::verify::{MAX_SMALL_ENTRY_BYTES, VerifyReport, read_named_entry, verify_detailed};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct Report {
    pub report_version: u32,
    pub generator: String,
    pub package: PackageInfo,
    pub verification: VerifyReport,
    pub summary: Option<Summary>,
    /// Contents of `reports/inventory.json`; only included if the package is valid.
    pub packaging: Option<serde_json::Value>,
    /// Contents of `reports/export.json` (per-component decisions and secrets); only if the package is valid.
    pub export: Option<serde_json::Value>,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct PackageInfo {
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct TopLevel {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct ComponentSummary {
    pub id: String,
    pub kind: String,
    pub redistribution: String,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub project_name: String,
    pub revision: Option<String>,
    pub format_version: String,
    pub created_at: String,
    pub engine: Option<Engine>,
    pub authorization_status: String,
    pub restoration_status: String,
    pub file_count: u64,
    pub total_bytes: u64,
    pub logical_inventory_sha256: String,
    pub components: Vec<ComponentSummary>,
    /// Files and bytes per top-level directory (`.` = files at the root).
    pub by_top_level: BTreeMap<String, TopLevel>,
}

pub fn build_report(package: &Path) -> Result<Report> {
    let (zip_sha256, size_bytes) = hash_reader(
        File::open(package).with_context(|| format!("could not open {}", package.display()))?,
    )?;
    let verified = verify_detailed(package)?;

    let summary = verified.manifest.as_ref().map(|m| {
        let mut by_top: BTreeMap<String, TopLevel> = BTreeMap::new();
        if let Some(inv) = &verified.inventory {
            for f in &inv.files {
                let key = match f.path.split_once('/') {
                    Some((top, _)) => top.to_string(),
                    None => ".".to_string(),
                };
                let e = by_top.entry(key).or_insert(TopLevel { files: 0, bytes: 0 });
                e.files += 1;
                e.bytes += f.size;
            }
        }
        Summary {
            project_name: m.project.name.clone(),
            revision: m.project.revision.clone(),
            format_version: m.format_version.clone(),
            created_at: m.created_at.clone(),
            engine: m.engine.clone(),
            authorization_status: m.authorization.status.clone(),
            restoration_status: m.reproducibility.restoration.status.clone(),
            file_count: m.integrity.file_count,
            total_bytes: m.integrity.total_bytes,
            logical_inventory_sha256: m.integrity.logical_inventory_sha256.clone(),
            components: m
                .components
                .iter()
                .map(|c| ComponentSummary {
                    id: c.id.clone(),
                    kind: c.kind.clone(),
                    redistribution: c.redistribution.clone(),
                })
                .collect(),
            by_top_level: by_top,
        }
    });

    let packaging = if verified.report.is_valid() {
        read_named_entry(package, INVENTORY_REPORT_PATH, MAX_SMALL_ENTRY_BYTES)?
            .and_then(|b| serde_json::from_slice(&b).ok())
    } else {
        None
    };
    let export = if verified.report.is_valid() {
        read_named_entry(package, EXPORT_REPORT_PATH, MAX_SMALL_ENTRY_BYTES)?
            .and_then(|b| serde_json::from_slice(&b).ok())
    } else {
        None
    };

    Ok(Report {
        report_version: 1,
        generator: format!("tessel {}", env!("CARGO_PKG_VERSION")),
        package: PackageInfo {
            file_name: package
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            size_bytes,
            sha256: zip_sha256,
        },
        verification: verified.report,
        summary,
        packaging,
        export,
        limitations: vec![
            "Unsigned package: verification confirms internal consistency, not authorship.",
            "Restoration and build were not tested in this version (restoration.status = not_tested).",
            "Licenses and redistribution rights were not assessed (redistribution = unreviewed).",
            "Declared authorization is not verified by the offline CLI.",
        ],
    })
}
