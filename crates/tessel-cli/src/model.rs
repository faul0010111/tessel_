//! TSP v1 models (manifest and integrity inventory).
//!
//! Keeps three concepts apart: inventory (what was found),
//! policy (what may be included) and attestation (what was verified).
//! In this version the package only asserts the inventory; policy and attestation are
//! explicitly left as `unreviewed` / `not_tested` / unsigned.

use crate::inventory::FileEntry;
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "TSP";
pub const FORMAT_VERSION: &str = "1.0.0";
pub const SUPPORTED_VERSIONS: &[&str] = &[FORMAT_VERSION];

pub const MANIFEST_PATH: &str = "manifest.json";
pub const INTEGRITY_PATH: &str = "integrity/files.json";
pub const SOURCE_PREFIX: &str = "source/";
pub const INVENTORY_REPORT_PATH: &str = "reports/inventory.json";
pub const PROVENANCE_PATH: &str = "provenance/components.jsonl";
pub const UNITY_ENV_PATH: &str = "environments/unity.json";
/// Applied export policy (byte-for-byte copy of the file used).
pub const POLICY_PATH: &str = "policy/policy.json";
/// Per-component decisions and the result of the secret scan.
pub const EXPORT_REPORT_PATH: &str = "reports/export.json";
/// Files omitted by the policy, with hashes, for authorized acquisition and checking.
pub const EXTERNAL_PATH: &str = "integrity/external.json";
pub const SOURCE_COMPONENT_ID: &str = "component-project-source";

pub const REDISTRIBUTION_STATES: &[&str] = &["approved", "unreviewed", "not_permitted"];
pub const RESTORATION_STATES: &[&str] = &[
    "not_tested",
    "blocked_missing_dependency",
    "blocked_authorization",
    "failed_integrity",
    "build_failed",
    "success",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub format_version: String,
    pub created_at: String,
    pub generator: Generator,
    pub project: Project,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<Engine>,
    pub authorization: Authorization,
    pub components: Vec<Component>,
    pub integrity: Integrity,
    /// Metadata files (everything outside `source/`, except the manifest and inventory),
    /// each with a hash. The manifest is the root of trust and does not reference itself.
    pub metadata_files: Vec<MetaFile>,
    pub reproducibility: Reproducibility,
    /// Export policy used; lets `verify` check conformance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generator {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engine {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// `unspecified` or `unverified` in the offline CLI; `approved` only after review of the studio's policy.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    pub approved_operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub redistribution: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions_ref: Option<String>,
    /// *Declared* SPDX identifier; it is not equivalent to confirmed permission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_declared: Option<String>,
    /// Origin path in the project (informational; for omitted components it is the only record of the location).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// For omitted components: file with paths, sizes and hashes of what was left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    pub algorithm: String,
    pub inventory_path: String,
    /// SHA-256 of the bytes of `integrity/files.json`.
    pub inventory_sha256: String,
    /// Logical inventory digest (independent of ZIP, timestamps and order).
    pub logical_inventory_sha256: String,
    pub file_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reproducibility {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_recipe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_plan: Option<String>,
    pub restoration: Restoration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Restoration {
    pub status: String,
    /// Required when `status == "success"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
}

/// Contents of `integrity/files.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityFile {
    pub algorithm: String,
    pub root: String,
    pub logical_inventory_sha256: String,
    pub files: Vec<FileEntry>,
}

/// Contents of `reports/inventory.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryReport {
    pub file_count: u64,
    pub total_bytes: u64,
    pub excluded: Vec<String>,
    pub unmatched_excludes: Vec<String>,
    pub skipped: Vec<crate::inventory::Skipped>,
    pub warnings: Vec<crate::unity::Warning>,
    pub unity: Option<crate::unity::UnityInfo>,
}
