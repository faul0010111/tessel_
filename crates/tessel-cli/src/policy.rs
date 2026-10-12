//! Per-component export policy.
//!
//! A policy maps project paths to *components* with a redistribution
//! status (`approved`, `unreviewed`, `not_permitted`) and defines which
//! statuses may go into a shared package (`include`).
//!
//! Safety rules:
//! - `not_permitted` is **never** exported, even if it appears in `include`;
//! - each file belongs to the component with the most specific prefix;
//! - files without a component inherit `default_redistribution` (default `unreviewed`);
//! - omitted files have their path, size and SHA-256 recorded in
//!   `integrity/external.json`, so another team can confirm that it acquired
//!   exactly the same dependency through authorized means.
//!
//! A license *declared* in the policy is not a confirmed permission: it only
//! documents what the team asserts. The `redistribution` field decides.

use crate::inventory::{FileEntry, Inventory};
use crate::model::{REDISTRIBUTION_STATES, SOURCE_COMPONENT_ID};
use crate::secrets::{self, Finding, ScanOutcome};
use crate::unity::Warning;
use crate::util::{hex_sha256, is_safe_rel_path, open_regular};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const POLICY_VERSION: u32 = 1;
pub const MAX_POLICY_BYTES: u64 = 1024 * 1024;

fn default_include() -> Vec<String> {
    vec!["approved".into(), "unreviewed".into()]
}

fn default_redistribution() -> String {
    "unreviewed".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: u32,
    /// Redistribution statuses that may be exported. Default: approved + unreviewed.
    #[serde(default = "default_include")]
    pub include: Vec<String>,
    /// Status of files that no component claims.
    #[serde(default = "default_redistribution")]
    pub default_redistribution: String,
    #[serde(default)]
    pub components: Vec<PolicyComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyComponent {
    pub id: String,
    pub kind: String,
    /// Path relative to the project root (file or directory).
    pub path: String,
    pub redistribution: String,
    /// Identificador SPDX *declarado* (ex.: `MIT`, `LicenseRef-Vendor-EULA`).
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    /// How to obtain the component when it is not exported (e.g. `external_authorized_acquisition`).
    #[serde(default)]
    pub availability: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl Policy {
    /// Permissive behaviour: everything exportable, nothing classified.
    pub fn permissive() -> Self {
        Policy {
            version: POLICY_VERSION,
            include: default_include(),
            default_redistribution: default_redistribution(),
            components: vec![],
        }
    }

    /// Parses and validates the bytes of a policy. Returns all errors at once.
    pub fn parse(bytes: &[u8]) -> std::result::Result<Policy, Vec<String>> {
        let mut p: Policy =
            serde_json::from_slice(bytes).map_err(|e| vec![format!("invalid JSON: {e}")])?;
        for c in &mut p.components {
            c.path = c.path.trim_end_matches('/').to_string();
        }
        let errors = p.validate();
        if errors.is_empty() {
            Ok(p)
        } else {
            Err(errors)
        }
    }

    pub fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        if self.version != POLICY_VERSION {
            e.push(format!(
                "version {} not supported (expected {POLICY_VERSION})",
                self.version
            ));
        }
        for s in &self.include {
            if s == "not_permitted" {
                e.push("include must not contain \"not_permitted\"".into());
            } else if !REDISTRIBUTION_STATES.contains(&s.as_str()) {
                e.push(format!("include: invalid status {s:?}"));
            }
        }
        if !REDISTRIBUTION_STATES.contains(&self.default_redistribution.as_str()) {
            e.push(format!(
                "invalid default_redistribution: {:?}",
                self.default_redistribution
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for c in &self.components {
            let who = format!("component {:?}", c.id);
            if c.id.is_empty()
                || !c
                    .id
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
            {
                e.push(format!("{who}: id must use only [A-Za-z0-9._-]"));
            } else if c.id == SOURCE_COMPONENT_ID {
                e.push(format!("{who}: id reserved"));
            } else if !ids.insert(c.id.as_str()) {
                e.push(format!("{who}: duplicate id"));
            }
            if c.kind.trim().is_empty() {
                e.push(format!("{who}: kind is empty"));
            }
            if !is_safe_rel_path(&c.path) {
                e.push(format!("{who}: unsafe or empty path ({:?})", c.path));
            } else if !paths.insert(c.path.as_str()) {
                e.push(format!("{who}: duplicate path ({:?})", c.path));
            }
            if !REDISTRIBUTION_STATES.contains(&c.redistribution.as_str()) {
                e.push(format!(
                    "{who}: invalid redistribution ({:?})",
                    c.redistribution
                ));
            }
            if let Some(l) = &c.license
                && (l.trim().is_empty()
                    || l.len() > 128
                    || !l
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ".+-:() ".contains(ch)))
            {
                e.push(format!(
                    "{who}: license must be an SPDX identifier/expression ({l:?})"
                ));
            }
            if c.availability
                .as_deref()
                .is_some_and(|a| a.trim().is_empty())
            {
                e.push(format!("{who}: availability is empty"));
            }
        }
        e
    }

    fn allows(&self, redistribution: &str) -> bool {
        redistribution != "not_permitted" && self.include.iter().any(|s| s == redistribution)
    }
}

fn path_matches(file: &str, prefix: &str) -> bool {
    file == prefix
        || (file.len() > prefix.len()
            && file.starts_with(prefix)
            && file.as_bytes()[prefix.len()] == b'/')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentDecision {
    pub id: String,
    pub kind: String,
    /// Origin path in the project; `None` for the implicit (root) component.
    pub origin_path: Option<String>,
    pub redistribution: String,
    pub license: Option<String>,
    pub version: Option<String>,
    pub availability: Option<String>,
    pub note: Option<String>,
    pub included: bool,
    pub reason: String,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmittedFile {
    pub component: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub included: Vec<FileEntry>,
    pub omitted: Vec<OmittedFile>,
    pub components: Vec<ComponentDecision>,
    pub warnings: Vec<Warning>,
}

impl Decision {
    pub fn omitted_bytes(&self) -> u64 {
        self.omitted.iter().map(|o| o.size).sum()
    }
}

/// Classifies each file into the component with the most specific prefix and decides the export.
pub fn apply(policy: &Policy, files: &[FileEntry]) -> Decision {
    let mut comps: Vec<&PolicyComponent> = policy.components.iter().collect();
    comps.sort_by(|a, b| b.path.len().cmp(&a.path.len()).then(a.id.cmp(&b.id)));

    let mut stats: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut included = Vec::new();
    let mut omitted = Vec::new();
    for f in files {
        let (id, state) = match comps.iter().find(|c| path_matches(&f.path, &c.path)) {
            Some(c) => (c.id.as_str(), c.redistribution.as_str()),
            None => (SOURCE_COMPONENT_ID, policy.default_redistribution.as_str()),
        };
        let s = stats.entry(id.to_string()).or_default();
        s.0 += 1;
        s.1 += f.size;
        if policy.allows(state) {
            included.push(f.clone());
        } else {
            omitted.push(OmittedFile {
                component: id.to_string(),
                path: f.path.clone(),
                size: f.size,
                sha256: f.sha256.clone(),
            });
        }
    }

    let reason = |state: &str| -> String {
        if policy.allows(state) {
            format!("included (redistribution={state})")
        } else if state == "not_permitted" {
            "redistribution=not_permitted: never exported".to_string()
        } else {
            format!("redistribution={state} is not in the policy's include")
        }
    };

    let mut components = Vec::new();
    let mut warnings = Vec::new();
    for c in &policy.components {
        match stats.get(&c.id) {
            Some(&(files, bytes)) => components.push(ComponentDecision {
                id: c.id.clone(),
                kind: c.kind.clone(),
                origin_path: Some(c.path.clone()),
                redistribution: c.redistribution.clone(),
                license: c.license.clone(),
                version: c.version.clone(),
                availability: c.availability.clone(),
                note: c.note.clone(),
                included: policy.allows(&c.redistribution),
                reason: reason(&c.redistribution),
                files,
                bytes,
            }),
            None => warnings.push(Warning {
                code: "policy_component_matched_nothing".into(),
                message: format!(
                    "component '{}' (path '{}') did not match any file",
                    c.id, c.path
                ),
            }),
        }
        if c.redistribution == "approved" && c.license.is_none() {
            warnings.push(Warning {
                code: "approved_without_license".into(),
                message: format!(
                    "component '{}' is 'approved' without a declared license; record the basis for the approval",
                    c.id
                ),
            });
        }
        if c.redistribution == "not_permitted" && c.availability.is_none() {
            warnings.push(Warning {
                code: "blocked_without_availability".into(),
                message: format!(
                    "component '{}' will not be exported and does not say how to acquire it (availability)",
                    c.id
                ),
            });
        }
    }
    if let Some(&(files, bytes)) = stats.get(SOURCE_COMPONENT_ID) {
        components.push(ComponentDecision {
            id: SOURCE_COMPONENT_ID.into(),
            kind: "source".into(),
            origin_path: None,
            redistribution: policy.default_redistribution.clone(),
            license: None,
            version: None,
            availability: None,
            note: None,
            included: policy.allows(&policy.default_redistribution),
            reason: reason(&policy.default_redistribution),
            files,
            bytes,
        });
    }
    components.sort_by(|a, b| a.id.cmp(&b.id));
    omitted.sort_by(|a, b| a.path.cmp(&b.path));

    Decision {
        included,
        omitted,
        components,
        warnings,
    }
}

// ---------------------------------------------------------------- package files

/// Contents of `integrity/external.json`: what was left out and how to check it later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalInventory {
    pub note: String,
    pub components: Vec<ExternalComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalComponent {
    pub id: String,
    pub origin_path: Option<String>,
    pub redistribution: String,
    pub availability: Option<String>,
    /// Paths relative to the root of the source project.
    pub files: Vec<FileEntry>,
}

pub fn external_inventory(decision: &Decision) -> Option<ExternalInventory> {
    let mut out = Vec::new();
    for c in decision.components.iter().filter(|c| !c.included) {
        let mut files: Vec<FileEntry> = decision
            .omitted
            .iter()
            .filter(|o| o.component == c.id)
            .map(|o| FileEntry {
                path: o.path.clone(),
                size: o.size,
                sha256: o.sha256.clone(),
            })
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        out.push(ExternalComponent {
            id: c.id.clone(),
            origin_path: c.origin_path.clone(),
            redistribution: c.redistribution.clone(),
            availability: c.availability.clone(),
            files,
        });
    }
    (!out.is_empty()).then(|| ExternalInventory {
        note: "Files omitted from the package by the export policy. Acquire them through authorized means and check path, size and SHA-256.".into(),
        components: out,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsReport {
    pub scanned_files: usize,
    pub skipped_binary: usize,
    pub skipped_large: usize,
    pub truncated: bool,
    /// `true` if the package was created with `--allow-secret-findings` despite blocking findings.
    pub acknowledged: bool,
    pub findings: Vec<Finding>,
}

/// Contents of `reports/export.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportReport {
    pub policy_applied: bool,
    pub policy_sha256: Option<String>,
    pub include: Vec<String>,
    pub default_redistribution: String,
    pub components: Vec<ComponentDecision>,
    pub included_files: u64,
    pub included_bytes: u64,
    pub omitted_files: u64,
    pub omitted_bytes: u64,
    pub secrets: SecretsReport,
    pub warnings: Vec<Warning>,
}

// ---------------------------------------------------------------- export plan

pub fn load_policy(path: Option<&Path>) -> Result<(Policy, Option<Vec<u8>>)> {
    let Some(path) = path else {
        return Ok((Policy::permissive(), None));
    };
    let file =
        open_regular(path).with_context(|| format!("could not open policy {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        anyhow::bail!("the policy exceeds {MAX_POLICY_BYTES} bytes");
    }
    match Policy::parse(&bytes) {
        Ok(p) => Ok((p, Some(bytes))),
        Err(errs) => {
            let mut msg = format!("invalid policy ({}):", path.display());
            for e in errs {
                msg.push_str(&format!("\n  - {e}"));
            }
            anyhow::bail!(msg)
        }
    }
}

/// Result of inventory + policy + secret scan, before anything is written.
pub struct ExportPlan {
    pub root: PathBuf,
    pub inventory: Inventory,
    pub policy: Policy,
    pub policy_bytes: Option<Vec<u8>>,
    pub decision: Decision,
    pub secrets: ScanOutcome,
}

impl ExportPlan {
    /// Inventory of only what will be exported (same auxiliary lists as the full inventory).
    pub fn included_inventory(&self) -> Inventory {
        Inventory {
            files: self.decision.included.clone(),
            ..self.inventory.clone()
        }
    }

    pub fn blocking_findings(&self) -> Vec<&Finding> {
        self.secrets.blocking()
    }

    /// Export report written to `reports/export.json` and shown by `check`.
    pub fn export_report(&self, acknowledged: bool) -> ExportReport {
        let included = &self.decision.included;
        ExportReport {
            policy_applied: self.policy_bytes.is_some(),
            policy_sha256: self.policy_bytes.as_deref().map(hex_sha256),
            include: self.policy.include.clone(),
            default_redistribution: self.policy.default_redistribution.clone(),
            components: self.decision.components.clone(),
            included_files: included.len() as u64,
            included_bytes: included.iter().map(|f| f.size).sum(),
            omitted_files: self.decision.omitted.len() as u64,
            omitted_bytes: self.decision.omitted_bytes(),
            secrets: SecretsReport {
                scanned_files: self.secrets.scanned_files,
                skipped_binary: self.secrets.skipped_binary,
                skipped_large: self.secrets.skipped_large,
                truncated: self.secrets.truncated,
                acknowledged,
                findings: self.secrets.findings.clone(),
            },
            warnings: self.decision.warnings.clone(),
        }
    }

    /// Reasons the export would be blocked (empty = allowed).
    pub fn blocking_reasons(&self, allow_secret_findings: bool) -> Vec<String> {
        let mut r = Vec::new();
        if !self.inventory.errors.is_empty() {
            r.push(format!(
                "{} read error(s) in the inventory",
                self.inventory.errors.len()
            ));
        }
        if !self.secrets.errors.is_empty() {
            r.push(format!(
                "{} failure(s) in the secret scan",
                self.secrets.errors.len()
            ));
        }
        let blocking = self.secrets.blocking().len();
        if blocking > 0 && !allow_secret_findings {
            r.push(format!("{blocking} blocking secret finding(s)"));
        }
        if self.inventory.files.is_empty() {
            r.push("no files to package".into());
        } else if self.decision.included.is_empty() {
            r.push("the policy omitted all files".into());
        }
        r
    }
}

/// Result of `tessel check`: what would be exported, what would be left out and what blocks.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub allowed: bool,
    pub blocking_reasons: Vec<String>,
    pub export: ExportReport,
    pub inventory_errors: Vec<crate::inventory::ScanError>,
    pub secret_scan_errors: Vec<String>,
}

pub fn check_report(plan: &ExportPlan, allow_secret_findings: bool) -> CheckReport {
    let blocking_reasons = plan.blocking_reasons(allow_secret_findings);
    let acknowledged = allow_secret_findings && !plan.secrets.blocking().is_empty();
    CheckReport {
        allowed: blocking_reasons.is_empty(),
        blocking_reasons,
        export: plan.export_report(acknowledged),
        inventory_errors: plan.inventory.errors.clone(),
        secret_scan_errors: plan.secrets.errors.clone(),
    }
}

pub fn plan_export(
    root: &Path,
    excludes: &[String],
    policy_path: Option<&Path>,
    skip_paths: &[PathBuf],
) -> Result<ExportPlan> {
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("could not access {}", root.display()))?;
    let (policy, policy_bytes) = load_policy(policy_path)?;
    let inventory = crate::inventory::scan(
        &root,
        &crate::inventory::ScanOptions {
            excludes,
            skip_paths,
        },
    )?;
    let decision = apply(&policy, &inventory.files);
    // Only what would be exported is scanned: omitted files never leave the machine.
    let secrets = secrets::scan_files(&root, &decision.included);
    Ok(ExportPlan {
        root,
        inventory,
        policy,
        policy_bytes,
        decision,
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(p: &str, size: u64) -> FileEntry {
        FileEntry {
            path: p.into(),
            size,
            sha256: "a".repeat(64),
        }
    }

    fn policy(json: &str) -> Policy {
        Policy::parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn longest_prefix_wins_and_default_applies() {
        let p = policy(
            r#"{"version":1,"components":[
              {"id":"assets","kind":"source","path":"Assets","redistribution":"approved","license":"MIT"},
              {"id":"vendor","kind":"dependency","path":"Assets/Plugins/Vendor/","redistribution":"not_permitted","availability":"external_authorized_acquisition"}
            ]}"#,
        );
        let files = vec![
            fe("Assets/a.cs", 1),
            fe("Assets/Plugins/Vendor/sdk.dll", 10),
            fe("Assets/Plugins/VendorX/ok.cs", 2),
            fe("ProjectSettings/x.asset", 3),
        ];
        let d = apply(&p, &files);
        let inc: Vec<&str> = d.included.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            inc,
            vec![
                "Assets/a.cs",
                "Assets/Plugins/VendorX/ok.cs",
                "ProjectSettings/x.asset"
            ]
        );
        assert_eq!(d.omitted.len(), 1);
        assert_eq!(d.omitted[0].component, "vendor");
        let ids: Vec<&str> = d.components.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["assets", "component-project-source", "vendor"]);
        let vendor = d.components.iter().find(|c| c.id == "vendor").unwrap();
        assert!(!vendor.included && vendor.files == 1 && vendor.bytes == 10);
        assert!(d.warnings.is_empty());
    }

    #[test]
    fn strict_include_omits_unreviewed_default() {
        let p = policy(
            r#"{"version":1,"include":["approved"],"components":[
            {"id":"own","kind":"source","path":"Assets/Own","redistribution":"approved","license":"Apache-2.0"}]}"#,
        );
        let d = apply(&p, &[fe("Assets/Own/a.cs", 1), fe("Other/b.cs", 1)]);
        assert_eq!(d.included.len(), 1);
        assert_eq!(d.omitted[0].path, "Other/b.cs");
        let ext = external_inventory(&d).unwrap();
        assert_eq!(ext.components[0].id, "component-project-source");
    }

    #[test]
    fn not_permitted_is_never_exported_even_if_listed() {
        let errs =
            Policy::parse(br#"{"version":1,"include":["approved","not_permitted"]}"#).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("not_permitted")));
    }

    #[test]
    fn validation_catches_bad_policies() {
        let bad = |json: &str, needle: &str| {
            let errs = Policy::parse(json.as_bytes()).unwrap_err();
            assert!(
                errs.iter().any(|e| e.contains(needle)),
                "{needle}: {errs:?}"
            );
        };
        bad(r#"{"version":2}"#, "version");
        bad(r#"{"version":1,"include":["maybe"]}"#, "invalid status");
        bad(
            r#"{"version":1,"default_redistribution":"yes"}"#,
            "default_redistribution",
        );
        bad(
            r#"{"version":1,"components":[{"id":"a b","kind":"k","path":"x","redistribution":"approved"}]}"#,
            "id must use",
        );
        bad(
            r#"{"version":1,"components":[{"id":"component-project-source","kind":"k","path":"x","redistribution":"approved"}]}"#,
            "reserved",
        );
        bad(
            r#"{"version":1,"components":[{"id":"a","kind":"k","path":"../x","redistribution":"approved"}]}"#,
            "unsafe",
        );
        bad(
            r#"{"version":1,"components":[{"id":"a","kind":"k","path":"/abs","redistribution":"approved"}]}"#,
            "unsafe",
        );
        bad(
            r#"{"version":1,"components":[{"id":"a","kind":"k","path":"x","redistribution":"approved"},{"id":"a","kind":"k","path":"y","redistribution":"approved"}]}"#,
            "duplicate",
        );
        bad(
            r#"{"version":1,"components":[{"id":"a","kind":"k","path":"x","redistribution":"approved","license":"MIT; rm -rf"}]}"#,
            "SPDX",
        );
        bad(
            r#"{"version":1,"components":[{"id":"a","kind":"k","path":"x","redistribution":"sure"}]}"#,
            "invalid redistribution",
        );
        bad("not json", "invalid JSON");
    }

    #[test]
    fn warnings_for_unused_and_underdocumented_components() {
        let p = policy(
            r#"{"version":1,"components":[
          {"id":"ghost","kind":"source","path":"Nope","redistribution":"approved"},
          {"id":"sdk","kind":"dependency","path":"Sdk","redistribution":"not_permitted"}]}"#,
        );
        let d = apply(&p, &[fe("Sdk/a.dll", 1)]);
        let codes: Vec<&str> = d.warnings.iter().map(|w| w.code.as_str()).collect();
        assert!(codes.contains(&"policy_component_matched_nothing"));
        assert!(codes.contains(&"approved_without_license"));
        assert!(codes.contains(&"blocked_without_availability"));
    }

    #[test]
    fn permissive_policy_matches_ogc001_behaviour() {
        let d = apply(&Policy::permissive(), &[fe("a", 1), fe("b/c", 2)]);
        assert_eq!(d.included.len(), 2);
        assert!(d.omitted.is_empty());
        assert_eq!(d.components.len(), 1);
        assert!(external_inventory(&d).is_none());
    }
}
