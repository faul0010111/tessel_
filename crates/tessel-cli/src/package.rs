//! TSP package creation.
//!
//! Flow: inventory → export policy → secret scan →
//! copy only the approved files → verify the bytes *at the destination* → publish.
//! The ZIP is written to `<output>.partial` and renamed after verification; any failure
//! removes the partial file, so a "valid" package never comes from a failed read.

use crate::inventory::{FileEntry, Inventory};
use crate::model::*;
use crate::policy::{self, ExportPlan};
use crate::secrets::Finding;
use crate::unity::{self, UnityInfo, Warning};
use crate::util::{hash_reader, hex_sha256, now_rfc3339, open_regular};
use crate::verify::verify_detailed;
use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub struct PackageOptions {
    pub root: PathBuf,
    pub output: PathBuf,
    pub excludes: Vec<String>,
    pub name: Option<String>,
    pub revision: Option<String>,
    pub authorization_ref: Option<String>,
    pub force: bool,
    /// Export policy file (default: everything exportable, as before policy support).
    pub policy: Option<PathBuf>,
    /// Create the package even with blocking secret findings (recorded in the package).
    pub allow_secret_findings: bool,
}

#[derive(Debug)]
pub struct PackageSummary {
    pub output: PathBuf,
    pub file_count: usize,
    pub total_bytes: u64,
    pub zip_bytes: u64,
    pub zip_sha256: String,
    pub logical_inventory_sha256: String,
    pub skipped: usize,
    pub warnings: Vec<Warning>,
    pub omitted_files: usize,
    pub omitted_bytes: u64,
    /// IDs of the components the policy left out of the package.
    pub omitted_components: Vec<String>,
    pub secret_findings: Vec<Finding>,
    pub secrets_acknowledged: bool,
}

struct Metadata {
    manifest: Vec<u8>,
    files_json: Vec<u8>,
    /// (path in the package, contents) of the remaining metadata.
    others: Vec<(String, Vec<u8>)>,
}

fn json_bytes<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    Ok(b)
}

fn absolute_output(out: &Path) -> Result<PathBuf> {
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)
        .with_context(|| format!("output directory does not exist: {}", parent.display()))?;
    let name = out.file_name().context("invalid output path")?;
    Ok(parent.join(name))
}

/// Read errors block packaging.
pub fn ensure_packageable(inv: &Inventory) -> Result<()> {
    if !inv.errors.is_empty() {
        let mut msg = format!(
            "{} error(s) during the inventory; no package was created:",
            inv.errors.len()
        );
        for e in inv.errors.iter().take(20) {
            msg.push_str(&format!("\n  - {}: {}", e.path, e.error));
        }
        if inv.errors.len() > 20 {
            msg.push_str(&format!("\n  ... and {} more", inv.errors.len() - 20));
        }
        bail!(msg);
    }
    if inv.files.is_empty() {
        bail!("no files to package (empty directory or everything excluded)");
    }
    Ok(())
}

/// Block message for secret findings (never includes the value found).
pub fn secrets_block_message(blocking: &[&Finding]) -> String {
    let mut msg = format!(
        "{} blocking finding(s) in the secret scan; no package was created:",
        blocking.len()
    );
    for f in blocking.iter().take(20) {
        if f.line == 0 {
            msg.push_str(&format!("\n  - {} [{}]", f.path, f.rule));
        } else {
            msg.push_str(&format!("\n  - {}:{} [{}]", f.path, f.line, f.rule));
        }
    }
    if blocking.len() > 20 {
        msg.push_str(&format!("\n  ... and {} more", blocking.len() - 20));
    }
    msg.push_str(
        "\nRemove or exclude the files, adjust the policy, or use --allow-secret-findings after human review.",
    );
    msg
}

fn build_metadata(
    opts: &PackageOptions,
    plan: &ExportPlan,
    pkg_inv: &Inventory,
    root_name: &str,
    unity_info: Option<&UnityInfo>,
    warnings: Vec<Warning>,
    acknowledged: bool,
) -> Result<Metadata> {
    let decision = &plan.decision;
    let logical = pkg_inv.logical_digest();

    let files_json = json_bytes(&IntegrityFile {
        algorithm: "sha256".into(),
        root: SOURCE_PREFIX.into(),
        logical_inventory_sha256: logical.clone(),
        files: pkg_inv.files.clone(),
    })?;

    // One provenance line per component (included or omitted).
    let provenance = {
        let mut out = Vec::new();
        for c in &decision.components {
            let line = json!({
                "component": c.id,
                "origin": "local-directory",
                "origin_name": root_name,
                "origin_path": c.origin_path,
                "status": if c.included { "included" } else { "omitted" },
                "file_count": c.files,
                "bytes": c.bytes,
                "tool": format!("tessel {}", env!("CARGO_PKG_VERSION")),
            });
            out.extend_from_slice(&serde_json::to_vec(&line)?);
            out.push(b'\n');
        }
        out
    };

    let mut all_warnings = warnings;
    all_warnings.extend(decision.warnings.iter().cloned());

    let inv_report = json_bytes(&InventoryReport {
        file_count: pkg_inv.files.len() as u64,
        total_bytes: pkg_inv.total_bytes(),
        excluded: plan.inventory.excluded.clone(),
        unmatched_excludes: plan.inventory.unmatched_excludes.clone(),
        skipped: plan.inventory.skipped.clone(),
        warnings: all_warnings,
        unity: unity_info.cloned(),
    })?;

    let export_report = json_bytes(&plan.export_report(acknowledged))?;

    let mut others: Vec<(String, Vec<u8>)> = vec![
        (PROVENANCE_PATH.to_string(), provenance),
        (INVENTORY_REPORT_PATH.to_string(), inv_report),
        (EXPORT_REPORT_PATH.to_string(), export_report),
    ];
    if let Some(u) = unity_info {
        let env = json_bytes(&json!({
            "engine": "Unity",
            "editor_version": u.editor_version,
            "editor_version_with_revision": u.editor_version_with_revision,
            "packages": u.packages,
            "note": "Values declared by the project; not verified against an Editor installation.",
        }))?;
        others.push((UNITY_ENV_PATH.to_string(), env));
    }
    let external = policy::external_inventory(decision);
    if let Some(ext) = &external {
        others.push((EXTERNAL_PATH.to_string(), json_bytes(ext)?));
    }
    if let Some(bytes) = &plan.policy_bytes {
        others.push((POLICY_PATH.to_string(), bytes.clone()));
    }
    others.sort_by(|a, b| a.0.cmp(&b.0));

    let metadata_files: Vec<MetaFile> = others
        .iter()
        .map(|(p, b)| MetaFile {
            path: p.clone(),
            size: b.len() as u64,
            sha256: hex_sha256(b),
        })
        .collect();

    let components: Vec<Component> = decision
        .components
        .iter()
        .map(|c| Component {
            id: c.id.clone(),
            kind: c.kind.clone(),
            path: c.included.then(|| match &c.origin_path {
                Some(o) => format!("{SOURCE_PREFIX}{o}/"),
                None => SOURCE_PREFIX.to_string(),
            }),
            version: c.version.clone(),
            redistribution: c.redistribution.clone(),
            availability: c.availability.clone(),
            provenance_ref: Some(PROVENANCE_PATH.into()),
            instructions_ref: None,
            license_declared: c.license.clone(),
            origin_path: c.origin_path.clone(),
            note: c.note.clone(),
            external_ref: (!c.included).then(|| EXTERNAL_PATH.to_string()),
        })
        .collect();

    let manifest = Manifest {
        format: FORMAT.into(),
        format_version: FORMAT_VERSION.into(),
        created_at: now_rfc3339(),
        generator: Generator {
            name: "tessel".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        project: Project {
            name: opts.name.clone().unwrap_or_else(|| root_name.to_string()),
            revision: opts.revision.clone(),
        },
        engine: unity_info.map(|u| Engine {
            name: "Unity".into(),
            editor_version: u.editor_version.clone(),
        }),
        authorization: Authorization {
            status: if opts.authorization_ref.is_some() {
                "unverified".into()
            } else {
                "unspecified".into()
            },
            evidence_ref: opts.authorization_ref.clone(),
            // Nothing was approved by review: the offline CLI only records the declaration.
            approved_operations: vec![],
        },
        components,
        integrity: Integrity {
            algorithm: "sha256".into(),
            inventory_path: INTEGRITY_PATH.into(),
            inventory_sha256: hex_sha256(&files_json),
            logical_inventory_sha256: logical,
            file_count: pkg_inv.files.len() as u64,
            total_bytes: pkg_inv.total_bytes(),
        },
        metadata_files,
        reproducibility: Reproducibility {
            environment: unity_info.map(|_| UNITY_ENV_PATH.to_string()),
            build_recipe: None,
            test_plan: None,
            restoration: Restoration {
                status: "not_tested".into(),
                evidence_ref: None,
            },
        },
        policy_ref: plan.policy_bytes.as_ref().map(|_| POLICY_PATH.to_string()),
    };

    Ok(Metadata {
        manifest: json_bytes(&manifest)?,
        files_json,
        others,
    })
}

fn file_options(size: u64) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        // Fixed date and permissions: the ZIP contents do not depend on mtime/umask.
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644)
        .large_file(size >= 0xFFFF_FFFF)
}

fn write_bytes(zip: &mut ZipWriter<File>, name: &str, bytes: &[u8]) -> Result<()> {
    zip.start_file(name, file_options(bytes.len() as u64))?;
    zip.write_all(bytes)?;
    Ok(())
}

fn add_source_files(zip: &mut ZipWriter<File>, root: &Path, files: &[FileEntry]) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    for f in files {
        let src = root.join(&f.path);
        let mut input = open_regular(&src)
            .with_context(|| format!("failed to open {} for packaging", f.path))?;
        zip.start_file(format!("{SOURCE_PREFIX}{}", f.path), file_options(f.size))?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        loop {
            let n = input
                .read(&mut buf)
                .with_context(|| format!("read failure on {}", f.path))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            zip.write_all(&buf[..n])?;
            total += n as u64;
        }
        if hex::encode(hasher.finalize()) != f.sha256 || total != f.size {
            bail!("file changed during packaging: {}", f.path);
        }
    }
    Ok(())
}

fn write_zip(partial: &Path, root: &Path, files: &[FileEntry], meta: &Metadata) -> Result<()> {
    let file =
        File::create(partial).with_context(|| format!("could not create {}", partial.display()))?;
    let mut zip = ZipWriter::new(file);
    write_bytes(&mut zip, MANIFEST_PATH, &meta.manifest)?;
    write_bytes(&mut zip, INTEGRITY_PATH, &meta.files_json)?;
    for (path, bytes) in &meta.others {
        write_bytes(&mut zip, path, bytes)?;
    }
    add_source_files(&mut zip, root, files)?;
    let file = zip.finish()?;
    file.sync_all()?;
    Ok(())
}

pub fn create_package(opts: &PackageOptions) -> Result<PackageSummary> {
    let root = fs::canonicalize(&opts.root)
        .with_context(|| format!("could not access {}", opts.root.display()))?;
    let output = absolute_output(&opts.output)?;
    if output.is_dir() {
        bail!("{} is a directory; provide a .zip file", output.display());
    }
    if output.exists() && !opts.force {
        bail!(
            "{} already exists (use --force to overwrite)",
            output.display()
        );
    }
    let mut partial_name = output.file_name().unwrap().to_os_string();
    partial_name.push(".partial");
    let partial = output.with_file_name(partial_name);

    // The output package may be inside the project: never include it in itself.
    let skip = [output.clone(), partial.clone()];
    let plan = policy::plan_export(&root, &opts.excludes, opts.policy.as_deref(), &skip)?;
    ensure_packageable(&plan.inventory)?;

    let pkg_inv = plan.included_inventory();
    if pkg_inv.files.is_empty() {
        bail!(
            "the policy omitted all {} file(s); review 'include' and 'default_redistribution'",
            plan.decision.omitted.len()
        );
    }

    if !plan.secrets.errors.is_empty() {
        bail!(
            "secret scan failed; no package was created:\n  - {}",
            plan.secrets.errors.join("\n  - ")
        );
    }
    let blocking = plan.blocking_findings();
    if !blocking.is_empty() && !opts.allow_secret_findings {
        bail!(secrets_block_message(&blocking));
    }
    let acknowledged = !blocking.is_empty();

    let unity_info = unity::detect(&root);
    let warnings = unity::warnings(unity_info.as_ref(), &plan.inventory);
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "project".into());
    let meta = build_metadata(
        opts,
        &plan,
        &pkg_inv,
        &root_name,
        unity_info.as_ref(),
        warnings.clone(),
        acknowledged,
    )?;

    let result = (|| -> Result<()> {
        write_zip(&partial, &root, &pkg_inv.files, &meta)?;
        // Verify the bytes at the destination before publishing.
        let verified = verify_detailed(&partial)?;
        if !verified.report.is_valid() {
            bail!(
                "the generated package failed verification ({:?}); discarded",
                verified.report.status
            );
        }
        if output.exists() {
            fs::remove_file(&output)
                .with_context(|| format!("could not replace {}", output.display()))?;
        }
        fs::rename(&partial, &output)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&partial);
        return Err(e);
    }

    let (zip_sha256, zip_bytes) = hash_reader(File::open(&output)?)?;
    let mut summary_warnings = warnings;
    summary_warnings.extend(plan.decision.warnings.iter().cloned());
    Ok(PackageSummary {
        output,
        file_count: pkg_inv.files.len(),
        total_bytes: pkg_inv.total_bytes(),
        zip_bytes,
        zip_sha256,
        logical_inventory_sha256: pkg_inv.logical_digest(),
        skipped: plan.inventory.skipped.len(),
        warnings: summary_warnings,
        omitted_files: plan.decision.omitted.len(),
        omitted_bytes: plan.decision.omitted_bytes(),
        omitted_components: plan
            .decision
            .components
            .iter()
            .filter(|c| !c.included)
            .map(|c| c.id.clone())
            .collect(),
        secret_findings: plan.secrets.findings.clone(),
        secrets_acknowledged: acknowledged,
    })
}
