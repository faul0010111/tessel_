use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tessel_core::analyze::{Analysis, AnalyzeOptions, analyze};
use tessel_core::diff::{DiffReport, diff_dirs};
use tessel_core::inventory::{self, Inventory, ScanOptions};
use tessel_core::package::{PackageOptions, create_package};
use tessel_core::policy::{CheckReport, check_report, plan_export};
use tessel_core::report::build_report;
use tessel_core::unity;
use tessel_core::util::human_bytes;
use tessel_core::verify::{VerifyReport, VerifyStatus, verify_package};

/// Tessel: inventory, export policy and verifiable TSP packages for game projects.
///
/// Exit codes: 0 = success, 1 = findings (integrity failure, differences,
/// read errors), 2 = usage or execution error.
#[derive(Parser)]
#[command(name = "tessel", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inventory a directory (read-only; nothing is executed)
    Inspect {
        path: PathBuf,
        /// Exclude a path relative to the root (repeatable), e.g. --exclude Library
        #[arg(long)]
        exclude: Vec<String>,
        /// JSON output, including the full file list
        #[arg(long)]
        json: bool,
    },
    /// Create a verifiable TSP package (.zip)
    Package {
        path: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Exclude a path relative to the root (repeatable)
        #[arg(long)]
        exclude: Vec<String>,
        /// Project name in the manifest (default: directory name)
        #[arg(long)]
        name: Option<String>,
        /// Source revision, e.g. git:0123abc (as given, not detected)
        #[arg(long)]
        revision: Option<String>,
        /// Reference to the authorization evidence (recorded as unverified)
        #[arg(long)]
        authorization_ref: Option<String>,
        /// Overwrite the output file if it exists
        #[arg(long)]
        force: bool,
        /// Export policy (JSON): components, redistribution status and what may leave
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Create the package even with blocking secret findings (recorded in the package)
        #[arg(long)]
        allow_secret_findings: bool,
    },
    /// Dry-run the export: per-component decisions, omissions and secrets (writes nothing)
    Check {
        path: PathBuf,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Treat secret findings as acknowledged (as in `package --allow-secret-findings`)
        #[arg(long)]
        allow_secret_findings: bool,
        #[arg(long)]
        json: bool,
    },
    /// Verify the integrity of a TSP package
    Verify {
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compare two directories (e.g. original build vs. reproduced build)
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Static analysis of a build or directory: binaries (PE/ELF/Mach-O/...) and Unity builds
    Analyze {
        path: PathBuf,
        /// Exclude a path relative to the root (repeatable)
        #[arg(long)]
        exclude: Vec<String>,
        /// Source Unity project, to compare Editor version and assembly names
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Produce a readable JSON report for a package
    Report {
        package: PathBuf,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

const OK: u8 = 0;
const FINDINGS: u8 = 1;
const FAILURE: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(FAILURE)
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Command::Inspect {
            path,
            exclude,
            json,
        } => inspect(&path, &exclude, json),
        Command::Package {
            path,
            output,
            exclude,
            name,
            revision,
            authorization_ref,
            force,
            policy,
            allow_secret_findings,
        } => {
            let s = create_package(&PackageOptions {
                root: path,
                output,
                excludes: exclude,
                name,
                revision,
                authorization_ref,
                force,
                policy,
                allow_secret_findings,
            })?;
            println!("Package created and verified: {}", s.output.display());
            println!(
                "  {} file(s), {} of content; ZIP: {}",
                s.file_count,
                human_bytes(s.total_bytes),
                human_bytes(s.zip_bytes)
            );
            println!(
                "  logical inventory (sha256): {}",
                s.logical_inventory_sha256
            );
            println!("  ZIP (sha256):               {}", s.zip_sha256);
            if s.skipped > 0 {
                println!(
                    "  {} item(s) skipped (symlinks/special files): see `tessel report`",
                    s.skipped
                );
            }
            if s.omitted_files > 0 {
                println!(
                    "  OMITTED by policy: {} file(s), {} (components: {}); hashes in integrity/external.json",
                    s.omitted_files,
                    human_bytes(s.omitted_bytes),
                    s.omitted_components.join(", ")
                );
            }
            let low = s
                .secret_findings
                .iter()
                .filter(|f| !f.severity.blocks())
                .count();
            if s.secrets_acknowledged {
                println!(
                    "  WARNING: package created with acknowledged blocking secret findings (--allow-secret-findings); recorded in reports/export.json"
                );
            }
            if low > 0 {
                println!("  {low} informational finding(s) (e-mail/CPF): see `tessel report`");
            }
            for w in &s.warnings {
                println!("  warning [{}]: {}", w.code, w.message);
            }
            Ok(OK)
        }
        Command::Check {
            path,
            exclude,
            policy,
            allow_secret_findings,
            json,
        } => {
            let plan = plan_export(&path, &exclude, policy.as_deref(), &[])?;
            let rep = check_report(&plan, allow_secret_findings);
            if json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else {
                print_check(&path, &rep);
            }
            Ok(if rep.allowed { OK } else { FINDINGS })
        }
        Command::Verify { package, json } => {
            let rep = verify_package(&package)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else {
                print_verify(&package, &rep);
            }
            Ok(if rep.is_valid() { OK } else { FINDINGS })
        }
        Command::Diff {
            left,
            right,
            exclude,
            json,
        } => {
            let d = diff_dirs(&left, &right, &exclude)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&d)?);
            } else {
                print_diff(&d);
            }
            Ok(if d.identical { OK } else { FINDINGS })
        }
        Command::Analyze {
            path,
            exclude,
            source,
            json,
        } => {
            let a = analyze(
                &path,
                &AnalyzeOptions {
                    excludes: &exclude,
                    source: source.as_deref(),
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&a)?);
            } else {
                print_analysis(&a);
            }
            Ok(if a.has_findings() { FINDINGS } else { OK })
        }
        Command::Report { package, output } => {
            let rep = build_report(&package)?;
            let text = serde_json::to_string_pretty(&rep)? + "\n";
            match output {
                Some(p) => {
                    std::fs::write(&p, text)
                        .with_context(|| format!("could not write {}", p.display()))?;
                    println!("Report written to {}", p.display());
                }
                None => print!("{text}"),
            }
            Ok(if rep.verification.is_valid() {
                OK
            } else {
                FINDINGS
            })
        }
    }
}

fn inspect(path: &Path, excludes: &[String], as_json: bool) -> Result<u8> {
    let inv: Inventory = inventory::scan(
        path,
        &ScanOptions {
            excludes,
            skip_paths: &[],
        },
    )?;
    let root = std::fs::canonicalize(path)?;
    let unity_info = unity::detect(&root);
    let warnings = unity::warnings(unity_info.as_ref(), &inv);
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    if as_json {
        let out = json!({
            "root_name": name,
            "file_count": inv.files.len(),
            "total_bytes": inv.total_bytes(),
            "logical_inventory_sha256": inv.logical_digest(),
            "unity": unity_info,
            "warnings": warnings,
            "excluded": inv.excluded,
            "unmatched_excludes": inv.unmatched_excludes,
            "skipped": inv.skipped,
            "errors": inv.errors,
            "files": inv.files,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Directory: {name}");
        println!(
            "Files: {}   Content: {}",
            inv.files.len(),
            human_bytes(inv.total_bytes())
        );
        println!("Logical inventory (sha256): {}", inv.logical_digest());
        if let Some(u) = &unity_info {
            println!(
                "Unity: Editor {} declared; {} package(s) in Packages/manifest.json",
                u.editor_version.as_deref().unwrap_or("(unknown)"),
                u.packages.len()
            );
        } else {
            println!("Unity: ProjectSettings/ProjectVersion.txt not found (generic directory)");
        }
        print_list("Excluded", inv.excluded.iter().cloned(), 20);
        print_list(
            "Skipped",
            inv.skipped
                .iter()
                .map(|s| format!("{} ({})", s.path, s.reason)),
            20,
        );
        for w in &warnings {
            println!("warning [{}]: {}", w.code, w.message);
        }
        print_list(
            "READ ERRORS",
            inv.errors
                .iter()
                .map(|e| format!("{}: {}", e.path, e.error)),
            20,
        );
    }
    Ok(if inv.errors.is_empty() { OK } else { FINDINGS })
}

fn print_list(title: &str, items: impl Iterator<Item = String>, max: usize) {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        return;
    }
    println!("{title} ({}):", items.len());
    for i in items.iter().take(max) {
        println!("  - {i}");
    }
    if items.len() > max {
        println!("  ... and {} more", items.len() - max);
    }
}

fn print_verify(package: &Path, rep: &VerifyReport) {
    println!("Package: {}", package.display());
    let label = match rep.status {
        VerifyStatus::Valid => "VALID (internal integrity confirmed)",
        VerifyStatus::FailedIntegrity => "INTEGRITY FAILURE",
        VerifyStatus::PolicyViolation => "EXPORT POLICY VIOLATION",
        VerifyStatus::InvalidPackage => "INVALID PACKAGE",
    };
    println!("Status: {label}");
    println!("Files checked: {}", rep.files_checked);
    print_list("Missing", rep.missing.iter().cloned(), 50);
    print_list(
        "Modified",
        rep.modified.iter().map(|m| match &m.note {
            Some(n) => format!("{} ({n})", m.path),
            None => m.path.clone(),
        }),
        50,
    );
    print_list("Unexpected", rep.unexpected.iter().cloned(), 50);
    print_list("Integrity errors", rep.integrity_errors.iter().cloned(), 50);
    print_list("Format errors", rep.schema_errors.iter().cloned(), 50);
    print_list(
        "Policy violations",
        rep.policy_violations.iter().cloned(),
        50,
    );
    if rep.is_valid() {
        println!("Signature: none (verification does not prove authorship).");
    }
}

fn print_check(path: &Path, rep: &CheckReport) {
    let e = &rep.export;
    println!("Directory: {}", path.display());
    match &e.policy_sha256 {
        Some(h) => println!("Policy applied (sha256 {}…)", &h[..12]),
        None => println!("Policy: none (permissive default: approved + unreviewed)"),
    }
    println!("Components:");
    for c in &e.components {
        println!(
            "  {:<32} {:<14} {:<9} {:>7} files {:>10}   {}",
            c.id,
            c.redistribution,
            if c.included { "INCLUDED" } else { "OMITTED" },
            c.files,
            human_bytes(c.bytes),
            c.origin_path.as_deref().unwrap_or("(root)")
        );
    }
    println!(
        "Will be exported: {} file(s), {}",
        e.included_files,
        human_bytes(e.included_bytes)
    );
    if e.omitted_files > 0 {
        println!(
            "Omitted by policy: {} file(s), {} (hashes recorded in integrity/external.json)",
            e.omitted_files,
            human_bytes(e.omitted_bytes)
        );
    }
    println!(
        "Secret scan: {} text file(s) scanned, {} binary and {} large file(s) not scanned{}",
        e.secrets.scanned_files,
        e.secrets.skipped_binary,
        e.secrets.skipped_large,
        if e.secrets.truncated {
            " (result truncated)"
        } else {
            ""
        }
    );
    let fmt = |f: &tessel_core::secrets::Finding| {
        if f.line == 0 {
            format!("{} [{}]", f.path, f.rule)
        } else {
            format!("{}:{} [{}]", f.path, f.line, f.rule)
        }
    };
    print_list(
        "BLOCKING FINDINGS",
        e.secrets
            .findings
            .iter()
            .filter(|f| f.severity.blocks())
            .map(fmt),
        30,
    );
    print_list(
        "Informational findings",
        e.secrets
            .findings
            .iter()
            .filter(|f| !f.severity.blocks())
            .map(fmt),
        10,
    );
    print_list(
        "READ ERRORS",
        rep.inventory_errors
            .iter()
            .map(|x| format!("{}: {}", x.path, x.error)),
        20,
    );
    print_list("SCAN FAILURES", rep.secret_scan_errors.iter().cloned(), 20);
    print_list(
        "Warnings",
        e.warnings
            .iter()
            .map(|w| format!("[{}] {}", w.code, w.message)),
        20,
    );
    if rep.allowed {
        println!("Result: EXPORT ALLOWED");
    } else {
        println!("Result: EXPORT BLOCKED");
        for r in &rep.blocking_reasons {
            println!("  - {r}");
        }
    }
}

fn print_diff(d: &DiffReport) {
    if d.identical {
        println!("Directories are identical ({} file(s)).", d.unchanged);
        return;
    }
    println!(
        "Differences: {} added, {} removed, {} modified, {} unchanged",
        d.added.len(),
        d.removed.len(),
        d.modified.len(),
        d.unchanged
    );
    print_list("Added (right only)", d.added.iter().cloned(), 50);
    print_list("Removed (left only)", d.removed.iter().cloned(), 50);
    print_list(
        "Modified",
        d.modified
            .iter()
            .map(|m| format!("{} ({} -> {} bytes)", m.path, m.left_size, m.right_size)),
        50,
    );
    print_list(
        "READ ERRORS (left)",
        d.left_errors
            .iter()
            .map(|e| format!("{}: {}", e.path, e.error)),
        20,
    );
    print_list(
        "READ ERRORS (right)",
        d.right_errors
            .iter()
            .map(|e| format!("{}: {}", e.path, e.error)),
        20,
    );
}

fn print_analysis(a: &Analysis) {
    println!("Static analysis of {}", a.root_name);
    println!("  {} file(s), {}", a.files, human_bytes(a.total_bytes));
    if !a.by_format.is_empty() {
        let fmts: Vec<String> = a
            .by_format
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        println!("  formats: {}", fmts.join(", "));
    }
    if let Some(b) = &a.unity_build {
        println!("Unity build:");
        println!("  platform: {}", b.platform);
        println!("  scripting backend: {}", b.scripting_backend);
        println!(
            "  Editor version: {}",
            b.unity_version.as_deref().unwrap_or("not detected")
        );
        if let Some(v) = b.il2cpp_metadata_version {
            println!("  IL2CPP metadata version: {v}");
        }
        if let Some(i) = &b.app_info {
            println!(
                "  app.info: company={} product={}",
                i.company.as_deref().unwrap_or("?"),
                i.product.as_deref().unwrap_or("?")
            );
        }
        if !b.project_assemblies.is_empty() {
            println!("  project assemblies: {}", b.project_assemblies.join(", "));
        }
        for n in &b.notes {
            println!("  note: {n}");
        }
    }
    if let Some(c) = &a.source_comparison {
        println!("Comparison with source (by name only):");
        println!(
            "  Editor version: project={} build={} -> {}",
            c.unity_version
                .declared_by_project
                .as_deref()
                .unwrap_or("?"),
            c.unity_version.found_in_build.as_deref().unwrap_or("?"),
            c.unity_version.status
        );
        println!("  assemblies: {}", c.assemblies);
        print_list("Missing from build", c.missing_in_build.iter().cloned(), 30);
        print_list("Build only", c.build_only.iter().cloned(), 30);
    }
    println!("Binaries: {}", a.binaries.len());
    print_list(
        "Binaries",
        a.binaries.iter().map(|b| {
            format!(
                "{} [{} {} {}{}]",
                b.path,
                b.format.as_str(),
                b.arch.as_deref().unwrap_or("?"),
                b.kind.as_deref().unwrap_or("?"),
                if b.managed_dotnet == Some(true) {
                    ", managed .NET"
                } else {
                    ""
                }
            )
        }),
        40,
    );
    print_list(
        "FINDINGS",
        a.findings.iter().map(|f| {
            format!(
                "[{}] {}{}",
                f.code,
                f.path
                    .as_deref()
                    .map(|p| format!("{p}: "))
                    .unwrap_or_default(),
                f.message
            )
        }),
        30,
    );
    print_list(
        "READ ERRORS",
        a.errors.iter().map(|e| format!("{}: {}", e.path, e.error)),
        20,
    );
    for u in &a.unmatched_excludes {
        println!("warning: --exclude '{u}' did not match any path");
    }
}
