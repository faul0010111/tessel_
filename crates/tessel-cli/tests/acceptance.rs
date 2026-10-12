//! Acceptance tests for the CLI (eight acceptance criteria) and TSP validation rules.
//!
//! The numbered tests `crit1_...` to `crit8_...` correspond to the eight acceptance criteria.

use serde_json::Value;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

// ---------------------------------------------------------------- helpers

fn tessel(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tessel"))
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("failed to run tessel")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("process terminated by signal")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn fixture_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "ProjectSettings/ProjectVersion.txt",
            b"m_EditorVersion: 6000.3.0f1\nm_EditorVersionWithRevision: 6000.3.0f1 (abc123)\n"
                .to_vec(),
        ),
        (
            "Packages/manifest.json",
            br#"{"dependencies":{"com.unity.test-framework":"1.4.5"}}"#.to_vec(),
        ),
        (
            "Packages/packages-lock.json",
            br#"{"dependencies":{}}"#.to_vec(),
        ),
        (
            "Assets/Scripts/Player.cs",
            b"public class Player { }\n".to_vec(),
        ),
        (
            "Assets/Scripts/Player.cs.meta",
            b"fileFormatVersion: 2\nguid: 0123456789abcdef0123456789abcdef\n".to_vec(),
        ),
        (
            "Assets/Scenes/Main.unity",
            b"%YAML 1.1\n--- !u!29 &1\nOcclusionCullingSettings:\n".to_vec(),
        ),
        (
            "Assets/Plugins/native.bin",
            (0..=255u8).cycle().take(100_000).collect(),
        ),
        ("Library/cache.bin", vec![7u8; 4096]),
        ("Temp/x.tmp", b"tmp".to_vec()),
        ("Logs/editor.log", b"log".to_vec()),
    ]
}

fn write_file(root: &Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

fn make_fixture(root: &Path, reverse: bool) {
    let mut files = fixture_files();
    if reverse {
        files.reverse();
    }
    for (rel, content) in files {
        write_file(root, rel, &content);
    }
}

const EXCLUDES: [&str; 6] = [
    "--exclude",
    "Library",
    "--exclude",
    "Temp",
    "--exclude",
    "Logs",
];

fn package(project: &Path, out: &Path, extra: &[&str]) -> Output {
    let mut args: Vec<&str> = vec!["package", s(project), "--output", s(out)];
    args.extend_from_slice(&EXCLUDES);
    args.extend_from_slice(extra);
    tessel(&args)
}

/// Fixture project + generated package. Returns (tempdir, project, zip).
fn packaged() -> (TempDir, PathBuf, PathBuf) {
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    make_fixture(&proj, false);
    let zip = base.path().join("proj.tsp.zip");
    let o = package(&proj, &zip, &[]);
    assert_eq!(code(&o), 0, "package failed: {}", stderr(&o));
    (base, proj, zip)
}

fn verify_json(zip: &Path) -> (i32, Value) {
    let o = tessel(&["verify", s(zip), "--json"]);
    let v = serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON ({e}): {}", stdout(&o)));
    (code(&o), v)
}

type Entries = Vec<(String, Vec<u8>)>;

fn read_zip(path: &Path) -> Entries {
    let mut a = ZipArchive::new(File::open(path).unwrap()).unwrap();
    let mut out = Vec::new();
    for i in 0..a.len() {
        let mut f = a.by_index(i).unwrap();
        if f.is_dir() {
            continue;
        }
        let mut b = Vec::new();
        f.read_to_end(&mut b).unwrap();
        out.push((f.name().to_string(), b));
    }
    out
}

fn write_zip(path: &Path, entries: &Entries) {
    let mut w = ZipWriter::new(File::create(path).unwrap());
    let o = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for (n, b) in entries {
        w.start_file(n.as_str(), o).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap();
}

fn tamper(src: &Path, dst: &Path, f: impl FnOnce(&mut Entries)) {
    let mut e = read_zip(src);
    f(&mut e);
    write_zip(dst, &e);
}

fn edit_manifest(src: &Path, dst: &Path, f: impl FnOnce(&mut Value)) {
    tamper(src, dst, |e| {
        let m = e.iter_mut().find(|(n, _)| n == "manifest.json").unwrap();
        let mut v: Value = serde_json::from_slice(&m.1).unwrap();
        f(&mut v);
        m.1 = serde_json::to_vec_pretty(&v).unwrap();
    });
}

fn entry_names(zip: &Path) -> Vec<String> {
    read_zip(zip).into_iter().map(|(n, _)| n).collect()
}

fn entry_bytes(zip: &Path, name: &str) -> Vec<u8> {
    read_zip(zip)
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("entry {name} missing"))
        .1
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------- criteria 1–8

#[test]
fn crit1_fixture_generates_package_and_verifies_again() {
    let (base, _proj, zip) = packaged();

    let names = entry_names(&zip);
    for expected in [
        "manifest.json",
        "integrity/files.json",
        "provenance/components.jsonl",
        "reports/inventory.json",
        "environments/unity.json",
        "source/Assets/Scripts/Player.cs",
        "source/Assets/Scripts/Player.cs.meta",
        "source/Packages/manifest.json",
        "source/ProjectSettings/ProjectVersion.txt",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing {expected}: {names:?}"
        );
    }
    for n in &names {
        assert!(
            !n.starts_with("source/Library/")
                && !n.starts_with("source/Temp/")
                && !n.starts_with("source/Logs/"),
            "exclusion ignored: {n}"
        );
        assert!(
            !n.starts_with('/') && !n.contains(".."),
            "unsafe path in the package: {n}"
        );
    }
    assert!(!base.path().join("proj.tsp.zip.partial").exists());

    let (c, v) = verify_json(&zip);
    assert_eq!(c, 0);
    assert_eq!(v["status"], "valid");
    assert_eq!(v["signature"], "not_present");
    assert!(v["files_checked"].as_u64().unwrap() >= 8);

    // The manifest does not assert anything that was not verified.
    let m: Value = serde_json::from_slice(&entry_bytes(&zip, "manifest.json")).unwrap();
    assert_eq!(m["format"], "TSP");
    assert_eq!(m["engine"]["editor_version"], "6000.3.0f1");
    assert_eq!(m["reproducibility"]["restoration"]["status"], "not_tested");
    assert_eq!(m["authorization"]["status"], "unspecified");
    assert_eq!(
        m["authorization"]["approved_operations"],
        serde_json::json!([])
    );
    assert_eq!(m["components"][0]["redistribution"], "unreviewed");

    // The text output also returns 0.
    let o = tessel(&["verify", s(&zip)]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("VALID"));
}

#[test]
fn crit2_flipping_one_byte_fails_integrity() {
    let (base, _proj, zip) = packaged();
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        let f = e
            .iter_mut()
            .find(|(n, _)| n == "source/Assets/Scripts/Player.cs")
            .unwrap();
        f.1[3] ^= 0x01;
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "failed_integrity");
    let modified: Vec<&str> = v["modified"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["path"].as_str().unwrap())
        .collect();
    assert_eq!(modified, vec!["source/Assets/Scripts/Player.cs"]);
    assert!(v["missing"].as_array().unwrap().is_empty());
    assert!(v["unexpected"].as_array().unwrap().is_empty());

    let o = tessel(&["verify", s(&bad)]);
    assert_eq!(code(&o), 1);
    assert!(stdout(&o).contains("INTEGRITY FAILURE"));
}

#[test]
fn crit3_removed_file_is_reported_missing() {
    let (base, _proj, zip) = packaged();
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        e.retain(|(n, _)| n != "source/Assets/Scenes/Main.unity")
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "failed_integrity");
    assert_eq!(
        strings(&v["missing"]),
        vec!["source/Assets/Scenes/Main.unity"]
    );
}

#[test]
fn crit4_unexpected_files_are_detected() {
    let (base, _proj, zip) = packaged();
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        e.push(("source/Assets/evil.cs".into(), b"class Evil {}".to_vec()));
        e.push(("stray.txt".into(), b"x".to_vec()));
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "failed_integrity");
    assert_eq!(
        strings(&v["unexpected"]),
        vec!["source/Assets/evil.cs", "stray.txt"]
    );
}

#[cfg(unix)]
#[test]
fn crit5_symlink_pointing_outside_root_never_copies_external_files() {
    use std::os::unix::fs::symlink;
    let base = tempfile::tempdir().unwrap();
    let outside = base.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"TOPSECRET-12345").unwrap();

    let proj = base.path().join("proj");
    make_fixture(&proj, false);
    symlink(outside.join("secret.txt"), proj.join("Assets/leak.txt")).unwrap();
    symlink(&outside, proj.join("Assets/leakdir")).unwrap();
    symlink("/etc/hostname", proj.join("Assets/abs-leak")).unwrap();
    symlink("nonexistent-target", proj.join("Assets/dangling")).unwrap();

    let zip = base.path().join("p.tsp.zip");
    let o = package(&proj, &zip, &[]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));

    for (name, bytes) in read_zip(&zip) {
        assert!(
            !name.contains("leak") && !name.contains("dangling"),
            "symlink entered the package: {name}"
        );
        assert!(
            !bytes.windows(9).any(|w| w == b"TOPSECRET"),
            "external content leaked into {name}"
        );
    }
    let (c, _) = verify_json(&zip);
    assert_eq!(c, 0);

    // The links are recorded as skipped; they do not silently disappear.
    let o = tessel(&["inspect", s(&proj), "--json"]);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let skipped: Vec<(String, String)> = v["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["path"].as_str().unwrap().into(),
                x["reason"].as_str().unwrap().into(),
            )
        })
        .collect();
    for link in [
        "Assets/leak.txt",
        "Assets/leakdir",
        "Assets/abs-leak",
        "Assets/dangling",
    ] {
        assert!(
            skipped.contains(&(link.to_string(), "symlink".to_string())),
            "{link} not recorded: {skipped:?}"
        );
    }
}

#[test]
fn crit5b_verify_rejects_symlink_and_traversal_entries() {
    let (base, _proj, zip) = packaged();

    // Names with traversal / absolute / backslash.
    for evil in [
        "source/../evil.txt",
        "/abs/evil.txt",
        "source\\evil.txt",
        "C:/evil.txt",
    ] {
        let bad = base.path().join("bad.zip");
        tamper(&zip, &bad, |e| e.push((evil.to_string(), b"x".to_vec())));
        let (c, v) = verify_json(&bad);
        assert_eq!(c, 1, "{evil}");
        assert_eq!(v["status"], "invalid_package", "{evil}");
        assert!(
            strings(&v["schema_errors"])
                .iter()
                .any(|e| e.contains("unsafe")),
            "{evil}: {v}"
        );
    }

    // Entry that is a symlink.
    let bad = base.path().join("sym.zip");
    {
        let mut w = ZipWriter::new(File::create(&bad).unwrap());
        for (n, b) in read_zip(&zip) {
            w.start_file(
                n.as_str(),
                SimpleFileOptions::default().unix_permissions(0o644),
            )
            .unwrap();
            w.write_all(&b).unwrap();
        }
        w.add_symlink(
            "source/Assets/link",
            "/etc/passwd",
            SimpleFileOptions::default(),
        )
        .unwrap();
        w.finish().unwrap();
    }
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "invalid_package");
    assert!(
        strings(&v["schema_errors"])
            .iter()
            .any(|e| e.contains("symlink"))
    );
}

#[cfg(unix)]
#[test]
fn crit6_read_failure_never_produces_a_valid_package() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    make_fixture(&proj, false);
    let locked = proj.join("Assets/locked.bin");
    fs::write(&locked, b"data").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

    if File::open(&locked).is_ok() {
        // root ignores file permissions; the case is covered by crit6b at library level.
        eprintln!("crit6: skipped (running as root, chmod 000 does not prevent reading)");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }

    let zip = base.path().join("p.tsp.zip");
    let o = package(&proj, &zip, &[]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(code(&o), 2, "stdout={} stderr={}", stdout(&o), stderr(&o));
    assert!(stderr(&o).contains("locked.bin"), "{}", stderr(&o));
    assert!(!zip.exists(), "package should not exist");
    assert!(!base.path().join("p.tsp.zip.partial").exists());
}

#[test]
fn crit6b_inventory_errors_block_packaging() {
    use tessel_core::inventory::{Inventory, ScanError};
    use tessel_core::package::ensure_packageable;

    let mut inv = Inventory::default();
    inv.files.push(tessel_core::inventory::FileEntry {
        path: "a.txt".into(),
        size: 1,
        sha256: "0".repeat(64),
    });
    assert!(ensure_packageable(&inv).is_ok());
    inv.errors.push(ScanError {
        path: "locked.bin".into(),
        error: "read failure: permission denied".into(),
    });
    let err = ensure_packageable(&inv).unwrap_err().to_string();
    assert!(err.contains("locked.bin"), "{err}");
}

#[test]
fn crit6c_unreadable_directory_entry_is_an_error_for_inspect() {
    // Nonexistent directory: execution error (2), never a "valid" empty inventory.
    let base = tempfile::tempdir().unwrap();
    let o = tessel(&["inspect", s(&base.path().join("does-not-exist"))]);
    assert_eq!(code(&o), 2);
    let o = tessel(&["verify", s(&base.path().join("does-not-exist.zip"))]);
    assert_eq!(code(&o), 2);
}

#[test]
fn crit7_inspection_never_executes_project_code() {
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    make_fixture(&proj, false);
    write_file(
        &proj,
        "Assets/Editor/Build.cs",
        b"public static class Build { public static void Run() {} }",
    );
    write_file(
        &proj,
        "Assets/Editor/run.sh",
        b"#!/bin/sh\ntouch \"$(dirname \"$0\")/EXECUTED\"\ntouch /tmp/tessel-executed-marker-should-not-exist\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            proj.join("Assets/Editor/run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let zip = base.path().join("p.tsp.zip");
    assert_eq!(code(&tessel(&["inspect", s(&proj)])), 0);
    assert_eq!(code(&package(&proj, &zip, &[])), 0);
    assert_eq!(code(&tessel(&["verify", s(&zip)])), 0);
    assert_eq!(code(&tessel(&["report", s(&zip)])), 0);
    assert!(
        !proj.join("Assets/Editor/EXECUTED").exists(),
        "project script was executed!"
    );
    assert!(!Path::new("/tmp/tessel-executed-marker-should-not-exist").exists());
}

#[test]
fn crit7b_source_never_spawns_processes() {
    // Static guard: the crate must not contain any process-execution API.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let forbidden = [
        "process::Command",
        "Command::new",
        "CommandExt",
        "libc::exec",
        "libloading",
    ];
    for entry in fs::read_dir(&src).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&p).unwrap();
            for f in forbidden {
                // Comments describing the guarantee ("no function ... spawns processes") do not contain these tokens.
                assert!(!text.contains(f), "{} usa {f}", p.display());
            }
        }
    }
}

#[test]
fn crit8_logical_inventory_is_independent_of_enumeration_order() {
    // Two directories with the same content, created in opposite orders and at different times.
    let base_a = tempfile::tempdir().unwrap();
    let base_b = tempfile::tempdir().unwrap();
    let a = base_a.path().join("proj");
    let b = base_b.path().join("proj");
    make_fixture(&a, false);
    std::thread::sleep(std::time::Duration::from_millis(20));
    make_fixture(&b, true);

    let digest = |p: &Path| -> String {
        let o = tessel(&["inspect", s(p), "--json"]);
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        v["logical_inventory_sha256"].as_str().unwrap().to_string()
    };
    assert_eq!(digest(&a), digest(&b));
    // Second run over the same content.
    assert_eq!(digest(&a), digest(&a));

    let za = base_a.path().join("a.tsp.zip");
    let zb = base_b.path().join("b.tsp.zip");
    assert_eq!(code(&package(&a, &za, &[])), 0);
    assert_eq!(code(&package(&b, &zb, &[])), 0);

    let ma: Value = serde_json::from_slice(&entry_bytes(&za, "manifest.json")).unwrap();
    let mb: Value = serde_json::from_slice(&entry_bytes(&zb, "manifest.json")).unwrap();
    assert_eq!(ma["integrity"], mb["integrity"]);
    assert_eq!(
        entry_bytes(&za, "integrity/files.json"),
        entry_bytes(&zb, "integrity/files.json")
    );
    // The package digest is the same one `inspect` computes with the same exclusions.
    let mut args = vec!["inspect", s(&a), "--json"];
    args.extend_from_slice(&EXCLUDES);
    let v: Value = serde_json::from_slice(&tessel(&args).stdout).unwrap();
    assert_eq!(
        ma["integrity"]["logical_inventory_sha256"],
        v["logical_inventory_sha256"]
    );
}

#[test]
fn crit8b_zip_bytes_are_reproducible_with_fixed_date() {
    // Bonus beyond the criterion: with SOURCE_DATE_EPOCH the ZIP itself comes out identical.
    let base_a = tempfile::tempdir().unwrap();
    let base_b = tempfile::tempdir().unwrap();
    let a = base_a.path().join("proj");
    let b = base_b.path().join("proj");
    make_fixture(&a, false);
    make_fixture(&b, true);
    let za = base_a.path().join("a.tsp.zip");
    let zb = base_b.path().join("b.tsp.zip");
    assert_eq!(code(&package(&a, &za, &[])), 0);
    assert_eq!(code(&package(&b, &zb, &[])), 0);
    assert_eq!(fs::read(&za).unwrap(), fs::read(&zb).unwrap());
}

// ---------------------------------------------------------------- CLI behaviour

#[test]
fn package_refuses_overwrite_without_force() {
    let (base, proj, zip) = packaged();
    let o = package(&proj, &zip, &[]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("--force"));
    assert_eq!(code(&package(&proj, &zip, &["--force"])), 0);
    assert!(!base.path().join("proj.tsp.zip.partial").exists());
}

#[test]
fn package_output_inside_project_is_not_included_in_itself() {
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    make_fixture(&proj, false);
    let zip = proj.join("out.tsp.zip");
    assert_eq!(code(&package(&proj, &zip, &[])), 0);
    assert_eq!(code(&package(&proj, &zip, &["--force"])), 0);
    assert!(entry_names(&zip).iter().all(|n| !n.contains("out.tsp.zip")));
    assert_eq!(code(&tessel(&["verify", s(&zip)])), 0);
}

#[test]
fn package_fails_when_everything_is_excluded() {
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    write_file(&proj, "a.txt", b"x");
    let zip = base.path().join("p.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip), "--exclude", "a.txt"]);
    assert_eq!(code(&o), 2);
    assert!(!zip.exists());
}

#[test]
fn excludes_are_root_anchored_and_unmatched_ones_warn() {
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    make_fixture(&proj, false);
    // "Library" nested under Assets must NOT be excluded by --exclude Library.
    write_file(&proj, "Assets/Library/keep.cs", b"class Keep {}");
    let o = tessel(&[
        "inspect",
        s(&proj),
        "--json",
        "--exclude",
        "Library",
        "--exclude",
        "Typo",
    ]);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let files = strings(&Value::Array(
        v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].clone())
            .collect(),
    ));
    assert!(files.contains(&"Assets/Library/keep.cs".to_string()));
    assert!(!files.iter().any(|f| f.starts_with("Library/")));
    assert_eq!(strings(&v["unmatched_excludes"]), vec!["Typo"]);
    assert!(
        v["warnings"]
            .to_string()
            .contains("exclude_matched_nothing")
    );
}

#[test]
fn warns_when_required_unity_dir_is_excluded() {
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    make_fixture(&proj, false);
    let o = tessel(&[
        "inspect",
        s(&proj),
        "--json",
        "--exclude",
        "ProjectSettings",
    ]);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(
        v["warnings"].to_string().contains("required_dir_excluded"),
        "{}",
        v["warnings"]
    );
}

#[test]
fn diff_reports_added_removed_modified_and_identical() {
    let base = tempfile::tempdir().unwrap();
    let a = base.path().join("build-original");
    let b = base.path().join("build-reproduced");
    write_file(&a, "game.dll", b"v1");
    write_file(&a, "data/level.bin", b"L");
    write_file(&a, "only-left.txt", b"x");
    write_file(&b, "game.dll", b"v2");
    write_file(&b, "data/level.bin", b"L");
    write_file(&b, "only-right.txt", b"y");

    let o = tessel(&["diff", s(&a), s(&b), "--json"]);
    assert_eq!(code(&o), 1);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["identical"], false);
    assert_eq!(strings(&v["added"]), vec!["only-right.txt"]);
    assert_eq!(strings(&v["removed"]), vec!["only-left.txt"]);
    assert_eq!(v["modified"][0]["path"], "game.dll");
    assert_eq!(v["unchanged"], 1);

    let o = tessel(&["diff", s(&a), s(&a)]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("identical"));
}

#[test]
fn report_summarizes_package_and_exit_code_reflects_validity() {
    let (base, _proj, zip) = packaged();
    let out = base.path().join("report.json");
    let o = tessel(&["report", s(&zip), "--output", s(&out)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["verification"]["status"], "valid");
    assert_eq!(v["summary"]["project_name"], "proj");
    assert_eq!(v["summary"]["restoration_status"], "not_tested");
    assert!(
        v["summary"]["by_top_level"]["Assets"]["files"]
            .as_u64()
            .unwrap()
            >= 4
    );
    assert_eq!(v["package"]["file_name"], "proj.tsp.zip");
    assert_eq!(v["package"]["sha256"].as_str().unwrap().len(), 64);
    assert!(v["packaging"]["excluded"].to_string().contains("Library"));
    assert!(!v["limitations"].as_array().unwrap().is_empty());

    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        e.retain(|(n, _)| n != "source/Assets/Scenes/Main.unity")
    });
    let o = tessel(&["report", s(&bad)]);
    assert_eq!(code(&o), 1);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["verification"]["status"], "failed_integrity");
    assert!(v["packaging"].is_null());
}

#[test]
fn garbage_file_is_an_invalid_package() {
    let base = tempfile::tempdir().unwrap();
    let p = base.path().join("garbage.zip");
    fs::write(&p, b"this is not a zip").unwrap();
    let (c, v) = verify_json(&p);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "invalid_package");
}

#[test]
fn missing_manifest_is_an_invalid_package() {
    let (base, _proj, zip) = packaged();
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| e.retain(|(n, _)| n != "manifest.json"));
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "invalid_package");
}

// ---------------------------------------------------------------- validation rules of tsp-core

fn assert_manifest_rejected(edit: impl FnOnce(&mut Value), status: &str, needle: &str) {
    let (base, _proj, zip) = packaged();
    let bad = base.path().join("bad.zip");
    edit_manifest(&zip, &bad, edit);
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1, "{v}");
    assert_eq!(v["status"], status, "{v}");
    let all = format!("{} {}", v["schema_errors"], v["integrity_errors"]);
    assert!(all.contains(needle), "expected {needle:?} in {all}");
}

#[test]
fn tsp_rejects_unknown_schema_version() {
    assert_manifest_rejected(
        |m| m["format_version"] = "2.0.0".into(),
        "invalid_package",
        "format_version",
    );
}

#[test]
fn tsp_rejects_wrong_format_name() {
    assert_manifest_rejected(
        |m| m["format"] = "ZIP".into(),
        "invalid_package",
        "format must be",
    );
}

#[test]
fn tsp_rejects_missing_required_fields() {
    assert_manifest_rejected(
        |m| {
            m.as_object_mut().unwrap().remove("integrity");
        },
        "invalid_package",
        "invalid manifest",
    );
}

#[test]
fn tsp_rejects_references_to_nonexistent_files() {
    assert_manifest_rejected(
        |m| m["reproducibility"]["build_recipe"] = "build/build.json".into(),
        "invalid_package",
        "does not exist",
    );
}

#[test]
fn tsp_rejects_unsafe_manifest_paths() {
    assert_manifest_rejected(
        |m| m["components"][0]["provenance_ref"] = "../../etc/passwd".into(),
        "invalid_package",
        "unsafe",
    );
    assert_manifest_rejected(
        |m| m["integrity"]["inventory_path"] = "/abs/files.json".into(),
        "invalid_package",
        "unsafe",
    );
}

#[test]
fn tsp_rejects_malformed_hashes() {
    assert_manifest_rejected(
        |m| m["integrity"]["logical_inventory_sha256"] = "XYZ".into(),
        "invalid_package",
        "malformed",
    );
    assert_manifest_rejected(
        |m| m["metadata_files"][0]["sha256"] = "ABC".into(),
        "invalid_package",
        "malformed hash",
    );
}

#[test]
fn tsp_detects_hashes_that_do_not_match_files() {
    assert_manifest_rejected(
        |m| m["integrity"]["inventory_sha256"] = "0".repeat(64).into(),
        "failed_integrity",
        "SHA-256",
    );
    assert_manifest_rejected(
        |m| m["integrity"]["logical_inventory_sha256"] = "0".repeat(64).into(),
        "failed_integrity",
        "logical inventory digest",
    );
    assert_manifest_rejected(
        |m| m["metadata_files"][0]["sha256"] = "0".repeat(64).into(),
        "failed_integrity",
        "",
    );
    assert_manifest_rejected(
        |m| m["integrity"]["file_count"] = 999.into(),
        "failed_integrity",
        "count",
    );
}

#[test]
fn tsp_rejects_blocked_component_included_in_export() {
    assert_manifest_rejected(
        |m| {
            m["components"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "id": "component-commercial-sdk",
                    "kind": "dependency",
                    "path": "source/Assets/Plugins",
                    "redistribution": "not_permitted"
                }));
        },
        "invalid_package",
        "blocked component included",
    );
}

#[test]
fn tsp_allows_external_blocked_dependency_without_including_it() {
    let (base, _proj, zip) = packaged();
    let ok = base.path().join("ok.zip");
    edit_manifest(&zip, &ok, |m| {
        m["components"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": "component-commercial-sdk",
                "kind": "dependency",
                "version": "7.0",
                "redistribution": "not_permitted",
                "availability": "external_authorized_acquisition"
            }));
    });
    let (c, v) = verify_json(&ok);
    assert_eq!((c, v["status"].as_str().unwrap()), (0, "valid"), "{v}");
}

#[test]
fn tsp_rejects_restoration_success_without_evidence() {
    assert_manifest_rejected(
        |m| m["reproducibility"]["restoration"]["status"] = "success".into(),
        "invalid_package",
        "without test evidence",
    );
    assert_manifest_rejected(
        |m| m["reproducibility"]["restoration"]["status"] = "great".into(),
        "invalid_package",
        "restoration.status",
    );
}

#[test]
fn tsp_rejects_references_without_hash_protection() {
    // The file exists in the package, but is not in metadata_files: it could be tampered with undetected.
    let (base, _proj, zip) = packaged();
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        e.push(("docs/deps.json".into(), b"{}".to_vec()))
    });
    let bad2 = base.path().join("bad2.zip");
    edit_manifest(&bad, &bad2, |m| {
        m["components"][0]["instructions_ref"] = "docs/deps.json".into();
    });
    let (c, v) = verify_json(&bad2);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "invalid_package");
    assert!(v["schema_errors"].to_string().contains("no hash"), "{v}");
}

#[test]
fn tampering_with_inventory_and_metadata_is_detected() {
    let (base, _proj, zip) = packaged();

    // Tamper with files.json without updating the manifest.
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        let f = e
            .iter_mut()
            .find(|(n, _)| n == "integrity/files.json")
            .unwrap();
        let mut v: Value = serde_json::from_slice(&f.1).unwrap();
        v["files"][0]["size"] = 12345.into();
        f.1 = serde_json::to_vec_pretty(&v).unwrap();
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "failed_integrity");

    // Tamper with a metadata file.
    let bad = base.path().join("bad2.zip");
    tamper(&zip, &bad, |e| {
        let f = e
            .iter_mut()
            .find(|(n, _)| n == "provenance/components.jsonl")
            .unwrap();
        f.1.extend_from_slice(b"{\"forged\":true}\n");
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(
        strings(&Value::Array(
            v["modified"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["path"].clone())
                .collect()
        )),
        vec!["provenance/components.jsonl"]
    );
}
