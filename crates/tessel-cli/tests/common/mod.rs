//! Helpers shared by the integration tests (policy, secrets, binaries).
#![allow(dead_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub fn tessel(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tessel"))
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("failed to run tessel")
}

pub fn code(o: &Output) -> i32 {
    o.status.code().expect("process terminated by signal")
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

pub fn write_file(root: &Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

/// Minimal Unity project with a "commercial SDK" in Assets/Plugins/Vendor.
pub fn make_project(root: &Path) {
    write_file(
        root,
        "ProjectSettings/ProjectVersion.txt",
        b"m_EditorVersion: 6000.3.0f1\nm_EditorVersionWithRevision: 6000.3.0f1 (abc123)\n",
    );
    write_file(
        root,
        "Packages/manifest.json",
        br#"{"dependencies":{"com.unity.test-framework":"1.4.5"}}"#,
    );
    write_file(
        root,
        "Packages/packages-lock.json",
        br#"{"dependencies":{}}"#,
    );
    write_file(
        root,
        "Assets/Scripts/Player.cs",
        b"public class Player { }\n",
    );
    write_file(
        root,
        "Assets/Scripts/Player.cs.meta",
        b"fileFormatVersion: 2\nguid: 0123456789abcdef0123456789abcdef\n",
    );
    write_file(
        root,
        "Assets/Scenes/Main.unity",
        b"%YAML 1.1\n--- !u!29 &1\nOcclusionCullingSettings:\n",
    );
    write_file(
        root,
        "Assets/Plugins/Vendor/sdk.dll",
        &(0..=255u8).cycle().take(5000).collect::<Vec<u8>>(),
    );
    write_file(
        root,
        "Assets/Plugins/Vendor/README.txt",
        b"Vendor SDK 7.0 - proprietary\n",
    );
}

pub const POLICY: &str = r#"{
  "version": 1,
  "components": [
    {"id": "game-source", "kind": "source", "path": "Assets/Scripts", "redistribution": "approved", "license": "MIT"},
    {"id": "commercial-sdk", "kind": "dependency", "path": "Assets/Plugins/Vendor/", "version": "7.0",
     "redistribution": "not_permitted", "availability": "external_authorized_acquisition",
     "license": "LicenseRef-Vendor-EULA"}
  ]
}"#;

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub type Entries = Vec<(String, Vec<u8>)>;

pub fn read_zip(path: &Path) -> Entries {
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

pub fn write_zip(path: &Path, entries: &Entries) {
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

pub fn tamper(src: &Path, dst: &Path, f: impl FnOnce(&mut Entries)) {
    let mut e = read_zip(src);
    f(&mut e);
    write_zip(dst, &e);
}

pub fn entry_names(zip: &Path) -> Vec<String> {
    read_zip(zip).into_iter().map(|(n, _)| n).collect()
}

pub fn entry_bytes(zip: &Path, name: &str) -> Vec<u8> {
    read_zip(zip)
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("entry {name} missing"))
        .1
}

pub fn entry_json(zip: &Path, name: &str) -> Value {
    serde_json::from_slice(&entry_bytes(zip, name)).unwrap()
}

pub fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

pub fn json_out(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON ({e}): {}", stdout(o)))
}

pub fn verify_json(zip: &Path) -> (i32, Value) {
    let o = tessel(&["verify", s(zip), "--json"]);
    (code(&o), json_out(&o))
}

/// Creates a temporary base directory with the project in `proj/`; returns (tempdir, project path).
pub fn project() -> (TempDir, PathBuf) {
    let base = tempfile::tempdir().unwrap();
    let proj = base.path().join("proj");
    make_project(&proj);
    (base, proj)
}

/// Writes the test policy to `<base>/policy.json`.
pub fn policy_file(base: &Path, json: &str) -> PathBuf {
    let p = base.join("policy.json");
    fs::write(&p, json).unwrap();
    p
}
