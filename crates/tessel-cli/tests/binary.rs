//! Tests for `tessel analyze`: binary classification and analysis of (synthetic) Unity builds.

mod common;

use common::*;
use serde_json::Value;
use std::path::Path;

fn pe(machine: u16, chars: u16, magic: u16, clr: u32) -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[0] = b'M';
    b[1] = b'Z';
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    b[0x96..0x98].copy_from_slice(&chars.to_le_bytes());
    let opt = 0x98;
    b[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
    let (count, dirs) = if magic == 0x20b {
        (opt + 108, opt + 112)
    } else {
        (opt + 92, opt + 96)
    };
    b[count..count + 4].copy_from_slice(&16u32.to_le_bytes());
    b[dirs + 14 * 8..dirs + 14 * 8 + 4].copy_from_slice(&clr.to_le_bytes());
    b
}

fn native_exe() -> Vec<u8> {
    pe(0x8664, 0x0022, 0x20b, 0)
}
fn native_dll() -> Vec<u8> {
    pe(0x8664, 0x2022, 0x20b, 0)
}
fn managed_dll() -> Vec<u8> {
    pe(0x014c, 0x2102, 0x10b, 0x2000)
}

fn elf_so() -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[16..18].copy_from_slice(&3u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b
}

/// Serialized file (globalgamemanagers) with the Editor version.
fn serialized(editor: &str) -> Vec<u8> {
    let mut b = vec![0u8; 48];
    b[8..12].copy_from_slice(&22u32.to_be_bytes());
    b.extend_from_slice(editor.as_bytes());
    b.push(0);
    b.resize(b.len() + 64, 0);
    b
}

fn il2cpp_metadata(version: u32) -> Vec<u8> {
    let mut b = vec![0xaf, 0x1b, 0xb1, 0xfa];
    b.extend_from_slice(&version.to_le_bytes());
    b.resize(256, 0);
    b
}

/// Synthetic Windows/Mono build.
fn mono_build(root: &Path, editor: &str) {
    write_file(root, "Game.exe", &native_exe());
    write_file(root, "UnityPlayer.dll", &native_dll());
    write_file(root, "Game_Data/app.info", b"Acme Studio\nSuper Game\n");
    write_file(root, "Game_Data/globalgamemanagers", &serialized(editor));
    write_file(root, "Game_Data/level0", b"scene data");
    write_file(
        root,
        "Game_Data/Managed/Assembly-CSharp.dll",
        &managed_dll(),
    );
    write_file(root, "Game_Data/Managed/Assembly-CSharp.dll.mdb", b"mdb");
    write_file(root, "Game_Data/Managed/Gameplay.dll", &managed_dll());
    write_file(
        root,
        "Game_Data/Managed/UnityEngine.CoreModule.dll",
        &managed_dll(),
    );
    write_file(root, "Game_Data/Managed/mscorlib.dll", &managed_dll());
}

/// Unity source with Assembly-CSharp, a runtime asmdef, an Editor asmdef and a test asmdef.
fn source_project(root: &Path) {
    make_project(root); // ProjectVersion 6000.3.0f1 + Assets/Scripts/Player.cs
    write_file(
        root,
        "Assets/Gameplay/Gameplay.asmdef",
        br#"{"name":"Gameplay"}"#,
    );
    write_file(root, "Assets/Gameplay/Logic.cs", b"class Logic {}");
    write_file(
        root,
        "Assets/EditorTools/EditorTools.asmdef",
        br#"{"name":"EditorTools","includePlatforms":["Editor"]}"#,
    );
    write_file(root, "Assets/EditorTools/Tool.cs", b"class Tool {}");
    write_file(
        root,
        "Assets/Tests/Tests.asmdef",
        br#"{"name":"Tests","defineConstraints":["UNITY_INCLUDE_TESTS"]}"#,
    );
    write_file(root, "Assets/Tests/T.cs", b"class T {}");
    write_file(root, "Assets/Editor/E.cs", b"class E {}");
}

fn analyze_json(args: &[&str]) -> (i32, Value) {
    let mut a = vec!["analyze"];
    a.extend_from_slice(args);
    a.push("--json");
    let o = tessel(&a);
    (code(&o), json_out(&o))
}

fn bin<'a>(v: &'a Value, path: &str) -> &'a Value {
    v["binaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["path"] == path)
        .unwrap_or_else(|| panic!("binary {path} missing"))
}

fn finding_codes(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn analyzes_windows_mono_build() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    mono_build(&b, "6000.3.0f1");
    let (c, v) = analyze_json(&[s(&b)]);
    assert_eq!(c, 0, "{v}");
    let u = &v["unity_build"];
    assert_eq!(u["platform"], "windows");
    assert_eq!(u["scripting_backend"], "mono");
    assert_eq!(u["unity_version"], "6000.3.0f1");
    assert!(
        u["unity_version_source"]
            .as_str()
            .unwrap()
            .contains("globalgamemanagers")
    );
    assert_eq!(u["app_info"]["company"], "Acme Studio");
    assert_eq!(u["app_info"]["product"], "Super Game");
    assert_eq!(
        strings(&u["project_assemblies"]),
        vec!["Assembly-CSharp.dll"]
    );

    let exe = bin(&v, "Game.exe");
    assert_eq!(exe["format"], "pe");
    assert_eq!(exe["arch"], "x86_64");
    assert_eq!(exe["kind"], "executable");
    assert_eq!(exe["managed_dotnet"], false);
    assert_eq!(exe["sha256"], sha256_hex(&native_exe()));

    let asm = bin(&v, "Game_Data/Managed/Assembly-CSharp.dll");
    assert_eq!(asm["managed_dotnet"], true);
    assert_eq!(asm["bits"], 32);
    assert_eq!(
        strings(&asm["symbols"]),
        vec!["Game_Data/Managed/Assembly-CSharp.dll.mdb"]
    );
    assert_eq!(v["binaries"].as_array().unwrap().len(), 6);
    assert_eq!(v["by_format"]["pe"], 6);
}

#[test]
fn compares_build_with_matching_source() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    let src = base.path().join("src");
    mono_build(&b, "6000.3.0f1");
    source_project(&src);
    let (c, v) = analyze_json(&[s(&b), "--source", s(&src)]);
    assert_eq!(c, 0, "{v}");
    let cmp = &v["source_comparison"];
    assert_eq!(cmp["method"], "name_only");
    assert_eq!(cmp["unity_version"]["status"], "match");
    assert_eq!(cmp["assemblies"], "applicable");
    // Editor and test assemblies are not expected in the player; UnityEngine/mscorlib belong to the platform.
    assert_eq!(
        strings(&cmp["expected_in_build"]),
        vec!["Assembly-CSharp", "Gameplay"]
    );
    assert_eq!(
        strings(&cmp["matched"]),
        vec!["Assembly-CSharp", "Gameplay"]
    );
    assert!(strings(&cmp["missing_in_build"]).is_empty());
    assert!(strings(&cmp["build_only"]).is_empty());
}

#[test]
fn reports_version_mismatch_and_missing_assembly() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    let src = base.path().join("src");
    mono_build(&b, "2022.3.10f1");
    source_project(&src);
    write_file(&src, "Assets/Extra/Extra.asmdef", br#"{"name":"Extra"}"#);
    write_file(&src, "Assets/Extra/X.cs", b"class X {}");
    write_file(&b, "Game_Data/Managed/Vendor.Plugin.dll", &managed_dll());
    let (c, v) = analyze_json(&[s(&b), "--source", s(&src)]);
    assert_eq!(c, 1, "a different version is a finding");
    assert!(finding_codes(&v).contains(&"unity_version_mismatch".to_string()));
    let cmp = &v["source_comparison"];
    assert_eq!(cmp["unity_version"]["status"], "mismatch");
    assert_eq!(strings(&cmp["missing_in_build"]), vec!["Extra"]);
    assert_eq!(strings(&cmp["build_only"]), vec!["Vendor.Plugin"]);
}

#[test]
fn analyzes_il2cpp_linux_build() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    write_file(&b, "Game.x86_64", &elf_so());
    write_file(&b, "UnityPlayer.so", &elf_so());
    write_file(&b, "GameAssembly.so", &elf_so());
    write_file(
        &b,
        "Game_Data/il2cpp_data/Metadata/global-metadata.dat",
        &il2cpp_metadata(29),
    );
    write_file(
        &b,
        "Game_Data/globalgamemanagers",
        &serialized("2022.3.10f1"),
    );
    let src = base.path().join("src");
    source_project(&src);
    let (c, v) = analyze_json(&[s(&b), "--source", s(&src)]);
    let u = &v["unity_build"];
    assert_eq!(u["platform"], "linux");
    assert_eq!(u["scripting_backend"], "il2cpp");
    assert_eq!(u["il2cpp_metadata_version"], 29);
    assert_eq!(v["source_comparison"]["assemblies"], "not_applicable");
    assert_eq!(bin(&v, "GameAssembly.so")["format"], "elf");
    assert_eq!(bin(&v, "GameAssembly.so")["arch"], "x86_64");
    assert_eq!(c, 1, "version 2022.3 vs 6000.3 must be reported");
}

#[test]
fn flags_unrecognized_il2cpp_metadata() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    write_file(&b, "GameAssembly.dll", &native_dll());
    write_file(&b, "UnityPlayer.dll", &native_dll());
    write_file(
        &b,
        "Game_Data/il2cpp_data/Metadata/global-metadata.dat",
        &vec![0x55u8; 256],
    );
    let (c, v) = analyze_json(&[s(&b)]);
    assert_eq!(c, 1);
    assert!(finding_codes(&v).contains(&"il2cpp_metadata_unrecognized".to_string()));
    assert_eq!(v["unity_build"]["il2cpp_metadata_version"], Value::Null);
}

#[test]
fn analyzes_webgl_build() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    write_file(&b, "Build/web.wasm", b"\0asm\x01\0\0\0rest");
    write_file(&b, "Build/web.framework.js", b"// js");
    write_file(&b, "Build/web.loader.js", b"// js");
    write_file(&b, "index.html", b"<html></html>");
    let (c, v) = analyze_json(&[s(&b)]);
    assert_eq!(c, 0, "{v}");
    assert_eq!(v["unity_build"]["platform"], "webgl");
    assert_eq!(v["unity_build"]["scripting_backend"], "il2cpp");
    assert_eq!(bin(&v, "Build/web.wasm")["format"], "wasm");
}

#[test]
fn reads_editor_version_from_unityfs() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    let mut fs_head = b"UnityFS\0".to_vec();
    fs_head.extend_from_slice(&8u32.to_be_bytes());
    fs_head.extend_from_slice(b"5.x.x\0");
    fs_head.extend_from_slice(b"2021.3.5f1\0");
    fs_head.resize(200, 0);
    write_file(&b, "Game_Data/data.unity3d", &fs_head);
    write_file(&b, "Game_Data/Managed/Assembly-CSharp.dll", &managed_dll());
    write_file(&b, "UnityPlayer.dll", &native_dll());
    let (_, v) = analyze_json(&[s(&b)]);
    assert_eq!(v["unity_build"]["unity_version"], "2021.3.5f1");
}

#[test]
fn flags_extension_mismatch_and_truncated_header() {
    let base = tempfile::tempdir().unwrap();
    let d = base.path().join("d");
    write_file(&d, "fake.dll", b"this is not a PE");
    write_file(&d, "libx.so", b"");
    let full = native_dll();
    write_file(&d, "cut.dll", &full[..0x90]);
    write_file(&d, "notes.txt", b"texto");
    let (c, v) = analyze_json(&[s(&d)]);
    assert_eq!(c, 1);
    let f = v["findings"].as_array().unwrap();
    let has = |path: &str, code: &str| f.iter().any(|x| x["path"] == path && x["code"] == code);
    assert!(has("fake.dll", "extension_mismatch"));
    assert!(has("libx.so", "extension_mismatch"));
    assert!(has("cut.dll", "truncated_header"));
    assert!(!f.iter().any(|x| x["path"] == "notes.txt"));
    assert_eq!(v["by_format"]["other"], 3);
    assert!(v["unity_build"].is_null());
}

#[test]
fn source_without_build_is_a_finding() {
    let base = tempfile::tempdir().unwrap();
    let d = base.path().join("d");
    write_file(&d, "a.txt", b"x");
    let src = base.path().join("src");
    source_project(&src);
    let (c, v) = analyze_json(&[s(&d), "--source", s(&src)]);
    assert_eq!(c, 1);
    assert!(finding_codes(&v).contains(&"no_unity_build".to_string()));
}

#[test]
fn analysis_is_deterministic_and_honors_excludes() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    mono_build(&b, "6000.3.0f1");
    write_file(&b, "Skip/other.dll", &native_dll());
    let (_, v1) = analyze_json(&[s(&b), "--exclude", "Skip"]);
    let (_, v2) = analyze_json(&[s(&b), "--exclude", "Skip"]);
    assert_eq!(v1, v2);
    assert!(
        v1["binaries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["path"] != "Skip/other.dll")
    );
    let o = tessel(&["analyze", s(&b), "--exclude", "NaoExiste"]);
    assert!(stdout(&o).contains("did not match"), "{}", stdout(&o));
}

#[cfg(unix)]
#[test]
fn never_follows_symlinks_to_binaries() {
    let base = tempfile::tempdir().unwrap();
    let outside = base.path().join("outside.dll");
    std::fs::write(&outside, native_dll()).unwrap();
    let d = base.path().join("d");
    write_file(&d, "a.txt", b"x");
    std::os::unix::fs::symlink(&outside, d.join("link.dll")).unwrap();
    let (c, v) = analyze_json(&[s(&d)]);
    assert_eq!(c, 0);
    assert!(v["binaries"].as_array().unwrap().is_empty());
    assert_eq!(v["skipped"][0]["reason"], "symlink");
}

#[test]
fn human_output_summarizes_build() {
    let base = tempfile::tempdir().unwrap();
    let b = base.path().join("build");
    mono_build(&b, "6000.3.0f1");
    let o = tessel(&["analyze", s(&b)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("platform: windows"), "{out}");
    assert!(out.contains("6000.3.0f1"));
    assert!(out.contains("managed .NET"));
}

#[test]
fn missing_path_is_usage_error() {
    let o = tessel(&["analyze", "/path/that/does/not/exist"]);
    assert_eq!(code(&o), 2);
}
