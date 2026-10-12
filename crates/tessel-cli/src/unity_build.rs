//! Static analysis of a Unity player build (Windows, macOS, Linux, Android, WebGL).
//!
//! Everything is inferred from file names and small headers (UnityFS, serialized
//! file, `global-metadata.dat`, `app.info`). Nothing is executed. Values are
//! *hints* read from the build; they do not prove that the build matches a given source.

use crate::binary::Finding;
use crate::inventory::FileEntry;
use crate::unity::read_small_regular;
use crate::util::open_regular;
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct AppInfo {
    pub company: Option<String>,
    pub product: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnityBuild {
    /// windows, macos, linux, android, webgl or unknown.
    pub platform: String,
    pub data_dir: Option<String>,
    /// mono, il2cpp or unknown.
    pub scripting_backend: String,
    pub il2cpp_metadata_version: Option<u32>,
    pub unity_version: Option<String>,
    /// Where `unity_version` was read from (file and format).
    pub unity_version_source: Option<String>,
    pub app_info: Option<AppInfo>,
    /// DLLs in `<data>/Managed` (Mono backend only).
    pub managed_assemblies: Vec<String>,
    /// Assemblies Unity generates from project scripts (`Assembly-CSharp*`).
    pub project_assemblies: Vec<String>,
    pub evidence: Vec<String>,
    pub notes: Vec<String>,
    pub findings: Vec<Finding>,
}

fn file_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn read_prefix(path: &Path, n: usize) -> Option<Vec<u8>> {
    let f = open_regular(path).ok()?;
    let mut buf = Vec::new();
    f.take(n as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn cstr(b: &[u8], start: usize) -> Option<(&str, usize)> {
    let rest = b.get(start..)?;
    let end = rest.iter().position(|&c| c == 0)?;
    let s = std::str::from_utf8(&rest[..end]).ok()?;
    Some((s, start + end + 1))
}

fn version_regex() -> Regex {
    Regex::new(r"^\d{1,4}\.\d+\.\d+[abfpx]\d+(c\d+)?$").expect("valid regex")
}

/// Editor version stored in a UnityFS bundle: `"UnityFS\0"`, format version (u32 BE),
/// minimum player version (e.g. `5.x.x`) and Editor revision (e.g. `2022.3.10f1`).
pub fn unityfs_editor_version(head: &[u8]) -> Option<String> {
    if !head.starts_with(b"UnityFS\0") {
        return None;
    }
    let (_player, next) = cstr(head, 12)?;
    let (rev, _) = cstr(head, next)?;
    version_regex().is_match(rev).then(|| rev.to_string())
}

/// Editor version stored in the header of a serialized file (`globalgamemanagers`).
/// Layout (big-endian): metadata_size, file_size, version, data_offset; if version ≥ 9, an
/// endianness byte + 3 reserved bytes; if version ≥ 22, 4+8+8+8 more bytes; then the version string.
pub fn serialized_editor_version(head: &[u8]) -> Option<String> {
    let version = u32::from_be_bytes(head.get(8..12)?.try_into().ok()?);
    if !(9..=40).contains(&version) {
        return None;
    }
    let start = if version >= 22 { 48 } else { 20 };
    let (s, _) = cstr(head, start)?;
    version_regex().is_match(s).then(|| s.to_string())
}

/// IL2CPP `global-metadata.dat`: magic `AF 1B B1 FA` and version (u32 LE).
pub fn il2cpp_metadata_version(head: &[u8]) -> Option<u32> {
    if head.get(0..4)? != [0xaf, 0x1b, 0xb1, 0xfa] {
        return None;
    }
    Some(u32::from_le_bytes(head.get(4..8)?.try_into().ok()?))
}

fn is_framework_assembly(stem: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "UnityEngine",
        "Unity.",
        "System",
        "mscorlib",
        "Mono.",
        "netstandard",
        "Microsoft.",
        "I18N",
        "Bee.",
    ];
    PREFIXES.iter().any(|p| stem.starts_with(p))
}

pub fn assembly_stem(path: &str) -> &str {
    let n = file_name(path);
    n.strip_suffix(".dll")
        .or_else(|| n.strip_suffix(".DLL"))
        .unwrap_or(n)
}

pub fn detect(root: &Path, files: &[FileEntry]) -> Option<UnityBuild> {
    let paths: BTreeSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let lower: Vec<(String, &str)> = files
        .iter()
        .map(|f| (f.path.to_ascii_lowercase(), f.path.as_str()))
        .collect();
    let has_name = |name: &str| lower.iter().any(|(l, _)| file_name(l) == name);
    let first_with = |pred: &dyn Fn(&str) -> bool| {
        lower
            .iter()
            .find(|(l, _)| pred(l))
            .map(|(_, orig)| orig.to_string())
    };

    // Data directory: the shallowest one that has player markers.
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for p in &paths {
        let Some((dir, name)) = p.rsplit_once('/') else {
            continue;
        };
        let ln = name.to_ascii_lowercase();
        if matches!(
            ln.as_str(),
            "globalgamemanagers" | "data.unity3d" | "globalgamemanagers.assets"
        ) {
            candidates.insert(dir.to_string());
        }
        if ln.ends_with(".dll")
            && let Some(parent) = dir.strip_suffix("/Managed")
        {
            candidates.insert(parent.to_string());
        }
        if let Some(i) = p.find("/il2cpp_data/") {
            candidates.insert(p[..i].to_string());
        }
    }
    let data_dir = candidates
        .into_iter()
        .min_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));

    let mut evidence = Vec::new();
    let mut note_ev = |p: Option<String>| {
        if let Some(p) = p {
            evidence.push(p);
        }
    };

    let win = first_with(&|l| file_name(l) == "unityplayer.dll");
    let lin = first_with(&|l| file_name(l) == "unityplayer.so");
    let mac = first_with(&|l| l.contains(".app/contents/") || file_name(l) == "unityplayer.dylib");
    let android = first_with(&|l| {
        l.ends_with(".apk")
            || l.ends_with(".aab")
            || (l.contains("/libunity.so") || l.starts_with("libunity.so"))
    });
    let web = first_with(&|l| l.ends_with(".framework.js") || l.ends_with(".loader.js"));

    let platform = if win.is_some() {
        "windows"
    } else if mac.is_some() {
        "macos"
    } else if lin.is_some() {
        "linux"
    } else if android.is_some() {
        "android"
    } else if web.is_some() {
        "webgl"
    } else {
        "unknown"
    };
    for p in [win, mac, lin, android, web] {
        note_ev(p);
    }

    if data_dir.is_none() && platform == "unknown" {
        return None;
    }
    if let Some(d) = &data_dir {
        evidence.push(format!("{d}/"));
    }

    let mut notes = Vec::new();
    let mut findings = Vec::new();

    // Scripting backend.
    let metadata_path = paths
        .iter()
        .find(|p| file_name(p).eq_ignore_ascii_case("global-metadata.dat"))
        .map(|p| p.to_string());
    let has_gameassembly = has_name("gameassembly.dll")
        || has_name("gameassembly.so")
        || has_name("gameassembly.dylib")
        || has_name("libil2cpp.so");
    let managed_dir = data_dir
        .as_ref()
        .map(|d| format!("{d}/Managed/"))
        .unwrap_or_else(|| "Managed/".into());
    let managed_assemblies: Vec<String> = files
        .iter()
        .filter(|f| {
            f.path.starts_with(&managed_dir)
                && !f.path[managed_dir.len()..].contains('/')
                && f.path.to_ascii_lowercase().ends_with(".dll")
        })
        .map(|f| file_name(&f.path).to_string())
        .collect();

    let backend = if metadata_path.is_some() || has_gameassembly || platform == "webgl" {
        "il2cpp"
    } else if !managed_assemblies.is_empty() {
        "mono"
    } else {
        "unknown"
    };
    if backend == "unknown" && platform == "android" {
        notes.push(
            "Android build packaged as APK/AAB: the package contents were not opened in this analysis."
                .into(),
        );
    }

    // IL2CPP metadata version.
    let mut il2cpp_version = None;
    if let Some(mp) = &metadata_path {
        match read_prefix(&root.join(mp), 8) {
            Some(head) => match il2cpp_metadata_version(&head) {
                Some(v) => il2cpp_version = Some(v),
                None => findings.push(Finding::new(
                    Some(mp),
                    "il2cpp_metadata_unrecognized",
                    "global-metadata.dat does not start with the IL2CPP magic: file is encrypted, obfuscated or corrupted",
                )),
            },
            None => findings.push(Finding::new(
                Some(mp),
                "read_failed",
                "could not read global-metadata.dat",
            )),
        }
    }
    if backend == "il2cpp" && metadata_path.is_none() && platform != "webgl" {
        notes.push("IL2CPP backend without a visible global-metadata.dat (it may be outside the analysed build or packaged).".into());
    }

    // Editor version.
    let mut unity_version = None;
    let mut source = None;
    if let Some(d) = &data_dir {
        let try_files: [(String, bool); 2] = [
            (format!("{d}/data.unity3d"), true),
            (format!("{d}/globalgamemanagers"), false),
        ];
        for (rel, is_fs) in try_files {
            if !paths.contains(rel.as_str()) {
                continue;
            }
            if let Some(head) = read_prefix(&root.join(&rel), 512) {
                let v = if is_fs {
                    unityfs_editor_version(&head)
                } else {
                    serialized_editor_version(&head)
                };
                if let Some(v) = v {
                    unity_version = Some(v);
                    source = Some(format!(
                        "{rel} ({})",
                        if is_fs {
                            "UnityFS header"
                        } else {
                            "serialized file header"
                        }
                    ));
                    break;
                }
            }
        }
    }
    if unity_version.is_none() {
        notes.push(
            "Editor version not detected in the build (unrecognized format or missing file)."
                .into(),
        );
    }

    // app.info: empresa e produto.
    let app_info = data_dir.as_ref().and_then(|d| {
        let rel = format!("{d}/app.info");
        if !paths.contains(rel.as_str()) {
            return None;
        }
        let bytes = read_small_regular(&root.join(&rel))?;
        let text = String::from_utf8_lossy(&bytes);
        let mut lines = text.lines().map(|l| l.trim()).filter(|l| !l.is_empty());
        Some(AppInfo {
            company: lines.next().map(str::to_string),
            product: lines.next().map(str::to_string),
        })
    });

    let project_assemblies: Vec<String> = managed_assemblies
        .iter()
        .filter(|a| {
            let s = assembly_stem(a);
            s.starts_with("Assembly-CSharp")
                || s.starts_with("Assembly-UnityScript")
                || s.starts_with("Assembly-Boo")
        })
        .cloned()
        .collect();

    if backend == "mono" && project_assemblies.is_empty() {
        notes.push("Mono backend without Assembly-CSharp*.dll: the project may use only asmdef, or the code may be protected/removed.".into());
    }

    evidence.sort();
    evidence.dedup();
    Some(UnityBuild {
        platform: platform.into(),
        data_dir,
        scripting_backend: backend.into(),
        il2cpp_metadata_version: il2cpp_version,
        unity_version,
        unity_version_source: source,
        app_info,
        managed_assemblies,
        project_assemblies,
        evidence,
        notes,
        findings,
    })
}

// ---------------------------------------------------------------------------------------
// Source vs. build comparison (by name only).
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VersionComparison {
    pub declared_by_project: Option<String>,
    pub found_in_build: Option<String>,
    /// match, mismatch or unknown.
    pub status: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SourceComparison {
    /// Always `name_only`: compares assembly names, not contents.
    pub method: String,
    pub unity_version: VersionComparison,
    /// applicable or not_applicable (e.g. IL2CPP backend, no managed DLLs).
    pub assemblies: String,
    pub expected_in_build: Vec<String>,
    pub matched: Vec<String>,
    pub missing_in_build: Vec<String>,
    pub build_only: Vec<String>,
    pub caveats: Vec<String>,
}

struct Asmdef {
    dir: String,
    name: String,
    editor_only: bool,
    test_only: bool,
}

fn parse_asmdef(root: &Path, rel: &str) -> Option<Asmdef> {
    let bytes = read_small_regular(&root.join(rel))?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    let name = v.get("name")?.as_str()?.to_string();
    let strs = |key: &str| -> Vec<String> {
        v.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let platforms = strs("includePlatforms");
    let constraints = strs("defineConstraints");
    Some(Asmdef {
        dir: rel
            .rsplit_once('/')
            .map(|(d, _)| d)
            .unwrap_or("")
            .to_string(),
        name,
        editor_only: platforms.len() == 1 && platforms[0] == "Editor",
        test_only: constraints.iter().any(|c| c == "UNITY_INCLUDE_TESTS"),
    })
}

/// Runtime assemblies the source should produce (heuristic by names).
pub fn expected_assemblies(
    root: &Path,
    files: &[FileEntry],
    caveats: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut asmdefs: BTreeMap<String, Asmdef> = BTreeMap::new();
    for f in files {
        let under = f.path.starts_with("Assets/") || f.path.starts_with("Packages/");
        if under && f.path.ends_with(".asmdef") {
            if let Some(a) = parse_asmdef(root, &f.path) {
                asmdefs.entry(a.dir.clone()).or_insert(a);
            } else {
                caveats.push(format!("{} could not be read as a valid asmdef.", f.path));
            }
        }
    }

    let mut with_scripts: BTreeSet<String> = BTreeSet::new(); // asmdef names with ≥ 1 .cs
    let mut predefined: BTreeSet<&'static str> = BTreeSet::new();
    for f in files {
        if !f.path.starts_with("Assets/") || !f.path.ends_with(".cs") {
            continue;
        }
        // Nearest asmdef among the ancestor directories.
        let mut dir = f.path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let owner = loop {
            if let Some(a) = asmdefs.get(dir) {
                break Some(a);
            }
            match dir.rsplit_once('/') {
                Some((parent, _)) => dir = parent,
                None => break None,
            }
        };
        match owner {
            Some(a) => {
                with_scripts.insert(a.name.clone());
            }
            None => {
                let comps: Vec<&str> = f.path.split('/').collect();
                let editor = comps.contains(&"Editor");
                let first_pass = comps.get(1).is_some_and(|c| {
                    matches!(*c, "Plugins" | "Standard Assets" | "Pro Standard Assets")
                });
                if editor {
                    continue; // Editor code does not go into the player
                }
                predefined.insert(if first_pass {
                    "Assembly-CSharp-firstpass"
                } else {
                    "Assembly-CSharp"
                });
            }
        }
    }

    let mut out: BTreeSet<String> = predefined.iter().map(|s| s.to_string()).collect();
    for a in asmdefs.values() {
        if a.editor_only || a.test_only {
            continue;
        }
        if with_scripts.contains(&a.name) {
            out.insert(a.name.clone());
        }
    }
    out
}

pub fn compare(
    source_root: &Path,
    source_files: &[FileEntry],
    declared_version: Option<String>,
    build: &UnityBuild,
) -> SourceComparison {
    let mut caveats = vec![
        "Comparison by assembly name and declared version only: it does not prove the source produced this build."
            .to_string(),
    ];
    let expected = expected_assemblies(source_root, source_files, &mut caveats);

    let status = match (&declared_version, &build.unity_version) {
        (Some(a), Some(b)) if a == b => "match",
        (Some(_), Some(_)) => "mismatch",
        _ => "unknown",
    };
    let version = VersionComparison {
        declared_by_project: declared_version,
        found_in_build: build.unity_version.clone(),
        status: status.into(),
    };

    if build.scripting_backend != "mono" {
        caveats.push(
            "Backend without managed DLLs in Managed/ (IL2CPP or unknown): assemblies could not be compared."
                .into(),
        );
        return SourceComparison {
            method: "name_only".into(),
            unity_version: version,
            assemblies: "not_applicable".into(),
            expected_in_build: expected.into_iter().collect(),
            matched: vec![],
            missing_in_build: vec![],
            build_only: vec![],
            caveats,
        };
    }

    let in_build: BTreeSet<String> = build
        .managed_assemblies
        .iter()
        .map(|a| assembly_stem(a).to_string())
        .collect();
    let matched: Vec<String> = expected.intersection(&in_build).cloned().collect();
    let missing: Vec<String> = expected.difference(&in_build).cloned().collect();
    let build_only: Vec<String> = in_build
        .difference(&expected)
        .filter(|s| !is_framework_assembly(s))
        .cloned()
        .collect();
    if !build_only.is_empty() {
        caveats.push(
            "Assemblies only in the build may come from Package Manager packages (PackageCache is not part of the source) or from plugins."
                .into(),
        );
    }
    SourceComparison {
        method: "name_only".into(),
        unity_version: version,
        assemblies: "applicable".into(),
        expected_in_build: expected.into_iter().collect(),
        matched,
        missing_in_build: missing,
        build_only,
        caveats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unityfs(player: &str, rev: &str) -> Vec<u8> {
        let mut b = b"UnityFS\0".to_vec();
        b.extend_from_slice(&8u32.to_be_bytes());
        b.extend_from_slice(player.as_bytes());
        b.push(0);
        b.extend_from_slice(rev.as_bytes());
        b.push(0);
        b
    }

    #[test]
    fn reads_unityfs_editor_version() {
        assert_eq!(
            unityfs_editor_version(&unityfs("5.x.x", "2022.3.10f1")).as_deref(),
            Some("2022.3.10f1")
        );
        assert_eq!(
            unityfs_editor_version(&unityfs("5.x.x", "6000.3.0f1")).as_deref(),
            Some("6000.3.0f1")
        );
        assert_eq!(unityfs_editor_version(&unityfs("5.x.x", "lixo")), None);
        assert_eq!(unityfs_editor_version(b"UnityWeb\0"), None);
        assert_eq!(unityfs_editor_version(b"UnityFS\0\0\0"), None);
    }

    #[test]
    fn reads_serialized_editor_version() {
        let mut old = vec![0u8; 20];
        old[8..12].copy_from_slice(&17u32.to_be_bytes());
        old.extend_from_slice(b"2019.4.40f1\0");
        assert_eq!(
            serialized_editor_version(&old).as_deref(),
            Some("2019.4.40f1")
        );

        let mut new = vec![0u8; 48];
        new[8..12].copy_from_slice(&22u32.to_be_bytes());
        new.extend_from_slice(b"2022.3.10f1\0");
        assert_eq!(
            serialized_editor_version(&new).as_deref(),
            Some("2022.3.10f1")
        );

        let mut bad = vec![0u8; 20];
        bad[8..12].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(serialized_editor_version(&bad), None);
        assert_eq!(serialized_editor_version(&[0u8; 5]), None);
    }

    #[test]
    fn reads_il2cpp_metadata_version() {
        let mut b = vec![0xaf, 0x1b, 0xb1, 0xfa];
        b.extend_from_slice(&29u32.to_le_bytes());
        assert_eq!(il2cpp_metadata_version(&b), Some(29));
        assert_eq!(il2cpp_metadata_version(b"AAAAAAAA"), None);
        assert_eq!(il2cpp_metadata_version(&b[..6]), None);
    }

    #[test]
    fn framework_assemblies_are_recognized() {
        assert!(is_framework_assembly("UnityEngine.CoreModule"));
        assert!(is_framework_assembly("System.Core"));
        assert!(!is_framework_assembly("Assembly-CSharp"));
        assert!(!is_framework_assembly("MyGame.Core"));
    }
}
