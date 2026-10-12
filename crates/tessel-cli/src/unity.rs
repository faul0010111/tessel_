//! Static detection of Unity projects (read-only access to text/JSON files).
//!
//! Does not run the Editor or any project script. Values are *declared*
//! by the project; they are not verified against an Editor installation.

use crate::inventory::Inventory;
use crate::util::open_regular;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

const MAX_SMALL_FILE: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnityInfo {
    pub editor_version: Option<String>,
    pub editor_version_with_revision: Option<String>,
    pub packages: BTreeMap<String, String>,
    pub has_assets: bool,
    pub has_packages_dir: bool,
    pub has_project_settings: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

/// Reads a small file only if it is regular (never follows a symlink).
/// Files above the limit are ignored (`None`), never read partially.
pub fn read_small_regular(path: &Path) -> Option<Vec<u8>> {
    let file = open_regular(path).ok()?;
    if file.metadata().ok()?.len() > MAX_SMALL_FILE {
        return None;
    }
    let mut buf = Vec::new();
    file.take(MAX_SMALL_FILE + 1).read_to_end(&mut buf).ok()?;
    (buf.len() as u64 <= MAX_SMALL_FILE).then_some(buf)
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

pub fn detect(root: &Path) -> Option<UnityInfo> {
    let version_txt = read_small_regular(&root.join("ProjectSettings/ProjectVersion.txt"))?;
    let text = String::from_utf8_lossy(&version_txt);
    let mut info = UnityInfo::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("m_EditorVersion:") {
            info.editor_version = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("m_EditorVersionWithRevision:") {
            info.editor_version_with_revision = Some(v.trim().to_string());
        }
    }
    if let Some(bytes) = read_small_regular(&root.join("Packages/manifest.json"))
        && let Ok(serde_json::Value::Object(obj)) =
            serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(serde_json::Value::Object(deps)) = obj.get("dependencies")
    {
        for (k, v) in deps {
            if let Some(v) = v.as_str() {
                info.packages.insert(k.clone(), v.to_string());
            }
        }
    }
    info.has_assets = is_real_dir(&root.join("Assets"));
    info.has_packages_dir = is_real_dir(&root.join("Packages"));
    info.has_project_settings = is_real_dir(&root.join("ProjectSettings"));
    Some(info)
}

pub fn warnings(unity: Option<&UnityInfo>, inv: &Inventory) -> Vec<Warning> {
    let mut out = Vec::new();
    let w = |code: &str, message: String| Warning {
        code: code.to_string(),
        message,
    };
    for ex in &inv.unmatched_excludes {
        out.push(w(
            "exclude_matched_nothing",
            format!(
                "exclusion '{ex}' did not match any path (exclusions are relative to the root)"
            ),
        ));
    }
    let Some(u) = unity else { return out };

    for dir in ["Assets", "Packages", "ProjectSettings"] {
        if inv.excluded.iter().any(|e| e == dir) {
            out.push(w(
                "required_dir_excluded",
                format!("'{dir}' was excluded, but it is required to rebuild the Unity project"),
            ));
        }
    }
    if !u.has_assets {
        out.push(w("unity_dir_missing", "Assets directory missing".into()));
    }
    if u.editor_version.is_none() {
        out.push(w(
            "editor_version_unknown",
            "ProjectVersion.txt does not declare m_EditorVersion".into(),
        ));
    }
    if !inv
        .files
        .iter()
        .any(|f| f.path == "Packages/packages-lock.json")
        && !inv.excluded.iter().any(|e| e == "Packages")
    {
        out.push(w(
            "packages_lock_missing",
            "Packages/packages-lock.json missing: resolved package versions are not recorded"
                .into(),
        ));
    }
    if inv.files.iter().any(|f| f.path.starts_with("Library/")) {
        out.push(w(
            "library_included",
            "Library included: it is usually rebuildable and large; confirm with a restore test before excluding it".into(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_version_and_packages() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("ProjectSettings")).unwrap();
        fs::create_dir_all(d.path().join("Packages")).unwrap();
        fs::create_dir_all(d.path().join("Assets")).unwrap();
        fs::write(
            d.path().join("ProjectSettings/ProjectVersion.txt"),
            "m_EditorVersion: 6000.3.0f1\nm_EditorVersionWithRevision: 6000.3.0f1 (abc123)\n",
        )
        .unwrap();
        fs::write(
            d.path().join("Packages/manifest.json"),
            r#"{"dependencies":{"com.unity.test-framework":"1.4.5","x":1}}"#,
        )
        .unwrap();
        let u = detect(d.path()).unwrap();
        assert_eq!(u.editor_version.as_deref(), Some("6000.3.0f1"));
        assert_eq!(
            u.editor_version_with_revision.as_deref(),
            Some("6000.3.0f1 (abc123)")
        );
        assert_eq!(u.packages.len(), 1);
        assert!(u.has_assets && u.has_packages_dir && u.has_project_settings);
    }

    #[test]
    fn non_unity_directory_is_none() {
        let d = tempfile::tempdir().unwrap();
        assert!(detect(d.path()).is_none());
    }
}
