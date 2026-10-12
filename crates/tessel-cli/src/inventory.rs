//! Recursive inventory of an authorized directory.
//!
//! Propriedades garantidas:
//! - nothing is executed: files are only opened and read to compute the SHA-256;
//! - symlinks are never followed or included (prevents copying outside content);
//! - any read failure becomes a `ScanError` and blocks packaging;
//! - output is sorted, so it does not depend on filesystem enumeration order.

use crate::util::{hash_reader, is_safe_rel_path, open_regular};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanError {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Inventory {
    pub files: Vec<FileEntry>,
    pub skipped: Vec<Skipped>,
    pub errors: Vec<ScanError>,
    /// Paths (relative to the root) removed by `--exclude`.
    pub excluded: Vec<String>,
    /// Exclude patterns that matched nothing (probably a typo).
    pub unmatched_excludes: Vec<String>,
}

pub struct ScanOptions<'a> {
    /// Root-anchored exclusions: `Library` or `Assets/Cache`.
    pub excludes: &'a [String],
    /// Absolute (already canonical) paths to skip, e.g. the output package itself.
    pub skip_paths: &'a [PathBuf],
}

impl Inventory {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn logical_digest(&self) -> String {
        logical_digest(&self.files)
    }
}

/// Logical inventory digest: independent of ZIP, timestamps and enumeration order.
/// Canonical format: one `path\tsize\tsha256\n` line per file, in byte order of the path.
pub fn logical_digest(files: &[FileEntry]) -> String {
    let mut h = Sha256::new();
    for f in files {
        h.update(f.path.as_bytes());
        h.update(b"\t");
        h.update(f.size.to_string().as_bytes());
        h.update(b"\t");
        h.update(f.sha256.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

pub fn normalize_excludes(raw: &[String]) -> Vec<String> {
    raw.iter()
        .map(|s| {
            let s = s.trim().trim_start_matches("./");
            s.trim_matches('/').to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn matches_exclude(rel: &str, pattern: &str) -> bool {
    rel == pattern
        || (rel.len() > pattern.len()
            && rel.starts_with(pattern)
            && rel.as_bytes()[pattern.len()] == b'/')
}

fn rel_path(root: &Path, p: &Path) -> Result<String, String> {
    let rel = p
        .strip_prefix(root)
        .map_err(|_| "path outside the root".to_string())?;
    let mut parts = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => parts.push(
                s.to_str()
                    .ok_or("file name is not valid UTF-8")?
                    .to_string(),
            ),
            _ => return Err("unexpected path component".to_string()),
        }
    }
    Ok(parts.join("/"))
}

fn lossy_rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn scan(root: &Path, opts: &ScanOptions) -> Result<Inventory> {
    scan_with(root, opts, true)
}

/// Like `scan`, but with `hash = false` it only lists files and sizes (empty `sha256`).
/// Used for analysing large builds, where hashing everything would be unnecessary.
pub fn scan_with(root: &Path, opts: &ScanOptions, hash: bool) -> Result<Inventory> {
    let root =
        fs::canonicalize(root).with_context(|| format!("could not access {}", root.display()))?;
    if !root.is_dir() {
        bail!("{} is not a directory", root.display());
    }
    let excludes = normalize_excludes(opts.excludes);
    let mut matched: BTreeSet<usize> = BTreeSet::new();
    let mut inv = Inventory::default();

    let mut it = WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    while let Some(next) = it.next() {
        let entry = match next {
            Ok(e) => e,
            Err(e) => {
                inv.errors.push(ScanError {
                    path: e.path().map(|p| lossy_rel(&root, p)).unwrap_or_default(),
                    error: format!("failed to walk directory: {e}"),
                });
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let is_dir = entry.file_type().is_dir();

        let rel = match rel_path(&root, entry.path()) {
            Ok(r) => r,
            Err(msg) => {
                inv.errors.push(ScanError {
                    path: lossy_rel(&root, entry.path()),
                    error: msg,
                });
                if is_dir {
                    it.skip_current_dir();
                }
                continue;
            }
        };

        let mut excluded = false;
        for (i, pat) in excludes.iter().enumerate() {
            if matches_exclude(&rel, pat) {
                matched.insert(i);
                excluded = true;
            }
        }
        if excluded {
            inv.excluded.push(rel);
            if is_dir {
                it.skip_current_dir();
            }
            continue;
        }

        if opts.skip_paths.iter().any(|p| p == entry.path()) {
            inv.skipped.push(Skipped {
                path: rel,
                reason: "package_output".into(),
            });
            continue;
        }

        let ft = entry.file_type();
        if ft.is_symlink() {
            // Never followed: the target may be outside the root.
            inv.skipped.push(Skipped {
                path: rel,
                reason: "symlink".into(),
            });
            continue;
        }
        if is_dir {
            continue;
        }
        if !ft.is_file() {
            inv.skipped.push(Skipped {
                path: rel,
                reason: "non_regular_file".into(),
            });
            continue;
        }
        if !is_safe_rel_path(&rel) {
            inv.errors.push(ScanError {
                path: rel,
                error: "unsafe file name (backslash, control character or drive letter)".into(),
            });
            continue;
        }

        if !hash {
            match entry.metadata() {
                Ok(m) => inv.files.push(FileEntry {
                    path: rel,
                    size: m.len(),
                    sha256: String::new(),
                }),
                Err(e) => inv.errors.push(ScanError {
                    path: rel,
                    error: format!("read failure: {e}"),
                }),
            }
            continue;
        }

        match open_regular(entry.path()).and_then(hash_reader) {
            Ok((sha256, size)) => inv.files.push(FileEntry {
                path: rel,
                size,
                sha256,
            }),
            Err(e) => inv.errors.push(ScanError {
                path: rel,
                error: format!("read failure: {e}"),
            }),
        }
    }

    inv.files.sort_by(|a, b| a.path.cmp(&b.path));
    inv.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    inv.errors.sort_by(|a, b| a.path.cmp(&b.path));
    inv.excluded.sort();
    inv.unmatched_excludes = excludes
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched.contains(i))
        .map(|(_, p)| p.clone())
        .collect();
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_matching_is_root_anchored() {
        assert!(matches_exclude("Library", "Library"));
        assert!(matches_exclude("Library/a/b", "Library"));
        assert!(!matches_exclude("Assets/Library/a", "Library"));
        assert!(!matches_exclude("LibraryX/a", "Library"));
        assert!(matches_exclude("Assets/Cache/x", "Assets/Cache"));
    }

    #[test]
    fn normalizes_excludes() {
        let raw = vec!["./Library/".into(), "  Temp ".into(), "/".into(), "".into()];
        assert_eq!(normalize_excludes(&raw), vec!["Library", "Temp"]);
    }

    #[test]
    fn digest_depends_on_content_and_order() {
        let a = FileEntry {
            path: "a".into(),
            size: 1,
            sha256: "0".repeat(64),
        };
        let b = FileEntry {
            path: "b".into(),
            size: 2,
            sha256: "1".repeat(64),
        };
        assert_eq!(
            logical_digest(&[a.clone(), b.clone()]),
            logical_digest(&[a.clone(), b.clone()])
        );
        assert_ne!(
            logical_digest(&[a.clone(), b.clone()]),
            logical_digest(&[b, a])
        );
    }
}
