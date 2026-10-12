//! Comparison of two directories (e.g. original build vs. reproduced build) by inventory.

use crate::inventory::{self, FileEntry, Inventory, ScanError, ScanOptions, Skipped};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct DiffModified {
    pub path: String,
    pub left_sha256: String,
    pub right_sha256: String,
    pub left_size: u64,
    pub right_size: u64,
}

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub identical: bool,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<DiffModified>,
    pub unchanged: usize,
    pub left_logical_sha256: String,
    pub right_logical_sha256: String,
    pub left_skipped: Vec<Skipped>,
    pub right_skipped: Vec<Skipped>,
    pub left_errors: Vec<ScanError>,
    pub right_errors: Vec<ScanError>,
}

pub fn diff_inventories(left: &Inventory, right: &Inventory) -> DiffReport {
    let l: BTreeMap<&str, &FileEntry> = left.files.iter().map(|f| (f.path.as_str(), f)).collect();
    let r: BTreeMap<&str, &FileEntry> = right.files.iter().map(|f| (f.path.as_str(), f)).collect();

    let mut removed = Vec::new();
    let mut modified = Vec::new();
    let mut unchanged = 0usize;
    for (path, lf) in &l {
        match r.get(path) {
            None => removed.push(path.to_string()),
            Some(rf) if rf.sha256 == lf.sha256 && rf.size == lf.size => unchanged += 1,
            Some(rf) => modified.push(DiffModified {
                path: path.to_string(),
                left_sha256: lf.sha256.clone(),
                right_sha256: rf.sha256.clone(),
                left_size: lf.size,
                right_size: rf.size,
            }),
        }
    }
    let added: Vec<String> = r
        .keys()
        .filter(|p| !l.contains_key(*p))
        .map(|p| p.to_string())
        .collect();

    let identical = added.is_empty()
        && removed.is_empty()
        && modified.is_empty()
        && left.errors.is_empty()
        && right.errors.is_empty();

    DiffReport {
        identical,
        added,
        removed,
        modified,
        unchanged,
        left_logical_sha256: left.logical_digest(),
        right_logical_sha256: right.logical_digest(),
        left_skipped: left.skipped.clone(),
        right_skipped: right.skipped.clone(),
        left_errors: left.errors.clone(),
        right_errors: right.errors.clone(),
    }
}

pub fn diff_dirs(left: &Path, right: &Path, excludes: &[String]) -> Result<DiffReport> {
    let opts = ScanOptions {
        excludes,
        skip_paths: &[],
    };
    let l = inventory::scan(left, &opts)?;
    let r = inventory::scan(right, &opts)?;
    Ok(diff_inventories(&l, &r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(p: &str, size: u64, h: char) -> FileEntry {
        FileEntry {
            path: p.into(),
            size,
            sha256: h.to_string().repeat(64),
        }
    }

    #[test]
    fn classifies_changes() {
        let l = Inventory {
            files: vec![fe("a", 1, '1'), fe("b", 1, '2'), fe("c", 1, '3')],
            ..Default::default()
        };
        let r = Inventory {
            files: vec![fe("a", 1, '1'), fe("b", 2, '9'), fe("d", 1, '4')],
            ..Default::default()
        };
        let d = diff_inventories(&l, &r);
        assert!(!d.identical);
        assert_eq!(d.removed, vec!["c"]);
        assert_eq!(d.added, vec!["d"]);
        assert_eq!(d.modified.len(), 1);
        assert_eq!(d.modified[0].path, "b");
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn identical_when_equal() {
        let l = Inventory {
            files: vec![fe("a", 1, '1')],
            ..Default::default()
        };
        assert!(diff_inventories(&l, &l.clone()).identical);
    }
}
