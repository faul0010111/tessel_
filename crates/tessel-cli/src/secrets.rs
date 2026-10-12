//! Scan for secrets and personal data in the files that would be exported.
//!
//! Principles:
//! - **never records the value found**: only path, line, rule and severity
//!   (a report containing the secret would be a new leak);
//! - linear-time regex engine (`regex` crate), safe against ReDoS;
//! - the content read is checked against the inventory SHA-256, so the scan
//!   sees exactly the bytes that will be packaged;
//! - it is a heuristic filter: no findings does **not** prove there are no secrets.

use crate::inventory::FileEntry;
use crate::util::{hex_sha256, open_regular};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

pub const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FINDINGS_PER_FILE: usize = 50;
const MAX_FINDINGS_TOTAL: usize = 5000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational (e-mail, CPF): appears in the report, does not block.
    Low,
    /// Probable secret, possibly a false positive: blocks until acknowledged.
    Medium,
    /// Known credential format or sensitive file: blocks until acknowledged.
    High,
}

impl Severity {
    pub fn blocks(self) -> bool {
        self >= Severity::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    /// Line (1-based); 0 for findings based on the file name.
    pub line: u32,
    pub rule: String,
    pub severity: Severity,
}

struct Rule {
    id: &'static str,
    severity: Severity,
    re: Regex,
}

fn rule(id: &'static str, severity: Severity, pattern: &str) -> Rule {
    Rule {
        id,
        severity,
        re: Regex::new(pattern).expect("embedded regex must be valid"),
    }
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        use Severity::*;
        vec![
            rule("private_key", High, r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
            rule("aws_access_key_id", High, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            rule("github_token", High, r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
            rule("slack_token", High, r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
            rule("google_api_key", High, r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            rule(
                "jwt",
                High,
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            ),
            rule(
                "generic_secret_assignment",
                Medium,
                r#"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][^"'\s]{12,}["']"#,
            ),
            rule("pii_cpf", Low, r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
            rule(
                "pii_email",
                Low,
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            ),
        ]
    })
}

fn is_placeholder(matched: &str) -> bool {
    let l = matched.to_ascii_lowercase();
    [
        "example",
        "placeholder",
        "changeme",
        "your_",
        "your-",
        "xxxx",
        "${",
        "<",
        "dummy",
        "sample",
    ]
    .iter()
    .any(|p| l.contains(p))
}

/// File names that typically hold credentials (Android keystores, keys, `.env`).
pub fn is_sensitive_filename(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    const EXTS: [&str; 6] = [".pem", ".p12", ".pfx", ".jks", ".keystore", ".keytab"];
    EXTS.iter().any(|e| name.ends_with(e))
        || name == ".env"
        || name.starts_with(".env.")
        || name.starts_with("id_rsa")
        || name.starts_with("id_ed25519")
        || name.starts_with("id_ecdsa")
}

/// Scans text line by line. Returns `true` if the per-file limit cut the scan short.
pub fn scan_text(path: &str, text: &str, out: &mut Vec<Finding>) -> bool {
    let mut count = 0;
    for (i, line) in text.lines().enumerate() {
        for r in rules() {
            let Some(m) = r.re.find(line) else { continue };
            if r.id == "generic_secret_assignment" && is_placeholder(m.as_str()) {
                continue;
            }
            out.push(Finding {
                path: path.to_string(),
                line: (i + 1) as u32,
                rule: r.id.to_string(),
                severity: r.severity,
            });
            count += 1;
            if count >= MAX_FINDINGS_PER_FILE {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub scanned_files: usize,
    pub skipped_binary: usize,
    pub skipped_large: usize,
    /// Read failures or files changed during the scan.
    pub errors: Vec<String>,
    pub truncated: bool,
}

impl ScanOutcome {
    pub fn blocking(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity.blocks())
            .collect()
    }
}

pub fn scan_files(root: &Path, files: &[FileEntry]) -> ScanOutcome {
    let mut out = ScanOutcome::default();
    for f in files {
        if out.findings.len() >= MAX_FINDINGS_TOTAL {
            out.truncated = true;
            break;
        }
        if is_sensitive_filename(&f.path) {
            out.findings.push(Finding {
                path: f.path.clone(),
                line: 0,
                rule: "sensitive_filename".into(),
                severity: Severity::High,
            });
        }
        if f.size > MAX_SCAN_BYTES {
            out.skipped_large += 1;
            continue;
        }
        let mut buf = Vec::new();
        let read = open_regular(&root.join(&f.path))
            .and_then(|file| file.take(MAX_SCAN_BYTES + 1).read_to_end(&mut buf));
        if let Err(e) = read {
            out.errors.push(format!("{}: read failure: {e}", f.path));
            continue;
        }
        if buf.len() as u64 != f.size || hex_sha256(&buf) != f.sha256 {
            out.errors
                .push(format!("{}: file changed during the scan", f.path));
            continue;
        }
        if buf[..buf.len().min(8192)].contains(&0) {
            out.skipped_binary += 1;
            continue;
        }
        out.scanned_files += 1;
        let text = String::from_utf8_lossy(&buf);
        if scan_text(&f.path, &text, &mut out.findings) {
            out.truncated = true;
        }
    }
    out.findings.sort_by(|a, b| {
        (a.path.as_str(), a.line, a.rule.as_str()).cmp(&(b.path.as_str(), b.line, b.rule.as_str()))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_hit(text: &str) -> Vec<(String, Severity)> {
        let mut v = Vec::new();
        scan_text("f.txt", text, &mut v);
        v.into_iter().map(|f| (f.rule, f.severity)).collect()
    }

    #[test]
    fn detects_known_credential_formats() {
        assert_eq!(
            rules_hit("-----BEGIN RSA PRIVATE KEY-----"),
            vec![("private_key".into(), Severity::High)]
        );
        assert_eq!(
            rules_hit("id = AKIAABCDEFGHIJKLMNOP")[0].0,
            "aws_access_key_id"
        );
        let gh = format!("t = ghp_{}", "a".repeat(36));
        assert_eq!(rules_hit(&gh)[0].0, "github_token");
        assert_eq!(rules_hit("xoxb-1234567890-abcdefghij")[0].0, "slack_token");
        let g = format!("k = AIza{}", "B".repeat(35));
        assert_eq!(rules_hit(&g)[0].0, "google_api_key");
        assert_eq!(
            rules_hit("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop")[0].0,
            "jwt"
        );
    }

    #[test]
    fn generic_assignment_and_placeholders() {
        assert_eq!(
            rules_hit(r#"api_key = "k3j2h4g5f6d7s8a9""#),
            vec![("generic_secret_assignment".into(), Severity::Medium)]
        );
        assert!(
            rules_hit(r#"password: "hunter2hunter2hunter2""#)
                .iter()
                .any(|r| r.1 == Severity::Medium)
        );
        // placeholders and short values do not trigger
        assert!(rules_hit(r#"api_key = "your_api_key_goes_here""#).is_empty());
        assert!(rules_hit(r#"password = "short""#).is_empty());
        assert!(rules_hit("password = ${DB_PASSWORD}").is_empty());
    }

    #[test]
    fn pii_is_low_and_does_not_block() {
        let hits = rules_hit("contact: dev@example.com cpf 123.456.789-09");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.1 == Severity::Low && !h.1.blocks()));
        assert!(Severity::Medium.blocks() && Severity::High.blocks());
    }

    #[test]
    fn sensitive_filenames() {
        for p in [
            "Assets/user.keystore",
            "a/b/.env",
            ".env.production",
            "keys/server.PEM",
            "id_rsa",
            "x/id_ed25519.pub",
        ] {
            assert!(is_sensitive_filename(p), "{p}");
        }
        for p in ["Assets/environment.cs", "env.txt", "keystore.md"] {
            assert!(!is_sensitive_filename(p), "{p}");
        }
    }

    #[test]
    fn findings_never_contain_the_secret_value() {
        let mut v = Vec::new();
        scan_text("f", "AKIAABCDEFGHIJKLMNOP", &mut v);
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.contains("AKIAABCDEFGHIJKLMNOP"));
    }
}
