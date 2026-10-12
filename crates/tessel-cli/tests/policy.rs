//! Export policy and secret scanning.

mod common;
use common::*;
use serde_json::Value;
use std::fs;

const AWS_FAKE: &str = "AKIAIOSFODNN7EXAMPLE"; // example key from the AWS documentation (synthetic)

// ---------------------------------------------------------------- policy

#[test]
fn not_permitted_component_is_omitted_with_hashes_recorded() {
    let (base, proj) = project();
    let policy = policy_file(base.path(), POLICY);
    let zip = base.path().join("p.tsp.zip");

    let o = tessel(&["package", s(&proj), "-o", s(&zip), "--policy", s(&policy)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("OMITTED by policy: 2 file(s)"), "{out}");
    assert!(out.contains("commercial-sdk"), "{out}");

    // The SDK is not in the package.
    let names = entry_names(&zip);
    assert!(names.iter().all(|n| !n.contains("Vendor")), "{names:?}");
    assert!(names.contains(&"source/Assets/Scripts/Player.cs".to_string()));
    assert!(names.contains(&"policy/policy.json".to_string()));
    assert!(names.contains(&"reports/export.json".to_string()));
    assert!(names.contains(&"integrity/external.json".to_string()));

    // The policy is copied byte for byte.
    assert_eq!(entry_bytes(&zip, "policy/policy.json"), POLICY.as_bytes());

    // What was left out can be checked: path, size and SHA-256 of the original file.
    let ext = entry_json(&zip, "integrity/external.json");
    let comp = &ext["components"][0];
    assert_eq!(comp["id"], "commercial-sdk");
    assert_eq!(comp["availability"], "external_authorized_acquisition");
    let files = comp["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    let dll = files
        .iter()
        .find(|f| f["path"] == "Assets/Plugins/Vendor/sdk.dll")
        .unwrap();
    let original = fs::read(proj.join("Assets/Plugins/Vendor/sdk.dll")).unwrap();
    assert_eq!(dll["sha256"], sha256_hex(&original).as_str());
    assert_eq!(dll["size"], original.len());

    // Manifest: omitted component has no path in the package, with an external reference.
    let m = entry_json(&zip, "manifest.json");
    assert_eq!(m["policy_ref"], "policy/policy.json");
    let comps = m["components"].as_array().unwrap();
    let sdk = comps.iter().find(|c| c["id"] == "commercial-sdk").unwrap();
    assert!(sdk.get("path").is_none());
    assert_eq!(sdk["redistribution"], "not_permitted");
    assert_eq!(sdk["external_ref"], "integrity/external.json");
    assert_eq!(sdk["origin_path"], "Assets/Plugins/Vendor");
    assert_eq!(sdk["license_declared"], "LicenseRef-Vendor-EULA");
    assert_eq!(sdk["version"], "7.0");
    let own = comps.iter().find(|c| c["id"] == "game-source").unwrap();
    assert_eq!(own["path"], "source/Assets/Scripts/");
    assert_eq!(own["redistribution"], "approved");

    // The package verifies (integrity + conformance with the embedded policy).
    let (c, v) = verify_json(&zip);
    assert_eq!((c, v["status"].as_str().unwrap()), (0, "valid"), "{v}");
    assert!(v["policy_violations"].as_array().unwrap().is_empty());

    // Export report inside the package.
    let ex = entry_json(&zip, "reports/export.json");
    assert_eq!(ex["policy_applied"], true);
    assert_eq!(ex["omitted_files"], 2);
    assert_eq!(ex["policy_sha256"], sha256_hex(POLICY.as_bytes()).as_str());
}

#[test]
fn restoration_dependency_check_data_is_enough_to_verify_a_reacquired_sdk() {
    // A second team acquires the SDK through an authorized channel and checks it against external.json.
    let (base, proj) = project();
    let policy = policy_file(base.path(), POLICY);
    let zip = base.path().join("p.tsp.zip");
    assert_eq!(
        code(&tessel(&[
            "package",
            s(&proj),
            "-o",
            s(&zip),
            "--policy",
            s(&policy)
        ])),
        0
    );
    let ext = entry_json(&zip, "integrity/external.json");
    for f in ext["components"][0]["files"].as_array().unwrap() {
        let bytes = fs::read(proj.join(f["path"].as_str().unwrap())).unwrap();
        assert_eq!(sha256_hex(&bytes), f["sha256"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, f["size"].as_u64().unwrap());
    }
}

#[test]
fn strict_include_exports_only_approved_components() {
    let (base, proj) = project();
    let policy = policy_file(
        base.path(),
        r#"{"version":1,"include":["approved"],"components":[
            {"id":"game-source","kind":"source","path":"Assets/Scripts","redistribution":"approved","license":"MIT"}]}"#,
    );
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip), "--policy", s(&policy)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let src: Vec<String> = entry_names(&zip)
        .into_iter()
        .filter(|n| n.starts_with("source/"))
        .collect();
    assert_eq!(
        src,
        vec![
            "source/Assets/Scripts/Player.cs",
            "source/Assets/Scripts/Player.cs.meta"
        ]
    );
    // The rest becomes an omitted implicit component, also with recorded hashes.
    let ext = entry_json(&zip, "integrity/external.json");
    assert!(
        ext["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "component-project-source")
    );
    assert_eq!(code(&tessel(&["verify", s(&zip)])), 0);
}

#[test]
fn package_fails_when_policy_omits_everything() {
    let (base, proj) = project();
    let policy = policy_file(base.path(), r#"{"version":1,"include":["approved"]}"#);
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip), "--policy", s(&policy)]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("omitted all"), "{}", stderr(&o));
    assert!(!zip.exists());
}

#[test]
fn invalid_policy_is_rejected_with_all_errors() {
    let (base, proj) = project();
    let policy = policy_file(
        base.path(),
        r#"{"version":1,"include":["maybe"],"components":[
            {"id":"x y","kind":"k","path":"../up","redistribution":"yes"}]}"#,
    );
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip), "--policy", s(&policy)]);
    assert_eq!(code(&o), 2);
    let err = stderr(&o);
    for needle in [
        "invalid status",
        "id must use",
        "unsafe",
        "invalid redistribution",
    ] {
        assert!(err.contains(needle), "missing {needle:?} in: {err}");
    }
    assert!(!zip.exists());

    let o = tessel(&[
        "check",
        s(&proj),
        "--policy",
        s(&base.path().join("does-not-exist.json")),
    ]);
    assert_eq!(code(&o), 2);
}

#[cfg(unix)]
#[test]
fn policy_file_that_is_a_symlink_is_refused() {
    let (base, proj) = project();
    let real = policy_file(base.path(), POLICY);
    let link = base.path().join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let o = tessel(&["check", s(&proj), "--policy", s(&link)]);
    assert_eq!(code(&o), 2);
}

#[test]
fn verify_detects_policy_violation_in_an_otherwise_intact_package() {
    // Package created with a policy that approves the SDK; then the embedded policy starts to
    // block it, with metadata hashes updated: integrity ok, conformance violated.
    let (base, proj) = project();
    let permissive = policy_file(
        base.path(),
        r#"{"version":1,"components":[
          {"id":"commercial-sdk","kind":"dependency","path":"Assets/Plugins/Vendor","redistribution":"approved","license":"MIT"}]}"#,
    );
    let zip = base.path().join("p.tsp.zip");
    assert_eq!(
        code(&tessel(&[
            "package",
            s(&proj),
            "-o",
            s(&zip),
            "--policy",
            s(&permissive)
        ])),
        0
    );
    assert!(
        entry_names(&zip)
            .iter()
            .any(|n| n.contains("Vendor/sdk.dll"))
    );
    assert_eq!(verify_json(&zip).0, 0);

    let strict = br#"{"version":1,"components":[
      {"id":"commercial-sdk","kind":"dependency","path":"Assets/Plugins/Vendor","redistribution":"not_permitted","availability":"external_authorized_acquisition"}]}"#;
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        e.iter_mut()
            .find(|(n, _)| n == "policy/policy.json")
            .unwrap()
            .1 = strict.to_vec();
        let m = e.iter_mut().find(|(n, _)| n == "manifest.json").unwrap();
        let mut v: Value = serde_json::from_slice(&m.1).unwrap();
        for f in v["metadata_files"].as_array_mut().unwrap() {
            if f["path"] == "policy/policy.json" {
                f["sha256"] = sha256_hex(strict).into();
                f["size"] = strict.len().into();
            }
        }
        m.1 = serde_json::to_vec_pretty(&v).unwrap();
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "policy_violation", "{v}");
    assert!(v["modified"].as_array().unwrap().is_empty());
    let viol = strings(&v["policy_violations"]);
    assert_eq!(viol.len(), 2, "{viol:?}");
    assert!(viol[0].starts_with("source/Assets/Plugins/Vendor/"));
    assert!(stdout(&tessel(&["verify", s(&bad)])).contains("EXPORT POLICY VIOLATION"));
}

#[test]
fn embedded_invalid_policy_makes_the_package_invalid() {
    let (base, proj) = project();
    let policy = policy_file(base.path(), POLICY);
    let zip = base.path().join("p.tsp.zip");
    assert_eq!(
        code(&tessel(&[
            "package",
            s(&proj),
            "-o",
            s(&zip),
            "--policy",
            s(&policy)
        ])),
        0
    );
    let bad_policy = br#"{"version":9}"#;
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        e.iter_mut()
            .find(|(n, _)| n == "policy/policy.json")
            .unwrap()
            .1 = bad_policy.to_vec();
        let m = e.iter_mut().find(|(n, _)| n == "manifest.json").unwrap();
        let mut v: Value = serde_json::from_slice(&m.1).unwrap();
        for f in v["metadata_files"].as_array_mut().unwrap() {
            if f["path"] == "policy/policy.json" {
                f["sha256"] = sha256_hex(bad_policy).into();
                f["size"] = bad_policy.len().into();
            }
        }
        m.1 = serde_json::to_vec_pretty(&v).unwrap();
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "invalid_package");
    assert!(
        v["schema_errors"]
            .to_string()
            .contains("embedded policy invalid")
    );
}

#[test]
fn tampering_with_the_embedded_policy_is_an_integrity_failure() {
    let (base, proj) = project();
    let policy = policy_file(base.path(), POLICY);
    let zip = base.path().join("p.tsp.zip");
    assert_eq!(
        code(&tessel(&[
            "package",
            s(&proj),
            "-o",
            s(&zip),
            "--policy",
            s(&policy)
        ])),
        0
    );
    let bad = base.path().join("bad.zip");
    tamper(&zip, &bad, |e| {
        let p = e
            .iter_mut()
            .find(|(n, _)| n == "policy/policy.json")
            .unwrap();
        p.1.extend_from_slice(b"\n");
    });
    let (c, v) = verify_json(&bad);
    assert_eq!(c, 1);
    assert_eq!(v["status"], "failed_integrity");
    assert_eq!(v["modified"][0]["path"], "policy/policy.json");
}

#[test]
fn check_reports_components_without_writing_anything() {
    let (base, proj) = project();
    let policy = policy_file(base.path(), POLICY);
    let before: Vec<_> = fs::read_dir(base.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();

    let o = tessel(&["check", s(&proj), "--policy", s(&policy), "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json_out(&o);
    assert_eq!(v["allowed"], true);
    assert_eq!(v["export"]["omitted_files"], 2);
    let ids: Vec<&str> = v["export"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec!["commercial-sdk", "component-project-source", "game-source"]
    );
    let sdk = &v["export"]["components"][0];
    assert_eq!(sdk["included"], false);
    assert!(sdk["reason"].as_str().unwrap().contains("not_permitted"));

    let o = tessel(&["check", s(&proj), "--policy", s(&policy)]);
    let out = stdout(&o);
    assert!(out.contains("OMITTED") && out.contains("INCLUDED"), "{out}");
    assert!(out.contains("EXPORT ALLOWED"), "{out}");

    let after: Vec<_> = fs::read_dir(base.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before.len(), after.len(), "check must not create files");
}

#[test]
fn check_warns_about_policy_components_that_match_nothing() {
    let (base, proj) = project();
    let policy = policy_file(
        base.path(),
        r#"{"version":1,"components":[{"id":"ghost","kind":"source","path":"Nope","redistribution":"approved"}]}"#,
    );
    let v = json_out(&tessel(&[
        "check",
        s(&proj),
        "--policy",
        s(&policy),
        "--json",
    ]));
    let w = v["export"]["warnings"].to_string();
    assert!(
        w.contains("policy_component_matched_nothing") && w.contains("approved_without_license"),
        "{w}"
    );
}

#[test]
fn policy_makes_the_package_logical_inventory_deterministic() {
    let (b1, p1) = project();
    let (b2, p2) = project();
    let pol1 = policy_file(b1.path(), POLICY);
    let pol2 = policy_file(b2.path(), POLICY);
    let z1 = b1.path().join("a.zip");
    let z2 = b2.path().join("b.zip");
    assert_eq!(
        code(&tessel(&[
            "package",
            s(&p1),
            "-o",
            s(&z1),
            "--policy",
            s(&pol1)
        ])),
        0
    );
    assert_eq!(
        code(&tessel(&[
            "package",
            s(&p2),
            "-o",
            s(&z2),
            "--policy",
            s(&pol2)
        ])),
        0
    );
    assert_eq!(fs::read(&z1).unwrap(), fs::read(&z2).unwrap());
}

// ---------------------------------------------------------------- segredos

fn project_with_secret() -> (tempfile::TempDir, std::path::PathBuf) {
    let (base, proj) = project();
    write_file(
        &proj,
        "Assets/Config/cloud.txt",
        format!("region=us-east-1\naws_key = {AWS_FAKE}\n").as_bytes(),
    );
    (base, proj)
}

#[test]
fn secrets_block_packaging_by_default_and_never_leak_the_value() {
    let (base, proj) = project_with_secret();
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip)]);
    assert_eq!(code(&o), 2);
    let err = stderr(&o);
    assert!(
        err.contains("Assets/Config/cloud.txt:2 [aws_access_key_id]"),
        "{err}"
    );
    assert!(err.contains("--allow-secret-findings"), "{err}");
    assert!(
        !err.contains(AWS_FAKE) && !stdout(&o).contains(AWS_FAKE),
        "the secret value leaked into the output"
    );
    assert!(!zip.exists());
    assert!(!base.path().join("p.tsp.zip.partial").exists());
}

#[test]
fn check_reports_blocking_findings_with_exit_1() {
    let (_base, proj) = project_with_secret();
    let o = tessel(&["check", s(&proj), "--json"]);
    assert_eq!(code(&o), 1);
    let raw = stdout(&o);
    assert!(!raw.contains(AWS_FAKE));
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["allowed"], false);
    let f = &v["export"]["secrets"]["findings"][0];
    assert_eq!(
        (
            f["path"].as_str().unwrap(),
            f["line"].as_u64().unwrap(),
            f["rule"].as_str().unwrap(),
            f["severity"].as_str().unwrap()
        ),
        ("Assets/Config/cloud.txt", 2, "aws_access_key_id", "high")
    );

    let o = tessel(&["check", s(&proj)]);
    assert_eq!(code(&o), 1);
    let out = stdout(&o);
    assert!(
        out.contains("BLOCKING FINDINGS") && out.contains("EXPORT BLOCKED"),
        "{out}"
    );
    assert!(!out.contains(AWS_FAKE));
}

#[test]
fn allow_secret_findings_is_explicit_and_recorded_in_the_package() {
    let (base, proj) = project_with_secret();
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&[
        "package",
        s(&proj),
        "-o",
        s(&zip),
        "--allow-secret-findings",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("WARNING"), "{}", stdout(&o));

    let ex = entry_json(&zip, "reports/export.json");
    assert_eq!(ex["secrets"]["acknowledged"], true);
    assert_eq!(ex["secrets"]["findings"][0]["rule"], "aws_access_key_id");
    // The report never contains the value.
    assert!(!String::from_utf8_lossy(&entry_bytes(&zip, "reports/export.json")).contains(AWS_FAKE));
    assert_eq!(verify_json(&zip).0, 0);

    // `check` with the same flag also considers the export allowed.
    let o = tessel(&["check", s(&proj), "--allow-secret-findings", "--json"]);
    assert_eq!(code(&o), 0);
    assert_eq!(json_out(&o)["export"]["secrets"]["acknowledged"], true);
}

#[test]
fn sensitive_filenames_block_even_when_binary() {
    let (base, proj) = project();
    write_file(
        &proj,
        "Assets/Editor/user.keystore",
        &[0u8, 1, 2, 3, 0, 255],
    );
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip)]);
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("Assets/Editor/user.keystore [sensitive_filename]"),
        "{}",
        stderr(&o)
    );

    // Excluding the file resolves it.
    let o = tessel(&[
        "package",
        s(&proj),
        "-o",
        s(&zip),
        "--exclude",
        "Assets/Editor/user.keystore",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

#[test]
fn secrets_in_omitted_components_are_not_scanned_nor_blocking() {
    // The file with the key is in the omitted SDK: it does not leave the machine, so it does not block.
    let (base, proj) = project();
    write_file(
        &proj,
        "Assets/Plugins/Vendor/license.cfg",
        format!("key={AWS_FAKE}\n").as_bytes(),
    );
    let policy = policy_file(base.path(), POLICY);
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip), "--policy", s(&policy)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(entry_names(&zip).iter().all(|n| !n.contains("license.cfg")));
}

#[test]
fn low_severity_findings_are_informational_only() {
    let (base, proj) = project();
    write_file(
        &proj,
        "Assets/Scripts/Credits.cs",
        b"// author: dev@example.com  CPF 123.456.789-09\n",
    );
    let zip = base.path().join("p.tsp.zip");
    let o = tessel(&["package", s(&proj), "-o", s(&zip)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).contains("2 informational finding(s)"),
        "{}",
        stdout(&o)
    );
    let ex = entry_json(&zip, "reports/export.json");
    let rules: Vec<&str> = ex["secrets"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    assert!(
        rules.contains(&"pii_email") && rules.contains(&"pii_cpf"),
        "{rules:?}"
    );
    assert_eq!(ex["secrets"]["acknowledged"], false);
}

#[test]
fn placeholders_do_not_trigger_generic_secret_rule() {
    let (_base, proj) = project();
    write_file(
        &proj,
        "Assets/Scripts/Config.cs",
        b"const string apiKey = \"your_api_key_here\";\npassword = ${DB_PASSWORD}\n",
    );
    let o = tessel(&["check", s(&proj), "--json"]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
}

#[test]
fn report_includes_export_information_for_valid_packages() {
    let (base, proj) = project();
    let policy = policy_file(base.path(), POLICY);
    let zip = base.path().join("p.tsp.zip");
    assert_eq!(
        code(&tessel(&[
            "package",
            s(&proj),
            "-o",
            s(&zip),
            "--policy",
            s(&policy)
        ])),
        0
    );
    let o = tessel(&["report", s(&zip)]);
    assert_eq!(code(&o), 0);
    let v = json_out(&o);
    assert_eq!(
        v["verification"]["policy_violations"],
        serde_json::json!([])
    );
    let comps = v["summary"]["components"].as_array().unwrap();
    assert!(
        comps
            .iter()
            .any(|c| c["id"] == "commercial-sdk" && c["redistribution"] == "not_permitted")
    );
    assert_eq!(v["export"]["omitted_files"], 2);
    assert_eq!(v["export"]["policy_applied"], true);
}

#[test]
fn example_policy_in_docs_is_valid() {
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/policy.example.json");
    let (base, proj) = project();
    let o = tessel(&["check", s(&proj), "--policy", s(&example), "--json"]);
    assert_eq!(code(&o), 0, "{}{}", stdout(&o), stderr(&o));
    let v = json_out(&o);
    assert_eq!(v["allowed"], true);
    drop(base);
}
