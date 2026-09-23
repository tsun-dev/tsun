//! End-to-end CLI tests.
//!
//! These run the real binary with the mock engine, so they cover argument
//! parsing, validation, suppression, and exit-code gating without needing
//! Docker or a network.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::path::Path;
use tempfile::TempDir;

fn tsun() -> Command {
    Command::cargo_bin("tsun").expect("binary builds")
}

/// Run a mock scan writing JSON to `path`, returning the parsed report.
fn mock_scan_json(path: &Path, extra_args: &[&str]) -> serde_json::Value {
    let mut cmd = tsun();
    cmd.args([
        "scan",
        "--target",
        "https://example.com",
        "--engine",
        "mock",
        "--format",
        "json",
        "--output",
        path.to_str().unwrap(),
    ]);
    cmd.args(extra_args);
    cmd.assert().success();

    let content = std::fs::read_to_string(path).expect("report written");
    serde_json::from_str(&content).expect("report is valid JSON")
}

#[test]
fn help_documents_zap_as_the_default_engine() {
    tsun()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(contains("[default: zap]"));
}

#[test]
fn mock_engine_warns_that_findings_are_fake() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
        ])
        .assert()
        .stdout(contains("MOCK ENGINE").and(contains("FAKE")));
}

#[test]
fn reports_record_which_engine_produced_them() {
    let dir = TempDir::new().unwrap();
    let report = mock_scan_json(&dir.path().join("r.json"), &[]);

    assert_eq!(report["engine"], "mock");
}

#[test]
fn findings_carry_severity_and_estimated_cvss() {
    let dir = TempDir::new().unwrap();
    let report = mock_scan_json(&dir.path().join("r.json"), &["--min-severity", "info"]);

    let alerts = report["alerts"].as_array().unwrap();
    assert!(!alerts.is_empty());

    for alert in alerts {
        assert!(
            alert["severity"].is_string(),
            "every finding should carry an explicit severity"
        );
        assert_eq!(alert["cvss_estimated"], true);
    }

    let severities: Vec<&str> = alerts
        .iter()
        .map(|a| a["severity"].as_str().unwrap())
        .collect();
    assert!(severities.contains(&"critical"));
    assert!(severities.contains(&"info"));
}

#[test]
fn min_severity_low_excludes_informational() {
    let dir = TempDir::new().unwrap();
    let report = mock_scan_json(&dir.path().join("r.json"), &["--min-severity", "low"]);

    let severities: Vec<&str> = report["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["severity"].as_str().unwrap())
        .collect();

    assert!(!severities.contains(&"info"));
    assert!(severities.contains(&"low"));
}

#[test]
fn exit_on_severity_critical_is_reachable() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--exit-on-severity",
            "critical",
        ])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn exit_code_is_zero_when_nothing_meets_the_threshold() {
    let dir = TempDir::new().unwrap();
    // Suppress the one critical finding, then gate on critical.
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--ignore",
            "plugin:40018",
            "--exit-on-severity",
            "critical",
            "--output",
            dir.path().join("r.json").to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn ignore_rules_suppress_findings_without_discarding_them() {
    let dir = TempDir::new().unwrap();
    let report = mock_scan_json(&dir.path().join("r.json"), &["--ignore", "plugin:10038"]);

    let live: Vec<&str> = report["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["pluginid"].as_str().unwrap())
        .collect();
    assert!(
        !live.contains(&"10038"),
        "suppressed finding left in counts"
    );

    let suppressed = report["suppressed"].as_array().expect("suppressed section");
    assert_eq!(suppressed.len(), 1);
    assert_eq!(suppressed[0]["pluginid"], "10038");
    assert!(
        suppressed[0]["suppressed_by"].is_object(),
        "a suppressed finding should record the rule that hid it"
    );
}

#[test]
fn ignore_rules_can_come_from_a_file() {
    let dir = TempDir::new().unwrap();
    let rules = dir.path().join("ignore.yaml");
    std::fs::write(
        &rules,
        "- plugin: \"10038\"\n  reason: CSP set at the CDN\n",
    )
    .unwrap();

    let report = mock_scan_json(
        &dir.path().join("r.json"),
        &["--ignore-file", rules.to_str().unwrap()],
    );

    let suppressed = report["suppressed"].as_array().unwrap();
    assert_eq!(suppressed.len(), 1);
    assert_eq!(
        suppressed[0]["suppressed_by"]["reason"],
        "CSP set at the CDN"
    );
}

#[test]
fn fail_on_new_requires_a_baseline() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--fail-on-new",
        ])
        .assert()
        .failure()
        .stderr(contains("--fail-on-new requires --baseline"));
}

#[test]
fn fail_on_new_passes_when_nothing_is_new() {
    let dir = TempDir::new().unwrap();
    let baseline = dir.path().join("baseline.json");

    // Record a baseline, then scan again against it. The mock engine is
    // deterministic, so the second run introduces nothing.
    mock_scan_json(&baseline, &[]);

    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--baseline",
            baseline.to_str().unwrap(),
            "--fail-on-new",
            "--exit-on-severity",
            "low",
        ])
        .assert()
        .success();
}

#[test]
fn fail_on_new_gates_on_new_findings_only() {
    let dir = TempDir::new().unwrap();
    let baseline = dir.path().join("baseline.json");

    // A baseline that knows about nothing: every finding is therefore new.
    std::fs::write(
        &baseline,
        serde_json::json!({
            "target": "https://example.com",
            "timestamp": "2026-01-01T00:00:00Z",
            "engine": "mock",
            "alerts": []
        })
        .to_string(),
    )
    .unwrap();

    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--baseline",
            baseline.to_str().unwrap(),
            "--fail-on-new",
        ])
        .assert()
        .failure()
        .code(1)
        .stdout(contains("new finding"));
}

#[test]
fn fail_on_new_reports_an_unreadable_baseline_instead_of_passing() {
    let dir = TempDir::new().unwrap();
    let baseline = dir.path().join("missing.json");

    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--baseline",
            baseline.to_str().unwrap(),
            "--fail-on-new",
        ])
        .assert()
        .failure()
        .stderr(contains("baseline could not be read"));
}

#[test]
fn invalid_profile_is_rejected() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--profile",
            "thorough",
        ])
        .assert()
        .failure()
        .stderr(contains("Invalid profile"));
}

#[test]
fn invalid_severity_is_rejected_before_scanning() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--exit-on-severity",
            "severe",
        ])
        .assert()
        .failure()
        .stderr(contains("Invalid --exit-on-severity"));
}

#[test]
fn numeric_severity_codes_are_rejected_as_ambiguous() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--min-severity",
            "2",
        ])
        .assert()
        .failure()
        .stderr(contains("Invalid --min-severity"));
}

#[test]
fn malformed_ignore_rule_is_rejected() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--ignore",
            "10038",
        ])
        .assert()
        .failure()
        .stderr(contains("Expected key:value"));
}

#[test]
fn an_ignore_rule_that_would_hide_everything_is_rejected() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--ignore",
            "reason:because",
        ])
        .assert()
        .failure()
        .stderr(contains("at least one of"));
}

#[test]
fn invalid_target_url_is_rejected() {
    tsun()
        .args(["scan", "--target", "not-a-url", "--engine", "mock"])
        .assert()
        .failure()
        .stderr(contains("Invalid target URL"));
}

#[test]
fn sarif_output_carries_fingerprints_and_cwe_tags() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("r.sarif");

    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--format",
            "sarif",
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();

    assert_eq!(sarif["version"], "2.1.0");

    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(results
        .iter()
        .all(|r| r["fingerprints"]["tsun/v1"].is_string()));

    let rules = sarif["runs"][0]["rules"].as_array().unwrap();
    assert!(rules.iter().all(|r| r["helpUri"].is_string()));
    assert!(
        rules
            .iter()
            .any(|r| r["properties"]["cwe"].as_str() == Some("CWE-89")),
        "the SQL injection rule should carry CWE-89"
    );
}

#[test]
fn html_output_flags_mock_findings() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("r.html");

    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "mock",
            "--format",
            "html",
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let html = std::fs::read_to_string(&out).unwrap();
    assert!(html.contains("fabricated"));
    assert!(html.contains("estimates"), "CVSS caveat should be stated");
}

#[test]
fn init_writes_a_config_template_that_parses() {
    let dir = TempDir::new().unwrap();
    let config = dir.path().join("tsun.yaml");

    tsun()
        .args(["init", "--config", config.to_str().unwrap()])
        .assert()
        .success();

    let content = std::fs::read_to_string(&config).unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&content).expect("template is valid YAML");
    assert!(parsed.get("zap").is_some());
    assert!(
        content.contains("ignore:"),
        "template documents ignore rules"
    );
    assert!(
        content.contains("bearer"),
        "template documents auth methods"
    );
}

#[test]
fn unknown_engine_is_rejected() {
    tsun()
        .args([
            "scan",
            "--target",
            "https://example.com",
            "--engine",
            "burp",
        ])
        .assert()
        .failure()
        .stderr(contains("Invalid engine"));
}
