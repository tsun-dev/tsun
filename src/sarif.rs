use crate::report::{Alert, ScanReport};
use crate::severity::Severity;
use serde::{Deserialize, Serialize};

/// SARIF 2.1.0 format support for GitHub/GitLab integration
/// https://sarifweb.azurewebsites.net/

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<Run>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<Result>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Driver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri", skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    #[serde(rename = "semanticVersion", skip_serializing_if = "Option::is_none")]
    pub semantic_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Result {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub message: Message,
    pub level: String,
    pub locations: Vec<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
    #[serde(rename = "logicalLocations", skip_serializing_if = "Option::is_none")]
    pub logical_locations: Option<Vec<LogicalLocation>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhysicalLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogicalLocation {
    #[serde(rename = "fullyQualifiedName")]
    pub fully_qualified_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<ShortDescription>,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<FullDescription>,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: DefaultConfiguration,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShortDescription {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FullDescription {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultConfiguration {
    pub level: String,
}

/// ZAP plugin id → CWE, for the alerts teams see most often.
///
/// Deliberately partial: a wrong CWE is worse than none, so unknown plugins
/// carry no tag rather than a guess.
fn plugin_to_cwe(plugin_id: &str) -> Option<u32> {
    let cwe = match plugin_id {
        "40018" => 89,   // SQL Injection
        "40012" => 79,   // Reflected XSS
        "40014" => 79,   // Persistent XSS
        "40016" => 79,   // Persistent XSS (prime)
        "40017" => 79,   // Persistent XSS (spider)
        "40003" => 113,  // CRLF Injection
        "40008" => 643,  // Parameter Tampering / XPath
        "40009" => 611,  // Server Side Include
        "90019" => 94,   // Server Side Code Injection
        "90020" => 78,   // Remote OS Command Injection
        "90021" => 643,  // XPath Injection
        "90023" => 611,  // XML External Entity
        "6" => 22,       // Path Traversal
        "7" => 22,       // Remote File Inclusion
        "10010" => 614,  // Cookie without Secure flag
        "10011" => 319,  // Cookie without HttpOnly
        "10015" => 200,  // Server leaks version information
        "10016" => 200,  // Web browser XSS protection not enabled
        "10017" => 200,  // Cross-domain JavaScript source inclusion
        "10020" => 1021, // Missing X-Frame-Options
        "10021" => 693,  // Missing X-Content-Type-Options
        "10023" => 200,  // Information disclosure — debug error messages
        "10024" => 200,  // Information disclosure — sensitive info in URL
        "10025" => 525,  // Information disclosure — sensitive info in cache
        "10035" => 319,  // Strict-Transport-Security not set
        "10038" => 693,  // CSP header not set
        "10040" => 319,  // Secure pages include mixed content
        "10054" => 1004, // Cookie without SameSite attribute
        "10063" => 693,  // Permissions policy header not set
        "10098" => 200,  // Cross-domain misconfiguration
        "10202" => 352,  // Absence of anti-CSRF tokens
        _ => return None,
    };
    Some(cwe)
}

/// Convert a ScanReport to SARIF format
pub fn generate_sarif_report(report: &ScanReport) -> String {
    let mut results = Vec::new();
    let mut rules_map = std::collections::HashMap::new();

    for alert in &report.alerts {
        // Named for what it actually is: a ZAP plugin, not an OWASP reference.
        let rule_id = format!("ZAP-{}", alert.pluginid);
        let level = severity_to_sarif_level(alert.severity());
        let cwe = plugin_to_cwe(&alert.pluginid);

        // Stable across runs, so GitHub tracks one alert over time instead of
        // opening a new one whenever a volatile URL id changes.
        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("tsun/v1".to_string(), alert.fingerprint());

        // Create result
        results.push(Result {
            rule_id: rule_id.clone(),
            message: Message {
                text: alert.name.clone(),
                markdown: alert.description.clone(),
            },
            level: level.clone(),
            locations: vec![Location {
                physical_location: PhysicalLocation {
                    uri: alert.url.clone(),
                },
                logical_locations: None,
            }],
            fingerprints: Some(fingerprints),
            properties: Some(create_alert_properties(alert)),
        });

        rules_map.entry(rule_id.clone()).or_insert_with(|| {
            let mut rule_props = std::collections::HashMap::new();
            if let Some(cwe) = cwe {
                rule_props.insert(
                    "tags".to_string(),
                    serde_json::json!(["security", format!("external/cwe/cwe-{}", cwe)]),
                );
                rule_props.insert("cwe".to_string(), serde_json::json!(format!("CWE-{}", cwe)));
            } else {
                rule_props.insert("tags".to_string(), serde_json::json!(["security"]));
            }
            rule_props.insert(
                "security-severity".to_string(),
                serde_json::json!(format!("{:.1}", alert.cvss_score)),
            );

            Rule {
                id: rule_id.clone(),
                name: alert.name.clone(),
                short_description: Some(ShortDescription {
                    text: alert.alert.clone(),
                }),
                full_description: alert
                    .description
                    .as_ref()
                    .map(|d| FullDescription { text: d.clone() }),
                default_configuration: DefaultConfiguration {
                    level: level.clone(),
                },
                help_uri: Some(format!(
                    "https://www.zaproxy.org/docs/alerts/{}/",
                    alert.pluginid
                )),
                properties: Some(rule_props),
            }
        });
    }

    let rules: Vec<Rule> = rules_map.into_values().collect();

    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "tsun".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: Some("https://github.com/tsun-dev/tsun".to_string()),
                    semantic_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                },
            },
            results,
            rules,
        }],
    };

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

/// Map severity to a SARIF level.
///
/// GitHub renders `error` and `warning` prominently, `note` quietly, and
/// `none` not at all — which is the right home for informational findings.
fn severity_to_sarif_level(severity: Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
    .to_string()
}

/// Create additional properties for the result
fn create_alert_properties(alert: &Alert) -> std::collections::HashMap<String, serde_json::Value> {
    let mut props = std::collections::HashMap::new();

    props.insert(
        "pluginId".to_string(),
        serde_json::Value::String(alert.pluginid.clone()),
    );
    props.insert(
        "confidence".to_string(),
        serde_json::Value::String(alert.confidence.clone()),
    );
    props.insert(
        "cvssScore".to_string(),
        serde_json::Value::Number(
            serde_json::Number::from_f64(alert.cvss_score as f64)
                .unwrap_or(serde_json::Number::from(0)),
        ),
    );
    props.insert(
        "vulnerabilityType".to_string(),
        serde_json::Value::String(alert.vulnerability_type.clone()),
    );
    props.insert(
        "severity".to_string(),
        serde_json::Value::String(alert.severity().to_string()),
    );
    props.insert(
        "cvssEstimated".to_string(),
        serde_json::Value::Bool(alert.cvss_estimated),
    );

    if !alert.instances.is_empty() {
        let instance = &alert.instances[0];
        props.insert(
            "method".to_string(),
            serde_json::Value::String(instance.method.clone()),
        );
        if let Some(param) = &instance.param {
            props.insert(
                "parameter".to_string(),
                serde_json::Value::String(param.clone()),
            );
        }
    }

    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{AlertInstance, ScanReport};

    fn report_with(alerts: Vec<Alert>) -> ScanReport {
        ScanReport::from_alerts("https://example.com".to_string(), alerts)
    }

    fn alert(plugin: &str, risk: &str, confidence: &str, url: &str, param: Option<&str>) -> Alert {
        Alert::from_zap(
            plugin.to_string(),
            plugin.to_string(),
            "Test Vulnerability".to_string(),
            risk,
            confidence,
            url.to_string(),
            Some("Test description".to_string()),
            vec![AlertInstance {
                uri: url.to_string(),
                method: "GET".to_string(),
                param: param.map(str::to_string),
                attack: None,
                evidence: None,
            }],
        )
    }

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level(Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(Severity::High), "error");
        assert_eq!(severity_to_sarif_level(Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(Severity::Info), "none");
    }

    #[test]
    fn test_generate_sarif_report_empty() {
        let sarif = generate_sarif_report(&report_with(vec![]));
        assert!(sarif.contains("sarif-schema-2.1.0"));
        assert!(sarif.contains("tsun"));
        assert!(sarif.contains("\"results\""));
    }

    #[test]
    fn test_generate_sarif_report_with_alerts() {
        let report = report_with(vec![alert(
            "10010",
            "Medium",
            "High",
            "https://example.com/test",
            None,
        )]);

        let sarif = generate_sarif_report(&report);
        assert!(sarif.contains("Test Vulnerability"));
        assert!(sarif.contains("warning"));
        assert!(sarif.contains("ZAP-10010"), "rule ids name the ZAP plugin");
        assert!(!sarif.contains("OWASP-10010"), "old id was misleading");
    }

    #[test]
    fn rules_carry_help_uri_and_cwe_tags() {
        let report = report_with(vec![alert(
            "40018",
            "High",
            "Confirmed",
            "https://example.com/search",
            Some("q"),
        )]);
        let sarif = generate_sarif_report(&report);

        assert!(sarif.contains("https://www.zaproxy.org/docs/alerts/40018/"));
        assert!(
            sarif.contains("external/cwe/cwe-89"),
            "SQLi should tag CWE-89"
        );
        assert!(sarif.contains("security-severity"));
        assert!(sarif.contains("\"error\""), "critical maps to error");
    }

    #[test]
    fn unknown_plugins_get_no_cwe_guess() {
        let report = report_with(vec![alert(
            "99999",
            "Low",
            "Medium",
            "https://example.com/x",
            None,
        )]);
        let sarif = generate_sarif_report(&report);

        assert!(sarif.contains("\"security\""));
        assert!(
            !sarif.contains("external/cwe/"),
            "no CWE is better than a wrong one"
        );
    }

    #[test]
    fn results_carry_stable_fingerprints() {
        let first = generate_sarif_report(&report_with(vec![alert(
            "40012",
            "Medium",
            "Medium",
            "https://example.com/u/1/p",
            Some("q"),
        )]));
        let second = generate_sarif_report(&report_with(vec![alert(
            "40012",
            "Medium",
            "Medium",
            "https://example.com/u/98765/p",
            Some("q"),
        )]));

        let extract = |s: &str| {
            let v: serde_json::Value = serde_json::from_str(s).unwrap();
            v["runs"][0]["results"][0]["fingerprints"]["tsun/v1"]
                .as_str()
                .unwrap()
                .to_string()
        };

        assert_eq!(
            extract(&first),
            extract(&second),
            "the same finding on a different row id must keep one GitHub alert"
        );
    }

    #[test]
    fn sarif_output_is_valid_json() {
        let report = report_with(vec![
            alert(
                "40018",
                "High",
                "Confirmed",
                "https://example.com/a",
                Some("q"),
            ),
            alert(
                "10015",
                "Informational",
                "High",
                "https://example.com/b",
                None,
            ),
        ]);
        let parsed: serde_json::Value =
            serde_json::from_str(&generate_sarif_report(&report)).expect("valid JSON");

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 2);
    }
}
