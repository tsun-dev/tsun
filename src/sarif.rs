use serde::{Deserialize, Serialize};
use crate::report::{ScanReport, Alert};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub informationUri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semanticVersion: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logicalLocations: Option<Vec<LogicalLocation>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shortDescription: Option<ShortDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fullDescription: Option<FullDescription>,
    pub defaultConfiguration: DefaultConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helpUri: Option<String>,
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

/// Convert a ScanReport to SARIF format
pub fn generate_sarif_report(report: &ScanReport) -> String {
    let mut results = Vec::new();
    let mut rules_map = std::collections::HashMap::new();

    for alert in &report.alerts {
        let rule_id = format!("OWASP-{}", alert.pluginid);
        let level = severity_to_sarif_level(&alert.riskcode);

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
                logicalLocations: None,
            }],
            fingerprints: None,
            properties: Some(create_alert_properties(alert)),
        });

        // Add rule if not already added
        if !rules_map.contains_key(&rule_id) {
            let rule = Rule {
                id: rule_id.clone(),
                name: alert.name.clone(),
                shortDescription: Some(ShortDescription {
                    text: alert.alert.clone(),
                }),
                fullDescription: alert.description.as_ref().map(|d| FullDescription {
                    text: d.clone(),
                }),
                defaultConfiguration: DefaultConfiguration {
                    level: level.clone(),
                },
                helpUri: None,
            };
            rules_map.insert(rule_id, rule);
        }
    }

    let rules: Vec<Rule> = rules_map.into_values().collect();

    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "arete".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    informationUri: Some("https://github.com/christavo/arete".to_string()),
                    semanticVersion: Some(env!("CARGO_PKG_VERSION").to_string()),
                },
            },
            results,
            rules,
        }],
    };

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

/// Map risk code to SARIF severity level
fn severity_to_sarif_level(riskcode: &str) -> String {
    match riskcode {
        "3" => "error".to_string(),
        "2" => "warning".to_string(),
        "1" => "note".to_string(),
        _ => "none".to_string(),
    }
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
            serde_json::Number::from_f64(alert.cvss_score as f64).unwrap_or(serde_json::Number::from(0)),
        ),
    );
    props.insert(
        "vulnerabilityType".to_string(),
        serde_json::Value::String(alert.vulnerability_type.clone()),
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

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(severity_to_sarif_level("3"), "error");
        assert_eq!(severity_to_sarif_level("2"), "warning");
        assert_eq!(severity_to_sarif_level("1"), "note");
        assert_eq!(severity_to_sarif_level("0"), "none");
    }

    #[test]
    fn test_generate_sarif_report_empty() {
        let report = ScanReport {
            target: "https://example.com".to_string(),
            timestamp: chrono::Local::now().to_rfc3339(),
            alerts: vec![],
        };

        let sarif = generate_sarif_report(&report);
        assert!(sarif.contains("sarif-schema-2.1.0"));
        assert!(sarif.contains("arete"));
        assert!(sarif.contains("\"results\""));
    }

    #[test]
    fn test_generate_sarif_report_with_alerts() {
        let report = ScanReport {
            target: "https://example.com".to_string(),
            timestamp: chrono::Local::now().to_rfc3339(),
            alerts: vec![crate::report::Alert {
                pluginid: "10010".to_string(),
                alert_ref: "10010".to_string(),
                alert: "Test Alert".to_string(),
                name: "Test Vulnerability".to_string(),
                riskcode: "2".to_string(),
                confidence: "2".to_string(),
                riskdesc: "High".to_string(),
                url: "https://example.com/test".to_string(),
                description: Some("Test description".to_string()),
                instances: vec![],
                cvss_score: 7.5,
                vulnerability_type: "Test Type".to_string(),
            }],
        };

        let sarif = generate_sarif_report(&report);
        assert!(sarif.contains("Test Vulnerability"));
        assert!(sarif.contains("warning"));
        assert!(sarif.contains("OWASP-10010"));
    }
}
