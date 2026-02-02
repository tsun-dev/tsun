use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub pluginid: String,
    pub alertRef: String,
    pub alert: String,
    pub name: String,
    pub riskcode: String,
    pub confidence: String,
    pub riskdesc: String,
    pub url: String,
    pub description: Option<String>,
    pub instances: Vec<AlertInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInstance {
    pub uri: String,
    pub method: String,
    pub param: Option<String>,
    pub attack: Option<String>,
    pub evidence: Option<String>,
}

/// Security scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub timestamp: String,
    pub alerts: Vec<Alert>,
}

impl ScanReport {
    pub fn from_alerts(target: String, alerts: Vec<Alert>) -> Self {
        Self {
            target,
            timestamp: chrono::Local::now().to_rfc3339(),
            alerts,
        }
    }

    pub fn vulnerability_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn critical_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.riskcode == "3")
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.riskcode == "2")
            .count()
    }

    pub fn medium_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.riskcode == "1")
            .count()
    }

    pub fn low_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.riskcode == "0")
            .count()
    }

    pub fn summary(&self) -> String {
        format!(
            "Summary:\n  Critical: {}\n  High: {}\n  Medium: {}\n  Low: {}",
            self.critical_count(),
            self.high_count(),
            self.medium_count(),
            self.low_count()
        )
    }

    pub fn save<P: AsRef<Path>>(&self, path: P, format: &str) -> anyhow::Result<()> {
        let content = match format {
            "json" => serde_json::to_string_pretty(&self)?,
            "yaml" => serde_yaml::to_string(&self)?,
            "html" => crate::html::generate_html_report(self),
            _ => anyhow::bail!("Unsupported format: {}. Supported formats: json, yaml, html", format),
        };

        std::fs::write(path, content)?;
        Ok(())
    }
}
