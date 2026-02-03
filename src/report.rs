use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum VulnerabilityType {
    SqlInjection,
    CrossSiteScripting,
    CsrfToken,
    AuthenticationBypass,
    SecurityMisconfiguration,
    SensitiveDataExposure,
    XmlExternalEntity,
    BrokenAccessControl,
    UsingComponentsWithKnownVulnerabilities,
    InsufficientLogging,
    Other,
}

impl VulnerabilityType {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnerabilityType::SqlInjection => "SQL Injection",
            VulnerabilityType::CrossSiteScripting => "Cross-Site Scripting (XSS)",
            VulnerabilityType::CsrfToken => "CSRF Token",
            VulnerabilityType::AuthenticationBypass => "Authentication Bypass",
            VulnerabilityType::SecurityMisconfiguration => "Security Misconfiguration",
            VulnerabilityType::SensitiveDataExposure => "Sensitive Data Exposure",
            VulnerabilityType::XmlExternalEntity => "XML External Entity (XXE)",
            VulnerabilityType::BrokenAccessControl => "Broken Access Control",
            VulnerabilityType::UsingComponentsWithKnownVulnerabilities => "Using Components with Known Vulnerabilities",
            VulnerabilityType::InsufficientLogging => "Insufficient Logging & Monitoring",
            VulnerabilityType::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub pluginid: String,
    #[serde(rename = "alertRef")]
    pub alert_ref: String,
    pub alert: String,
    pub name: String,
    pub riskcode: String,
    pub confidence: String,
    pub riskdesc: String,
    pub url: String,
    pub description: Option<String>,
    pub instances: Vec<AlertInstance>,
    #[serde(default)]
    pub cvss_score: f32,
    #[serde(default)]
    pub vulnerability_type: String,
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

    /// Convert risk code string to SeverityLevel
    fn risk_code_to_severity(riskcode: &str) -> SeverityLevel {
        match riskcode {
            "3" => SeverityLevel::Critical,
            "2" => SeverityLevel::High,
            "1" => SeverityLevel::Medium,
            _ => SeverityLevel::Low,
        }
    }

    /// Parse severity level from string
    pub fn parse_severity(level: &str) -> anyhow::Result<SeverityLevel> {
        match level.to_lowercase().as_str() {
            "critical" | "3" => Ok(SeverityLevel::Critical),
            "high" | "2" => Ok(SeverityLevel::High),
            "medium" | "1" => Ok(SeverityLevel::Medium),
            "low" | "0" => Ok(SeverityLevel::Low),
            _ => anyhow::bail!("Invalid severity level: {}. Valid: critical, high, medium, low", level),
        }
    }

    /// Filter alerts to only include those at or above the minimum severity
    pub fn filter_by_severity(&mut self, min_level: &str) -> anyhow::Result<()> {
        let min_severity = Self::parse_severity(min_level)?;
        
        let original_count = self.alerts.len();
        self.alerts.retain(|alert| {
            let alert_severity = Self::risk_code_to_severity(&alert.riskcode);
            alert_severity >= min_severity
        });

        if original_count != self.alerts.len() {
            tracing::info!(
                "Filtered {} alerts: {} → {} (min severity: {})",
                original_count - self.alerts.len(),
                original_count,
                self.alerts.len(),
                min_level
            );
        }

        Ok(())
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

    /// Calculate average CVSS score across all alerts
    pub fn average_cvss_score(&self) -> f32 {
        if self.alerts.is_empty() {
            return 0.0;
        }
        let sum: f32 = self.alerts.iter().map(|a| a.cvss_score).sum();
        sum / self.alerts.len() as f32
    }

    /// Get maximum CVSS score
    pub fn max_cvss_score(&self) -> f32 {
        self.alerts
            .iter()
            .map(|a| a.cvss_score)
            .fold(0.0, f32::max)
    }

    /// Count vulnerabilities by type
    pub fn vulnerabilities_by_type(&self) -> std::collections::HashMap<String, usize> {
        let mut map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for alert in &self.alerts {
            *map.entry(alert.vulnerability_type.clone())
                .or_insert(0) += 1;
        }
        map
    }

    /// Get risk breakdown (count by severity and CVSS)
    pub fn risk_breakdown(&self) -> RiskBreakdown {
        RiskBreakdown {
            critical_count: self.critical_count(),
            high_count: self.high_count(),
            medium_count: self.medium_count(),
            low_count: self.low_count(),
            average_cvss: self.average_cvss_score(),
            max_cvss: self.max_cvss_score(),
            vulnerabilities_by_type: self.vulnerabilities_by_type(),
        }
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

#[derive(Debug, Clone, Serialize)]
pub struct RiskBreakdown {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub average_cvss: f32,
    pub max_cvss: f32,
    pub vulnerabilities_by_type: std::collections::HashMap<String, usize>,
}
