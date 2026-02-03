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
            "sarif" => crate::sarif::generate_sarif_report(self),
            _ => anyhow::bail!("Unsupported format: {}. Supported formats: json, yaml, html, sarif", format),
        };

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load a report from a JSON or YAML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(&path)?;
        let path_str = path.as_ref().to_string_lossy();

        // Try to parse as JSON first, then YAML
        if path_str.ends_with(".json") {
            let report = serde_json::from_str(&content)?;
            Ok(report)
        } else if path_str.ends_with(".yaml") || path_str.ends_with(".yml") {
            let report = serde_yaml::from_str(&content)?;
            Ok(report)
        } else {
            // Try JSON first, fallback to YAML
            serde_json::from_str(&content)
                .or_else(|_| serde_yaml::from_str(&content))
                .map_err(|e| anyhow::anyhow!("Failed to parse report file: {}", e))
        }
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
/// Comparison between two scan reports
#[derive(Debug, Clone, Serialize)]
pub struct ReportComparison {
    /// Vulnerabilities in the new report but not in baseline
    pub new_vulnerabilities: Vec<Alert>,
    /// Vulnerabilities in the baseline but not in the new report (fixed)
    pub fixed_vulnerabilities: Vec<Alert>,
    /// Vulnerabilities present in both reports
    pub unchanged_vulnerabilities: Vec<Alert>,
    /// Change in total count (positive = worse, negative = better)
    pub total_delta: i32,
    /// Change in critical count
    pub critical_delta: i32,
    /// Change in high count
    pub high_delta: i32,
    /// Change in medium count
    pub medium_delta: i32,
    /// Change in low count
    pub low_delta: i32,
    /// Change in average CVSS score
    pub average_cvss_delta: f32,
    /// Improvement status
    pub is_improvement: bool,
}

impl ReportComparison {
    /// Create a new comparison between baseline and current report
    pub fn new(baseline: &ScanReport, current: &ScanReport) -> Self {
        let mut new_vulns = Vec::new();
        let mut fixed_vulns = Vec::new();
        let mut unchanged_vulns = Vec::new();

        for current_alert in &current.alerts {
            if !baseline
                .alerts
                .iter()
                .any(|a| Self::alerts_equal(a, current_alert))
            {
                new_vulns.push(current_alert.clone());
            } else {
                unchanged_vulns.push(current_alert.clone());
            }
        }

        for baseline_alert in &baseline.alerts {
            if !current
                .alerts
                .iter()
                .any(|a| Self::alerts_equal(a, baseline_alert))
            {
                fixed_vulns.push(baseline_alert.clone());
            }
        }

        let baseline_breakdown = baseline.risk_breakdown();
        let current_breakdown = current.risk_breakdown();

        let total_delta = current.alerts.len() as i32 - baseline.alerts.len() as i32;
        let critical_delta = current_breakdown.critical_count as i32 - baseline_breakdown.critical_count as i32;
        let high_delta = current_breakdown.high_count as i32 - baseline_breakdown.high_count as i32;
        let medium_delta = current_breakdown.medium_count as i32 - baseline_breakdown.medium_count as i32;
        let low_delta = current_breakdown.low_count as i32 - baseline_breakdown.low_count as i32;
        let average_cvss_delta = current.average_cvss_score() - baseline.average_cvss_score();

        let is_improvement =
            total_delta < 0
                || (total_delta == 0 && average_cvss_delta < 0.0)
                || (total_delta == 0 && average_cvss_delta == 0.0 && fixed_vulns.len() > 0);

        Self {
            new_vulnerabilities: new_vulns,
            fixed_vulnerabilities: fixed_vulns,
            unchanged_vulnerabilities: unchanged_vulns,
            total_delta,
            critical_delta,
            high_delta,
            medium_delta,
            low_delta,
            average_cvss_delta,
            is_improvement,
        }
    }

    /// Check if two alerts represent the same vulnerability
    fn alerts_equal(a: &Alert, b: &Alert) -> bool {
        a.pluginid == b.pluginid
            && a.alert == b.alert
            && a.url == b.url
            && a.riskcode == b.riskcode
    }

    /// Get summary of comparison
    pub fn summary(&self) -> String {
        let status = if self.is_improvement {
            "✓ IMPROVED".to_string()
        } else if self.total_delta == 0 && self.average_cvss_delta == 0.0 {
            "= UNCHANGED".to_string()
        } else {
            "✗ REGRESSED".to_string()
        };

        format!(
            "Comparison Summary: {}\n  Total: {} ({})\n  New: {} | Fixed: {}\n  Critical: {} | High: {} | Medium: {} | Low: {}\n  Avg CVSS: {:+.1}",
            status,
            self.unchanged_vulnerabilities.len(),
            if self.total_delta > 0 {
                format!("+{}", self.total_delta)
            } else {
                self.total_delta.to_string()
            },
            self.new_vulnerabilities.len(),
            self.fixed_vulnerabilities.len(),
            if self.critical_delta > 0 {
                format!("+{}", self.critical_delta)
            } else {
                self.critical_delta.to_string()
            },
            if self.high_delta > 0 {
                format!("+{}", self.high_delta)
            } else {
                self.high_delta.to_string()
            },
            if self.medium_delta > 0 {
                format!("+{}", self.medium_delta)
            } else {
                self.medium_delta.to_string()
            },
            if self.low_delta > 0 {
                format!("+{}", self.low_delta)
            } else {
                self.low_delta.to_string()
            },
            self.average_cvss_delta,
        )
    }
}