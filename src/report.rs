use crate::ignore::IgnoreRule;
use crate::severity::{self, Severity};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub pluginid: String,
    #[serde(rename = "alertRef")]
    pub alert_ref: String,
    pub alert: String,
    pub name: String,
    /// Legacy ZAP-style risk code, retained so reports written by older
    /// versions still parse and downstream consumers keep working. Prefer
    /// [`Alert::severity`] for any new logic.
    pub riskcode: String,
    pub confidence: String,
    pub riskdesc: String,
    pub url: String,
    pub description: Option<String>,
    pub instances: Vec<AlertInstance>,
    /// Estimated CVSS base score. ZAP does not emit CVSS, so this is derived
    /// from risk and confidence — see [`crate::severity::estimate_cvss`].
    #[serde(default)]
    pub cvss_score: f32,
    /// True when `cvss_score` is a Tsun estimate rather than a vendor score.
    #[serde(default)]
    pub cvss_estimated: bool,
    #[serde(default)]
    pub vulnerability_type: String,
    /// Absent in reports written before severity classification existed; those
    /// fall back to `riskcode`. Read it through [`Alert::severity`].
    #[serde(default)]
    pub severity: Option<Severity>,
    /// Populated when the finding was matched by an ignore rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<IgnoreRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInstance {
    pub uri: String,
    pub method: String,
    pub param: Option<String>,
    pub attack: Option<String>,
    pub evidence: Option<String>,
}

impl Alert {
    /// Build an alert from ZAP's wire fields, deriving severity and an
    /// estimated CVSS score. This is the single place classification happens,
    /// so the real and mock engines cannot drift apart.
    #[allow(clippy::too_many_arguments)]
    pub fn from_zap(
        plugin_id: String,
        alert_ref: String,
        name: String,
        risk: &str,
        confidence: &str,
        url: String,
        description: Option<String>,
        instances: Vec<AlertInstance>,
    ) -> Alert {
        let sev = severity::classify(risk, confidence);
        Alert {
            pluginid: plugin_id,
            alert_ref,
            alert: name.clone(),
            riskcode: sev.to_risk_code(),
            confidence: confidence.to_string(),
            riskdesc: risk.to_string(),
            url,
            description,
            instances,
            cvss_score: severity::estimate_cvss(risk, confidence),
            cvss_estimated: true,
            vulnerability_type: name.clone(),
            name,
            severity: Some(sev),
            suppressed_by: None,
        }
    }

    /// Severity of this finding, falling back to the legacy `riskcode` for
    /// reports written before the `severity` field existed.
    pub fn severity(&self) -> Severity {
        self.severity
            .unwrap_or_else(|| Severity::from_risk_code(&self.riskcode))
    }

    /// The injection point, when ZAP identified one.
    pub fn param(&self) -> Option<&str> {
        self.instances
            .first()
            .and_then(|i| i.param.as_deref())
            .filter(|p| !p.is_empty())
    }

    /// Stable identity across scans, used for baseline comparison and SARIF
    /// fingerprints.
    pub fn fingerprint(&self) -> String {
        crate::fingerprint::finding_fingerprint(
            &self.pluginid,
            &self.alert,
            &self.url,
            self.param(),
        )
    }
}

/// Security scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub timestamp: String,
    /// Which engine produced this report ("zap" or "mock"). Reports from the
    /// mock engine contain fabricated findings.
    #[serde(default = "default_engine")]
    pub engine: String,
    pub alerts: Vec<Alert>,
    /// Findings matched by an ignore rule. Excluded from counts and gating,
    /// but kept so suppressions remain auditable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressed: Vec<Alert>,
}

fn default_engine() -> String {
    "unknown".to_string()
}

impl ScanReport {
    pub fn from_alerts(target: String, alerts: Vec<Alert>) -> Self {
        Self {
            target,
            timestamp: chrono::Local::now().to_rfc3339(),
            engine: default_engine(),
            alerts,
            suppressed: Vec::new(),
        }
    }

    pub fn with_engine(mut self, engine: &str) -> Self {
        self.engine = engine.to_string();
        self
    }

    /// True when these findings were fabricated by the mock engine.
    pub fn is_mock(&self) -> bool {
        self.engine == "mock"
    }

    /// Drop alerts below `min_level`. Note that `low` now excludes
    /// informational findings, which previously collapsed into Low.
    pub fn filter_by_severity(&mut self, min_level: &str) -> anyhow::Result<()> {
        let min_severity = Severity::parse(min_level)?;

        let original_count = self.alerts.len();
        self.alerts.retain(|alert| alert.severity() >= min_severity);

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

    /// Move alerts matching any ignore rule into `suppressed`. Returns the
    /// number suppressed.
    pub fn apply_ignore_rules(&mut self, rules: &[IgnoreRule]) -> usize {
        if rules.is_empty() {
            return 0;
        }

        let mut kept = Vec::with_capacity(self.alerts.len());
        let previously_suppressed = self.suppressed.len();
        let mut suppressed = std::mem::take(&mut self.suppressed);

        for mut alert in std::mem::take(&mut self.alerts) {
            match rules
                .iter()
                .find(|r| r.matches(&alert.pluginid, &alert.alert, &alert.url))
            {
                Some(rule) => {
                    alert.suppressed_by = Some(rule.clone());
                    suppressed.push(alert);
                }
                None => kept.push(alert),
            }
        }

        let newly_suppressed = suppressed.len() - previously_suppressed;
        self.alerts = kept;
        self.suppressed = suppressed;

        if newly_suppressed > 0 {
            tracing::info!("Suppressed {} alerts via ignore rules", newly_suppressed);
        }

        newly_suppressed
    }

    pub fn vulnerability_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn suppressed_count(&self) -> usize {
        self.suppressed.len()
    }

    fn count_at(&self, level: Severity) -> usize {
        self.alerts.iter().filter(|a| a.severity() == level).count()
    }

    pub fn critical_count(&self) -> usize {
        self.count_at(Severity::Critical)
    }

    pub fn high_count(&self) -> usize {
        self.count_at(Severity::High)
    }

    pub fn medium_count(&self) -> usize {
        self.count_at(Severity::Medium)
    }

    pub fn low_count(&self) -> usize {
        self.count_at(Severity::Low)
    }

    pub fn info_count(&self) -> usize {
        self.count_at(Severity::Info)
    }

    /// True when any finding is at or above `threshold`.
    pub fn has_at_or_above(&self, threshold: Severity) -> bool {
        self.alerts.iter().any(|a| a.severity() >= threshold)
    }

    pub fn summary(&self) -> String {
        format!(
            "Summary:\n  Critical: {}\n  High: {}\n  Medium: {}\n  Low: {}\n  Info: {}",
            self.critical_count(),
            self.high_count(),
            self.medium_count(),
            self.low_count(),
            self.info_count()
        )
    }

    /// Average estimated CVSS score across all alerts.
    pub fn average_cvss_score(&self) -> f32 {
        if self.alerts.is_empty() {
            return 0.0;
        }
        let sum: f32 = self.alerts.iter().map(|a| a.cvss_score).sum();
        sum / self.alerts.len() as f32
    }

    /// Highest estimated CVSS score.
    pub fn max_cvss_score(&self) -> f32 {
        self.alerts.iter().map(|a| a.cvss_score).fold(0.0, f32::max)
    }

    /// Count vulnerabilities by type
    pub fn vulnerabilities_by_type(&self) -> std::collections::HashMap<String, usize> {
        let mut map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for alert in &self.alerts {
            *map.entry(alert.vulnerability_type.clone()).or_insert(0) += 1;
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
            info_count: self.info_count(),
            average_cvss: self.average_cvss_score(),
            max_cvss: self.max_cvss_score(),
            vulnerabilities_by_type: self.vulnerabilities_by_type(),
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P, format: &str) -> anyhow::Result<()> {
        let content = match format.to_lowercase().as_str() {
            "json" => serde_json::to_string_pretty(&self)?,
            "yaml" | "yml" => serde_yaml::to_string(&self)?,
            "html" => crate::html::generate_html_report(self),
            "sarif" => crate::sarif::generate_sarif_report(self),
            _ => anyhow::bail!(
                "Unsupported format: {}. Supported formats: json, yaml, html, sarif",
                format
            ),
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
    pub info_count: usize,
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
    /// Change in average estimated CVSS score
    pub average_cvss_delta: f32,
    /// Improvement status
    pub is_improvement: bool,
}

impl ReportComparison {
    /// Create a new comparison between baseline and current report.
    ///
    /// Findings are matched by fingerprint rather than exact URL, so volatile
    /// ids and query values no longer make an unchanged finding look new.
    pub fn new(baseline: &ScanReport, current: &ScanReport) -> Self {
        let baseline_prints: std::collections::HashSet<String> =
            baseline.alerts.iter().map(|a| a.fingerprint()).collect();
        let current_prints: std::collections::HashSet<String> =
            current.alerts.iter().map(|a| a.fingerprint()).collect();

        let mut new_vulns = Vec::new();
        let mut unchanged_vulns = Vec::new();
        for alert in &current.alerts {
            if baseline_prints.contains(&alert.fingerprint()) {
                unchanged_vulns.push(alert.clone());
            } else {
                new_vulns.push(alert.clone());
            }
        }

        let fixed_vulns: Vec<Alert> = baseline
            .alerts
            .iter()
            .filter(|a| !current_prints.contains(&a.fingerprint()))
            .cloned()
            .collect();

        let baseline_breakdown = baseline.risk_breakdown();
        let current_breakdown = current.risk_breakdown();

        let total_delta = current.alerts.len() as i32 - baseline.alerts.len() as i32;
        let critical_delta =
            current_breakdown.critical_count as i32 - baseline_breakdown.critical_count as i32;
        let high_delta = current_breakdown.high_count as i32 - baseline_breakdown.high_count as i32;
        let medium_delta =
            current_breakdown.medium_count as i32 - baseline_breakdown.medium_count as i32;
        let low_delta = current_breakdown.low_count as i32 - baseline_breakdown.low_count as i32;
        let average_cvss_delta = current.average_cvss_score() - baseline.average_cvss_score();

        // An improvement means findings went away and none arrived. Severity
        // is weighted: trading one critical for two lows is still progress.
        let severity_delta =
            critical_delta * 1000 + high_delta * 100 + medium_delta * 10 + low_delta;
        let is_improvement =
            new_vulns.is_empty() && (!fixed_vulns.is_empty() || severity_delta < 0);

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

    /// Highest severity among findings that are new since the baseline.
    pub fn max_new_severity(&self) -> Option<Severity> {
        self.new_vulnerabilities.iter().map(|a| a.severity()).max()
    }

    /// True when any new finding is at or above `threshold`.
    pub fn has_new_at_or_above(&self, threshold: Severity) -> bool {
        self.new_vulnerabilities
            .iter()
            .any(|a| a.severity() >= threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(plugin: &str, risk: &str, confidence: &str, url: &str) -> Alert {
        Alert::from_zap(
            plugin.to_string(),
            plugin.to_string(),
            format!("Finding {}", plugin),
            risk,
            confidence,
            url.to_string(),
            None,
            vec![AlertInstance {
                uri: url.to_string(),
                method: "GET".to_string(),
                param: None,
                attack: None,
                evidence: None,
            }],
        )
    }

    fn report(alerts: Vec<Alert>) -> ScanReport {
        ScanReport::from_alerts("https://x.com".to_string(), alerts)
    }

    #[test]
    fn severity_is_derived_from_risk_and_confidence() {
        assert_eq!(
            alert("1", "High", "High", "https://x.com/a").severity(),
            Severity::Critical
        );
        assert_eq!(
            alert("2", "High", "Low", "https://x.com/a").severity(),
            Severity::High
        );
        assert_eq!(
            alert("3", "Informational", "Medium", "https://x.com/a").severity(),
            Severity::Info
        );
    }

    #[test]
    fn cvss_is_populated_and_marked_estimated() {
        let a = alert("1", "High", "Confirmed", "https://x.com/a");
        assert!(a.cvss_score > 0.0);
        assert!(a.cvss_estimated);
    }

    #[test]
    fn counts_split_info_from_low() {
        let r = report(vec![
            alert("1", "Informational", "Medium", "https://x.com/a"),
            alert("2", "Low", "Medium", "https://x.com/b"),
        ]);
        assert_eq!(r.info_count(), 1);
        assert_eq!(r.low_count(), 1);
    }

    #[test]
    fn filter_low_excludes_informational() {
        let mut r = report(vec![
            alert("1", "Informational", "Medium", "https://x.com/a"),
            alert("2", "Low", "Medium", "https://x.com/b"),
        ]);
        r.filter_by_severity("low").unwrap();
        assert_eq!(r.vulnerability_count(), 1);
        assert_eq!(r.info_count(), 0);
    }

    #[test]
    fn critical_gating_is_reachable() {
        let r = report(vec![alert("1", "High", "Confirmed", "https://x.com/a")]);
        assert_eq!(r.critical_count(), 1);
        assert!(r.has_at_or_above(Severity::Critical));
    }

    #[test]
    fn legacy_reports_without_severity_still_load() {
        // A report as written by an older Tsun: riskcode, no severity field.
        let json = r#"{
            "target": "https://x.com",
            "timestamp": "2026-01-01T00:00:00Z",
            "alerts": [{
                "pluginid": "40012",
                "alertRef": "40012",
                "alert": "XSS",
                "name": "XSS",
                "riskcode": "2",
                "confidence": "2",
                "riskdesc": "High",
                "url": "https://x.com/s",
                "description": null,
                "instances": []
            }]
        }"#;
        let r: ScanReport = serde_json::from_str(json).unwrap();
        assert_eq!(r.alerts[0].severity(), Severity::High);
        assert_eq!(r.high_count(), 1);
        assert_eq!(r.engine, "unknown");
    }

    #[test]
    fn suppression_moves_alerts_out_of_counts() {
        let mut r = report(vec![
            alert("10038", "Medium", "Medium", "https://x.com/a"),
            alert("40012", "High", "High", "https://x.com/b"),
        ]);
        let rules = vec![IgnoreRule {
            plugin: Some("10038".into()),
            reason: Some("handled at CDN".into()),
            ..Default::default()
        }];

        assert_eq!(r.apply_ignore_rules(&rules), 1);
        assert_eq!(r.vulnerability_count(), 1);
        assert_eq!(r.suppressed_count(), 1);
        assert_eq!(r.medium_count(), 0);
        assert_eq!(
            r.suppressed[0]
                .suppressed_by
                .as_ref()
                .unwrap()
                .reason
                .as_deref(),
            Some("handled at CDN")
        );
    }

    #[test]
    fn suppression_is_idempotent() {
        let mut r = report(vec![alert("10038", "Medium", "Medium", "https://x.com/a")]);
        let rules = vec![IgnoreRule {
            plugin: Some("10038".into()),
            ..Default::default()
        }];
        assert_eq!(r.apply_ignore_rules(&rules), 1);
        assert_eq!(r.apply_ignore_rules(&rules), 0);
        assert_eq!(r.suppressed_count(), 1);
    }

    #[test]
    fn comparison_ignores_volatile_url_ids() {
        let baseline = report(vec![alert(
            "40012",
            "Medium",
            "Medium",
            "https://x.com/u/1/p",
        )]);
        let current = report(vec![alert(
            "40012",
            "Medium",
            "Medium",
            "https://x.com/u/98765/p",
        )]);

        let cmp = ReportComparison::new(&baseline, &current);
        assert_eq!(
            cmp.new_vulnerabilities.len(),
            0,
            "same finding, different row id"
        );
        assert_eq!(cmp.fixed_vulnerabilities.len(), 0);
        assert_eq!(cmp.unchanged_vulnerabilities.len(), 1);
    }

    #[test]
    fn comparison_detects_genuinely_new_findings() {
        let baseline = report(vec![alert("40012", "Medium", "Medium", "https://x.com/a")]);
        let current = report(vec![
            alert("40012", "Medium", "Medium", "https://x.com/a"),
            alert("40018", "High", "Confirmed", "https://x.com/b"),
        ]);

        let cmp = ReportComparison::new(&baseline, &current);
        assert_eq!(cmp.new_vulnerabilities.len(), 1);
        assert_eq!(cmp.max_new_severity(), Some(Severity::Critical));
        assert!(cmp.has_new_at_or_above(Severity::High));
        assert!(!cmp.is_improvement);
    }

    #[test]
    fn improvement_requires_no_new_findings() {
        let baseline = report(vec![
            alert("40012", "Medium", "Medium", "https://x.com/a"),
            alert("40018", "High", "Confirmed", "https://x.com/b"),
        ]);
        let current = report(vec![alert("40012", "Medium", "Medium", "https://x.com/a")]);

        let cmp = ReportComparison::new(&baseline, &current);
        assert!(cmp.is_improvement);
        assert_eq!(cmp.fixed_vulnerabilities.len(), 1);
    }

    #[test]
    fn swapping_a_finding_is_not_an_improvement() {
        let baseline = report(vec![alert("40012", "High", "Confirmed", "https://x.com/a")]);
        let current = report(vec![alert("40018", "High", "Confirmed", "https://x.com/b")]);

        let cmp = ReportComparison::new(&baseline, &current);
        assert_eq!(cmp.total_delta, 0);
        assert!(!cmp.is_improvement, "one fixed but one new is not progress");
    }

    #[test]
    fn save_accepts_uppercase_format_names() {
        let r = report(vec![alert("1", "Low", "Medium", "https://x.com/a")]);
        let path = std::env::temp_dir().join("tsun_report_case.json");
        r.save(&path, "JSON").expect("uppercase format should work");
        let _ = std::fs::remove_file(&path);
    }
}
