use crate::report::{Alert, AlertInstance};
use crate::zap::ScanEngine;
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

/// Mock ZAP client for testing without a real ZAP server.
///
/// Findings produced here are fabricated. Reports carry `engine: "mock"` so
/// nothing downstream mistakes them for a real scan.
#[derive(Debug)]
pub struct MockZapClient;

impl MockZapClient {
    pub fn new() -> Result<Self> {
        Ok(MockZapClient)
    }
}

#[async_trait::async_trait]
impl ScanEngine for MockZapClient {
    async fn check_health(&self) -> Result<()> {
        // Simulate network latency
        sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    async fn start_scan(
        &self,
        _target: &str,
        _max_urls: Option<u32>,
        _attack_strength: Option<&str>,
        _alert_threshold: Option<&str>,
    ) -> Result<String> {
        // Return a fake scan ID
        Ok("12345".to_string())
    }

    async fn wait_for_scan(&self, scan_id: &str, _timeout_secs: u64) -> Result<()> {
        tracing::info!("Mock scan {} progressing: 25%", scan_id);
        sleep(Duration::from_millis(100)).await;
        tracing::info!("Mock scan {} progressing: 50%", scan_id);
        sleep(Duration::from_millis(100)).await;
        tracing::info!("Mock scan {} progressing: 75%", scan_id);
        sleep(Duration::from_millis(100)).await;
        tracing::info!("Mock scan {} completed: 100%", scan_id);
        Ok(())
    }

    async fn get_alerts(&self, target: &str) -> Result<Vec<Alert>> {
        Ok(generate_mock_alerts(target))
    }
}

/// One fabricated finding, shaped the way ZAP's API returns them.
struct MockFinding {
    plugin_id: &'static str,
    name: &'static str,
    risk: &'static str,
    confidence: &'static str,
    path: &'static str,
    method: &'static str,
    param: Option<&'static str>,
    attack: Option<&'static str>,
    evidence: Option<&'static str>,
    description: &'static str,
}

/// Generate realistic mock vulnerability alerts for testing.
///
/// The set deliberately spans every severity the classifier can produce —
/// including a Critical (High risk + Confirmed confidence) and an
/// Informational — so filtering and gating logic is exercised end to end.
fn generate_mock_alerts(target: &str) -> Vec<Alert> {
    let findings = [
        MockFinding {
            plugin_id: "40018",
            name: "SQL Injection",
            risk: "High",
            confidence: "Confirmed",
            path: "/search",
            method: "POST",
            param: Some("query"),
            attack: Some("' OR '1'='1"),
            evidence: Some("You have an error in your SQL syntax"),
            description: "SQL injection may be possible. The application appears to pass unsanitized input into a database query.",
        },
        MockFinding {
            plugin_id: "40012",
            name: "Cross Site Scripting (Reflected)",
            risk: "High",
            confidence: "Medium",
            path: "/profile",
            method: "GET",
            param: Some("name"),
            attack: Some("<script>alert(1)</script>"),
            evidence: Some("<script>alert(1)</script>"),
            description: "Cross-site scripting was found. User input is reflected into the response without encoding.",
        },
        MockFinding {
            plugin_id: "10010",
            name: "Cookie Without Secure Flag",
            risk: "Medium",
            confidence: "High",
            path: "/login",
            method: "POST",
            param: Some("session"),
            attack: None,
            evidence: Some("Set-Cookie: session=abc123"),
            description: "A cookie has been set without the Secure flag, so it can be transmitted over an unencrypted connection.",
        },
        MockFinding {
            plugin_id: "10038",
            name: "Content Security Policy (CSP) Header Not Set",
            risk: "Medium",
            confidence: "Medium",
            path: "/",
            method: "GET",
            param: None,
            attack: None,
            evidence: None,
            description: "No Content-Security-Policy header was set, so the browser has no policy limiting where content may load from.",
        },
        MockFinding {
            plugin_id: "10021",
            name: "X-Content-Type-Options Header Missing",
            risk: "Low",
            confidence: "Medium",
            path: "/static/app.js",
            method: "GET",
            param: None,
            attack: None,
            evidence: None,
            description: "The X-Content-Type-Options header was not set to 'nosniff', allowing older browsers to MIME-sniff the response.",
        },
        MockFinding {
            plugin_id: "10015",
            name: "Server Leaks Version Information",
            risk: "Informational",
            confidence: "High",
            path: "/",
            method: "GET",
            param: None,
            attack: None,
            evidence: Some("Server: nginx/1.18.0"),
            description: "The web server responds with a header disclosing its version, which helps an attacker target known issues.",
        },
    ];

    findings
        .into_iter()
        .map(|f| {
            let url = format!("{}{}", target.trim_end_matches('/'), f.path);
            Alert::from_zap(
                f.plugin_id.to_string(),
                f.plugin_id.to_string(),
                f.name.to_string(),
                f.risk,
                f.confidence,
                url.clone(),
                Some(f.description.to_string()),
                vec![AlertInstance {
                    uri: url,
                    method: f.method.to_string(),
                    param: f.param.map(str::to_string),
                    attack: f.attack.map(str::to_string),
                    evidence: f.evidence.map(str::to_string),
                }],
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::Severity;

    #[test]
    fn mock_alerts_span_every_severity() {
        let alerts = generate_mock_alerts("https://example.com");
        let severities: Vec<Severity> = alerts.iter().map(|a| a.severity()).collect();

        for expected in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            assert!(
                severities.contains(&expected),
                "mock data should include a {:?} finding so gating logic is exercised",
                expected
            );
        }
    }

    #[test]
    fn mock_alerts_have_estimated_cvss() {
        for alert in generate_mock_alerts("https://example.com") {
            assert!(alert.cvss_estimated);
            if alert.severity() > Severity::Info {
                assert!(alert.cvss_score > 0.0, "{} scored 0", alert.alert);
            }
        }
    }

    #[test]
    fn mock_urls_are_built_without_double_slashes() {
        let alerts = generate_mock_alerts("https://example.com/");
        assert!(alerts.iter().all(|a| !a.url.contains("com//")));
    }
}
