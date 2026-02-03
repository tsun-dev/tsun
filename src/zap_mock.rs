use crate::report::Alert;
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

/// Mock ZAP client for testing without a real ZAP server
#[derive(Debug)]
pub struct MockZapClient;

impl MockZapClient {
    pub fn new() -> Result<Self> {
        Ok(MockZapClient)
    }

    pub async fn check_health(&self) -> Result<()> {
        // Simulate network latency
        sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    pub async fn start_scan(&self, _target: &str) -> Result<String> {
        // Return a fake scan ID
        Ok("12345".to_string())
    }

    pub async fn wait_for_scan(&self, scan_id: &str, _timeout_secs: u64) -> Result<()> {
        tracing::info!("Mock scan {} progressing: 25%", scan_id);
        sleep(Duration::from_millis(100)).await;
        tracing::info!("Mock scan {} progressing: 50%", scan_id);
        sleep(Duration::from_millis(100)).await;
        tracing::info!("Mock scan {} progressing: 75%", scan_id);
        sleep(Duration::from_millis(100)).await;
        tracing::info!("Mock scan {} completed: 100%", scan_id);
        Ok(())
    }

    pub async fn get_alerts(&self, target: &str) -> Result<Vec<Alert>> {
        Ok(generate_mock_alerts(target))
    }
}

/// Generate realistic mock vulnerability alerts for testing
fn generate_mock_alerts(target: &str) -> Vec<Alert> {
    vec![
        Alert {
            pluginid: "10010".to_string(),
            alert_ref: "10010".to_string(),
            alert: "Cookie without Secure Flag".to_string(),
            name: "Cookie without Secure Flag".to_string(),
            riskcode: "2".to_string(), // High
            confidence: "2".to_string(), // High
            riskdesc: "High".to_string(),
            url: format!("{}/login", target),
            description: Some(
                "A cookie has been set without the Secure flag. The Secure flag is an option that can be set by the application server when sending a new cookie to the user within an HTTP Secure (HTTPS) response.".to_string()
            ),
            instances: vec![
                crate::report::AlertInstance {
                    uri: format!("{}/login", target),
                    method: "POST".to_string(),
                    param: Some("session_id".to_string()),
                    attack: None,
                    evidence: Some("Set-Cookie: session_id=abc123".to_string()),
                },
            ],
        },
        Alert {
            pluginid: "10015".to_string(),
            alert_ref: "10015".to_string(),
            alert: "Re-CAPTCHA Detected".to_string(),
            name: "Re-CAPTCHA Detected".to_string(),
            riskcode: "0".to_string(), // Informational
            confidence: "1".to_string(), // Low
            riskdesc: "Informational".to_string(),
            url: format!("{}/signup", target),
            description: Some("A Re-CAPTCHA was detected".to_string()),
            instances: vec![
                crate::report::AlertInstance {
                    uri: format!("{}/signup", target),
                    method: "GET".to_string(),
                    param: None,
                    attack: None,
                    evidence: Some("script src=\"https://www.google.com/recaptcha/api.js\"".to_string()),
                },
            ],
        },
        Alert {
            pluginid: "90018".to_string(),
            alert_ref: "90018".to_string(),
            alert: "Header Injection".to_string(),
            name: "Header Injection".to_string(),
            riskcode: "2".to_string(), // High
            confidence: "1".to_string(), // Low
            riskdesc: "High".to_string(),
            url: format!("{}/search", target),
            description: Some("The application may be vulnerable to Header Injection attacks.".to_string()),
            instances: vec![
                crate::report::AlertInstance {
                    uri: format!("{}/search?q=test", target),
                    method: "GET".to_string(),
                    param: Some("q".to_string()),
                    attack: Some("test%0d%0aSet-Cookie:%20admin=true".to_string()),
                    evidence: None,
                },
            ],
        },
        Alert {
            pluginid: "10021".to_string(),
            alert_ref: "10021".to_string(),
            alert: "X-Frame-Options Header Missing".to_string(),
            name: "X-Frame-Options Header Missing".to_string(),
            riskcode: "2".to_string(), // High
            confidence: "2".to_string(), // High
            riskdesc: "High".to_string(),
            url: target.to_string(),
            description: Some("The response does not include an X-Frame-Options header.".to_string()),
            instances: vec![
                crate::report::AlertInstance {
                    uri: target.to_string(),
                    method: "GET".to_string(),
                    param: None,
                    attack: None,
                    evidence: None,
                },
            ],
        },
        Alert {
            pluginid: "10035".to_string(),
            alert_ref: "10035".to_string(),
            alert: "Strict-Transport-Security Header Missing".to_string(),
            name: "Strict-Transport-Security Header Missing".to_string(),
            riskcode: "1".to_string(), // Medium
            confidence: "2".to_string(), // High
            riskdesc: "Medium".to_string(),
            url: target.to_string(),
            description: Some("HTTP Strict-Transport-Security (HSTS) header is missing.".to_string()),
            instances: vec![
                crate::report::AlertInstance {
                    uri: target.to_string(),
                    method: "GET".to_string(),
                    param: None,
                    attack: None,
                    evidence: None,
                },
            ],
        },
        Alert {
            pluginid: "10037".to_string(),
            alert_ref: "10037".to_string(),
            alert: "Server Leaks Version Information".to_string(),
            name: "Server Leaks Version Information".to_string(),
            riskcode: "1".to_string(), // Medium
            confidence: "1".to_string(), // Low
            riskdesc: "Medium".to_string(),
            url: target.to_string(),
            description: Some("The server software version is exposed via HTTP headers.".to_string()),
            instances: vec![
                crate::report::AlertInstance {
                    uri: target.to_string(),
                    method: "GET".to_string(),
                    param: None,
                    attack: None,
                    evidence: Some("Server: Apache/2.4.41 (Ubuntu)".to_string()),
                },
            ],
        },
    ]
}
