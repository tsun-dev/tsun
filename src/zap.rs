use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;

/// Abstraction over real and mock ZAP clients
#[derive(Debug)]
pub enum ZapClient {
    Real(RealZapClient),
    Mock(crate::zap_mock::MockZapClient),
}

#[derive(Debug)]
pub struct RealZapClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ZapResponse<T> {
    #[serde(flatten)]
    data: T,
}

#[derive(Debug, Deserialize)]
struct ScanIdResponse {
    scan: String,
}

#[derive(Debug, Deserialize)]
struct ScanProgressResponse {
    #[serde(rename = "scanProgress")]
    scan_progress: Vec<serde_json::Value>,  // Mixed array: [url_string, {HostProcess: ...}]
}

#[derive(Debug, Deserialize)]
struct AlertsResponse {
    alerts: Vec<crate::report::Alert>,
}

impl ZapClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(ZapClient::Real(RealZapClient {
            client,
            base_url: base_url.to_string(),
        }))
    }

    /// Create a ZapClient with default headers applied to the underlying HTTP client
    pub fn new_with_headers(base_url: &str, headers: &[(String, String)]) -> Result<Self> {
        let mut header_map = reqwest::header::HeaderMap::new();
        for (k, v) in headers {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(val) = reqwest::header::HeaderValue::from_str(v) {
                    header_map.insert(name, val);
                }
            }
        }

        let client = Client::builder()
            .default_headers(header_map)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(ZapClient::Real(RealZapClient {
            client,
            base_url: base_url.to_string(),
        }))
    }

    pub fn mock() -> Result<Self> {
        Ok(ZapClient::Mock(crate::zap_mock::MockZapClient::new()?))
    }

    pub async fn check_health(&self) -> Result<()> {
        match self {
            ZapClient::Real(client) => client.check_health().await,
            ZapClient::Mock(client) => client.check_health().await,
        }
    }

    pub async fn start_scan(&self, target: &str) -> Result<String> {
        match self {
            ZapClient::Real(client) => client.start_scan(target).await,
            ZapClient::Mock(client) => client.start_scan(target).await,
        }
    }

    pub async fn wait_for_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()> {
        match self {
            ZapClient::Real(client) => client.wait_for_scan(scan_id, timeout_secs).await,
            ZapClient::Mock(client) => client.wait_for_scan(scan_id, timeout_secs).await,
        }
    }

    pub async fn get_alerts(&self, target: &str) -> Result<Vec<crate::report::Alert>> {
        match self {
            ZapClient::Real(client) => client.get_alerts(target).await,
            ZapClient::Mock(client) => client.get_alerts(target).await,
        }
    }
}

impl RealZapClient {
    pub async fn check_health(&self) -> Result<()> {
        let url = format!("{}/JSON/core/action/version/", self.base_url);
        self.client.get(&url).send().await?;
        Ok(())
    }

    /// Access a URL to add it to ZAP's site tree before scanning
    async fn access_url(&self, target: &str) -> Result<()> {
        let url = format!(
            "{}/JSON/core/action/accessUrl/",
            self.base_url.trim_end_matches('/')
        );

        tracing::debug!("ZAP API: Accessing URL to add to site tree: {}", target);

        let request = self
            .client
            .get(&url)
            .query(&[("url", target)])
            .build()?;

        let resp = self.client.execute(request).await?;
        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            tracing::warn!("ZAP accessUrl warning: HTTP {} - Body: {}", status, body);
        }

        Ok(())
    }

    pub async fn start_scan(&self, target: &str) -> Result<String> {
        // First, access the URL to add it to ZAP's site tree
        self.access_url(target).await?;

        let url = format!(
            "{}/JSON/ascan/action/scan/",
            self.base_url.trim_end_matches('/')
        );

        tracing::info!("ZAP API: Starting scan for {}", target);

        let request = self
            .client
            .get(&url)
            .query(&[("url", target)])
            .build()?;

        let resp = self
            .client
            .execute(request)
            .await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            tracing::error!("ZAP API error: HTTP {} - Body: {}", status, body);
            return Err(anyhow::anyhow!("ZAP start_scan failed: HTTP {} - {}", status, body));
        }

        let response: ScanIdResponse = serde_json::from_str(&body)
            .map_err(|e| {
                tracing::error!("JSON parse error: {} - Body: {}", e, body);
                anyhow::anyhow!("Failed to parse ZAP response as JSON: {} - Body: {}", e, body)
            })?;

        Ok(response.scan)
    }

    pub async fn wait_for_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        
        // Give ZAP a moment to actually start the scan
        sleep(Duration::from_secs(3)).await;
        
        let mut was_running = false;
        let mut empty_count = 0;
        let mut last_progress = 0;

        loop {
            if start.elapsed() > timeout {
                eprintln!("  ⚠ Scan timeout exceeded after {}s", timeout_secs);
                anyhow::bail!("Scan timeout exceeded");
            }

            let url = format!(
                "{}/JSON/ascan/view/scanProgress/",
                self.base_url.trim_end_matches('/')
            );

            let resp = self
                .client
                .get(&url)
                .query(&[("scanId", scan_id)])
                .send()
                .await?;

            let status = resp.status();
            let body = resp.text().await?;

            if !status.is_success() {
                tracing::warn!("ZAP API warning: HTTP {}", status);
                sleep(Duration::from_secs(2)).await;
                continue;
            }

            let response: ScanProgressResponse = serde_json::from_str(&body)
                .map_err(|e| {
                    tracing::error!("JSON parse error in wait_for_scan: {} - Body: {}", e, body);
                    anyhow::anyhow!("Failed to parse ZAP status response: {} - Body: {}", e, body)
                })?;

            if response.scan_progress.is_empty() {
                empty_count += 1;
                
                // If empty for too long, scan may have finished quickly or not started
                if empty_count > 6 {  // 30 seconds of empty
                    if was_running {
                        break;
                    } else {
                        // Try to get alerts anyway - maybe scan finished instantly
                        break;
                    }
                }
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            
            empty_count = 0;  // Reset on non-empty response

            // Parse the complex scanProgress format
            let mut total_plugins = 0;
            let mut completed_plugins = 0;
            let mut has_active = false;
            
            // scanProgress is: [url_string, {"HostProcess": [{"Plugin": [name,id,rel,status,...]}, ...]}]
            if let Some(progress_val) = response.scan_progress.get(1) {
                if let Some(host_process) = progress_val.get("HostProcess") {
                    if let Some(plugin_list) = host_process.as_array() {
                        for plugin_obj in plugin_list {
                            // Each element is {"Plugin": [name, id, release, status, ...]}
                            if let Some(plugin_data) = plugin_obj.get("Plugin").and_then(|v| v.as_array()) {
                                total_plugins += 1;
                                // Plugin format: [name, id, release, status, ...]
                                if let Some(status_str) = plugin_data.get(3).and_then(|v| v.as_str()) {
                                    if status_str == "Complete" {
                                        completed_plugins += 1;
                                    } else if status_str.ends_with('%') {
                                        has_active = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if total_plugins > 0 {
                was_running = true;
                let progress_pct = (completed_plugins * 100) / total_plugins;
                
                // Only print when progress changes significantly
                if progress_pct != last_progress || progress_pct == 100 {
                    eprintln!("  Scan progress: {}/{} plugins complete ({}%)", completed_plugins, total_plugins, progress_pct);
                    last_progress = progress_pct;
                }
                
                // Scan is done when no plugins are actively running (showing %)
                if !has_active && completed_plugins > 0 {
                    break;
                }
            } else if was_running {
                // Empty progress after running means done
                break;
            }
            // If never started running and still empty, keep waiting

            sleep(Duration::from_secs(5)).await;
        }

        Ok(())
    }

    pub async fn get_alerts(&self, target: &str) -> Result<Vec<crate::report::Alert>> {
        let url = format!(
            "{}/JSON/core/view/alerts/?baseurl={}",
            self.base_url,
            urlencoding::encode(target)
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            tracing::error!("ZAP API error: HTTP {} - Body: {}", status, body);
            return Err(anyhow::anyhow!("ZAP get_alerts failed: HTTP {} - {}", status, body));
        }

        let response: AlertsResponse = serde_json::from_str(&body)
            .map_err(|e| {
                tracing::error!("JSON parse error in get_alerts: {} - Body: {}", e, body);
                anyhow::anyhow!("Failed to parse ZAP alerts response: {} - Body: {}", e, body)
            })?;

        Ok(response.alerts)
    }
}

pub async fn check_health(host: &str) -> Result<()> {
    let client = ZapClient::new(host)?;
    client.check_health().await
}
