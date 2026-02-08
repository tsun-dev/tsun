use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;

/// Trait defining the scan-engine contract.
///
/// Both the real ZAP HTTP client and the mock implement this,
/// allowing `Scanner` to work with either via `Arc<dyn ScanEngine>`.
#[async_trait::async_trait]
pub trait ScanEngine: Send + Sync + std::fmt::Debug {
    async fn check_health(&self) -> Result<()>;

    async fn start_scan(
        &self,
        target: &str,
        max_urls: Option<u32>,
        attack_strength: Option<&str>,
        alert_threshold: Option<&str>,
    ) -> Result<String>;

    async fn wait_for_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()>;

    async fn get_alerts(&self, target: &str) -> Result<Vec<crate::report::Alert>>;
}

/// Create a real ZAP scan engine pointing at `base_url`.
pub fn new_real_client(base_url: &str) -> Result<Box<dyn ScanEngine>> {
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
    Ok(Box::new(RealZapClient {
        client,
        base_url: base_url.to_string(),
    }))
}

/// Create a real ZAP scan engine with default headers applied.
pub fn new_real_client_with_headers(
    base_url: &str,
    headers: &[(String, String)],
) -> Result<Box<dyn ScanEngine>> {
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

    Ok(Box::new(RealZapClient {
        client,
        base_url: base_url.to_string(),
    }))
}

/// Create a mock scan engine for testing.
pub fn new_mock_client() -> Result<Box<dyn ScanEngine>> {
    Ok(Box::new(crate::zap_mock::MockZapClient::new()?))
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
struct SpiderStatusResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct ScanProgressResponse {
    #[serde(rename = "scanProgress")]
    scan_progress: Vec<serde_json::Value>, // Mixed array: [url_string, {HostProcess: ...}]
}

// NOTE: We intentionally parse ZAP's alert schema via `ZapAlertsApiResponse` and
// convert into `crate::report::Alert` to handle version/schema drift.

#[derive(Debug, Deserialize)]
struct ZapAlertsApiResponse {
    alerts: Vec<ZapAlertApi>,
}

#[derive(Debug, Deserialize)]
struct ZapAlertApi {
    #[serde(alias = "pluginid")]
    #[serde(rename = "pluginId")]
    plugin_id: String,

    #[serde(rename = "alertRef")]
    alert_ref: String,

    alert: String,
    name: String,
    url: String,

    #[serde(default)]
    description: Option<String>,

    /// ZAP typically returns risk as "Informational" | "Low" | "Medium" | "High".
    #[serde(default, alias = "riskcode")]
    risk: String,

    #[serde(default)]
    confidence: String,

    #[serde(default)]
    method: String,

    #[serde(default)]
    param: Option<String>,

    #[serde(default)]
    attack: Option<String>,

    #[serde(default)]
    evidence: Option<String>,
}

fn zap_risk_to_code(risk: &str) -> String {
    match risk.to_lowercase().as_str() {
        // ZAP commonly uses these.
        "high" => "2".to_string(),
        "medium" => "1".to_string(),
        "low" => "0".to_string(),
        "informational" | "info" => "0".to_string(),
        // Some ZAP APIs/versions can return numeric-like strings.
        "3" | "2" | "1" | "0" => risk.to_string(),
        // Unknown → low.
        _ => "0".to_string(),
    }
}

#[async_trait::async_trait]
impl ScanEngine for RealZapClient {
    async fn check_health(&self) -> Result<()> {
        let url = format!("{}/JSON/core/action/version/", self.base_url);
        self.client.get(&url).send().await?;
        Ok(())
    }

    async fn start_scan(
        &self,
        target: &str,
        max_urls: Option<u32>,
        attack_strength: Option<&str>,
        alert_threshold: Option<&str>,
    ) -> Result<String> {
        self.do_start_scan(target, max_urls, attack_strength, alert_threshold)
            .await
    }

    async fn wait_for_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()> {
        self.do_wait_for_scan(scan_id, timeout_secs).await
    }

    async fn get_alerts(&self, target: &str) -> Result<Vec<crate::report::Alert>> {
        self.do_get_alerts(target).await
    }
}

/// Private implementation helpers for `RealZapClient`.
impl RealZapClient {
    /// Access a URL to add it to ZAP's site tree before scanning
    async fn access_url(&self, target: &str) -> Result<()> {
        let url = format!(
            "{}/JSON/core/action/accessUrl/",
            self.base_url.trim_end_matches('/')
        );

        tracing::debug!("ZAP API: Accessing URL to add to site tree: {}", target);

        let request = self.client.get(&url).query(&[("url", target)]).build()?;

        let resp = self.client.execute(request).await?;
        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            tracing::warn!("ZAP accessUrl warning: HTTP {} - Body: {}", status, body);
        }

        Ok(())
    }

    async fn start_spider_scan(&self, target: &str, max_urls: Option<u32>) -> Result<String> {
        let url = format!(
            "{}/JSON/spider/action/scan/",
            self.base_url.trim_end_matches('/')
        );

        tracing::info!(
            "ZAP API: Spidering target to populate site tree: {}",
            target
        );

        let mut query_params = vec![("url", target.to_string())];
        if let Some(max) = max_urls {
            query_params.push(("maxChildren", max.to_string()));
        }

        let request = self.client.get(&url).query(&query_params).build()?;
        let resp = self.client.execute(request).await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            tracing::warn!("ZAP spider scan warning: HTTP {} - Body: {}", status, body);
            anyhow::bail!("ZAP spider scan failed: HTTP {} - {}", status, body);
        }

        let response: ScanIdResponse = serde_json::from_str(&body).map_err(|e| {
            tracing::error!(
                "JSON parse error in start_spider_scan: {} - Body: {}",
                e,
                body
            );
            anyhow::anyhow!(
                "Failed to parse ZAP spider response as JSON: {} - Body: {}",
                e,
                body
            )
        })?;

        Ok(response.scan)
    }

    async fn wait_for_spider_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("Spider timeout exceeded after {}s", timeout_secs);
            }

            let url = format!(
                "{}/JSON/spider/view/status/",
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
                tracing::warn!("ZAP spider status warning: HTTP {}", status);
                sleep(Duration::from_secs(2)).await;
                continue;
            }

            let response: SpiderStatusResponse = serde_json::from_str(&body).map_err(|e| {
                tracing::error!(
                    "JSON parse error in wait_for_spider_scan: {} - Body: {}",
                    e,
                    body
                );
                anyhow::anyhow!(
                    "Failed to parse ZAP spider status response: {} - Body: {}",
                    e,
                    body
                )
            })?;

            if response.status == "100" {
                return Ok(());
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    async fn do_start_scan(
        &self,
        target: &str,
        max_urls: Option<u32>,
        attack_strength: Option<&str>,
        alert_threshold: Option<&str>,
    ) -> Result<String> {
        // First, access the URL to add it to ZAP's site tree
        self.access_url(target).await?;

        let url = format!(
            "{}/JSON/ascan/action/scan/",
            self.base_url.trim_end_matches('/')
        );

        tracing::info!("ZAP API: Starting scan for {}", target);

        let mut query_params = vec![("url", target.to_string())];

        if let Some(max) = max_urls {
            query_params.push(("maxChildren", max.to_string()));
        }

        if let Some(strength) = attack_strength {
            query_params.push(("attackStrength", strength.to_uppercase()));
        }

        if let Some(threshold) = alert_threshold {
            query_params.push(("alertThreshold", threshold.to_uppercase()));
        }

        let request = self.client.get(&url).query(&query_params).build()?;

        let resp = self.client.execute(request).await?;

        let status = resp.status();
        let body = resp.text().await?;

        let (status, body) =
            if !status.is_success() && status.as_u16() == 400 && body.contains("\"url_not_found\"")
            {
                tracing::warn!(
                    "ZAP returned url_not_found; spidering target then retrying active scan"
                );
                let spider_id = self.start_spider_scan(target, max_urls).await?;
                // Keep this short; it's just to populate the site tree.
                self.wait_for_spider_scan(&spider_id, 60).await?;

                let request = self.client.get(&url).query(&query_params).build()?;
                let resp = self.client.execute(request).await?;
                let status = resp.status();
                let body = resp.text().await?;
                (status, body)
            } else {
                (status, body)
            };

        if !status.is_success() {
            tracing::error!("ZAP API error: HTTP {} - Body: {}", status, body);
            return Err(anyhow::anyhow!(
                "ZAP start_scan failed: HTTP {} - {}",
                status,
                body
            ));
        }

        let response: ScanIdResponse = serde_json::from_str(&body).map_err(|e| {
            tracing::error!("JSON parse error: {} - Body: {}", e, body);
            anyhow::anyhow!(
                "Failed to parse ZAP response as JSON: {} - Body: {}",
                e,
                body
            )
        })?;

        Ok(response.scan)
    }

    async fn do_wait_for_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let mut last_print = std::time::Instant::now();
        let print_every = Duration::from_secs(20);

        // Give ZAP a moment to actually start the scan
        sleep(Duration::from_secs(3)).await;

        let mut was_running = false;
        let mut empty_count = 0;
        let mut last_overall_pct: i32 = -1;

        loop {
            if start.elapsed() > timeout {
                println!("  ⚠ Scan timeout exceeded after {}s", timeout_secs);
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

            let response: ScanProgressResponse = serde_json::from_str(&body).map_err(|e| {
                tracing::error!("JSON parse error in wait_for_scan: {} - Body: {}", e, body);
                anyhow::anyhow!(
                    "Failed to parse ZAP status response: {} - Body: {}",
                    e,
                    body
                )
            })?;

            if response.scan_progress.is_empty() {
                empty_count += 1;
                if empty_count == 1 || empty_count % 3 == 0 {
                    println!("  Waiting for scan to start... ({} checks)", empty_count);
                }

                // If empty for too long, scan may have finished quickly or not started
                if empty_count > 6 {
                    // 30 seconds of empty
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

            empty_count = 0; // Reset on non-empty response

            // Parse the complex scanProgress format
            let mut total_plugins = 0;
            let mut completed_plugins = 0;
            let mut _has_active = false;
            let mut sum_pct: i32 = 0;
            let mut active_plugins = 0;
            let mut pending_plugins = 0;
            let mut most_advanced_active: Option<(String, i32)> = None;

            // scanProgress is: [url_string, {"HostProcess": [{"Plugin": [name,id,rel,status,...]}, ...]}]
            if let Some(progress_val) = response.scan_progress.get(1) {
                if let Some(host_process) = progress_val.get("HostProcess") {
                    if let Some(plugin_list) = host_process.as_array() {
                        for plugin_obj in plugin_list {
                            // Each element is {"Plugin": [name, id, release, status, ...]}
                            if let Some(plugin_data) =
                                plugin_obj.get("Plugin").and_then(|v| v.as_array())
                            {
                                total_plugins += 1;
                                // Plugin format: [name, id, release, status, ...]
                                if let Some(status_str) =
                                    plugin_data.get(3).and_then(|v| v.as_str())
                                {
                                    let pct: i32 =
                                        if status_str == "Complete" || status_str == "100%" {
                                            completed_plugins += 1;
                                            100
                                        } else if let Some(raw) = status_str.strip_suffix('%') {
                                            // Prefer to treat any N% as active work.
                                            if let Ok(p) = raw.parse::<i32>() {
                                                if p < 100 {
                                                    _has_active = true;
                                                    active_plugins += 1;
                                                    let name = plugin_data
                                                        .first()
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("(unknown)")
                                                        .to_string();

                                                    let is_better = most_advanced_active
                                                        .as_ref()
                                                        .map(|(_, best_pct)| p > *best_pct)
                                                        .unwrap_or(true);
                                                    if is_better {
                                                        most_advanced_active = Some((name, p));
                                                    }
                                                }
                                                p.clamp(0, 100)
                                            } else {
                                                pending_plugins += 1;
                                                0
                                            }
                                        } else {
                                            // e.g. "Pending", "Queued", "" or other strings.
                                            pending_plugins += 1;
                                            0
                                        };
                                    sum_pct += pct;
                                }
                            }
                        }
                    }
                }
            }

            if total_plugins > 0 {
                was_running = true;
                let overall_pct = (sum_pct / total_plugins).clamp(0, 100);

                // Print to stdout so it doesn't get overwritten by the spinner/tracing output (stderr).
                if overall_pct != last_overall_pct || last_print.elapsed() >= print_every {
                    let active_hint = most_advanced_active
                        .as_ref()
                        .map(|(name, pct)| {
                            let mut n = name.clone();
                            const MAX: usize = 48;
                            if n.len() > MAX {
                                n.truncate(MAX);
                                n.push_str("...");
                            }
                            format!("; active: {} {}%", n, pct)
                        })
                        .unwrap_or_default();

                    println!(
                        "  Scan progress: {}% ({}/{} complete, {} active, {} pending{})",
                        overall_pct,
                        completed_plugins,
                        total_plugins,
                        active_plugins,
                        pending_plugins,
                        active_hint
                    );
                    last_overall_pct = overall_pct;
                    last_print = std::time::Instant::now();
                }

                // Scan is done when all plugins are complete.
                // Do NOT stop just because nothing is "active"—ZAP can have queued/pending plugins.
                if completed_plugins >= total_plugins {
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

    async fn do_get_alerts(&self, target: &str) -> Result<Vec<crate::report::Alert>> {
        let url = format!(
            "{}/JSON/core/view/alerts/?baseurl={}",
            self.base_url,
            urlencoding::encode(target)
        );

        let resp = self.client.get(&url).send().await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            tracing::error!("ZAP API error: HTTP {} - Body: {}", status, body);
            return Err(anyhow::anyhow!(
                "ZAP get_alerts failed: HTTP {} - {}",
                status,
                body
            ));
        }

        // ZAP's alerts schema varies between versions/addons (pluginId vs pluginid, risk vs riskcode, etc).
        // Parse using a tolerant API struct and convert to our internal Alert model.
        let api_response: ZapAlertsApiResponse = serde_json::from_str(&body).map_err(|e| {
            tracing::error!("JSON parse error in get_alerts: {} - Body: {}", e, body);
            anyhow::anyhow!(
                "Failed to parse ZAP alerts response: {} - Body: {}",
                e,
                body
            )
        })?;

        let alerts = api_response
            .alerts
            .into_iter()
            .map(|a| crate::report::Alert {
                pluginid: a.plugin_id,
                alert_ref: a.alert_ref,
                alert: a.alert.clone(),
                name: a.name,
                riskcode: zap_risk_to_code(&a.risk),
                confidence: a.confidence,
                riskdesc: a.risk,
                url: a.url.clone(),
                description: a.description,
                instances: vec![crate::report::AlertInstance {
                    uri: a.url,
                    method: a.method,
                    param: a.param,
                    attack: a.attack,
                    evidence: a.evidence,
                }],
                cvss_score: 0.0,
                vulnerability_type: a.alert,
            })
            .collect();

        Ok(alerts)
    }
}

pub async fn check_health(host: &str) -> Result<()> {
    let client = new_real_client(host)?;
    client.check_health().await
}
