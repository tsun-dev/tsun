use anyhow::{Context, Result};
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
    new_real_client_with_headers(base_url, &[], None)
}

/// Create a real ZAP scan engine.
///
/// `headers` are credentials for the *scanned target*, not for ZAP's own API.
/// They are installed as ZAP replacer rules before scanning so they ride along
/// on the requests ZAP sends out; `api_key` authenticates us to ZAP itself.
pub fn new_real_client_with_headers(
    base_url: &str,
    headers: &[(String, String)],
    api_key: Option<String>,
) -> Result<Box<dyn ScanEngine>> {
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

    Ok(Box::new(RealZapClient {
        client,
        base_url: base_url.trim_end_matches('/').to_string(),
        api_key,
        auth_headers: headers.to_vec(),
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
    /// Authenticates Tsun to the ZAP API.
    api_key: Option<String>,
    /// Headers to inject into ZAP's outbound requests to the target.
    auth_headers: Vec<(String, String)>,
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
    #[serde(default, alias = "pluginid")]
    #[serde(rename = "pluginId")]
    plugin_id: String,

    #[serde(default, rename = "alertRef")]
    alert_ref: String,

    #[serde(default)]
    alert: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
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

#[async_trait::async_trait]
impl ScanEngine for RealZapClient {
    async fn check_health(&self) -> Result<()> {
        // No blanket context here: api_get already explains connection failures,
        // and wrapping would mask the specific "check your API key" message.
        let body = self.api_get("/JSON/core/view/version/", &[]).await?;

        // A 2xx from something that is not ZAP is not a healthy ZAP.
        let parsed: serde_json::Value = serde_json::from_str(&body).with_context(|| {
            format!("ZAP returned a non-JSON response: {}", truncate(&body, 200))
        })?;

        match parsed.get("version").and_then(|v| v.as_str()) {
            Some(version) => {
                tracing::info!("ZAP version {}", version);
                Ok(())
            }
            None => anyhow::bail!(
                "Endpoint responded but does not look like ZAP: {}",
                truncate(&body, 200)
            ),
        }
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

/// Truncate a response body for error messages so a huge HTML error page does
/// not swamp the log.
fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{}… ({} bytes total)", head, s.len())
}

/// Private implementation helpers for `RealZapClient`.
impl RealZapClient {
    /// Issue a GET against the ZAP API, attaching the API key when configured.
    /// Returns the raw status and body; callers decide what a failure means.
    async fn api_get_raw(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<(reqwest::StatusCode, String)> {
        let url = format!("{}{}", self.base_url, path);

        let mut query: Vec<(&str, String)> = params.to_vec();
        if let Some(ref key) = self.api_key {
            query.push(("apikey", key.clone()));
        }

        let resp = self
            .client
            .get(&url)
            .query(&query)
            .send()
            .await
            .with_context(|| format!("Request to ZAP failed: {}", path))?;

        let status = resp.status();
        let body = resp.text().await?;

        // A 401/403 from ZAP almost always means the API key is wrong; say so
        // rather than surfacing a bare status code.
        if status.as_u16() == 401 || status.as_u16() == 403 {
            anyhow::bail!(
                "ZAP rejected the request (HTTP {}). Check the ZAP API key{}.",
                status,
                if self.api_key.is_some() {
                    ""
                } else {
                    " — none was configured"
                }
            );
        }

        Ok((status, body))
    }

    /// Issue a GET and require a successful status.
    async fn api_get(&self, path: &str, params: &[(&str, String)]) -> Result<String> {
        let (status, body) = self.api_get_raw(path, params).await?;
        if !status.is_success() {
            anyhow::bail!(
                "ZAP API {} failed: HTTP {} - {}",
                path,
                status,
                truncate(&body, 300)
            );
        }
        Ok(body)
    }

    /// Install the target credentials as ZAP replacer rules.
    ///
    /// This is what makes `--header` and `--cookies` reach the scanned
    /// application: ZAP adds these headers to every request it sends, including
    /// spider and active-scan traffic. Setting them on our own HTTP client only
    /// ever authenticated us to ZAP's API, never to the target.
    async fn install_auth_rules(&self) -> Result<()> {
        if self.auth_headers.is_empty() {
            return Ok(());
        }

        for (name, value) in &self.auth_headers {
            if value.trim().is_empty() {
                tracing::warn!("Skipping empty auth header '{}'", name);
                continue;
            }

            let description = format!("tsun-auth-{}", name.to_lowercase());

            // Remove any rule left over from a previous run against a reused
            // ZAP instance; a duplicate description makes addRule fail.
            let _ = self
                .api_get_raw(
                    "/JSON/replacer/action/removeRule/",
                    &[("description", description.clone())],
                )
                .await;

            let params = vec![
                ("description", description.clone()),
                ("enabled", "true".to_string()),
                ("matchType", "REQ_HEADER".to_string()),
                ("matchString", name.clone()),
                ("matchRegex", "false".to_string()),
                ("replacement", value.clone()),
            ];

            let (status, body) = self
                .api_get_raw("/JSON/replacer/action/addRule/", &params)
                .await?;

            if !status.is_success() {
                if body.contains("does_not_exist") || status.as_u16() == 404 {
                    anyhow::bail!(
                        "ZAP's Replacer add-on is not available, so --header/--cookies cannot be \
                         applied to scan traffic. Use a ZAP image that bundles the Replacer \
                         add-on (zaproxy/zap-stable does), or remove the auth flags."
                    );
                }
                anyhow::bail!(
                    "Failed to install auth header '{}' into ZAP: HTTP {} - {}",
                    name,
                    status,
                    truncate(&body, 300)
                );
            }

            tracing::info!("Installed auth header '{}' for scan traffic", name);
        }

        Ok(())
    }

    /// Access a URL to add it to ZAP's site tree before scanning
    async fn access_url(&self, target: &str) -> Result<()> {
        tracing::debug!("ZAP API: Accessing URL to add to site tree: {}", target);

        let (status, body) = self
            .api_get_raw(
                "/JSON/core/action/accessUrl/",
                &[("url", target.to_string())],
            )
            .await?;

        if !status.is_success() {
            tracing::warn!("ZAP accessUrl warning: HTTP {} - Body: {}", status, body);
        }

        Ok(())
    }

    async fn start_spider_scan(&self, target: &str, max_urls: Option<u32>) -> Result<String> {
        tracing::info!(
            "ZAP API: Spidering target to populate site tree: {}",
            target
        );

        let mut query_params = vec![("url", target.to_string())];
        if let Some(max) = max_urls {
            query_params.push(("maxChildren", max.to_string()));
        }

        let (status, body) = self
            .api_get_raw("/JSON/spider/action/scan/", &query_params)
            .await?;

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

        tracing::info!("ZAP spider scan started with id {}", response.scan);
        Ok(response.scan)
    }

    async fn wait_for_spider_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("Spider timeout exceeded after {}s", timeout_secs);
            }

            let (status, body) = self
                .api_get_raw(
                    "/JSON/spider/view/status/",
                    &[("scanId", scan_id.to_string())],
                )
                .await?;

            if !status.is_success() {
                // ZAP answers `does_not_exist` when it has no such spider scan.
                // Polling on would just burn the whole timeout on a request
                // that can never succeed, so surface it now.
                if body.contains("does_not_exist") {
                    anyhow::bail!(
                        "ZAP does not recognize spider scan '{}'. The spider may have been \
                         removed, or ZAP was restarted mid-scan.",
                        scan_id
                    );
                }
                tracing::warn!(
                    "ZAP spider status warning: HTTP {} - Body: {}",
                    status,
                    truncate(&body, 300)
                );
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
        // Credentials must be in place before any traffic leaves ZAP, so that
        // the site tree is built from authenticated responses.
        self.install_auth_rules().await?;

        // First, access the URL to add it to ZAP's site tree
        self.access_url(target).await?;

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

        let (status, body) = self
            .api_get_raw("/JSON/ascan/action/scan/", &query_params)
            .await?;

        let (status, body) =
            if !status.is_success() && status.as_u16() == 400 && body.contains("\"url_not_found\"")
            {
                tracing::warn!(
                    "ZAP returned url_not_found; spidering target then retrying active scan"
                );
                let spider_id = self.start_spider_scan(target, max_urls).await?;
                // Keep this short; it's just to populate the site tree.
                self.wait_for_spider_scan(&spider_id, 60).await?;

                self.api_get_raw("/JSON/ascan/action/scan/", &query_params)
                    .await?
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

            let (status, body) = self
                .api_get_raw(
                    "/JSON/ascan/view/scanProgress/",
                    &[("scanId", scan_id.to_string())],
                )
                .await?;

            if !status.is_success() {
                if body.contains("does_not_exist") {
                    anyhow::bail!(
                        "ZAP does not recognize active scan '{}'. ZAP may have been restarted \
                         mid-scan.",
                        scan_id
                    );
                }
                tracing::warn!(
                    "ZAP API warning: HTTP {} - Body: {}",
                    status,
                    truncate(&body, 300)
                );
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
        let body = self
            .api_get(
                "/JSON/core/view/alerts/",
                &[("baseurl", target.to_string())],
            )
            .await?;

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
            .map(|a| {
                let instances = vec![crate::report::AlertInstance {
                    uri: a.url.clone(),
                    method: a.method,
                    param: a.param,
                    attack: a.attack,
                    evidence: a.evidence,
                }];

                crate::report::Alert::from_zap(
                    a.plugin_id,
                    a.alert_ref,
                    if a.name.is_empty() { a.alert } else { a.name },
                    &a.risk,
                    &a.confidence,
                    a.url,
                    a.description,
                    instances,
                )
            })
            .collect();

        Ok(alerts)
    }
}

pub async fn check_health(host: &str) -> Result<()> {
    let client = new_real_client(host)?;
    client.check_health().await
}
