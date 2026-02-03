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
struct ScanStatusResponse {
    status: String,
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

    pub async fn start_scan(&self, target: &str) -> Result<String> {
        let url = format!(
            "{}/JSON/ascan/action/scan/?url={}",
            self.base_url,
            urlencoding::encode(target)
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await?
            .json::<ScanIdResponse>()
            .await?;

        Ok(response.scan)
    }

    pub async fn wait_for_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("Scan timeout exceeded");
            }

            let url = format!(
                "{}/JSON/ascan/view/scanProgress/?scanId={}",
                self.base_url, scan_id
            );

            let response = self
                .client
                .get(&url)
                .send()
                .await?
                .json::<ScanStatusResponse>()
                .await?;

            let progress: i32 = response.status.parse().unwrap_or(0);

            if progress >= 100 {
                break;
            }

            tracing::debug!("Scan progress: {}%", progress);
            sleep(Duration::from_secs(2)).await;
        }

        Ok(())
    }

    pub async fn get_alerts(&self, target: &str) -> Result<Vec<crate::report::Alert>> {
        let url = format!(
            "{}/JSON/core/view/alerts/?baseurl={}",
            self.base_url,
            urlencoding::encode(target)
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await?
            .json::<AlertsResponse>()
            .await?;

        Ok(response.alerts)
    }
}

pub async fn check_health(host: &str) -> Result<()> {
    let client = ZapClient::new(host)?;
    client.check_health().await
}
