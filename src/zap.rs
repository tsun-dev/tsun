use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug)]
pub struct ZapClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Deserialize)]
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

        Ok(Self {
            client,
            base_url: base_url.to_string(),
        })
    }

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
