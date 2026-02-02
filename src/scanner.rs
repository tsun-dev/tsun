use crate::config::ScanConfig;
use crate::report::ScanReport;
use anyhow::Result;
use std::sync::Arc;

/// Main scanner interface
pub struct Scanner {
    target: String,
    config: ScanConfig,
    verbose: bool,
    zap_client: Arc<crate::zap::ZapClient>,
}

impl Scanner {
    pub fn new(target: String, config: ScanConfig) -> Result<Self> {
        let zap_client = Arc::new(crate::zap::ZapClient::new(&config.zap.host)?);
        Ok(Self {
            target,
            config,
            verbose: false,
            zap_client,
        })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub async fn run(&self) -> Result<ScanReport> {
        if self.verbose {
            tracing::info!("Starting security scan on target: {}", self.target);
        }

        // Start new scan
        let scan_id = self.zap_client.start_scan(&self.target).await?;

        if self.verbose {
            tracing::info!("Scan ID: {}", scan_id);
        }

        // Wait for scan to complete
        self.zap_client
            .wait_for_scan(&scan_id, self.config.timeout.unwrap_or(300))
            .await?;

        if self.verbose {
            tracing::info!("Scan completed, retrieving results");
        }

        // Get scan results
        let alerts = self.zap_client.get_alerts(&self.target).await?;

        let report = ScanReport::from_alerts(self.target.clone(), alerts);

        Ok(report)
    }
}
