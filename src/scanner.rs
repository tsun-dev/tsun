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
    max_urls: Option<u32>,
    attack_strength: Option<String>,
    alert_threshold: Option<String>,
}

impl Scanner {
    /// Convenience constructor kept for compatibility (no headers)
    #[allow(dead_code)]
    pub fn new(target: String, config: ScanConfig, use_mock: bool) -> Result<Self> {
        Self::new_with_headers(target, config, use_mock, Vec::new())
    }

    pub fn new_with_headers(
        target: String,
        config: ScanConfig,
        use_mock: bool,
        headers: Vec<(String, String)>,
    ) -> Result<Self> {
        let zap_client = if use_mock {
            Arc::new(crate::zap::ZapClient::mock()?)
        } else {
            Arc::new(crate::zap::ZapClient::new_with_headers(
                &config.zap.host,
                &headers,
            )?)
        };

        Ok(Self {
            target,
            config,
            verbose: false,
            zap_client,
            max_urls: None,
            attack_strength: None,
            alert_threshold: None,
        })
    }

    /// Create a scanner with managed ZAP (Docker-based)
    pub fn new_with_managed_zap(
        target: String,
        config: ScanConfig,
        managed: &crate::zap_managed::ZapManaged,
        headers: Vec<(String, String)>,
    ) -> Result<Self> {
        let zap_client = Arc::new(crate::zap::ZapClient::new_with_headers(
            &managed.zap_url,
            &headers,
        )?);

        Ok(Self {
            target,
            config,
            verbose: false,
            zap_client,
            max_urls: None,
            attack_strength: None,
            alert_threshold: None,
        })
    }

    #[allow(dead_code)]
    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn set_scan_params(
        &mut self,
        max_urls: Option<u32>,
        attack_strength: Option<String>,
        alert_threshold: Option<String>,
    ) {
        self.max_urls = max_urls;
        self.attack_strength = attack_strength;
        self.alert_threshold = alert_threshold;
    }

    pub async fn run(&self) -> Result<ScanReport> {
        if self.verbose {
            tracing::info!("Starting security scan on target: {}", self.target);
        }

        // Start new scan with parameters
        let scan_id = self
            .zap_client
            .start_scan(
                &self.target,
                self.max_urls,
                self.attack_strength.as_deref(),
                self.alert_threshold.as_deref(),
            )
            .await?;

        if self.verbose {
            tracing::info!("Scan ID: {}", scan_id);
        }

        // Wait for scan to complete
        self.zap_client
            .wait_for_scan(&scan_id, self.config.timeout.unwrap_or(1800))
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
