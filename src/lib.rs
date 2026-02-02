#[cfg(test)]
mod tests {
    use crate::config::ScanConfig;
    use crate::scanner::Scanner;

    #[tokio::test]
    async fn test_mock_scan() {
        let config = ScanConfig::default();
        let mut scanner = Scanner::new(
            "https://example.com".to_string(),
            config,
            true, // use_mock
        )
        .expect("Failed to create scanner");

        scanner.set_verbose(true);

        let report: crate::report::ScanReport = scanner
            .run()
            .await
            .expect("Failed to run mock scan");

        assert_eq!(report.target, "https://example.com");
        assert!(report.vulnerability_count() > 0);
        println!("Mock scan summary:\n{}", report.summary());
    }

    #[tokio::test]
    async fn test_mock_scan_severity_counts() {
        let config = ScanConfig::default();
        let scanner = Scanner::new(
            "https://example.com".to_string(),
            config,
            true, // use_mock
        )
        .expect("Failed to create scanner");

        let report: crate::report::ScanReport = scanner
            .run()
            .await
            .expect("Failed to run mock scan");

        // Verify we got the expected mock vulnerabilities
        assert_eq!(report.critical_count(), 0);
        assert!(report.high_count() > 0);
        assert!(report.medium_count() > 0);
        assert!(report.low_count() > 0);
    }

    #[tokio::test]
    async fn test_config_template_generation() {
        let template = ScanConfig::template();
        assert!(template.contains("zap:"));
        assert!(template.contains("host:"));
        assert!(template.contains("policies:"));
    }

    #[test]
    fn test_config_default() {
        let config = ScanConfig::default();
        assert_eq!(config.zap.host, "http://localhost:8080");
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0], "default");
    }

    #[tokio::test]
    async fn test_html_report_generation() {
        let config = ScanConfig::default();
        let scanner = Scanner::new(
            "https://example.com".to_string(),
            config,
            true, // use_mock
        )
        .expect("Failed to create scanner");

        let report: crate::report::ScanReport = scanner
            .run()
            .await
            .expect("Failed to run mock scan");

        let html = crate::html::generate_html_report(&report);
        
        // Verify HTML contains expected elements
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Security Scan Report"));
        assert!(html.contains("https://example.com"));
        assert!(html.contains("Vulnerability Summary"));
        assert!(html.contains("HIGH"));
        assert!(html.contains("MEDIUM"));
        assert!(html.contains("LOW"));
        assert!(html.contains("<table"));
        assert!(html.contains("Detailed Findings"));
    }
}

pub mod config;
pub mod report;
pub mod scanner;
pub mod zap;
pub mod zap_mock;
pub mod html;
