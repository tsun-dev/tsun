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

    #[tokio::test]
    async fn test_severity_filtering_high() {
        let config = ScanConfig::default();
        let scanner = Scanner::new(
            "https://example.com".to_string(),
            config,
            true, // use_mock
        )
        .expect("Failed to create scanner");

        let mut report: crate::report::ScanReport = scanner
            .run()
            .await
            .expect("Failed to run mock scan");

        let original_count = report.vulnerability_count();
        report.filter_by_severity("high").expect("Filter failed");
        
        // Should only have high severity issues (excludes medium/low)
        assert!(report.vulnerability_count() < original_count);
        assert!(report.high_count() > 0);
        assert_eq!(report.medium_count(), 0);
        assert_eq!(report.low_count(), 0);
    }

    #[tokio::test]
    async fn test_severity_filtering_medium() {
        let config = ScanConfig::default();
        let scanner = Scanner::new(
            "https://example.com".to_string(),
            config,
            true, // use_mock
        )
        .expect("Failed to create scanner");

        let mut report: crate::report::ScanReport = scanner
            .run()
            .await
            .expect("Failed to run mock scan");

        let original_count = report.vulnerability_count();
        report.filter_by_severity("medium").expect("Filter failed");
        
        // Should have medium and high (excludes low)
        assert!(report.vulnerability_count() < original_count);
        assert_eq!(report.low_count(), 0);
    }

    #[tokio::test]
    async fn test_severity_filtering_low() {
        let config = ScanConfig::default();
        let scanner = Scanner::new(
            "https://example.com".to_string(),
            config,
            true, // use_mock
        )
        .expect("Failed to create scanner");

        let mut report: crate::report::ScanReport = scanner
            .run()
            .await
            .expect("Failed to run mock scan");

        let original_count = report.vulnerability_count();
        report.filter_by_severity("low").expect("Filter failed");
        
        // Should have all alerts (nothing filtered)
        assert_eq!(report.vulnerability_count(), original_count);
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(
            crate::report::ScanReport::parse_severity("high").unwrap(),
            crate::report::SeverityLevel::High
        );
        assert_eq!(
            crate::report::ScanReport::parse_severity("critical").unwrap(),
            crate::report::SeverityLevel::Critical
        );
        assert_eq!(
            crate::report::ScanReport::parse_severity("2").unwrap(),
            crate::report::SeverityLevel::High
        );
        assert!(crate::report::ScanReport::parse_severity("invalid").is_err());
    }

    #[tokio::test]
    async fn test_cvss_metrics() {
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

        let avg_cvss = report.average_cvss_score();
        let max_cvss = report.max_cvss_score();

        // Verify CVSS scores are reasonable
        assert!(avg_cvss >= 0.0 && avg_cvss <= 10.0);
        assert!(max_cvss >= 0.0 && max_cvss <= 10.0);
        assert!(max_cvss >= avg_cvss);

        println!(
            "CVSS Metrics - Average: {:.1}, Max: {:.1}",
            avg_cvss, max_cvss
        );
    }

    #[tokio::test]
    async fn test_vulnerabilities_by_type() {
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

        let breakdown = report.risk_breakdown();
        let by_type = &breakdown.vulnerabilities_by_type;

        // Verify we have vulnerability types
        assert!(!by_type.is_empty());
        assert!(by_type.contains_key("Security Misconfiguration")
            || by_type.contains_key("Cross-Site Scripting (XSS)")
            || by_type.contains_key("Sensitive Data Exposure"));

        println!("Vulnerability Types: {:?}", by_type);
    }

    #[tokio::test]
    async fn test_report_comparison_improvement() {
        let _config = ScanConfig::default();

        // Baseline scan with 6 alerts
        let baseline_scanner = Scanner::new(
            "https://example.com".to_string(),
            _config.clone(),
            true,
        )
        .expect("Failed to create baseline scanner");

        let baseline_report = baseline_scanner
            .run()
            .await
            .expect("Failed to run baseline scan");

        // Current scan with fewer alerts (filtered high severity = 3 alerts)
        let mut current_report = baseline_report.clone();
        current_report.filter_by_severity("high").expect("Failed to filter");

        let comparison = crate::report::ReportComparison::new(&baseline_report, &current_report);

        // Should show improvement
        assert!(comparison.is_improvement);
        assert!(comparison.total_delta < 0);
        assert_eq!(comparison.new_vulnerabilities.len(), 0);
        assert!(comparison.fixed_vulnerabilities.len() > 0);

        println!(
            "Comparison: {} fixed, {} new",
            comparison.fixed_vulnerabilities.len(),
            comparison.new_vulnerabilities.len()
        );
    }

    #[test]
    fn test_report_load_from_json() {
        let config = ScanConfig::default();
        let report = crate::report::ScanReport {
            target: "https://example.com".to_string(),
            timestamp: chrono::Local::now().to_rfc3339(),
            alerts: vec![],
        };

        // Save and load
        let json_str = serde_json::to_string_pretty(&report).expect("Failed to serialize");
        let loaded: crate::report::ScanReport =
            serde_json::from_str(&json_str).expect("Failed to deserialize");

        assert_eq!(loaded.target, report.target);
    }
}

pub mod config;
pub mod report;
pub mod scanner;
pub mod zap;
pub mod zap_mock;
pub mod html;
pub mod validation;
pub mod display;
