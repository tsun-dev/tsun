//! Tsun - Security scanning tool powered by OWASP ZAP
//!
//! This library provides the core scanning functionality for the Tsun security scanner.

pub mod auth;
pub mod config;
pub mod display;
pub mod fingerprint;
pub mod html;
pub mod ignore;
pub mod report;
pub mod sarif;
pub mod scanner;
pub mod severity;
pub mod validation;
pub mod zap;
pub mod zap_managed;
pub mod zap_mock;

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

        let report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

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

        let report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

        // The mock set spans every severity, including a Critical (High risk
        // at Confirmed confidence) and an Informational.
        assert!(report.critical_count() > 0);
        assert!(report.high_count() > 0);
        assert!(report.medium_count() > 0);
        assert!(report.low_count() > 0);
        assert!(report.info_count() > 0);
    }

    #[tokio::test]
    async fn test_mock_reports_are_labelled_as_mock() {
        let scanner = Scanner::new(
            "https://example.com".to_string(),
            ScanConfig::default(),
            true,
        )
        .expect("Failed to create scanner");

        let report = scanner.run().await.expect("Failed to run mock scan");

        assert_eq!(report.engine, "mock");
        assert!(report.is_mock());

        let html = crate::html::generate_html_report(&report);
        assert!(
            html.contains("fabricated"),
            "HTML from a mock scan must say so"
        );
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

        let report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

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

        let mut report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

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

        let mut report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

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

        let mut report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

        let original_count = report.vulnerability_count();
        let info_count = report.info_count();
        assert!(
            info_count > 0,
            "fixture should contain informational findings"
        );

        report.filter_by_severity("low").expect("Filter failed");

        // "low" now excludes informational, which used to collapse into it.
        assert_eq!(report.vulnerability_count(), original_count - info_count);
        assert_eq!(report.info_count(), 0);
    }

    #[test]
    fn test_parse_severity() {
        use crate::severity::Severity;

        assert_eq!(Severity::parse("high").unwrap(), Severity::High);
        assert_eq!(Severity::parse("critical").unwrap(), Severity::Critical);
        assert_eq!(Severity::parse("info").unwrap(), Severity::Info);
        assert!(Severity::parse("invalid").is_err());
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

        let report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

        let avg_cvss = report.average_cvss_score();
        let max_cvss = report.max_cvss_score();

        // Verify CVSS scores are reasonable
        assert!((0.0..=10.0).contains(&avg_cvss));
        assert!((0.0..=10.0).contains(&max_cvss));
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

        let report: crate::report::ScanReport =
            scanner.run().await.expect("Failed to run mock scan");

        let breakdown = report.risk_breakdown();
        let by_type = &breakdown.vulnerabilities_by_type;

        // Verify we have vulnerability types
        assert!(!by_type.is_empty());
        assert!(
            by_type.contains_key("SQL Injection")
                || by_type.contains_key("Cross Site Scripting (Reflected)")
        );

        println!("Vulnerability Types: {:?}", by_type);
    }

    #[tokio::test]
    async fn test_report_comparison_improvement() {
        let _config = ScanConfig::default();

        // Baseline scan with 6 alerts
        let baseline_scanner =
            Scanner::new("https://example.com".to_string(), _config.clone(), true)
                .expect("Failed to create baseline scanner");

        let baseline_report = baseline_scanner
            .run()
            .await
            .expect("Failed to run baseline scan");

        // Current scan with fewer alerts (filtered high severity = 3 alerts)
        let mut current_report = baseline_report.clone();
        current_report
            .filter_by_severity("high")
            .expect("Failed to filter");

        let comparison = crate::report::ReportComparison::new(&baseline_report, &current_report);

        // Should show improvement
        assert!(comparison.is_improvement);
        assert!(comparison.total_delta < 0);
        assert_eq!(comparison.new_vulnerabilities.len(), 0);
        assert!(!comparison.fixed_vulnerabilities.is_empty());

        println!(
            "Comparison: {} fixed, {} new",
            comparison.fixed_vulnerabilities.len(),
            comparison.new_vulnerabilities.len()
        );
    }

    #[test]
    fn test_report_load_from_json() {
        let _config = ScanConfig::default();
        let report =
            crate::report::ScanReport::from_alerts("https://example.com".to_string(), vec![]);

        // Save and load
        let json_str = serde_json::to_string_pretty(&report).expect("Failed to serialize");
        let loaded: crate::report::ScanReport =
            serde_json::from_str(&json_str).expect("Failed to deserialize");

        assert_eq!(loaded.target, report.target);
    }
}
