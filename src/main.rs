use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod zap;
mod zap_mock;
mod config;
mod scanner;
mod report;
mod html;
mod validation;
mod display;

use scanner::Scanner;
use config::ScanConfig;
use display::Display;

#[derive(Parser)]
#[command(name = "arete")]
#[command(about = "Security scanning tool powered by OWASP ZAP", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a security scan on a target
    Scan {
        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Configuration file path (YAML)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output report format (json, html, xml)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Minimum severity level to include (low, medium, high, critical)
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Verbose logging
        #[arg(short, long)]
        verbose: bool,

        /// Use mock ZAP client for testing
        #[arg(long)]
        mock: bool,

        /// Path to baseline report for comparison
        #[arg(long)]
        baseline: Option<PathBuf>,
    },
    /// Generate a configuration template
    Init {
        /// Configuration file name
        #[arg(short, long, default_value = "arete.yaml")]
        config: String,
    },
    /// Check ZAP server connectivity
    Status {
        /// ZAP server host
        #[arg(long, default_value = "http://localhost:8080")]
        host: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("arete=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            config,
            format,
            output,
            verbose,
            min_severity,
            mock,
            baseline,
        } => {
            run_scan(target, config, format, output, verbose, min_severity, mock, baseline).await?;
        }
        Commands::Init { config } => {
            run_init(config)?;
        }
        Commands::Status { host } => {
            run_status(host).await?;
        }
    }

    Ok(())
}

async fn run_scan(
    target: String,
    config_path: Option<PathBuf>,
    format: String,
    output: Option<PathBuf>,
    verbose: bool,
    min_severity: String,
    use_mock: bool,
    baseline_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Validate inputs
    validation::validate_url(&target)
        .map_err(|e| anyhow::anyhow!("Invalid target URL: {}", e))?;
    
    validation::validate_format(&format)
        .map_err(|e| anyhow::anyhow!("Invalid format: {}", e))?;

    if let Some(ref config_file) = config_path {
        validation::validate_config_file(config_file)
            .map_err(|e| anyhow::anyhow!("Invalid config file: {}", e))?;
    }

    if let Some(ref output_file) = output {
        validation::validate_output_path(output_file)
            .map_err(|e| anyhow::anyhow!("Invalid output path: {}", e))?;
    }

    Display::section_header("Security Scan");
    Display::status("Target", &target);
    Display::status("Format", &format);
    if let Some(ref path) = config_path {
        Display::status("Config", path.to_string_lossy().as_ref());
    }

    let config = if let Some(path) = config_path {
        ScanConfig::from_file(&path)?
    } else {
        ScanConfig::default()
    };

    let mut scanner = Scanner::new(target, config, use_mock)?;

    if verbose {
        Display::info("Verbose logging enabled");
        scanner.set_verbose(true);
    }

    if use_mock {
        Display::warning("Using mock ZAP client (test mode)");
    }

    // Run scan with spinner
    let spinner = Display::spinner("Executing security scan...");
    let mut report = scanner.run().await?;
    spinner.finish_with_message("✓ Scan completed");

    // Apply severity filter
    report.filter_by_severity(&min_severity)?;

    // Display results
    Display::vulnerability_summary(
        report.vulnerability_count(),
        report.critical_count(),
        report.high_count(),
        report.medium_count(),
        report.low_count(),
    );

    // Display CVSS metrics if there are alerts
    if report.vulnerability_count() > 0 {
        Display::cvss_metrics(report.average_cvss_score(), report.max_cvss_score());
        let breakdown = report.risk_breakdown();
        Display::vulnerabilities_by_type(&breakdown.vulnerabilities_by_type);
    }

    // Perform comparison if baseline is provided
    if let Some(baseline_file) = baseline_path {
        match report::ScanReport::load_from_file(&baseline_file) {
            Ok(baseline_report) => {
                let comparison = report::ReportComparison::new(&baseline_report, &report);
                Display::comparison_report(&comparison);
            }
            Err(e) => {
                Display::warning(&format!("Failed to load baseline report: {}", e));
            }
        }
    }

    if let Some(output_path) = output {
        report.save(&output_path, &format)?;
        Display::success(&format!("Report saved to: {}", output_path.display()));
    } else {
        println!("\n{}", report.summary());
    }

    Ok(())
}

fn run_init(config_path: String) -> anyhow::Result<()> {
    let template = ScanConfig::template();
    std::fs::write(&config_path, template)?;
    Display::success(&format!("Configuration template created: {}", config_path));
    Ok(())
}

async fn run_status(host: String) -> anyhow::Result<()> {
    Display::section_header("ZAP Server Status");
    Display::status("Host", &host);

    let spinner = Display::spinner("Checking connectivity...");
    match zap::check_health(&host).await {
        Ok(_) => {
            spinner.finish_with_message("✓ Server check complete");
            Display::success(&format!("ZAP server is healthy at {}", host));
        }
        Err(e) => {
            spinner.finish_with_message("✗ Server check failed");
            Display::error(&format!("Failed to connect to ZAP server: {}", e));
        }
    }

    Ok(())
}
