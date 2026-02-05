use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod auth;
mod config;
mod display;
mod html;
mod report;
mod sarif;
mod scanner;
mod validation;
mod zap;
mod zap_managed;
mod zap_mock;

use auth::{load_cookie_header, parse_headers};
use config::ScanConfig;
use display::Display;
use scanner::Scanner;

#[derive(Parser)]
#[command(name = "arete")]
#[command(about = "Security scanning tool powered by OWASP ZAP", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
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

        /// Scan engine: mock or zap (default: mock)
        #[arg(long, default_value = "mock")]
        engine: String,

        /// ZAP Docker image to use (stable, weekly, or full path)
        #[arg(long, default_value = "zaproxy/zap-stable")]
        zap_image: String,

        /// ZAP container host port (default: 8080)
        #[arg(long, default_value_t = 8080)]
        zap_port: u16,

        /// Keep ZAP container running after scan (for debugging)
        #[arg(long)]
        keep_zap: bool,

        /// Path to baseline report for comparison
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Exit with code 1 if findings at or above this severity are found
        #[arg(long, default_value = "none")]
        exit_on_severity: String,
        /// Static headers to include in requests (can be used multiple times)
        #[arg(long, value_delimiter = ',')]
        header: Vec<String>,

        /// Path to cookies file (Netscape cookies.txt or simple JSON)
        #[arg(long)]
        cookies: Option<PathBuf>,

        /// Run a login command before scanning (useful to generate session cookies)
        #[arg(long)]
        login_command: Option<String>,

        /// Scan timeout in seconds (default: 1800 = 30 minutes)
        #[arg(long)]
        timeout: Option<u64>,

        /// Scan profile: ci (fast, 10-15min), deep (thorough, 60-120min), or custom
        #[arg(long, default_value = "ci")]
        profile: String,

        /// Maximum URLs to spider (ci default: 200, deep: unlimited)
        #[arg(long)]
        max_urls: Option<u32>,

        /// Attack strength: low, medium, high, insane (ci default: low, deep: medium)
        #[arg(long)]
        attack_strength: Option<String>,

        /// Alert threshold: low, medium, high (ci default: medium, deep: low)
        #[arg(long)]
        alert_threshold: Option<String>,
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
    /// Upload a SARIF report to GitHub Code Scanning
    UploadSarif {
        /// Path to SARIF file
        #[arg(short, long)]
        file: PathBuf,

        /// GitHub repository in form owner/repo
        #[arg(long)]
        repo: Option<String>,

        /// Commit SHA associated with the SARIF
        #[arg(long)]
        commit: Option<String>,

        /// Git ref (e.g. refs/heads/main)
        #[arg(long)]
        git_ref: Option<String>,

        /// GitHub token (or set GITHUB_TOKEN env)
        #[arg(long)]
        token: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("arete=info".parse()?),
        )
        .init();

    // Install signal handler for graceful shutdown
    setup_signal_handlers();

    // Install panic hook for emergency cleanup
    setup_panic_hook();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            config,
            format,
            output,
            verbose,
            min_severity,
            engine,
            zap_image,
            zap_port,
            keep_zap,
            baseline,
            exit_on_severity,
            header,
            cookies,
            login_command,
            timeout,
            profile,
            max_urls,
            attack_strength,
            alert_threshold,
        } => {
            let exit_code = run_scan(
                target,
                config,
                format,
                output,
                verbose,
                min_severity,
                engine,
                zap_image,
                zap_port,
                keep_zap,
                baseline,
                exit_on_severity,
                header,
                cookies,
                login_command,
                timeout,
                profile,
                max_urls,
                attack_strength,
                alert_threshold,
            )
            .await?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Commands::Init { config } => {
            run_init(config)?;
        }
        Commands::Status { host } => {
            run_status(host).await?;
        }
        Commands::UploadSarif {
            file,
            repo,
            commit,
            git_ref,
            token,
        } => {
            run_upload_sarif(file, repo, commit, git_ref, token).await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(
    target: String,
    config_path: Option<PathBuf>,
    format: String,
    output: Option<PathBuf>,
    verbose: bool,
    min_severity: String,
    engine: String,
    zap_image: String,
    zap_port: u16,
    keep_zap: bool,
    baseline_path: Option<PathBuf>,
    exit_on_severity: String,
    headers: Vec<String>,
    cookies: Option<PathBuf>,
    login_command: Option<String>,
    timeout: Option<u64>,
    profile: String,
    max_urls: Option<u32>,
    attack_strength: Option<String>,
    alert_threshold: Option<String>,
) -> anyhow::Result<i32> {
    // Validate inputs
    validation::validate_url(&target).map_err(|e| anyhow::anyhow!("Invalid target URL: {}", e))?;

    validation::validate_format(&format).map_err(|e| anyhow::anyhow!("Invalid format: {}", e))?;

    if let Some(ref config_file) = config_path {
        validation::validate_config_file(config_file)
            .map_err(|e| anyhow::anyhow!("Invalid config file: {}", e))?;
    }

    if let Some(ref output_file) = output {
        validation::validate_output_path(output_file)
            .map_err(|e| anyhow::anyhow!("Invalid output path: {}", e))?;
    }

    let mut config = if let Some(ref path) = config_path {
        ScanConfig::from_file(path)?
    } else {
        ScanConfig::default()
    };

    // Apply scan profile defaults
    let (profile_timeout, profile_max_urls, profile_attack, profile_threshold) =
        match profile.as_str() {
            "ci" => (
                Some(900), // 15 minutes
                Some(200), // Limit crawling
                "low".to_string(),
                "medium".to_string(),
            ),
            "deep" => (
                Some(7200), // 2 hours
                None,       // No URL limit
                "medium".to_string(),
                "low".to_string(),
            ),
            _ => (None, None, "low".to_string(), "medium".to_string()),
        };

    // CLI timeout overrides profile and config file
    if let Some(t) = timeout {
        config.timeout = Some(t);
    } else if let Some(t) = profile_timeout {
        config.timeout = Some(t);
    }

    // Store scan tuning parameters for ZAP
    let scan_max_urls = max_urls.or(profile_max_urls);
    let scan_attack_strength = attack_strength.unwrap_or(profile_attack);
    let scan_alert_threshold = alert_threshold.unwrap_or(profile_threshold);

    // If a login command is provided, run it before scanning (user handles cookie persistence)
    if let Some(cmd) = login_command {
        if verbose {
            Display::info(&format!("Running login command: {}", cmd));
        }
        // Run the command via shell
        let status = std::process::Command::new("sh").arg("-c").arg(cmd).status();
        match status {
            Ok(s) if s.success() => {
                if verbose {
                    Display::info("Login command completed successfully");
                }
            }
            Ok(s) => {
                Display::warning(&format!("Login command exited with status: {}", s));
            }
            Err(e) => {
                Display::warning(&format!("Failed to run login command: {}", e));
            }
        }
    }

    // Parse headers and cookies
    let parsed_headers = parse_headers(&headers);
    let cookie_header = if let Some(cookie_path) = cookies {
        match load_cookie_header(&cookie_path) {
            Ok(h) => Some(h),
            Err(e) => {
                Display::warning(&format!("Failed to load cookies: {}", e));
                None
            }
        }
    } else {
        None
    };

    // Inject cookie header if present
    let mut effective_headers = parsed_headers;
    if let Some(ch) = cookie_header {
        effective_headers.push(("Cookie".to_string(), ch));
    }

    // Determine which scan engine to use
    let use_mock = engine == "mock";
    let mut _managed_zap: Option<zap_managed::ZapManaged> = None; // Keep alive for duration of scan

    let mut scanner = if use_mock {
        Scanner::new_with_headers(target.clone(), config, true, effective_headers)?
    } else if engine == "zap" {
        // Start managed ZAP container
        Display::section_header("Starting ZAP Engine");
        let spinner = Display::spinner("Starting managed ZAP container...");

        let managed = zap_managed::start_managed_zap(zap_managed::ManagedZapOptions {
            image: zap_image,
            host_port: zap_port,
            api_key: None, // For now, no API key required
            keep: keep_zap,
        })
        .await?;

        spinner.finish_with_message("✓ ZAP container started");
        Display::status("ZAP URL", &managed.zap_url);

        let scanner =
            Scanner::new_with_managed_zap(target.clone(), config, &managed, effective_headers)?;
        _managed_zap = Some(managed);
        scanner
    } else {
        return Err(anyhow::anyhow!(
            "Invalid engine: {}. Use 'mock' or 'zap'",
            engine
        ));
    };

    if verbose {
        Display::info("Verbose logging enabled");
        scanner.set_verbose(true);
    }

    // Configure scan parameters from profile/CLI
    scanner.set_scan_params(
        scan_max_urls,
        Some(scan_attack_strength.to_string()),
        Some(scan_alert_threshold.to_string()),
    );

    if use_mock {
        Display::warning("Using mock ZAP client (test mode)");
    } else {
        Display::status("Engine", "ZAP (Docker managed)");
    }

    // Run scan with spinner
    Display::section_header("Security Scan");
    Display::status("Target", &target);
    Display::status("Profile", &profile);
    Display::status("Format", &format);
    if let Some(ref path) = config_path {
        Display::status("Config", path.to_string_lossy().as_ref());
    }

    let spinner = Display::spinner("Executing security scan...");
    let mut report = scanner.run().await?;
    spinner.finish_with_message("✓ Scan completed");

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

    // Determine exit code based on exit_on_severity threshold
    let exit_code = if exit_on_severity != "none" {
        match report::ScanReport::parse_severity(&exit_on_severity) {
            Ok(threshold) => {
                if report.alerts.iter().any(|a| {
                    let alert_severity = report::ScanReport::parse_severity(&a.riskcode)
                        .unwrap_or(report::SeverityLevel::Low);
                    alert_severity >= threshold
                }) {
                    Display::error(&format!(
                        "Scan failed: found vulnerabilities at or above {} severity",
                        exit_on_severity
                    ));
                    1
                } else {
                    0
                }
            }
            Err(_) => {
                Display::warning(&format!(
                    "Invalid exit_on_severity value: {}",
                    exit_on_severity
                ));
                0
            }
        }
    } else {
        0
    };

    // Explicitly cleanup ZAP container if we started one
    if !use_mock {
        if let Some(managed) = _managed_zap {
            Display::info("Cleaning up ZAP container...");
            managed.stop().await?;
        }
    }

    Ok(exit_code)
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

async fn run_upload_sarif(
    file: PathBuf,
    repo: Option<String>,
    commit: Option<String>,
    git_ref: Option<String>,
    token: Option<String>,
) -> anyhow::Result<()> {
    // Basic validation
    if repo.is_none() {
        anyhow::bail!("--repo is required (owner/repo)");
    }
    let repo = repo.unwrap();

    // Read SARIF file
    let content = std::fs::read_to_string(&file)
        .map_err(|e| anyhow::anyhow!("Failed to read SARIF file {}: {}", file.display(), e))?;

    // Token from argument or env
    let gh_token = token.or_else(|| std::env::var("GITHUB_TOKEN").ok());
    if gh_token.is_none() {
        anyhow::bail!("GitHub token required: pass --token or set GITHUB_TOKEN env var");
    }
    let gh_token = gh_token.unwrap();

    let commit_sha = commit.unwrap_or_default();
    let ref_field = git_ref.unwrap_or_else(|| "refs/heads/main".to_string());

    let url = format!("https://api.github.com/repos/{}/code-scanning/sarifs", repo);

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "commit_sha": commit_sha,
        "ref": ref_field,
        "sarif": content,
        "tool_name": "arete",
    });

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", gh_token))
        .header("User-Agent", "arete")
        .header("Accept", "application/vnd.github+json")
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() {
        Display::success(&format!("SARIF uploaded successfully to {}", repo));
        Ok(())
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("SARIF upload failed: {} - {}", status, text);
    }
}

/// Setup signal handlers for graceful shutdown
fn setup_signal_handlers() {
    ctrlc::set_handler(move || {
        eprintln!("\n⚠ Received interrupt signal, cleaning up ZAP containers...");
        zap_managed::cleanup_all_containers();
        std::process::exit(130); // Standard exit code for SIGINT
    })
    .expect("Error setting Ctrl-C handler");
}

/// Setup panic hook for emergency cleanup
fn setup_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        eprintln!("⚠ Panic detected, performing emergency cleanup...");
        zap_managed::cleanup_all_containers();
        original_hook(panic_info);
    }));
}

#[cfg(test)]
mod tests {
    // Tests moved to src/auth.rs
}
