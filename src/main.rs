use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod auth;
mod config;
mod display;
mod features;
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
#[command(name = "tsun")]
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

        /// Output report format (json, yaml, html, sarif)
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
        #[arg(short, long, default_value = "tsun.yaml")]
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
    /// Run diagnostics to check Tsun setup
    Doctor,
}

/// Options for executing a scan and reporting results
struct ExecutionOptions<'a> {
    engine: &'a str,
    target: &'a str,
    profile: &'a str,
    format: &'a str,
    config_path: &'a Option<PathBuf>,
    output: Option<PathBuf>,
    min_severity: &'a str,
    baseline_path: Option<PathBuf>,
    exit_on_severity: &'a str,
    scanner: Scanner,
}

/// All options for a single scan invocation, gathered from CLI args.
struct ScanOptions {
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("tsun=info".parse()?),
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
            let opts = ScanOptions {
                target,
                config_path: config,
                format,
                output,
                verbose,
                min_severity,
                engine,
                zap_image,
                zap_port,
                keep_zap,
                baseline_path: baseline,
                exit_on_severity,
                headers: header,
                cookies,
                login_command,
                timeout,
                profile,
                max_urls,
                attack_strength,
                alert_threshold,
            };
            let exit_code = run_scan(opts).await?;
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
        Commands::Doctor => {
            run_doctor().await?;
        }
    }

    Ok(())
}

async fn run_scan(opts: ScanOptions) -> anyhow::Result<i32> {
    let ScanOptions {
        target,
        config_path,
        format,
        output,
        verbose,
        min_severity,
        engine,
        zap_image,
        zap_port,
        keep_zap,
        baseline_path,
        exit_on_severity,
        headers,
        cookies,
        login_command,
        timeout,
        profile,
        max_urls,
        attack_strength,
        alert_threshold,
    } = opts;

    // ── Phase 1: Validation ───────────────────────────────────
    let effective_profile = check_profile_access(&profile);

    validate_scan_inputs(&target, &format, &config_path, &output)?;

    // ── Phase 2: Config & profile resolution ────────────────────────────
    let mut config = if let Some(ref path) = config_path {
        ScanConfig::from_file(path)?
    } else {
        ScanConfig::default()
    };

    let resolved = config::resolve_profile(
        &effective_profile,
        &mut config,
        timeout,
        max_urls,
        attack_strength,
        alert_threshold,
    );

    // ── Phase 3: Auth preparation ───────────────────────────────────────
    let effective_headers = prepare_auth(login_command, &headers, cookies, verbose);

    // ── Phase 4: Engine creation ────────────────────────────────────────
    let (mut scanner, _managed_zap) = create_scanner(
        &engine,
        &target,
        config,
        effective_headers,
        zap_image,
        zap_port,
        keep_zap,
    )
    .await?;

    if verbose {
        Display::info("Verbose logging enabled");
        scanner.set_verbose(true);
    }

    scanner.set_scan_params(
        resolved.max_urls,
        Some(resolved.attack_strength.to_string()),
        Some(resolved.alert_threshold.to_string()),
    );

    // ── Phase 5: Execute scan, report, and determine exit code ──────────
    let exit_code = execute_and_report(ExecutionOptions {
        engine: &engine,
        target: &target,
        profile: &effective_profile,
        format: &format,
        config_path: &config_path,
        output,
        min_severity: &min_severity,
        baseline_path,
        exit_on_severity: &exit_on_severity,
        scanner,
    })
    .await?;

    // ── Phase 6: Cleanup ────────────────────────────────────────────────
    if engine != "mock" {
        if let Some(managed) = _managed_zap {
            Display::info("Cleaning up ZAP container...");
            managed.stop().await?;
        }
    }

    Ok(exit_code)
}

/// Check if the requested profile is available (all profiles are now available)
fn check_profile_access(profile: &str) -> String {
    profile.to_string()
}

/// Validate all scan inputs before proceeding.
fn validate_scan_inputs(
    target: &str,
    format: &str,
    config_path: &Option<PathBuf>,
    output: &Option<PathBuf>,
) -> anyhow::Result<()> {
    validation::validate_url(target).map_err(|e| anyhow::anyhow!("Invalid target URL: {}", e))?;

    validation::validate_format(format).map_err(|e| anyhow::anyhow!("Invalid format: {}", e))?;

    if let Some(ref config_file) = config_path {
        validation::validate_config_file(config_file)
            .map_err(|e| anyhow::anyhow!("Invalid config file: {}", e))?;
    }

    if let Some(ref output_file) = output {
        validation::validate_output_path(output_file)
            .map_err(|e| anyhow::anyhow!("Invalid output path: {}", e))?;
    }

    Ok(())
}

/// Run a shell command in a platform-appropriate way.
///
/// Uses `sh -c` on Unix and `cmd /C` on Windows.
fn run_shell_command(cmd: &str) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(unix)]
    {
        std::process::Command::new("sh").arg("-c").arg(cmd).status()
    }
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .arg("/C")
            .arg(cmd)
            .status()
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Fallback for other platforms — try sh first
        std::process::Command::new("sh").arg("-c").arg(cmd).status()
    }
}

/// Run login command (if any), parse headers and cookies into effective header list.
fn prepare_auth(
    login_command: Option<String>,
    headers: &[String],
    cookies: Option<PathBuf>,
    verbose: bool,
) -> Vec<(String, String)> {
    // If a login command is provided, run it before scanning (user handles cookie persistence)
    if let Some(cmd) = login_command {
        if verbose {
            Display::info(&format!("Running login command: {}", cmd));
        }
        let status = run_shell_command(&cmd);
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

    let parsed_headers = parse_headers(headers);
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

    let mut effective_headers = parsed_headers;
    if let Some(ch) = cookie_header {
        effective_headers.push(("Cookie".to_string(), ch));
    }
    effective_headers
}

/// Create the scanner and (optionally) a managed ZAP container.
///
/// The returned `Option<ZapManaged>` must be kept alive for the scan duration.
async fn create_scanner(
    engine: &str,
    target: &str,
    config: ScanConfig,
    headers: Vec<(String, String)>,
    zap_image: String,
    zap_port: u16,
    keep_zap: bool,
) -> anyhow::Result<(Scanner, Option<zap_managed::ZapManaged>)> {
    match engine {
        "mock" => {
            let scanner = Scanner::new_with_headers(target.to_string(), config, true, headers)?;
            Ok((scanner, None))
        }
        "zap" => {
            Display::section_header("Starting ZAP Engine");
            let spinner = Display::spinner("Starting managed ZAP container...");

            let managed = zap_managed::start_managed_zap(zap_managed::ManagedZapOptions {
                image: zap_image,
                host_port: zap_port,
                api_key: None,
                keep: keep_zap,
            })
            .await?;

            spinner.finish_with_message("✓ ZAP container started");
            Display::status("ZAP URL", &managed.zap_url);

            let scanner =
                Scanner::new_with_managed_zap(target.to_string(), config, &managed, headers)?;
            Ok((scanner, Some(managed)))
        }
        _ => Err(anyhow::anyhow!(
            "Invalid engine: {}. Use 'mock' or 'zap'",
            engine
        )),
    }
}

/// Execute the scan, display results, handle baseline comparison, save report,
/// and return the CI exit code.
async fn execute_and_report(opts: ExecutionOptions<'_>) -> anyhow::Result<i32> {
    let use_mock = opts.engine == "mock";

    if use_mock {
        Display::warning("Using mock ZAP client (test mode)");
    } else {
        Display::status("Engine", "ZAP (Docker managed)");
    }

    // Run scan with spinner
    Display::section_header("Security Scan");
    Display::status("Target", opts.target);
    Display::status("Profile", opts.profile);
    Display::status("Format", opts.format);
    if let Some(ref path) = opts.config_path {
        Display::status("Config", path.to_string_lossy().as_ref());
    }

    let spinner = Display::spinner("Executing security scan...");
    let mut report = opts.scanner.run().await?;
    spinner.finish_with_message("✓ Scan completed");

    report.filter_by_severity(opts.min_severity)?;

    // Display results
    Display::vulnerability_summary(
        report.vulnerability_count(),
        report.critical_count(),
        report.high_count(),
        report.medium_count(),
        report.low_count(),
    );

    if report.vulnerability_count() > 0 {
        Display::cvss_metrics(report.average_cvss_score(), report.max_cvss_score());
        let breakdown = report.risk_breakdown();
        Display::vulnerabilities_by_type(&breakdown.vulnerabilities_by_type);
    }

    // Perform comparison if baseline is provided
    if let Some(baseline_file) = opts.baseline_path {
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

    if let Some(output_path) = opts.output {
        let format_lower = opts.format.to_lowercase();
        let format_allowed = match format_lower.as_str() {
            "html" => true,
            "yaml" | "yml" => true,
            _ => true,
        };

        if format_allowed {
            report.save(&output_path, opts.format)?;
            Display::success(&format!("Report saved to: {}", output_path.display()));
        } else {
            Display::warning("Saving report as JSON (Pro required for HTML/YAML)");
            let json_path = output_path.with_extension("json");
            report.save(&json_path, "json")?;
            Display::success(&format!("Report saved to: {}", json_path.display()));
        }
    } else {
        println!("\n{}", report.summary());
    }

    // Show scan completion
    println!("\n{}", "=".repeat(50));
    Display::success("Scan completed successfully!");

    // Determine exit code based on exit_on_severity threshold
    let exit_code = if opts.exit_on_severity != "none" {
        match report::ScanReport::parse_severity(opts.exit_on_severity) {
            Ok(threshold) => {
                if report.alerts.iter().any(|a| {
                    let alert_severity = report::ScanReport::parse_severity(&a.riskcode)
                        .unwrap_or(report::SeverityLevel::Low);
                    alert_severity >= threshold
                }) {
                    Display::error(&format!(
                        "Scan failed: found vulnerabilities at or above {} severity",
                        opts.exit_on_severity
                    ));
                    1
                } else {
                    0
                }
            }
            Err(_) => {
                Display::warning(&format!(
                    "Invalid exit_on_severity value: {}",
                    opts.exit_on_severity
                ));
                0
            }
        }
    } else {
        0
    };

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
        "tool_name": "tsun",
    });

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", gh_token))
        .header("User-Agent", "tsun")
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

async fn run_doctor() -> anyhow::Result<()> {
    Display::section_header("Tsun Doctor - System Diagnostics");

    let mut checks_passed = 0;
    let mut checks_failed = 0;

    // Check 1: Docker availability
    print!("Checking Docker installation... ");
    match tokio::process::Command::new("docker")
        .arg("--version")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            println!("✓ {}", version.trim());
            checks_passed += 1;
        }
        _ => {
            println!("✗ Docker not found");
            Display::warning("Install Docker: https://docs.docker.com/get-docker/");
            checks_failed += 1;
        }
    }

    // Check 2: Docker permissions
    print!("Checking Docker permissions... ");
    match tokio::process::Command::new("docker")
        .arg("ps")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            println!("✓ Docker accessible");
            checks_passed += 1;
        }
        _ => {
            println!("✗ Cannot access Docker");
            Display::warning("Try: sudo usermod -aG docker $USER && newgrp docker");
            checks_failed += 1;
        }
    }

    // Check 3: Network connectivity
    print!("Checking network connectivity... ");
    match reqwest::Client::new()
        .get("https://api.github.com/zen")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(_) => {
            println!("✓ Internet accessible");
            checks_passed += 1;
        }
        Err(_) => {
            println!("✗ Network issues detected");
            Display::warning("Check your internet connection");
            checks_failed += 1;
        }
    }

    // Check 4: ZAP image availability
    print!("Checking ZAP Docker image... ");
    match tokio::process::Command::new("docker")
        .args(["image", "inspect", "zaproxy/zap-stable"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            println!("✓ ZAP image available");
            checks_passed += 1;
        }
        _ => {
            println!("⚠ ZAP image not cached (will download on first scan)");
            Display::info("First scan will pull the image (~500MB)");
            checks_passed += 1; // Not a failure, just info
        }
    }

    // Check 5: Config directory
    print!("Checking config directory... ");
    match std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        Ok(home) => {
            println!("✓ {}/.config/tsun", home);
            checks_passed += 1;
        }
        Err(_) => {
            println!("✗ Cannot determine config path");
            checks_failed += 1;
        }
    }

    // Summary
    println!("\n{}", "=".repeat(50));
    if checks_failed == 0 {
        Display::success(&format!(
            "All checks passed ({}/{})",
            checks_passed,
            checks_passed + checks_failed
        ));
        Display::info("You're ready to run: tsun scan --target <url>");
    } else {
        Display::warning(&format!(
            "Some checks failed ({} passed, {} failed)",
            checks_passed, checks_failed
        ));
        Display::info("Fix the issues above before running scans");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests moved to src/auth.rs
}
