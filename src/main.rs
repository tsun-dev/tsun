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
mod sarif;

use scanner::Scanner;
use config::ScanConfig;
use display::Display;
use reqwest;
use std::process::Stdio;

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
            exit_on_severity,
            header,
            cookies,
            login_command,
        } => {
            let exit_code = run_scan(
                target,
                config,
                format,
                output,
                verbose,
                min_severity,
                mock,
                baseline,
                exit_on_severity,
                header,
                cookies,
                login_command,
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
        Commands::UploadSarif { file, repo, commit, git_ref, token } => {
            run_upload_sarif(file, repo, commit, git_ref, token).await?;
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
    exit_on_severity: String,
    headers: Vec<String>,
    cookies: Option<PathBuf>,
    login_command: Option<String>,
) -> anyhow::Result<i32> {
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

    // If a login command is provided, run it before scanning (user handles cookie persistence)
    if let Some(cmd) = login_command {
        if verbose {
            Display::info(&format!("Running login command: {}", cmd));
        }
        // Run the command via shell
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status();
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

    let mut scanner = Scanner::new_with_headers(target, config, use_mock, effective_headers)?;

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

    // Determine exit code based on exit_on_severity threshold
    let exit_code = if exit_on_severity != "none" {
        match report::ScanReport::parse_severity(&exit_on_severity) {
            Ok(threshold) => {
                if report.alerts.iter().any(|a| {
                    let alert_severity = report::ScanReport::parse_severity(&a.riskcode).unwrap_or(report::SeverityLevel::Low);
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
                Display::warning(&format!("Invalid exit_on_severity value: {}", exit_on_severity));
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

    let commit_sha = commit.unwrap_or_else(|| "".to_string());
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

/// Parse header strings like "Name: value" into (Name, Value) pairs
fn parse_headers(inputs: &Vec<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for s in inputs {
        if let Some(idx) = s.find(':') {
            let key = s[..idx].trim();
            if key.is_empty() {
                continue;
            }
            let value = s[idx + 1..].trim();
            out.push((key.to_string(), value.to_string()));
        }
    }
    out
}

/// Load cookies from a Netscape-format cookies.txt and return a Cookie header string
fn load_cookie_header(path: &PathBuf) -> anyhow::Result<String> {
    let content = std::fs::read_to_string(path)?;

    // Try JSON cookie-jar formats first (array of {name,value} or {cookies: [...]})
    if let Some(first_char) = content.trim_start().chars().next() {
        if first_char == '{' || first_char == '[' {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                // Case: top-level array of objects
                if let Some(arr) = val.as_array() {
                    let mut pairs = Vec::new();
                    for item in arr {
                        if let (Some(name), Some(value)) = (item.get("name"), item.get("value")) {
                            if let (Some(n), Some(v)) = (name.as_str(), value.as_str()) {
                                pairs.push(format!("{}={}", n, v));
                            }
                        }
                    }
                    if !pairs.is_empty() {
                        return Ok(pairs.join("; "));
                    }
                }

                // Case: object with "cookies" array
                if let Some(obj) = val.as_object() {
                    if let Some(cookies_val) = obj.get("cookies") {
                        if let Some(arr) = cookies_val.as_array() {
                            let mut pairs = Vec::new();
                            for item in arr {
                                if let (Some(name), Some(value)) = (item.get("name"), item.get("value")) {
                                    if let (Some(n), Some(v)) = (name.as_str(), value.as_str()) {
                                        pairs.push(format!("{}={}", n, v));
                                    }
                                }
                            }
                            if !pairs.is_empty() {
                                return Ok(pairs.join("; "));
                            }
                        }
                    }
                }
            }
            // If JSON parsing didn't yield cookies, fall through to Netscape parsing
        }
    }

    // Netscape parsing fallback
    let mut pairs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Netscape format: domain TAB flag TAB path TAB secure TAB expiration TAB name TAB value
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 7 {
            let name = parts[5];
            let value = parts[6];
            pairs.push(format!("{}={}", name, value));
        }
    }
    Ok(pairs.join("; "))
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_headers() {
        let inputs = vec![
            "Authorization: Bearer token123".to_string(),
            "X-Test: value".to_string(),
            "MalformedHeader".to_string(),
        ];
        let parsed = parse_headers(&inputs);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "Authorization");
        assert_eq!(parsed[0].1, "Bearer token123");
        assert_eq!(parsed[1].0, "X-Test");
        assert_eq!(parsed[1].1, "value");
    }

    #[test]
    fn test_load_cookie_header_netscape() {
        // Prepare a temporary cookies file in the system temp dir
        let mut path = std::env::temp_dir();
        path.push("arete_test_cookies.txt");
        let mut f = std::fs::File::create(&path).expect("create cookie file");
        // Netscape format lines: domain\tflag\tpath\tsecure\texpiry\tname\tvalue
        let content = "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t2147483647\tSESSION\tabc123\nexample.com\tFALSE\t/\tFALSE\t2147483647\tTOKEN\txyz\n";
        f.write_all(content.as_bytes()).expect("write cookies");

        let header = load_cookie_header(&path).expect("load cookies");
        // Order preserved from file
        assert!(header.contains("SESSION=abc123"));
        assert!(header.contains("TOKEN=xyz"));

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_parse_headers_multiple_colons_and_trimming() {
        let inputs = vec![
            "X-Custom: a:b:c".to_string(),
            "  Key :  value  ".to_string(),
            ":no_key".to_string(),
        ];
        let parsed = parse_headers(&inputs);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "X-Custom");
        assert_eq!(parsed[0].1, "a:b:c");
        assert_eq!(parsed[1].0, "Key");
        assert_eq!(parsed[1].1, "value");
    }

    #[test]
    fn test_parse_headers_empty_and_malformed() {
        let inputs = vec!["".to_string(), "NoColonHere".to_string(), ":".to_string()];
        let parsed = parse_headers(&inputs);
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn test_load_cookie_header_ignores_malformed_lines() {
        let mut path = std::env::temp_dir();
        path.push("arete_test_cookies_malformed.txt");
        let mut f = std::fs::File::create(&path).expect("create cookie file");
        // One valid netscape line, one malformed
        let content = "# Netscape\n.example.com\tTRUE\t/\tFALSE\t2147483647\tSESSION\tabc123\nmalformed_line_without_tabs\n";
        use std::io::Write;
        f.write_all(content.as_bytes()).expect("write");

        let header = load_cookie_header(&path).expect("load cookies");
        assert!(header.contains("SESSION=abc123"));
        assert!(!header.contains("malformed_line_without_tabs"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_cookie_header_json_array() {
        let mut path = std::env::temp_dir();
        path.push("arete_test_cookies_json.txt");
        let mut f = std::fs::File::create(&path).expect("create cookie file");
        let content = r#"[
            {"name":"SID","value":"s1"},
            {"name":"TOKEN","value":"t2"}
        ]"#;
        use std::io::Write;
        f.write_all(content.as_bytes()).expect("write");

        let header = load_cookie_header(&path).expect("load cookies");
        assert!(header.contains("SID=s1"));
        assert!(header.contains("TOKEN=t2"));

        let _ = std::fs::remove_file(&path);
    }
}
