use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod zap;
mod zap_mock;
mod config;
mod scanner;
mod report;

use scanner::Scanner;
use config::ScanConfig;

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

        /// Verbose logging
        #[arg(short, long)]
        verbose: bool,

        /// Use mock ZAP client for testing
        #[arg(long)]
        mock: bool,
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
        #[arg(short, long, default_value = "http://localhost:8080")]
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
            mock,
        } => {
            run_scan(target, config, format, output, verbose, mock).await?;
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
    use_mock: bool,
) -> anyhow::Result<()> {
    println!("{}", "Initializing security scan...".blue().bold());

    let config = if let Some(path) = config_path {
        ScanConfig::from_file(&path)?
    } else {
        ScanConfig::default()
    };

    let mut scanner = Scanner::new(target, config, use_mock)?;

    if verbose {
        println!("{}", "Running in verbose mode".yellow());
        scanner.set_verbose(true);
    }

    if use_mock {
        println!("{}", "Using mock ZAP client (test mode)".magenta());
    }

    println!("{}", format!("Scanning target: {}", scanner.target()).cyan());
    
    let report = scanner.run().await?;

    println!("{}", "Scan completed successfully".green().bold());
    println!("\n{}", format!("Vulnerabilities found: {}", report.vulnerability_count()).yellow());

    if let Some(output_path) = output {
        report.save(&output_path, &format)?;
        println!("{}", format!("Report saved to: {}", output_path.display()).green());
    } else {
        println!("\n{}", report.summary());
    }

    Ok(())
}

fn run_init(config_path: String) -> anyhow::Result<()> {
    let template = ScanConfig::template();
    std::fs::write(&config_path, template)?;
    println!(
        "{}",
        format!("Configuration template created: {}", config_path).green()
    );
    Ok(())
}

async fn run_status(host: String) -> anyhow::Result<()> {
    println!("{}", "Checking ZAP server status...".cyan());
    
    match zap::check_health(&host).await {
        Ok(_) => {
            println!(
                "{}",
                format!("✓ ZAP server is healthy at {}", host).green().bold()
            );
        }
        Err(e) => {
            println!(
                "{}",
                format!("✗ Failed to connect to ZAP server: {}", e).red().bold()
            );
        }
    }

    Ok(())
}
