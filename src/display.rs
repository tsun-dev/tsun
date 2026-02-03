use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

/// Display utilities for CLI output
pub struct Display;

impl Display {
    /// Print a section header
    pub fn section_header(title: &str) {
        println!("\n{}", format!("━━ {} ━━", title).blue().bold());
    }

    /// Print a success message with checkmark
    pub fn success(msg: &str) {
        println!("{} {}", "✓".green().bold(), msg.green());
    }

    /// Print a warning message
    pub fn warning(msg: &str) {
        println!("{} {}", "⚠".yellow().bold(), msg.yellow());
    }

    /// Print an error message with X
    pub fn error(msg: &str) {
        println!("{} {}", "✗".red().bold(), msg.red());
    }

    /// Print an info message
    pub fn info(msg: &str) {
        println!("{} {}", "ℹ".cyan().bold(), msg.cyan());
    }

    /// Print a status message
    pub fn status(label: &str, value: &str) {
        println!("  {} {}", format!("{}:", label).dimmed(), value);
    }

    /// Print a metric with value
    #[allow(dead_code)]
    pub fn metric(label: &str, value: usize, color_fn: fn(&str) -> colored::ColoredString) {
        println!("  {} {}", label.dimmed(), color_fn(&value.to_string()).bold());
    }

    /// Create a spinner for long-running operations
    pub fn spinner(msg: &str) -> ProgressBar {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        spinner.set_message(msg.to_string());
        spinner
    }

    /// Create a progress bar for determinate operations
    #[allow(dead_code)]
    pub fn progress_bar(total: u64, msg: &str) -> ProgressBar {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} {msg} [{bar:40.cyan/blue}] {pos}/{len}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        pb.set_message(msg.to_string());
        pb
    }

    /// Print a summary table for vulnerabilities
    pub fn vulnerability_summary(
        total: usize,
        critical: usize,
        high: usize,
        medium: usize,
        low: usize,
    ) {
        Self::section_header("Vulnerability Summary");

        let total_str = total.to_string();
        let critical_str = critical.to_string();
        let high_str = high.to_string();
        let medium_str = medium.to_string();
        let low_str = low.to_string();

        // Print summary with colors
        println!("  {} {}", "Total Issues:".dimmed(), total_str.bold());

        if critical > 0 {
            println!("  {} {}", "Critical:".dimmed(), critical_str.red().bold());
        }
        if high > 0 {
            println!(
                "  {} {}",
                "High:".dimmed(),
                high_str.color(colored::Color::TrueColor {
                    r: 255,
                    g: 107,
                    b: 107
                })
            );
        }
        if medium > 0 {
            println!("  {} {}", "Medium:".dimmed(), medium_str.yellow().bold());
        }
        if low > 0 {
            println!("  {} {}", "Low:".dimmed(), low_str.cyan().bold());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_methods_dont_panic() {
        // These should not panic
        Display::success("Test success");
        Display::warning("Test warning");
        Display::error("Test error");
        Display::info("Test info");
        Display::status("Label", "Value");
        Display::section_header("Test Section");
    }

    #[test]
    fn test_metric_display() {
        Display::metric("High", 5, |s| s.red());
        Display::metric("Medium", 3, |s| s.yellow());
    }
}
