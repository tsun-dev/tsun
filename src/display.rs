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

    /// Print CVSS metrics
    pub fn cvss_metrics(average_cvss: f32, max_cvss: f32) {
        Self::section_header("CVSS Metrics");
        
        let avg_color = if average_cvss >= 7.0 {
            colored::Color::Red
        } else if average_cvss >= 4.0 {
            colored::Color::Yellow
        } else {
            colored::Color::Green
        };

        let max_color = if max_cvss >= 9.0 {
            colored::Color::Red
        } else if max_cvss >= 7.0 {
            colored::Color::TrueColor { r: 255, g: 107, b: 107 }
        } else if max_cvss >= 4.0 {
            colored::Color::Yellow
        } else {
            colored::Color::Green
        };

        println!(
            "  {} {:.1}",
            "Average CVSS:".dimmed(),
            format!("{:.1}", average_cvss).color(avg_color).bold()
        );
        println!(
            "  {} {:.1}",
            "Maximum CVSS:".dimmed(),
            format!("{:.1}", max_cvss).color(max_color).bold()
        );
    }

    /// Print vulnerabilities breakdown by type
    pub fn vulnerabilities_by_type(breakdown: &std::collections::HashMap<String, usize>) {
        if breakdown.is_empty() {
            return;
        }

        Self::section_header("Vulnerabilities by Type");
        let mut sorted: Vec<_> = breakdown.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        
        for (vuln_type, count) in sorted {
            println!("  {} {}", vuln_type.dimmed(), count.to_string().bold());
        }
    }

    /// Print report comparison results
    pub fn comparison_report(comparison: &crate::report::ReportComparison) {
        Self::section_header("Comparison Report");

        let status_text = if comparison.is_improvement {
            "✓ IMPROVED".green()
        } else if comparison.total_delta == 0 && comparison.average_cvss_delta == 0.0 {
            "= UNCHANGED".cyan()
        } else {
            "✗ REGRESSED".red()
        };

        println!("  Status: {}", status_text.bold());

        // Summary metrics
        println!(
            "  Total Issues: {} {}",
            comparison.unchanged_vulnerabilities.len(),
            format_delta(comparison.total_delta)
        );
        println!("  New Vulnerabilities: {}", comparison.new_vulnerabilities.len().to_string().red());
        println!("  Fixed Vulnerabilities: {}", comparison.fixed_vulnerabilities.len().to_string().green());

        // Severity deltas
        println!();
        println!("  Severity Changes:");
        if comparison.critical_delta != 0 {
            println!("    Critical: {}", format_delta(comparison.critical_delta).red());
        }
        if comparison.high_delta != 0 {
            println!("    High: {}", format_delta(comparison.high_delta).red());
        }
        if comparison.medium_delta != 0 {
            println!("    Medium: {}", format_delta(comparison.medium_delta).yellow());
        }
        if comparison.low_delta != 0 {
            println!("    Low: {}", format_delta(comparison.low_delta).cyan());
        }

        // CVSS change
        if comparison.average_cvss_delta != 0.0 {
            let cvss_color = if comparison.average_cvss_delta < 0.0 {
                colored::Color::Green
            } else {
                colored::Color::Red
            };
            println!(
                "  Avg CVSS Delta: {}",
                format!("{:+.1}", comparison.average_cvss_delta)
                    .color(cvss_color)
                    .bold()
            );
        }
    }
}

/// Format delta value with sign and color
fn format_delta(delta: i32) -> colored::ColoredString {
    if delta > 0 {
        format!("+{}", delta).red().bold()
    } else if delta < 0 {
        delta.to_string().green().bold()
    } else {
        "0".cyan()
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
