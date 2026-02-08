use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Configuration for a security scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// ZAP server configuration
    pub zap: ZapConfig,
    /// Scan policies
    pub policies: Vec<String>,
    /// Authentication settings
    pub auth: Option<AuthConfig>,
    /// Timeout in seconds
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZapConfig {
    /// ZAP server host URL
    pub host: String,
    /// API key for authentication
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication method (basic, bearer, custom)
    pub method: String,
    /// Credentials
    pub credentials: serde_json::Value,
}

impl ScanConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn template() -> String {
        r#"# Tsun Security Scan Configuration

zap:
  host: http://localhost:8080
  api_key: null

# Scan policies to apply
policies:
  - default

# Optional authentication configuration
# auth:
#   method: basic
#   credentials:
#     username: user
#     password: pass

# Scan timeout in seconds (default: 1800 = 30 minutes)
timeout: 1800
"#
        .to_string()
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            zap: ZapConfig {
                host: "http://localhost:8080".to_string(),
                api_key: None,
            },
            policies: vec!["default".to_string()],
            auth: None,
            timeout: Some(1800), // 30 minutes default for real ZAP scans
        }
    }
}

/// Resolved scan-tuning parameters after merging profile defaults with CLI overrides.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedProfile {
    pub max_urls: Option<u32>,
    pub attack_strength: String,
    pub alert_threshold: String,
}

/// Resolve profile defaults, then apply CLI overrides for timeout and tuning.
///
/// Priority: CLI flag > profile default > config-file value.
pub fn resolve_profile(
    profile: &str,
    config: &mut ScanConfig,
    cli_timeout: Option<u64>,
    cli_max_urls: Option<u32>,
    cli_attack_strength: Option<String>,
    cli_alert_threshold: Option<String>,
) -> ResolvedProfile {
    let (profile_timeout, profile_max_urls, profile_attack, profile_threshold) = match profile {
        "ci" => (
            Some(900u64), // 15 minutes
            Some(200u32), // Limit crawling
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

    // CLI timeout > profile default > existing config value
    if let Some(t) = cli_timeout {
        config.timeout = Some(t);
    } else if let Some(t) = profile_timeout {
        config.timeout = Some(t);
    }

    ResolvedProfile {
        max_urls: cli_max_urls.or(profile_max_urls),
        attack_strength: cli_attack_strength.unwrap_or(profile_attack),
        alert_threshold: cli_alert_threshold.unwrap_or(profile_threshold),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_profile_ci_defaults() {
        let mut config = ScanConfig::default();
        let resolved = resolve_profile("ci", &mut config, None, None, None, None);
        assert_eq!(config.timeout, Some(900));
        assert_eq!(resolved.max_urls, Some(200));
        assert_eq!(resolved.attack_strength, "low");
        assert_eq!(resolved.alert_threshold, "medium");
    }

    #[test]
    fn test_resolve_profile_deep_defaults() {
        let mut config = ScanConfig::default();
        let resolved = resolve_profile("deep", &mut config, None, None, None, None);
        assert_eq!(config.timeout, Some(7200));
        assert_eq!(resolved.max_urls, None);
        assert_eq!(resolved.attack_strength, "medium");
        assert_eq!(resolved.alert_threshold, "low");
    }

    #[test]
    fn test_resolve_profile_cli_overrides_profile() {
        let mut config = ScanConfig::default();
        let resolved = resolve_profile(
            "ci",
            &mut config,
            Some(600),
            Some(500),
            Some("high".to_string()),
            Some("high".to_string()),
        );
        assert_eq!(config.timeout, Some(600));
        assert_eq!(resolved.max_urls, Some(500));
        assert_eq!(resolved.attack_strength, "high");
        assert_eq!(resolved.alert_threshold, "high");
    }

    #[test]
    fn test_resolve_profile_custom_uses_defaults() {
        let mut config = ScanConfig::default();
        let resolved = resolve_profile("custom", &mut config, None, None, None, None);
        // Custom profile does not override config timeout
        assert_eq!(config.timeout, Some(1800));
        assert_eq!(resolved.max_urls, None);
        assert_eq!(resolved.attack_strength, "low");
        assert_eq!(resolved.alert_threshold, "medium");
    }
}
