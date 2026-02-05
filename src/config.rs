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
        r#"# Arete Security Scan Configuration

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
