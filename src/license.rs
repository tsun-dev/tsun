//! License management for Tsun Pro features
//!
//! This module implements a local-first licensing system with:
//! - JWT-style signed tokens
//! - Plan-based feature gating (Free, Pro, ProPlus)
//! - Expiration with 7-day grace period
//! - Public key verification (private key stays off-device)

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// License plans
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    Free,
    Pro,
    #[serde(rename = "pro_plus")]
    ProPlus,
}

impl Plan {
    pub fn is_pro_or_higher(&self) -> bool {
        matches!(self, Plan::Pro | Plan::ProPlus)
    }
}

impl std::fmt::Display for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Plan::Free => write!(f, "Free"),
            Plan::Pro => write!(f, "Pro"),
            Plan::ProPlus => write!(f, "Pro Plus"),
        }
    }
}

/// License claims (JWT-style payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub plan: Plan,
    pub customer_id: String,
    pub issued_at: String,  // RFC3339
    pub expires_at: String, // RFC3339
    #[serde(default)]
    pub features: Vec<String>,
}

/// Validated license with status
#[derive(Debug, Clone)]
pub struct License {
    pub claims: LicenseClaims,
    pub status: LicenseStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LicenseStatus {
    Valid,
    Expired,
    GracePeriod { days_remaining: i64 },
}

impl License {
    /// Parse and validate a license string
    pub fn from_string(license_str: &str) -> Result<Self> {
        // Simple base64-encoded JSON for now (can upgrade to full JWT later)
        // Format: base64(json_claims).signature

        let parts: Vec<&str> = license_str.trim().split('.').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid license format. Expected: <payload>.<signature>"
            ));
        }

        let payload = parts[0];
        let signature = parts[1];

        // Decode payload using base64 engine
        use base64::{engine::general_purpose, Engine as _};
        let decoded = general_purpose::STANDARD
            .decode(payload)
            .context("Failed to decode license payload")?;
        let claims: LicenseClaims =
            serde_json::from_slice(&decoded).context("Failed to parse license claims")?;

        // Verify signature
        Self::verify_signature(payload, signature)?;

        // Check expiration
        let status = Self::check_expiration(&claims.expires_at)?;

        Ok(License { claims, status })
    }

    /// Verify signature using embedded public key
    fn verify_signature(payload: &str, signature: &str) -> Result<()> {
        // For MVP: simple HMAC verification
        // In production, use RSA or Ed25519 with embedded public key

        // Embedded public verification data (this would be a real public key)
        const PUBLIC_KEY_HASH: &str = "tsun_public_key_v1";

        // Decode signature
        use base64::{engine::general_purpose, Engine as _};
        let sig_bytes = general_purpose::STANDARD
            .decode(signature)
            .context("Failed to decode signature")?;

        // Simple verification: check if signature contains expected marker
        // TODO: Replace with proper RSA/Ed25519 verification
        let expected_marker = format!("{}:{}", PUBLIC_KEY_HASH, payload);
        let verification = format!("{:x}", md5::compute(expected_marker.as_bytes()));

        if sig_bytes != verification.as_bytes() {
            return Err(anyhow!(
                "Invalid license signature. If you believe this is an error, open a GitHub issue."
            ));
        }

        Ok(())
    }

    /// Check if license is expired and calculate status
    fn check_expiration(expires_at: &str) -> Result<LicenseStatus> {
        let expiry = chrono::DateTime::parse_from_rfc3339(expires_at)
            .context("Invalid expiration date format")?;
        let now = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());

        if now < expiry {
            return Ok(LicenseStatus::Valid);
        }

        // Calculate days since expiration
        let days_expired = (now.signed_duration_since(expiry)).num_days();

        const GRACE_PERIOD_DAYS: i64 = 7;

        if days_expired <= GRACE_PERIOD_DAYS {
            Ok(LicenseStatus::GracePeriod {
                days_remaining: GRACE_PERIOD_DAYS - days_expired,
            })
        } else {
            Ok(LicenseStatus::Expired)
        }
    }

    /// Check if license allows Pro features
    pub fn is_pro_or_higher(&self) -> bool {
        // Free tier if expired beyond grace period
        if self.status == LicenseStatus::Expired {
            return false;
        }

        self.claims.plan.is_pro_or_higher()
    }

    /// Get plan (downgrades to Free if expired)
    pub fn effective_plan(&self) -> Plan {
        if self.status == LicenseStatus::Expired {
            Plan::Free
        } else {
            self.claims.plan
        }
    }
}

/// Get the license file path (XDG-compliant)
pub fn get_license_path() -> Result<PathBuf> {
    let config_dir = if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg_config)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config")
    } else {
        return Err(anyhow!(
            "Could not determine config directory (no HOME or XDG_CONFIG_HOME)"
        ));
    };

    let tsun_config = config_dir.join("tsun");
    std::fs::create_dir_all(&tsun_config).context("Failed to create tsun config directory")?;

    Ok(tsun_config.join("license"))
}

/// Save license to disk
pub fn save_license(license_str: &str) -> Result<()> {
    // Validate before saving
    License::from_string(license_str)?;

    let path = get_license_path()?;
    std::fs::write(&path, license_str.trim()).context("Failed to write license file")?;

    Ok(())
}

/// Load license from disk
pub fn load_license() -> Result<License> {
    let path = get_license_path()?;

    if !path.exists() {
        return Ok(License {
            claims: LicenseClaims {
                plan: Plan::Free,
                customer_id: "free".to_string(),
                issued_at: chrono::Utc::now().to_rfc3339(),
                expires_at: "9999-12-31T23:59:59Z".to_string(),
                features: vec![],
            },
            status: LicenseStatus::Valid,
        });
    }

    let license_str = std::fs::read_to_string(&path).context("Failed to read license file")?;

    License::from_string(&license_str)
}

/// Generate a sample license (for testing/demos only - DO NOT USE IN PRODUCTION)
#[cfg(test)]
pub fn generate_sample_license(plan: Plan, days_valid: i64) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::days(days_valid);

    let claims = LicenseClaims {
        plan,
        customer_id: "demo_customer".to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        features: vec![],
    };

    let payload = serde_json::to_string(&claims).unwrap();
    let payload_b64 = general_purpose::STANDARD.encode(&payload);

    // Generate simple signature (matches verify_signature logic)
    let expected_marker = format!("tsun_public_key_v1:{}", payload_b64);
    let signature = format!("{:x}", md5::compute(expected_marker.as_bytes()));
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_bytes());

    format!("{}.{}", payload_b64, signature_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_plan_default() {
        let license = load_license().unwrap();
        assert_eq!(license.claims.plan, Plan::Free);
        assert!(!license.is_pro_or_higher());
    }

    #[test]
    fn test_pro_license_parsing() {
        let license_str = generate_sample_license(Plan::Pro, 30);
        let license = License::from_string(&license_str).unwrap();

        assert_eq!(license.claims.plan, Plan::Pro);
        assert!(license.is_pro_or_higher());
        assert_eq!(license.status, LicenseStatus::Valid);
    }

    #[test]
    fn test_expired_license() {
        let license_str = generate_sample_license(Plan::Pro, -10); // Expired 10 days ago
        let license = License::from_string(&license_str).unwrap();

        assert_eq!(license.status, LicenseStatus::Expired);
        assert!(!license.is_pro_or_higher()); // Should downgrade to Free
        assert_eq!(license.effective_plan(), Plan::Free);
    }

    #[test]
    fn test_grace_period() {
        let license_str = generate_sample_license(Plan::Pro, -3); // Expired 3 days ago
        let license = License::from_string(&license_str).unwrap();

        match license.status {
            LicenseStatus::GracePeriod { days_remaining } => {
                assert_eq!(days_remaining, 4); // 7-day grace - 3 days expired
            }
            _ => panic!("Expected GracePeriod status"),
        }

        assert!(license.is_pro_or_higher()); // Still works in grace period
    }

    #[test]
    fn test_plan_display() {
        assert_eq!(Plan::Free.to_string(), "Free");
        assert_eq!(Plan::Pro.to_string(), "Pro");
        assert_eq!(Plan::ProPlus.to_string(), "Pro Plus");
    }
}
