//! Feature gating for Rukn Pro
//!
//! This module defines which features are available in Free vs Pro tiers
//! and provides helpers to check feature availability.

use crate::license::License;

/// Features available in Rukn
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum Feature {
    // Always Free
    BasicScan,
    CiProfile,
    AuthHeaders,
    AuthCookies,
    AuthLoginCommand,
    JsonOutput,
    SarifOutput,
    BasicExitGating,

    // Pro-only
    BaselineComparison,
    DeepProfile,
    CustomProfile,
    HtmlOutput,
    YamlOutput,
    SarifUpload,
    IgnoreRules,
}

impl Feature {
    /// Check if this feature requires Pro
    pub fn requires_pro(&self) -> bool {
        matches!(
            self,
            Feature::BaselineComparison
                | Feature::DeepProfile
                | Feature::CustomProfile
                | Feature::HtmlOutput
                | Feature::YamlOutput
                | Feature::SarifUpload
                | Feature::IgnoreRules
        )
    }

    /// Get user-friendly feature name
    pub fn name(&self) -> &'static str {
        match self {
            Feature::BasicScan => "Basic Scanning",
            Feature::CiProfile => "CI Profile",
            Feature::AuthHeaders => "Auth Headers",
            Feature::AuthCookies => "Auth Cookies",
            Feature::AuthLoginCommand => "Login Command",
            Feature::JsonOutput => "JSON Output",
            Feature::SarifOutput => "SARIF Output",
            Feature::BasicExitGating => "Exit Code Gating",
            Feature::BaselineComparison => "Baseline Comparison",
            Feature::DeepProfile => "Deep Profile",
            Feature::CustomProfile => "Custom Profile",
            Feature::HtmlOutput => "HTML Reports",
            Feature::YamlOutput => "YAML Reports",
            Feature::SarifUpload => "GitHub SARIF Upload",
            Feature::IgnoreRules => "Ignore Rules",
        }
    }

    /// Get the value proposition for this feature
    pub fn value_message(&self) -> &'static str {
        match self {
            Feature::BaselineComparison => {
                "Baseline comparison reduces CI noise by showing only new/fixed issues."
            }
            Feature::DeepProfile => {
                "Deep profile enables thorough security scans for production releases."
            }
            Feature::CustomProfile => {
                "Custom profiles let you balance scan time and coverage for your workflow."
            }
            Feature::HtmlOutput => {
                "HTML reports provide beautiful, shareable vulnerability documentation."
            }
            Feature::YamlOutput => "YAML output enables easy integration with custom tooling.",
            Feature::SarifUpload => "SARIF upload automates GitHub Code Scanning integration.",
            Feature::IgnoreRules => {
                "Ignore rules reduce false positives and improve CI reliability."
            }
            _ => "",
        }
    }
}

/// Check if a feature is available with the current license
pub fn is_feature_available(license: &License, feature: Feature) -> bool {
    if !feature.requires_pro() {
        return true; // Free features always available
    }

    license.is_pro_or_higher()
}

/// Get a helpful upgrade message for a Pro feature
pub fn get_upgrade_message(feature: Feature) -> String {
    if !feature.requires_pro() {
        return String::new();
    }

    format!(
        "\n⚠️  {} is part of Rukn Pro\n\n{}\n\nGet Pro: https://github.com/cWashington91/rukn#pricing\nOr run: rukn license set <your_license>\n",
        feature.name(),
        feature.value_message()
    )
}

/// Get list of all Pro features (for marketing/docs)
pub fn get_pro_features() -> Vec<Feature> {
    vec![
        Feature::BaselineComparison,
        Feature::DeepProfile,
        Feature::CustomProfile,
        Feature::HtmlOutput,
        Feature::YamlOutput,
        Feature::SarifUpload,
        Feature::IgnoreRules,
    ]
}

/// Format license summary for display
pub fn format_license_summary(license: &License) -> String {
    use crate::license::LicenseStatus;

    let plan = license.effective_plan();
    let status_msg = match &license.status {
        LicenseStatus::Valid => {
            let expires = &license.claims.expires_at;
            if let Ok(exp_date) = chrono::DateTime::parse_from_rfc3339(expires) {
                format!("expires {}", exp_date.format("%Y-%m-%d"))
            } else {
                "active".to_string()
            }
        }
        LicenseStatus::GracePeriod { days_remaining } => {
            format!(
                "⚠️  EXPIRED (grace period: {} days remaining)",
                days_remaining
            )
        }
        LicenseStatus::Expired => "⚠️  EXPIRED".to_string(),
    };

    format!("Plan: {} ({})", plan, status_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::{License, LicenseClaims, LicenseStatus, Plan};

    fn create_test_license(plan: Plan) -> License {
        License {
            claims: LicenseClaims {
                plan,
                customer_id: "test".to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: "2027-01-01T00:00:00Z".to_string(),
                features: vec![],
            },
            status: LicenseStatus::Valid,
        }
    }

    #[test]
    fn test_free_features_always_available() {
        let license = create_test_license(Plan::Free);

        assert!(is_feature_available(&license, Feature::BasicScan));
        assert!(is_feature_available(&license, Feature::CiProfile));
        assert!(is_feature_available(&license, Feature::AuthHeaders));
        assert!(is_feature_available(&license, Feature::JsonOutput));
    }

    #[test]
    fn test_pro_features_require_license() {
        let free_license = create_test_license(Plan::Free);
        let pro_license = create_test_license(Plan::Pro);

        assert!(!is_feature_available(
            &free_license,
            Feature::BaselineComparison
        ));
        assert!(!is_feature_available(&free_license, Feature::HtmlOutput));

        assert!(is_feature_available(
            &pro_license,
            Feature::BaselineComparison
        ));
        assert!(is_feature_available(&pro_license, Feature::HtmlOutput));
    }

    #[test]
    fn test_upgrade_message_format() {
        let msg = get_upgrade_message(Feature::BaselineComparison);
        assert!(msg.contains("Baseline Comparison"));
        assert!(msg.contains("rukn license set"));
        assert!(msg.contains("noise"));
    }

    #[test]
    fn test_feature_categorization() {
        assert!(!Feature::BasicScan.requires_pro());
        assert!(!Feature::CiProfile.requires_pro());
        assert!(Feature::BaselineComparison.requires_pro());
        assert!(Feature::DeepProfile.requires_pro());
    }
}
