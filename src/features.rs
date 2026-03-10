//! Feature definitions for Tsun
//!
//! This module defines the available features in Tsun.

/// Features available in Tsun
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum Feature {
    // Core features
    BasicScan,
    CiProfile,
    AuthHeaders,
    AuthCookies,
    AuthLoginCommand,
    JsonOutput,
    SarifOutput,
    BasicExitGating,

    // Advanced features (now all available)
    BaselineComparison,
    DeepProfile,
    CustomProfile,
    HtmlOutput,
    YamlOutput,
    SarifUpload,
    IgnoreRules,
}

impl Feature {
    /// Get user-friendly feature name
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

/// Check if a feature is available (all features are now available)
#[allow(dead_code)]
pub fn is_feature_available(_feature: Feature) -> bool {
    true // All features are available
}

/// Get list of all features
#[allow(dead_code)]
pub fn get_all_features() -> Vec<Feature> {
    vec![
        Feature::BasicScan,
        Feature::CiProfile,
        Feature::AuthHeaders,
        Feature::AuthCookies,
        Feature::AuthLoginCommand,
        Feature::JsonOutput,
        Feature::SarifOutput,
        Feature::BasicExitGating,
        Feature::BaselineComparison,
        Feature::DeepProfile,
        Feature::CustomProfile,
        Feature::HtmlOutput,
        Feature::YamlOutput,
        Feature::SarifUpload,
        Feature::IgnoreRules,
    ]
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_features_available() {
        // All features should be available
        assert!(is_feature_available(Feature::BasicScan));
        assert!(is_feature_available(Feature::CiProfile));
        assert!(is_feature_available(Feature::AuthHeaders));
        assert!(is_feature_available(Feature::JsonOutput));
        assert!(is_feature_available(Feature::BaselineComparison));
        assert!(is_feature_available(Feature::DeepProfile));
        assert!(is_feature_available(Feature::HtmlOutput));
        assert!(is_feature_available(Feature::YamlOutput));
        assert!(is_feature_available(Feature::SarifUpload));
    }
}
