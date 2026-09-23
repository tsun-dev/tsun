//! Severity classification and CVSS estimation.
//!
//! ZAP reports risk as Informational/Low/Medium/High — it has no "Critical"
//! level. Tsun promotes high-risk findings that ZAP is confident about to
//! Critical, and keeps Informational as its own level rather than collapsing it
//! into Low, so `--min-severity low` means what it says.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity of a finding, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Legacy `riskcode` string, kept so existing report consumers and baseline
    /// files continue to parse. Info and Low both map to "0".
    pub fn to_risk_code(self) -> String {
        match self {
            Severity::Critical => "3",
            Severity::High => "2",
            Severity::Medium => "1",
            Severity::Low | Severity::Info => "0",
        }
        .to_string()
    }

    /// Derive severity from a legacy `riskcode` string. Used when loading
    /// baseline reports written before the `severity` field existed.
    ///
    /// This reads **Tsun's** old scale (3=Critical, 2=High, 1=Medium, 0=Low),
    /// not ZAP's wire scale — see [`normalize_risk`] for that one.
    pub fn from_risk_code(code: &str) -> Severity {
        match code {
            "3" => Severity::Critical,
            "2" => Severity::High,
            "1" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    /// Parse a user-supplied severity name (CLI flags, config files).
    ///
    /// Names only. Numeric codes are deliberately rejected: ZAP's wire format,
    /// Tsun's legacy `riskcode`, and this scale all number their levels
    /// differently, so a bare "2" cannot be read unambiguously.
    pub fn parse(level: &str) -> anyhow::Result<Severity> {
        match level.trim().to_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" | "informational" => Ok(Severity::Info),
            _ => anyhow::bail!(
                "Invalid severity level: {}. Valid: critical, high, medium, low, info",
                level
            ),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ZAP's confidence levels, normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    FalsePositive,
    Low,
    Medium,
    High,
    Confirmed,
}

impl Confidence {
    pub fn parse(raw: &str) -> Confidence {
        match raw.trim().to_lowercase().as_str() {
            "confirmed" | "4" => Confidence::Confirmed,
            "high" | "3" => Confidence::High,
            "medium" | "2" => Confidence::Medium,
            "low" | "1" => Confidence::Low,
            "false positive" | "false_positive" | "0" => Confidence::FalsePositive,
            // ZAP omits confidence on some alerts; medium is its own default.
            _ => Confidence::Medium,
        }
    }
}

/// Normalize ZAP's risk string. Accepts both the word form ("High") and the
/// numeric form some ZAP versions and add-ons return.
///
/// Note the numeric scale here is **ZAP's**: 0=Informational, 1=Low, 2=Medium,
/// 3=High. That is not the same as Tsun's legacy `riskcode`, where 3=Critical
/// and 2=High — see [`Severity::from_risk_code`], which reads that one.
fn normalize_risk(raw: &str) -> Severity {
    match raw.trim().to_lowercase().as_str() {
        "high" | "3" => Severity::High,
        "medium" | "2" => Severity::Medium,
        "low" | "1" => Severity::Low,
        "informational" | "info" | "0" => Severity::Info,
        _ => Severity::Low,
    }
}

/// Classify a ZAP alert into a Tsun severity.
///
/// High-risk findings that ZAP rates High or Confirmed confidence are promoted
/// to Critical; everything else keeps ZAP's risk level.
pub fn classify(risk: &str, confidence: &str) -> Severity {
    let risk = normalize_risk(risk);
    let confidence = Confidence::parse(confidence);

    match (risk, confidence) {
        (Severity::High, Confidence::High | Confidence::Confirmed) => Severity::Critical,
        (other, _) => other,
    }
}

/// Estimate a representative CVSS base score from ZAP's risk and confidence.
///
/// ZAP does not emit CVSS scores. These are coarse stand-ins chosen so that
/// scores order the same way severities do; callers should surface them as
/// estimates, never as authoritative NVD scores.
pub fn estimate_cvss(risk: &str, confidence: &str) -> f32 {
    let risk = normalize_risk(risk);
    let confidence = Confidence::parse(confidence);

    match risk {
        Severity::High | Severity::Critical => match confidence {
            Confidence::Confirmed => 9.0,
            Confidence::High => 8.5,
            Confidence::Medium => 7.5,
            Confidence::Low | Confidence::FalsePositive => 7.0,
        },
        Severity::Medium => match confidence {
            Confidence::Confirmed | Confidence::High => 6.5,
            Confidence::Medium => 5.5,
            Confidence::Low | Confidence::FalsePositive => 4.5,
        },
        Severity::Low => 3.5,
        Severity::Info => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_risk_with_high_confidence_promotes_to_critical() {
        assert_eq!(classify("High", "High"), Severity::Critical);
        assert_eq!(classify("High", "Confirmed"), Severity::Critical);
    }

    #[test]
    fn high_risk_with_weak_confidence_stays_high() {
        assert_eq!(classify("High", "Medium"), Severity::High);
        assert_eq!(classify("High", "Low"), Severity::High);
    }

    #[test]
    fn non_high_risk_is_never_promoted() {
        assert_eq!(classify("Medium", "Confirmed"), Severity::Medium);
        assert_eq!(classify("Low", "Confirmed"), Severity::Low);
        assert_eq!(classify("Informational", "Confirmed"), Severity::Info);
    }

    #[test]
    fn informational_is_distinct_from_low() {
        assert_eq!(classify("Informational", "Medium"), Severity::Info);
        assert!(Severity::Info < Severity::Low);
    }

    #[test]
    fn unknown_risk_falls_back_to_low() {
        assert_eq!(classify("bogus", "Medium"), Severity::Low);
    }

    #[test]
    fn missing_confidence_defaults_to_medium() {
        assert_eq!(Confidence::parse(""), Confidence::Medium);
        // So a High alert with no confidence is not silently promoted.
        assert_eq!(classify("High", ""), Severity::High);
    }

    #[test]
    fn severity_ordering_is_ascending() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn parse_accepts_names_and_rejects_junk() {
        assert_eq!(Severity::parse("CRITICAL").unwrap(), Severity::Critical);
        assert_eq!(Severity::parse(" high ").unwrap(), Severity::High);
        assert_eq!(Severity::parse("informational").unwrap(), Severity::Info);
        assert!(Severity::parse("severe").is_err());
    }

    #[test]
    fn parse_rejects_numeric_codes_as_ambiguous() {
        // "2" means Medium on ZAP's wire scale but High on Tsun's legacy
        // riskcode scale; refusing it beats silently picking one.
        for code in ["0", "1", "2", "3", "4"] {
            assert!(
                Severity::parse(code).is_err(),
                "{} should be rejected",
                code
            );
        }
    }

    #[test]
    fn zap_numeric_risk_uses_zaps_own_scale() {
        assert_eq!(classify("3", "Medium"), Severity::High);
        assert_eq!(classify("2", "Medium"), Severity::Medium);
        assert_eq!(classify("1", "Medium"), Severity::Low);
        assert_eq!(classify("0", "Medium"), Severity::Info);
    }

    #[test]
    fn legacy_tsun_risk_codes_use_the_old_scale() {
        assert_eq!(Severity::from_risk_code("3"), Severity::Critical);
        assert_eq!(Severity::from_risk_code("2"), Severity::High);
        assert_eq!(Severity::from_risk_code("1"), Severity::Medium);
        assert_eq!(Severity::from_risk_code("0"), Severity::Low);
    }

    #[test]
    fn risk_code_round_trips_for_legacy_consumers() {
        assert_eq!(Severity::Critical.to_risk_code(), "3");
        assert_eq!(Severity::from_risk_code("3"), Severity::Critical);
        assert_eq!(Severity::from_risk_code("0"), Severity::Low);
    }

    #[test]
    fn cvss_estimates_track_severity_order() {
        assert!(estimate_cvss("High", "Confirmed") > estimate_cvss("High", "Medium"));
        assert!(estimate_cvss("High", "Medium") > estimate_cvss("Medium", "High"));
        assert!(estimate_cvss("Medium", "Medium") > estimate_cvss("Low", "High"));
        assert_eq!(estimate_cvss("Informational", "High"), 0.0);
    }
}
