//! Finding suppression rules.
//!
//! DAST output is only useful in CI if teams can retire findings they have
//! judged and accepted. A rule matches when *every* field it specifies matches
//! the finding, so a rule with both `alert` and `url` is narrower than either
//! alone. Suppressed findings are kept in the report (under `suppressed`) and
//! excluded from counts and exit-code gating — they are never silently dropped.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct IgnoreRule {
    /// ZAP plugin id, exact match (e.g. "10038").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// Alert name, `*` glob (e.g. "Cookie No HttpOnly*").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<String>,
    /// URL, `*` glob (e.g. "*/static/*").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Why this finding is accepted. Required in files so suppressions stay
    /// reviewable; optional for one-off `--ignore` flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Match `value` against a pattern containing `*` wildcards. Case-insensitive.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let value = value.to_lowercase();

    if !pattern.contains('*') {
        return pattern == value;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(found) => {
                // A leading literal (no `*` before it) must match at the start.
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }

    // A trailing literal (no `*` after it) must reach the end of the value.
    match parts.last() {
        Some(last) if !last.is_empty() => value.ends_with(last),
        _ => true,
    }
}

impl IgnoreRule {
    /// A rule with no criteria would suppress everything; reject it.
    pub fn validate(&self) -> Result<()> {
        if self.plugin.is_none() && self.alert.is_none() && self.url.is_none() {
            anyhow::bail!(
                "Ignore rule must specify at least one of: plugin, alert, url (rule would suppress every finding)"
            );
        }
        Ok(())
    }

    pub fn matches(&self, plugin_id: &str, alert_name: &str, url: &str) -> bool {
        if let Some(ref p) = self.plugin {
            if p.trim() != plugin_id.trim() {
                return false;
            }
        }
        if let Some(ref a) = self.alert {
            if !glob_match(a, alert_name) {
                return false;
            }
        }
        if let Some(ref u) = self.url {
            if !glob_match(u, url) {
                return false;
            }
        }
        true
    }

    /// Parse a CLI `--ignore` value: `plugin:10038`, `alert:Cookie*`,
    /// `url:*/static/*`, or several joined by `,`
    /// (`plugin:10038,url:*/legacy/*`).
    pub fn parse_cli(spec: &str) -> Result<IgnoreRule> {
        let mut rule = IgnoreRule::default();

        for clause in spec.split(',') {
            let clause = clause.trim();
            if clause.is_empty() {
                continue;
            }
            let (key, value) = clause.split_once(':').with_context(|| {
                format!(
                    "Invalid --ignore value '{}'. Expected key:value, e.g. plugin:10038, alert:'Cookie*', url:'*/static/*'",
                    clause
                )
            })?;
            let value = value.trim().to_string();
            if value.is_empty() {
                anyhow::bail!("Invalid --ignore value '{}': empty value", clause);
            }
            match key.trim().to_lowercase().as_str() {
                "plugin" | "pluginid" | "id" => rule.plugin = Some(value),
                "alert" | "name" => rule.alert = Some(value),
                "url" => rule.url = Some(value),
                "reason" => rule.reason = Some(value),
                other => anyhow::bail!(
                    "Unknown --ignore key '{}'. Valid keys: plugin, alert, url, reason",
                    other
                ),
            }
        }

        rule.validate()?;
        Ok(rule)
    }
}

/// A file of ignore rules: either a bare list or `{ ignore: [...] }` so the
/// same file can be a standalone ignore file or a slice of `tsun.yaml`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IgnoreFile {
    Wrapped { ignore: Vec<IgnoreRule> },
    Bare(Vec<IgnoreRule>),
}

/// Load ignore rules from a YAML or JSON file.
pub fn load_ignore_file<P: AsRef<Path>>(path: P) -> Result<Vec<IgnoreRule>> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read ignore file: {}", path.display()))?;

    let parsed: IgnoreFile = serde_yaml::from_str(&content)
        .with_context(|| format!("Ignore file is not valid YAML or JSON: {}", path.display()))?;

    let rules = match parsed {
        IgnoreFile::Wrapped { ignore } => ignore,
        IgnoreFile::Bare(rules) => rules,
    };

    for (i, rule) in rules.iter().enumerate() {
        rule.validate()
            .with_context(|| format!("Invalid rule #{} in {}", i + 1, path.display()))?;
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("login", "login"));
        assert!(!glob_match("login", "logins"));
    }

    #[test]
    fn glob_is_case_insensitive() {
        assert!(glob_match("Cookie*", "cookie no httponly flag"));
    }

    #[test]
    fn glob_prefix_suffix_and_middle() {
        assert!(glob_match("Cookie*", "Cookie No HttpOnly Flag"));
        assert!(glob_match("*Flag", "Cookie No HttpOnly Flag"));
        assert!(glob_match("*HttpOnly*", "Cookie No HttpOnly Flag"));
        assert!(glob_match("*/static/*", "https://x.com/static/app.js"));
    }

    #[test]
    fn glob_anchors_leading_literal() {
        assert!(!glob_match("Cookie*", "No Cookie Flag"));
    }

    #[test]
    fn glob_anchors_trailing_literal() {
        assert!(!glob_match("*.js", "https://x.com/app.js?v=1"));
        assert!(glob_match("*.js", "https://x.com/app.js"));
    }

    #[test]
    fn rule_requires_all_specified_fields() {
        let rule = IgnoreRule {
            plugin: Some("10038".into()),
            url: Some("*/legacy/*".into()),
            ..Default::default()
        };
        assert!(rule.matches("10038", "CSP Header Not Set", "https://x.com/legacy/a"));
        assert!(!rule.matches("10038", "CSP Header Not Set", "https://x.com/app/a"));
        assert!(!rule.matches("10020", "CSP Header Not Set", "https://x.com/legacy/a"));
    }

    #[test]
    fn empty_rule_is_rejected() {
        assert!(IgnoreRule::default().validate().is_err());
    }

    #[test]
    fn parse_cli_single_clause() {
        let rule = IgnoreRule::parse_cli("plugin:10038").unwrap();
        assert_eq!(rule.plugin.as_deref(), Some("10038"));
        assert!(rule.alert.is_none());
    }

    #[test]
    fn parse_cli_multiple_clauses() {
        let rule =
            IgnoreRule::parse_cli("plugin:10038,url:*/static/*,reason:handled at CDN").unwrap();
        assert_eq!(rule.plugin.as_deref(), Some("10038"));
        assert_eq!(rule.url.as_deref(), Some("*/static/*"));
        assert_eq!(rule.reason.as_deref(), Some("handled at CDN"));
    }

    #[test]
    fn parse_cli_rejects_malformed() {
        assert!(IgnoreRule::parse_cli("10038").is_err());
        assert!(IgnoreRule::parse_cli("plugin:").is_err());
        assert!(IgnoreRule::parse_cli("bogus:x").is_err());
        assert!(IgnoreRule::parse_cli("reason:only").is_err());
    }

    #[test]
    fn load_file_accepts_bare_list_and_wrapped() {
        let dir = std::env::temp_dir();

        let bare = dir.join("tsun_ignore_bare.yaml");
        std::fs::write(&bare, "- plugin: \"10038\"\n  reason: handled at CDN\n").unwrap();
        let rules = load_ignore_file(&bare).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].plugin.as_deref(), Some("10038"));
        let _ = std::fs::remove_file(&bare);

        let wrapped = dir.join("tsun_ignore_wrapped.yaml");
        std::fs::write(
            &wrapped,
            "ignore:\n  - alert: \"Cookie*\"\n    reason: accepted\n",
        )
        .unwrap();
        let rules = load_ignore_file(&wrapped).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].alert.as_deref(), Some("Cookie*"));
        let _ = std::fs::remove_file(&wrapped);
    }

    #[test]
    fn load_file_rejects_rule_with_no_criteria() {
        let path = std::env::temp_dir().join("tsun_ignore_empty.yaml");
        std::fs::write(&path, "- reason: nothing specified\n").unwrap();
        assert!(load_ignore_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
