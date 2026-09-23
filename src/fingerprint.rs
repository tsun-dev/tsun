//! Stable identity for findings across scans.
//!
//! Baseline comparison used to key on the exact URL, so a session id, a row id,
//! or a cache-busting query parameter made an unchanged finding look new on
//! every run. We normalize the URL into a template first: volatile path
//! segments become placeholders and query values are dropped (names are kept,
//! since a finding on `?q=` is not the same finding as one on `?id=`).

use url::Url;

/// Query parameters whose presence is incidental to the finding.
const VOLATILE_PARAMS: &[&str] = &[
    "_",
    "cachebuster",
    "cb",
    "csrf",
    "csrf_token",
    "nonce",
    "rand",
    "random",
    "session",
    "sessionid",
    "sid",
    "t",
    "timestamp",
    "ts",
    "v",
    "xsrf",
];

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(len, part)| part.len() == *len && is_hex(part))
}

/// True when a path segment looks like an identifier rather than a route name.
fn is_volatile_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }

    // Pure numbers: /users/12345
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    if is_uuid(segment) {
        return true;
    }

    // Long hex blobs: hashes, object ids, tokens.
    if segment.len() >= 12 && is_hex(segment) {
        return true;
    }

    // Mixed alphanumerics that are mostly digits: "a1b2c3d4e5", "order-99812".
    if segment.len() >= 8 {
        let digits = segment.chars().filter(|c| c.is_ascii_digit()).count();
        if digits * 2 >= segment.len() {
            return true;
        }
    }

    false
}

/// Collapse one path segment, keeping a file extension when there is one so
/// `app.a1b2c3d4.js` stays recognizable as a script rather than a bare `{id}`.
fn normalize_segment(segment: &str) -> String {
    match segment.rsplit_once('.') {
        // Only treat the tail as an extension if it looks like one.
        Some((stem, ext))
            if !stem.is_empty()
                && (1..=5).contains(&ext.len())
                && ext.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            if is_volatile_segment(stem) {
                format!("{{id}}.{}", ext)
            } else {
                segment.to_string()
            }
        }
        _ => {
            if is_volatile_segment(segment) {
                "{id}".to_string()
            } else {
                segment.to_string()
            }
        }
    }
}

/// Reduce a URL to a stable template: `https://x.com/users/42?sid=abc` becomes
/// `https://x.com/users/{id}?sid`.
///
/// Input that does not parse as a URL is returned trimmed and lowercased, so
/// callers always get *something* stable to hash.
pub fn normalize_url(raw: &str) -> String {
    let parsed = match Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return raw.trim().to_lowercase(),
    };

    let mut out = String::new();
    out.push_str(parsed.scheme());
    out.push_str("://");
    if let Some(host) = parsed.host_str() {
        out.push_str(&host.to_lowercase());
    }
    if let Some(port) = parsed.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }

    for segment in parsed.path().split('/') {
        if segment.is_empty() {
            continue;
        }
        out.push('/');
        out.push_str(&normalize_segment(segment));
    }
    if parsed.path().ends_with('/') && parsed.path() != "/" {
        out.push('/');
    }

    // Keep parameter names (they identify the injection point), drop values,
    // and sort so parameter order does not affect identity.
    let mut params: Vec<String> = parsed
        .query_pairs()
        .map(|(k, _)| k.to_lowercase())
        .filter(|k| !VOLATILE_PARAMS.contains(&k.as_str()))
        .collect();
    if !params.is_empty() {
        params.sort();
        params.dedup();
        out.push('?');
        out.push_str(&params.join("&"));
    }

    out
}

/// Stable identity for a finding: plugin, injection point, and normalized
/// location. Severity is deliberately excluded so that a finding whose severity
/// changes between runs is reported as changed rather than as one fixed plus
/// one new.
pub fn finding_fingerprint(
    plugin_id: &str,
    alert_name: &str,
    url: &str,
    param: Option<&str>,
) -> String {
    let normalized = normalize_url(url);
    let digest = md5::compute(format!(
        "{}|{}|{}|{}",
        plugin_id.trim(),
        alert_name.trim().to_lowercase(),
        normalized,
        param.unwrap_or("").trim().to_lowercase()
    ));
    format!("{:x}", digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_path_segments_collapse() {
        assert_eq!(
            normalize_url("https://x.com/users/12345/orders/6"),
            "https://x.com/users/{id}/orders/{id}"
        );
    }

    #[test]
    fn uuid_segments_collapse() {
        assert_eq!(
            normalize_url("https://x.com/o/550e8400-e29b-41d4-a716-446655440000/edit"),
            "https://x.com/o/{id}/edit"
        );
    }

    #[test]
    fn long_hex_segments_collapse() {
        assert_eq!(
            normalize_url("https://x.com/assets/d41d8cd98f00b204e9800998ecf8427e"),
            "https://x.com/assets/{id}"
        );
    }

    #[test]
    fn hashed_asset_names_collapse_but_keep_their_extension() {
        // Cache-busting hashes change every build; without this, every deploy
        // would report the same finding as new.
        assert_eq!(
            normalize_url("https://x.com/assets/d41d8cd98f00b204e9800998ecf8427e.js"),
            "https://x.com/assets/{id}.js"
        );
        assert_eq!(
            normalize_url("https://x.com/assets/app.js"),
            "https://x.com/assets/app.js",
            "an ordinary filename is not an id"
        );
    }

    #[test]
    fn route_names_are_preserved() {
        assert_eq!(
            normalize_url("https://x.com/api/v2/login"),
            "https://x.com/api/v2/login"
        );
    }

    #[test]
    fn query_values_are_dropped_but_names_kept() {
        assert_eq!(
            normalize_url("https://x.com/s?q=hello&page=2"),
            "https://x.com/s?page&q"
        );
    }

    #[test]
    fn volatile_params_are_dropped_entirely() {
        assert_eq!(
            normalize_url("https://x.com/s?q=a&_=1699999999&sid=abc"),
            "https://x.com/s?q"
        );
    }

    #[test]
    fn param_order_does_not_change_identity() {
        assert_eq!(
            normalize_url("https://x.com/s?b=1&a=2"),
            normalize_url("https://x.com/s?a=9&b=8")
        );
    }

    #[test]
    fn host_case_is_normalized() {
        assert_eq!(
            normalize_url("https://X.COM/Path"),
            "https://x.com/Path",
            "host lowercases but path case is significant"
        );
    }

    #[test]
    fn unparseable_input_is_still_stable() {
        assert_eq!(normalize_url("  NOT a url "), "not a url");
    }

    #[test]
    fn fingerprint_is_stable_across_volatile_ids() {
        let a = finding_fingerprint("40012", "XSS", "https://x.com/u/1/p?sid=aaa", Some("q"));
        let b = finding_fingerprint("40012", "XSS", "https://x.com/u/999/p?sid=zzz", Some("q"));
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_differs_by_injection_point() {
        let a = finding_fingerprint("40012", "XSS", "https://x.com/s", Some("q"));
        let b = finding_fingerprint("40012", "XSS", "https://x.com/s", Some("name"));
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_differs_by_plugin() {
        let a = finding_fingerprint("40012", "XSS", "https://x.com/s", None);
        let b = finding_fingerprint("40018", "SQLi", "https://x.com/s", None);
        assert_ne!(a, b);
    }
}
