/// Authentication and session handling utilities
use anyhow::Result;
use std::path::Path;

/// Parse header strings like "Name: value" into (Name, Value) pairs
pub fn parse_headers(inputs: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for s in inputs {
        if let Some(idx) = s.find(':') {
            let key = s[..idx].trim();
            if key.is_empty() {
                continue;
            }
            let value = s[idx + 1..].trim();
            out.push((key.to_string(), value.to_string()));
        }
    }
    out
}

/// Turn a config-file `auth:` block into request headers.
///
/// Supported methods: `basic` (username/password), `bearer` (token), and
/// `custom` (a map of header names to values).
pub fn headers_from_config(auth: &crate::config::AuthConfig) -> Result<Vec<(String, String)>> {
    use base64::Engine as _;

    let creds = &auth.credentials;
    let field = |name: &str| -> Option<String> {
        creds.get(name).and_then(|v| v.as_str()).map(str::to_string)
    };

    match auth.method.to_lowercase().as_str() {
        "basic" => {
            let username = field("username").ok_or_else(|| {
                anyhow::anyhow!("auth.method 'basic' requires credentials.username")
            })?;
            let password = field("password").unwrap_or_default();
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", username, password));
            Ok(vec![(
                "Authorization".to_string(),
                format!("Basic {}", encoded),
            )])
        }
        "bearer" => {
            let token = field("token")
                .or_else(|| field("access_token"))
                .ok_or_else(|| {
                    anyhow::anyhow!("auth.method 'bearer' requires credentials.token")
                })?;
            Ok(vec![(
                "Authorization".to_string(),
                format!("Bearer {}", token),
            )])
        }
        "custom" => {
            let map = creds.as_object().ok_or_else(|| {
                anyhow::anyhow!("auth.method 'custom' requires credentials to be a map of headers")
            })?;
            let mut headers = Vec::new();
            for (name, value) in map {
                let value = value.as_str().ok_or_else(|| {
                    anyhow::anyhow!("auth credential '{}' must be a string", name)
                })?;
                headers.push((name.clone(), value.to_string()));
            }
            Ok(headers)
        }
        other => anyhow::bail!(
            "Unsupported auth.method '{}'. Valid: basic, bearer, custom",
            other
        ),
    }
}

/// Load cookies from a Netscape-format cookies.txt or JSON and return a Cookie header string
pub fn load_cookie_header(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)?;

    // Try JSON cookie-jar formats first (array of {name,value} or {cookies: [...]})
    if let Some(first_char) = content.trim_start().chars().next() {
        if first_char == '{' || first_char == '[' {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                // Case: top-level array of objects
                if let Some(arr) = val.as_array() {
                    let mut pairs = Vec::new();
                    for item in arr {
                        if let (Some(name), Some(value)) = (item.get("name"), item.get("value")) {
                            if let (Some(n), Some(v)) = (name.as_str(), value.as_str()) {
                                pairs.push(format!("{}={}", n, v));
                            }
                        }
                    }
                    if !pairs.is_empty() {
                        return Ok(pairs.join("; "));
                    }
                }

                // Case: object with "cookies" array
                if let Some(obj) = val.as_object() {
                    if let Some(cookies_val) = obj.get("cookies") {
                        if let Some(arr) = cookies_val.as_array() {
                            let mut pairs = Vec::new();
                            for item in arr {
                                if let (Some(name), Some(value)) =
                                    (item.get("name"), item.get("value"))
                                {
                                    if let (Some(n), Some(v)) = (name.as_str(), value.as_str()) {
                                        pairs.push(format!("{}={}", n, v));
                                    }
                                }
                            }
                            if !pairs.is_empty() {
                                return Ok(pairs.join("; "));
                            }
                        }
                    }
                }
            }
            // If JSON parsing didn't yield cookies, fall through to Netscape parsing
        }
    }

    // Netscape parsing fallback
    let mut pairs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Netscape format: domain TAB flag TAB path TAB secure TAB expiration TAB name TAB value
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 7 {
            let name = parts[5];
            let value = parts[6];
            pairs.push(format!("{}={}", name, value));
        }
    }
    Ok(pairs.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use crate::config::AuthConfig;

    fn auth(method: &str, credentials: serde_json::Value) -> AuthConfig {
        AuthConfig {
            method: method.to_string(),
            credentials,
        }
    }

    #[test]
    fn config_basic_auth_becomes_authorization_header() {
        let headers = headers_from_config(&auth(
            "basic",
            serde_json::json!({"username": "alice", "password": "s3cret"}),
        ))
        .unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Authorization");
        // base64("alice:s3cret")
        assert_eq!(headers[0].1, "Basic YWxpY2U6czNjcmV0");
    }

    #[test]
    fn config_bearer_auth_becomes_authorization_header() {
        let headers =
            headers_from_config(&auth("bearer", serde_json::json!({"token": "abc123"}))).unwrap();
        assert_eq!(
            headers[0],
            ("Authorization".to_string(), "Bearer abc123".to_string())
        );
    }

    #[test]
    fn config_custom_auth_passes_headers_through() {
        let headers =
            headers_from_config(&auth("custom", serde_json::json!({"X-Api-Key": "k1"}))).unwrap();
        assert_eq!(headers[0], ("X-Api-Key".to_string(), "k1".to_string()));
    }

    #[test]
    fn config_auth_rejects_unknown_method_and_missing_fields() {
        assert!(headers_from_config(&auth("saml", serde_json::json!({}))).is_err());
        assert!(headers_from_config(&auth("basic", serde_json::json!({}))).is_err());
        assert!(headers_from_config(&auth("bearer", serde_json::json!({}))).is_err());
    }

    #[test]
    fn test_parse_headers() {
        let inputs = vec![
            "Authorization: Bearer token123".to_string(),
            "X-Test: value".to_string(),
            "MalformedHeader".to_string(),
        ];
        let parsed = parse_headers(&inputs);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "Authorization");
        assert_eq!(parsed[0].1, "Bearer token123");
        assert_eq!(parsed[1].0, "X-Test");
        assert_eq!(parsed[1].1, "value");
    }

    #[test]
    fn test_parse_headers_multiple_colons_and_trimming() {
        let inputs = vec![
            "X-Custom: a:b:c".to_string(),
            "  Key :  value  ".to_string(),
            ":no_key".to_string(),
        ];
        let parsed = parse_headers(&inputs);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "X-Custom");
        assert_eq!(parsed[0].1, "a:b:c");
        assert_eq!(parsed[1].0, "Key");
        assert_eq!(parsed[1].1, "value");
    }

    #[test]
    fn test_parse_headers_empty_and_malformed() {
        let inputs = vec!["".to_string(), "NoColonHere".to_string(), ":".to_string()];
        let parsed = parse_headers(&inputs);
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn test_load_cookie_header_netscape() {
        // Prepare a temporary cookies file in the system temp dir
        let mut path = std::env::temp_dir();
        path.push("tsun_test_cookies.txt");
        let mut f = std::fs::File::create(&path).expect("create cookie file");
        // Netscape format lines: domain\tflag\tpath\tsecure\texpiry\tname\tvalue
        let content = "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t2147483647\tSESSION\tabc123\nexample.com\tFALSE\t/\tFALSE\t2147483647\tTOKEN\txyz\n";
        f.write_all(content.as_bytes()).expect("write cookies");

        let header = load_cookie_header(&path).expect("load cookies");
        // Order preserved from file
        assert!(header.contains("SESSION=abc123"));
        assert!(header.contains("TOKEN=xyz"));

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_cookie_header_ignores_malformed_lines() {
        let mut path = std::env::temp_dir();
        path.push("tsun_test_cookies_malformed.txt");
        let mut f = std::fs::File::create(&path).expect("create cookie file");
        // One valid netscape line, one malformed
        let content = "# Netscape\n.example.com\tTRUE\t/\tFALSE\t2147483647\tSESSION\tabc123\nmalformed_line_without_tabs\n";
        f.write_all(content.as_bytes()).expect("write");

        let header = load_cookie_header(&path).expect("load cookies");
        assert!(header.contains("SESSION=abc123"));
        assert!(!header.contains("malformed_line_without_tabs"));

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_cookie_header_json_array() {
        let mut path = std::env::temp_dir();
        path.push("tsun_test_cookies_json.txt");
        let mut f = std::fs::File::create(&path).expect("create cookie file");
        let content = r#"[
            {"name":"SID","value":"s1"},
            {"name":"TOKEN","value":"t2"}
        ]"#;
        f.write_all(content.as_bytes()).expect("write");

        let header = load_cookie_header(&path).expect("load cookies");
        assert!(header.contains("SID=s1"));
        assert!(header.contains("TOKEN=t2"));

        // Clean up
        let _ = std::fs::remove_file(&path);
    }
}
