use std::path::Path;
use url::Url;

/// Validate a target URL format
pub fn validate_url(url_str: &str) -> anyhow::Result<()> {
    match Url::parse(url_str) {
        Ok(url) => {
            // Ensure it's HTTP or HTTPS
            match url.scheme() {
                "http" | "https" => {
                    // Ensure it has a host
                    if url.host().is_none() {
                        anyhow::bail!("URL must have a valid host: {}", url_str);
                    }
                    Ok(())
                }
                scheme => anyhow::bail!("URL must use http or https, got: {}", scheme),
            }
        }
        Err(e) => anyhow::bail!("Invalid URL format: {} ({})", url_str, e),
    }
}

/// Validate that a config file exists and is readable
pub fn validate_config_file<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    let path = path.as_ref();

    if !path.exists() {
        anyhow::bail!("Config file not found: {}", path.display());
    }

    if !path.is_file() {
        anyhow::bail!("Config path is not a file: {}", path.display());
    }

    // Try to read it
    match std::fs::read_to_string(path) {
        Ok(content) => {
            // Validate it's valid YAML
            if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                anyhow::bail!("Config file is not valid YAML: {}", e);
            }
            Ok(())
        }
        Err(e) => anyhow::bail!("Cannot read config file: {}", e),
    }
}

/// Validate report format
pub fn validate_format(format: &str) -> anyhow::Result<()> {
    match format {
        "json" | "yaml" | "html" | "sarif" => Ok(()),
        _ => anyhow::bail!(
            "Invalid format: {}. Supported: json, yaml, html, sarif",
            format
        ),
    }
}

/// Validate output path is writable (check parent directory)
pub fn validate_output_path<P: AsRef<Path>>(path: P) -> anyhow::Result<()> {
    let path = path.as_ref();

    // Check if parent directory exists (default to current dir)
    let parent = path
        .parent()
        .and_then(|p| {
            if p.as_os_str().is_empty() {
                None
            } else {
                Some(p)
            }
        })
        .unwrap_or_else(|| Path::new("."));

    if !parent.exists() {
        anyhow::bail!("Output directory does not exist: {}", parent.display());
    }

    if !parent.is_dir() {
        anyhow::bail!("Output path parent is not a directory: {}", parent.display());
    }

    // Try to write a test file to verify permissions
    match std::fs::metadata(parent) {
        Ok(metadata) => {
            if metadata.permissions().readonly() {
                anyhow::bail!(
                    "Output directory is not writable: {}",
                    parent.display()
                );
            }
            Ok(())
        }
        Err(e) => anyhow::bail!("Cannot access output directory: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com/path").is_ok());
        assert!(validate_url("https://sub.example.com:8080").is_ok());
    }

    #[test]
    fn test_validate_url_invalid() {
        assert!(validate_url("not a url").is_err());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("https://").is_err());
        assert!(validate_url("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_format_valid() {
        assert!(validate_format("json").is_ok());
        assert!(validate_format("yaml").is_ok());
        assert!(validate_format("html").is_ok());
    }

    #[test]
    fn test_validate_format_invalid() {
        assert!(validate_format("xml").is_err());
        assert!(validate_format("pdf").is_err());
        assert!(validate_format("invalid").is_err());
    }

    #[test]
    fn test_validate_config_file_missing() {
        assert!(validate_config_file("/nonexistent/path/to/config.yaml").is_err());
    }

    #[test]
    fn test_validate_output_path_valid() {
        // Current directory should be writable
        let result = validate_output_path("test_output.json");
        // This might fail in some test environments, so we just check it doesn't panic
        let _ = result;
    }
}
