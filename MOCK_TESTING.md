# Mock Testing Guide

## Overview

Tsun includes a comprehensive mock ZAP client for testing and development without requiring a running OWASP ZAP server.

## Usage

### Command Line

Run a mock scan using the `--mock` flag:

```bash
tsun scan --target https://example.com --mock
```

With verbose output:

```bash
tsun scan --target https://example.com --mock --verbose
```

Generate a report:

```bash
tsun scan --target https://example.com --mock --output report.json --format json
```

### What's Included in Mock Scans

The mock ZAP client generates realistic vulnerabilities for testing:

1. **Cookie without Secure Flag** (High)
   - Common security misconfiguration
   - Affects session management

2. **Re-CAPTCHA Detected** (Informational)
   - Bot protection detection
   - No security concern

3. **Header Injection** (High)
   - Potential HTTP header vulnerability
   - Parameter tampering

4. **X-Frame-Options Header Missing** (High)
   - Clickjacking vulnerability
   - Common web security issue

5. **Strict-Transport-Security Header Missing** (Medium)
   - Missing HSTS header
   - SSL/TLS vulnerability

6. **Server Leaks Version Information** (Medium)
   - Information disclosure
   - Server fingerprinting

## Testing Modes

### Development Testing

Perfect for testing the CLI and report generation:

```bash
tsun scan --target https://my-app.dev --mock --output test-report.json
```

### Continuous Integration

Use mock mode in CI/CD pipelines:

```bash
# GitHub Actions example
- name: Run security scan (mock)
  run: tsun scan --target ${{ env.TARGET_URL }} --mock --output results.json
```

### Integration Testing

The Rust test suite uses mock client automatically:

```bash
# Run unit and integration tests
cargo test

# Run specific test
cargo test test_mock_scan -- --nocapture
```

## Output Examples

### Terminal Output

```
Initializing security scan...
Using mock ZAP client (test mode)
Scanning target: https://example.com
Scan completed successfully

Vulnerabilities found: 6

Summary:
  Critical: 0
  High: 3
  Medium: 2
  Low: 0
```

### JSON Report

```json
{
  "target": "https://example.com",
  "timestamp": "2026-02-01T10:30:00+00:00",
  "alerts": [
    {
      "pluginid": "10010",
      "alert": "Cookie without Secure Flag",
      "riskcode": "2",
      "confidence": "2",
      "url": "https://example.com/login",
      "instances": [...]
    }
  ]
}
```

## Benefits

- **No External Dependencies**: Test without running ZAP
- **Fast Execution**: Mock scans complete in seconds
- **Consistent Results**: Same vulnerabilities every time
- **CI/CD Ready**: Works in automated pipelines
- **Development Friendly**: Rapid iteration and testing
