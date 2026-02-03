# arete

A security scanning tool powered by OWASP ZAP for continuous application security testing.

## Features

- **OWASP ZAP Integration**: Leverages OWASP ZAP for comprehensive security scanning
- **Mock Mode**: Built-in test mode for development and CI/CD without a ZAP server
- **Severity Filtering**: Reduce noise with `--min-severity` (critical, high, medium, low)
- **Multiple Report Formats**: Export results as **HTML** (with beautiful styling), **JSON**, or **YAML**
- **CLI Tool**: Easy-to-use command-line interface for running security scans
- **Flexible Configuration**: YAML-based configuration for customizing scan policies
- **Authentication Support**: Built-in support for various authentication methods
- **Timeout Management**: Configurable scan timeouts with progress monitoring

## Building

```bash
cargo build --release
```

## Usage

### Run a Scan

```bash
# Basic scan (requires ZAP server running)
arete scan --target https://example.com

# Mock scan (no ZAP server needed - perfect for testing)
arete scan --target https://example.com --mock

# Filter by minimum severity level
arete scan --target https://example.com --mock --min-severity high

# With custom configuration
arete scan --target https://example.com --config arete.yaml

# Generate HTML report
arete scan --target https://example.com --mock --output report.html --format html

# Generate JSON report
arete scan --target https://example.com --mock --output report.json --format json

# Generate YAML report
arete scan --target https://example.com --mock --output report.yaml --format yaml

# Verbose mode
arete scan --target https://example.com --verbose
```

### Generate Configuration Template

```bash
arete init --config arete.yaml
```

### Check ZAP Server Status

```bash
arete status --host http://localhost:8080
```

## Configuration

Create an `arete.yaml` file to configure your scans:

```yaml
zap:
  host: http://localhost:8080
  api_key: null

policies:
  - default

timeout: 300
```

## Requirements

- OWASP ZAP server running and accessible
- Rust 1.70+ (for building)

## Architecture

- **main.rs**: CLI entry point and command handling
- **scanner.rs**: Core scanning orchestration
- **zap.rs**: OWASP ZAP API client
- **config.rs**: Configuration management
- **report.rs**: Scan result reporting and formatting

## SARIF & CI Integration

arete can export SARIF reports and upload them to GitHub Code Scanning. This enables findings to appear in the Security tab and inline on PRs.

Usage examples:

Generate a SARIF report:

```bash
arete scan --target https://example.com --mock --format sarif --output report.sarif
```

Upload SARIF to GitHub (requires `GITHUB_TOKEN` or `--token`):

```bash
# using environment variable
arete upload-sarif --file report.sarif --repo owner/repo --commit <COMMIT_SHA> --git-ref refs/heads/main

# or passing a token directly
arete upload-sarif --file report.sarif --repo owner/repo --commit <COMMIT_SHA> --git-ref refs/heads/main --token $GITHUB_TOKEN
```

GitHub Actions example (upload SARIF as a post-job step):

```yaml
name: arete-scan
on: [pull_request]

jobs:
  arete:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run arete scan
        run: |
          cargo run -- scan --target https://example.com --mock --format sarif --output report.sarif
      - name: Upload SARIF to GitHub
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          cargo run -- upload-sarif --file report.sarif --repo ${{ github.repository }} --commit ${{ github.sha }} --git-ref ${{ github.ref }}
```

Notes:

- SARIF files and baseline files are typically generated artifacts and should be ignored in the repository. `.gitignore` already includes `*.sarif` and `baseline.json`.
- The `upload-sarif` helper posts to the GitHub Code Scanning SARIF endpoint and requires repository access.
