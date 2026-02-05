# arete

A security scanning tool powered by OWASP ZAP for continuous application security testing.

## Features

- **Docker-Managed ZAP**: Automatic ZAP container lifecycle — no manual setup required
- **Scan Profiles**: CI (15min) and Deep (2hr) profiles with tunable parameters
- **Real-Time Progress**: Plugin-level progress tracking with completion detection
- **Mock Mode**: Built-in test mode for development without ZAP server
- **Multiple Report Formats**: Export as **HTML**, **JSON**, **YAML**, or **SARIF**
- **Authentication Support**: Headers, cookies, and pre-scan login commands
- **Baseline Comparison**: Track vulnerability changes over time
- **Exit Code Gating**: Fail CI builds on high/critical findings
- **GitHub Integration**: SARIF upload for Code Scanning

## Installation

### Download Pre-built Binaries (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/cWashington91/arete/releases):

**Linux (x86_64):**
```bash
curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-linux-x86_64.tar.gz | tar xz
sudo mv arete /usr/local/bin/
arete --version
```

**macOS (Intel):**
```bash
curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-macos-x86_64.tar.gz | tar xz
sudo mv arete /usr/local/bin/
arete --version
```

**macOS (Apple Silicon):**
```bash
curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-macos-aarch64.tar.gz | tar xz
sudo mv arete /usr/local/bin/
arete --version
```

### Build from Source

Requires Rust 1.70+:

```bash
git clone https://github.com/cWashington91/arete.git
cd arete
cargo build --release
sudo cp target/release/arete /usr/local/bin/
```

## Quick Start

### Your First Scan (Mock Mode)

Test arete without ZAP server:

```bash
arete scan --target http://testphp.vulnweb.com --engine mock --format html --output report.html
```

### Real Scan with Docker-Managed ZAP

arete automatically starts and manages a ZAP Docker container:

```bash
# CI profile: fast 15-minute scan
arete scan --target http://testphp.vulnweb.com --engine zap --profile ci

# Deep profile: thorough 2-hour scan
arete scan --target http://testphp.vulnweb.com --engine zap --profile deep
```

**Requirements for `--engine zap`:**
- Docker installed and running
- Port 8080 available (or specify `--zap-port 8081`)

### Common Use Cases

```bash
# Generate HTML report
arete scan --target https://staging.example.com --engine zap --profile ci --format html --output security-report.html

# SARIF for GitHub Code Scanning
arete scan --target https://staging.example.com --engine zap --profile ci --format sarif --output report.sarif

# Exit with error if high/critical findings
arete scan --target https://staging.example.com --engine zap --profile ci --exit-on-severity high

# Custom scan parameters
arete scan --target https://staging.example.com --engine zap --timeout 600 --max-urls 100 --attack-strength medium

# With authentication headers
arete scan --target https://staging.example.com --engine zap --header "Authorization: Bearer TOKEN"

# With cookies file
arete scan --target https://staging.example.com --engine zap --cookies cookies.txt
```

## CI Integration (GitHub Actions)

Add security scanning to your pipeline in 2 minutes:

```yaml
name: Security Scan

on:
  pull_request:
  schedule:
    - cron: '0 2 * * 1'  # Weekly deep scan

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Download arete
        run: |
          curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-linux-x86_64.tar.gz | tar xz
          chmod +x arete
      
      - name: Run security scan
        run: |
          ./arete scan \
            --target https://staging.yourapp.com \
            --engine zap \
            --profile ci \
            --format sarif \
            --output report.sarif \
            --exit-on-severity high
      
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
      
      - name: Upload HTML report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.sarif
```

### GitLab CI Example

```yaml
security-scan:
  image: docker:24
  services:
    - docker:24-dind
  before_script:
    - apk add --no-cache curl
    - curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-linux-x86_64.tar.gz | tar xz
    - chmod +x arete
  script:
    - ./arete scan --target https://staging.yourapp.com --engine zap --profile ci --format json --output gl-security-report.json
  artifacts:
    reports:
      dependency_scanning: gl-security-report.json
    paths:
      - gl-security-report.json
    expire_in: 1 week
```

## Scan Profiles

| Profile | Timeout | Max URLs | Attack Strength | Alert Threshold | Use Case |
|---------|---------|----------|-----------------|-----------------|----------|
| `ci` (default) | 15 min | 200 | Low | Medium | Fast CI/CD pipeline scans |
| `deep` | 2 hours | Unlimited | Medium | Low | Comprehensive nightly/weekly scans |

**Override individual settings:**
```bash
arete scan --target URL --profile ci --timeout 1200 --max-urls 500 --attack-strength medium
```

## Usage

### Run a Scan

```bash
# Docker-managed ZAP (recommended)
arete scan --target https://example.com --engine zap --profile ci

# Mock mode (testing without ZAP)
arete scan --target https://example.com --engine mock

# With custom configuration file
arete scan --target https://example.com --engine zap --config arete.yaml

# Generate HTML report
arete scan --target https://example.com --engine zap --output report.html --format html

# Verbose logging
arete scan --target https://example.com --engine zap --verbose
```

### Authentication Examples

```bash
# Static headers
arete scan --target https://example.com --engine zap --header "Authorization: Bearer TOKEN"

# Multiple headers
arete scan --target https://example.com --engine zap --header "X-API-Key: key123,Authorization: Bearer TOKEN"

# Cookies from file (Netscape format or JSON)
arete scan --target https://example.com --engine zap --cookies cookies.txt

# Pre-scan login command (generates cookies)
arete scan --target https://example.com --engine zap --login-command "curl -c cookies.txt https://example.com/login -d 'user=admin&pass=secret'" --cookies cookies.txt
```

### Baseline Comparison

Track vulnerability changes over time:

```bash
# First scan - establish baseline
arete scan --target https://staging.example.com --engine zap --output baseline.json --format json

# Later scan - compare against baseline
arete scan --target https://staging.example.com --engine zap --baseline baseline.json --exit-on-severity high
```

The comparison report shows:
- New vulnerabilities introduced
- Fixed vulnerabilities
- Overall trend (improving/degrading/unchanged)

### Generate Configuration Template

```bash
arete init --config arete.yaml
```

### Check ZAP Server Status

```bash
# Check external ZAP server
arete status --host http://localhost:8080
```

## Configuration

Create an `arete.yaml` file to configure defaults:

```yaml
zap:
  host: http://localhost:8080
  api_key: null

policies:
  - default

# Timeout in seconds (default: 1800 = 30 minutes)
timeout: 1800
```

**Note:** When using `--engine zap`, arete manages ZAP automatically via Docker. The `host` in config is only used with external ZAP servers.

## Requirements

- **For `--engine zap`:** Docker installed and running
- **For building from source:** Rust 1.70+
- **For `--engine mock`:** No external dependencies

## Architecture

arete uses a modular architecture for flexibility and testability:

- **[src/main.rs](src/main.rs)**: CLI argument parsing and command orchestration
- **[src/scanner.rs](src/scanner.rs)**: Core scanning logic and ZAP client coordination
- **[src/zap.rs](src/zap.rs)**: Real ZAP API client (scan/progress/alerts)
- **[src/zap_mock.rs](src/zap_mock.rs)**: Mock ZAP client for testing without ZAP server
- **[src/zap_managed.rs](src/zap_managed.rs)**: Docker-managed ZAP lifecycle
- **[src/config.rs](src/config.rs)**: YAML configuration management
- **[src/report.rs](src/report.rs)**: Report models, severity filtering, baseline comparison
- **[src/html.rs](src/html.rs)**: HTML report generation with styling
- **[src/sarif.rs](src/sarif.rs)**: SARIF 2.1.0 export for GitHub Code Scanning
- **[src/auth.rs](src/auth.rs)**: Header and cookie parsing/loading
- **[src/display.rs](src/display.rs)**: Terminal UI (spinners, progress, colors)
- **[src/validation.rs](src/validation.rs)**: Input validation

## SARIF & GitHub Code Scanning

arete exports SARIF 2.1.0 reports compatible with GitHub Code Scanning:

**Generate SARIF:**
```bash
arete scan --target https://staging.example.com --engine zap --profile ci --format sarif --output report.sarif
```

**Upload to GitHub (via GitHub Actions):**
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

**Manual upload (requires GitHub token):**
```bash
arete upload-sarif \
  --file report.sarif \
  --repo owner/repo \
  --commit $GITHUB_SHA \
  --git-ref refs/heads/main \
  --token $GITHUB_TOKEN
```

Findings will appear in:
- **Security** tab → Code scanning alerts
- Pull request diffs (inline annotations)

## Troubleshooting

**"Port 8080 already in use"**
```bash
# Use different port
arete scan --target URL --engine zap --zap-port 8081
```

**"Permission denied" (Docker)**
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Then log out and back in
```

**Scan times out before completion**
```bash
# Increase timeout
arete scan --target URL --engine zap --timeout 3600  # 1 hour

# Or use deep profile (2 hours)
arete scan --target URL --engine zap --profile deep
```

**ZAP container not cleaned up**
```bash
# Manually remove ZAP containers
docker rm -f $(docker ps -aq --filter ancestor=zaproxy/zap-stable)
```

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
