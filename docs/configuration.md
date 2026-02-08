# Configuration

## Configuration File

Create a `tsun.yaml` file to configure defaults:

```yaml
zap:
  host: http://localhost:8080
  api_key: null

policies:
  - default

# Timeout in seconds (default: 1800 = 30 minutes)
timeout: 1800
```

**Note:** When using `--engine zap`, tsun manages ZAP automatically via Docker. The `host` in config is only used with external ZAP servers.

## Generate Configuration Template

```bash
tsun init --config tsun.yaml
```

## Usage

### Run a Scan

```bash
# Docker-managed ZAP (recommended)
tsun scan --target https://example.com --engine zap --profile ci

# Mock mode (testing without ZAP)
tsun scan --target https://example.com --engine mock

# With custom configuration file
tsun scan --target https://example.com --engine zap --config tsun.yaml

# Generate HTML report
tsun scan --target https://example.com --engine zap --output report.html --format html

# Verbose logging
tsun scan --target https://example.com --engine zap --verbose
```

### Check ZAP Server Status

```bash
# Check external ZAP server
tsun status --host http://localhost:8080
```

## Requirements

- **For `--engine zap`:** Docker installed and running
- **For building from source:** Rust 1.70+
- **For `--engine mock`:** No external dependencies

## Build from Source

Requires Rust 1.70+:

```bash
git clone https://github.com/tsun-dev/tsun.git
cd tsun
cargo build --release
sudo cp target/release/tsun /usr/local/bin/
```

## Mock Mode

Test tsun without ZAP server:

```bash
tsun scan --target http://testphp.vulnweb.com --engine mock --format html --output report.html
```

Mock mode is useful for:
- Testing tsun without Docker
- Development and CI testing
- Understanding output formats
