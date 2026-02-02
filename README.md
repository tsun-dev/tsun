# arete

A security scanning tool powered by OWASP ZAP. Designed as a StackHawk competitor for continuous security scanning.

## Features

- **OWASP ZAP Integration**: Leverages OWASP ZAP for comprehensive security scanning
- **Mock Mode**: Built-in test mode for development and CI/CD without a ZAP server
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