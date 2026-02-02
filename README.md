# arete

A security scanning tool powered by OWASP ZAP. Designed as a StackHawk competitor for continuous security scanning.

## Features

- **OWASP ZAP Integration**: Leverages OWASP ZAP for comprehensive security scanning
- **Mock Mode**: Built-in test mode for development and CI/CD without a ZAP server
- **CLI Tool**: Easy-to-use command-line interface for running security scans
- **Flexible Configuration**: YAML-based configuration for customizing scan policies
- **Multiple Report Formats**: Export results in JSON, YAML, or HTML
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

# With custom output
arete scan --target https://example.com --output results.json --format json

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