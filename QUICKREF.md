# arete Quick Reference

## Installation (End Users)

**One-line install:**
```bash
curl -sSL https://raw.githubusercontent.com/cWashington91/arete/main/install.sh | bash
```

**Manual download:**
```bash
# Linux x86_64
curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-linux-x86_64.tar.gz | tar xz

# macOS (Intel)
curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-macos-x86_64.tar.gz | tar xz

# macOS (Apple Silicon)
curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-macos-aarch64.tar.gz | tar xz
```

## Common Commands

### Scans

```bash
# Quick test (no Docker needed)
arete scan --target http://testphp.vulnweb.com --engine mock

# CI scan (15min, Docker required)
arete scan --target https://staging.example.com --engine zap --profile ci

# Deep scan (2hr)
arete scan --target https://staging.example.com --engine zap --profile deep

# Custom parameters
arete scan --target URL --engine zap --timeout 1200 --max-urls 500 --attack-strength medium

# With auth headers
arete scan --target URL --engine zap --header "Authorization: Bearer TOKEN"

# With cookies
arete scan --target URL --engine zap --cookies cookies.txt

# SARIF for GitHub
arete scan --target URL --engine zap --format sarif --output report.sarif

# Exit on high/critical findings
arete scan --target URL --engine zap --exit-on-severity high

# Baseline comparison
arete scan --target URL --engine zap --baseline baseline.json
```

### Output Formats

```bash
--format json    # Default, machine-readable
--format html    # Beautiful styled report
--format yaml    # Human-readable structured
--format sarif   # GitHub Code Scanning
```

### Profiles

| Profile | Timeout | Max URLs | Attack | Threshold | Use Case |
|---------|---------|----------|--------|-----------|----------|
| `ci` | 15 min | 200 | Low | Medium | Fast CI/CD |
| `deep` | 2 hours | ∞ | Medium | Low | Thorough scans |

## GitHub Actions Example

```yaml
- name: Download arete
  run: curl -L https://github.com/cWashington91/arete/releases/latest/download/arete-linux-x86_64.tar.gz | tar xz

- name: Security scan
  run: |
    ./arete scan \
      --target https://staging.yourapp.com \
      --engine zap \
      --profile ci \
      --format sarif \
      --output report.sarif \
      --exit-on-severity high

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

## Development

```bash
# Build
cargo build --release

# Test
cargo test

# Run locally
cargo run -- scan --target URL --engine mock

# Format
cargo fmt

# Lint
cargo clippy

# Release
git tag v0.2.0 && git push origin v0.2.0
```

## Troubleshooting

**Port conflict:**
```bash
arete scan --target URL --engine zap --zap-port 8081
```

**Timeout:**
```bash
arete scan --target URL --engine zap --timeout 3600  # 1 hour
```

**Cleanup ZAP containers:**
```bash
docker rm -f $(docker ps -aq --filter ancestor=zaproxy/zap-stable)
```

**Verbose logging:**
```bash
arete scan --target URL --engine zap --verbose
```

## Architecture Overview

```
main.rs          → CLI parsing + orchestration
scanner.rs       → Scan runner (wires everything together)
zap.rs           → Real ZAP API client
zap_mock.rs      → Mock client for testing
zap_managed.rs   → Docker lifecycle management
config.rs        → YAML config + defaults
report.rs        → Report models + baseline comparison
html.rs          → HTML report generation
sarif.rs         → SARIF 2.1.0 export
auth.rs          → Header/cookie parsing
display.rs       → Terminal UI
validation.rs    → Input validation
```

## Links

- **Repo**: https://github.com/cWashington91/arete
- **Releases**: https://github.com/cWashington91/arete/releases
- **Issues**: https://github.com/cWashington91/arete/issues
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
