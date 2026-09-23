# tsun Quick Reference

## Installation (End Users)

**One-line install:**
```bash
curl -sSL https://raw.githubusercontent.com/tsun-dev/tsun/main/install.sh | bash
```

**Manual download:**
```bash
# Linux x86_64
curl -L https://github.com/tsun-dev/tsun/releases/latest/download/tsun-linux-x86_64.tar.gz | tar xz

# macOS (Intel)
curl -L https://github.com/tsun-dev/tsun/releases/latest/download/tsun-macos-x86_64.tar.gz | tar xz

# macOS (Apple Silicon)
curl -L https://github.com/tsun-dev/tsun/releases/latest/download/tsun-macos-aarch64.tar.gz | tar xz
```

## Common Commands

### Scans

```bash
# CI scan (15 min) — --engine zap is the default, Docker required
tsun scan --target https://staging.example.com --profile ci

# Deep scan (2hr)
tsun scan --target https://staging.example.com --profile deep

# Quick CLI test — FABRICATED findings, no Docker, no target contacted
tsun scan --target http://testphp.vulnweb.com --engine mock

# Custom parameters
tsun scan --target URL --timeout 1200 --max-urls 500 --attack-strength medium

# With auth headers (installed as ZAP replacer rules)
tsun scan --target URL --header "Authorization: Bearer TOKEN"

# With cookies
tsun scan --target URL --cookies cookies.txt

# SARIF for GitHub
tsun scan --target URL --format sarif --output report.sarif

# Exit on high/critical findings
tsun scan --target URL --exit-on-severity high

# Fail only on findings new since the baseline
tsun scan --target URL --baseline baseline.json --fail-on-new

# Suppress accepted findings
tsun scan --target URL --ignore plugin:10038 --ignore "url:*/static/*"

# Diagnose the local setup
tsun doctor
```

### Severity levels

| Level | From ZAP |
|-------|----------|
| `critical` | High risk + High/Confirmed confidence |
| `high` | High risk + Medium/Low confidence |
| `medium` | Medium risk |
| `low` | Low risk |
| `info` | Informational (excluded by `--min-severity low`) |

Names only — numeric codes are rejected as ambiguous.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, nothing met the gate |
| 1 | Findings met the `--exit-on-severity` / `--fail-on-new` gate, or the scan failed |
| 130 | Interrupted (Ctrl+C); ZAP containers cleaned up |

### Output Formats

```bash
--format json    # Default, machine-readable
--format html    # Styled report
--format yaml    # Human-readable structured
--format sarif   # GitHub Code Scanning (fingerprints + CWE tags)
```

### Profiles

| Profile | Timeout | Max URLs | Attack | Threshold | Use Case |
|---------|---------|----------|--------|-----------|----------|
| `ci` | 15 min | 200 | Low | Medium | Fast CI/CD |
| `deep` | 2 hours | ∞ | Medium | Low | Thorough scans |

## GitHub Actions Example

```yaml
- name: Download tsun
  run: curl -L https://github.com/tsun-dev/tsun/releases/latest/download/tsun-linux-x86_64.tar.gz | tar xz

- name: Security scan
  run: |
    ./tsun scan \
      --target https://staging.yourapp.com \
      --profile ci \
      --format sarif \
      --output report.sarif \
      --baseline baseline.json \
      --fail-on-new \
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

# Integration tests (CLI end-to-end, and a fake ZAP over HTTP)
cargo test --test cli
cargo test --test zap_client

# Format
cargo fmt

# Lint
cargo clippy

# Release
git tag v0.6.0 && git push origin v0.6.0
```

## Troubleshooting

**Port conflict:**
```bash
tsun scan --target URL --engine zap --zap-port 8081
```

**Timeout:**
```bash
tsun scan --target URL --engine zap --timeout 3600  # 1 hour
```

**Cleanup ZAP containers:**
```bash
docker rm -f $(docker ps -aq --filter ancestor=zaproxy/zap-stable)
```

**Verbose logging:**
```bash
tsun scan --target URL --verbose
```

**External ZAP needs an API key:**
```bash
tsun scan --target URL --zap-api-key "$ZAP_KEY"   # or TSUN_ZAP_API_KEY
```

## Architecture Overview

```
main.rs          → CLI parsing + orchestration + exit-code gating
scanner.rs       → Scan runner (wires everything together)
zap.rs           → Real ZAP API client (+ replacer auth, API key)
zap_mock.rs      → Mock engine — fabricated findings for testing
zap_managed.rs   → Docker lifecycle, loopback bind, per-run API key
config.rs        → YAML config + profile resolution
severity.rs      → Severity classification + CVSS estimation
fingerprint.rs   → URL normalization + stable finding identity
ignore.rs        → Suppression rules (config / file / CLI)
report.rs        → Report models + baseline comparison
html.rs          → HTML report generation
sarif.rs         → SARIF 2.1.0 export (fingerprints, CWE tags)
auth.rs          → Header/cookie parsing + config-file credentials
display.rs       → Terminal UI
validation.rs    → Input validation
```

## Links

- **Repo**: https://github.com/tsun-dev/tsun
- **Releases**: https://github.com/tsun-dev/tsun/releases
- **Issues**: https://github.com/tsun-dev/tsun/issues
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
