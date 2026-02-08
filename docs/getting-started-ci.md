# Getting Started with CI Integration

## GitHub Actions

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
      
      - name: Download tsun
        run: |
          curl -L https://github.com/tsun-dev/tsun/releases/latest/download/tsun-linux-x86_64.tar.gz | tar xz
          chmod +x tsun
      
      - name: Run security scan
        run: |
          ./tsun scan \
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

## GitLab CI

```yaml
security-scan:
  image: docker:24
  services:
    - docker:24-dind
  before_script:
    - apk add --no-cache curl
    - curl -L https://github.com/tsun-dev/tsun/releases/latest/download/tsun-linux-x86_64.tar.gz | tar xz
    - chmod +x tsun
  script:
    - ./tsun scan --target https://staging.yourapp.com --engine zap --profile ci --format json --output gl-security-report.json
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

### Override individual settings

```bash
tsun scan --target URL --profile ci --timeout 1200 --max-urls 500 --attack-strength medium
```

## Common Use Cases

```bash
# Generate HTML report
tsun scan --target https://staging.example.com --engine zap --profile ci --format html --output security-report.html

# SARIF for GitHub Code Scanning
tsun scan --target https://staging.example.com --engine zap --profile ci --format sarif --output report.sarif

# Exit with error if high/critical findings
tsun scan --target https://staging.example.com --engine zap --profile ci --exit-on-severity high

# Custom scan parameters
tsun scan --target https://staging.example.com --engine zap --timeout 600 --max-urls 100 --attack-strength medium
```
