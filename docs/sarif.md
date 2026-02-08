# SARIF & GitHub Code Scanning

Tsun exports SARIF 2.1.0 reports compatible with GitHub Code Scanning.

## Generate SARIF

```bash
tsun scan --target https://staging.example.com --engine zap --profile ci --format sarif --output report.sarif
```

## Upload to GitHub (via GitHub Actions)

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

## Manual Upload

Requires GitHub token:

```bash
tsun upload-sarif \
  --file report.sarif \
  --repo owner/repo \
  --commit $GITHUB_SHA \
  --git-ref refs/heads/main \
  --token $GITHUB_TOKEN
```

## Where Findings Appear

- **Security** tab → Code scanning alerts
- Pull request diffs (inline annotations)

## Complete GitHub Actions Example

```yaml
name: Security Scan

on:
  pull_request:
  push:
    branches: [main]

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
            --output report.sarif
      
      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
```
