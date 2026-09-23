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

## What Tsun puts in the SARIF

| Field | Value |
|-------|-------|
| `ruleId` | `ZAP-<plugin id>`, e.g. `ZAP-40018` |
| `level` | `error` (critical/high), `warning` (medium), `note` (low), `none` (info) |
| `helpUri` | the ZAP alert page for that plugin |
| `properties.cwe` | `CWE-<n>` for recognized plugins |
| `properties.tags` | `security`, plus `external/cwe/cwe-<n>` when known |
| `properties.security-severity` | the estimated CVSS score, which drives GitHub's severity filter |
| `fingerprints["tsun/v1"]` | stable identity for the finding |

### Fingerprints and alert tracking

Each result carries a fingerprint computed from the plugin, the injection
point, and a normalized URL. GitHub uses it to recognize a finding across runs,
so an alert stays a single alert instead of closing and reopening whenever a
session id or row id in the URL changes. See
[baseline comparison](baseline-comparison.md#how-findings-are-matched) for how
normalization works.

### CWE tags

CWE mapping is a curated table covering the ZAP plugins teams see most often.
Unrecognized plugins carry no CWE tag — a wrong CWE is worse than none. The
table lives in `plugin_to_cwe` in `src/sarif.rs`; additions welcome.

### A note on severity

`security-severity` comes from Tsun's estimated CVSS score, derived from ZAP's
risk and confidence rather than assigned by a vendor. See
[configuration](configuration.md#cvss-scores).

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
