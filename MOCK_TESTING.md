# Mock Testing Guide

## Overview

Tsun ships a mock scan engine for exercising the CLI, report formats, and CI
wiring without Docker, a network, or a target.

**The mock engine fabricates findings.** It never contacts the target. Reports
it produces are stamped `"engine": "mock"`, the terminal prints an unmissable
banner, and HTML reports carry a warning — so mock output cannot be mistaken
for a real scan.

## Usage

```bash
tsun scan --target https://example.com --engine mock
```

With verbose output:

```bash
tsun scan --target https://example.com --engine mock --verbose
```

Generate a report:

```bash
tsun scan --target https://example.com --engine mock --output report.json --format json
```

Auth flags (`--header`, `--cookies`, `--login-command`) are accepted but
ignored, since nothing is sent anywhere. Tsun warns when you pass them.

## What the fixture contains

Six findings spanning every severity Tsun can produce, so filtering, gating,
and suppression are all exercised:

| Plugin | Finding | ZAP risk / confidence | Tsun severity |
|--------|---------|----------------------|---------------|
| 40018 | SQL Injection | High / Confirmed | **Critical** |
| 40012 | Cross Site Scripting (Reflected) | High / Medium | **High** |
| 10010 | Cookie Without Secure Flag | Medium / High | **Medium** |
| 10038 | Content Security Policy Header Not Set | Medium / Medium | **Medium** |
| 10021 | X-Content-Type-Options Header Missing | Low / Medium | **Low** |
| 10015 | Server Leaks Version Information | Informational / High | **Info** |

The Critical entry exists specifically so `--exit-on-severity critical` has
something to fire on; the Informational entry so `--min-severity low` has
something to exclude.

The fixture is defined in `generate_mock_alerts` in `src/zap_mock.rs`.

## Testing modes

### Development

```bash
cargo run -- scan --target https://my-app.dev --engine mock --output test-report.json
```

### CI smoke tests

The mock engine is deterministic and completes in under a second, which makes
it suitable for testing your pipeline's wiring:

```yaml
- name: Verify scan wiring
  run: tsun scan --target https://example.com --engine mock --output results.json
```

Do not use it as a stand-in for a security scan — it tells you nothing about
the target.

### Test suite

```bash
# Everything
cargo test

# CLI end-to-end (uses the mock engine)
cargo test --test cli

# ZAP client against a fake ZAP over HTTP
cargo test --test zap_client

# One test, with output
cargo test test_mock_scan -- --nocapture
```

`tests/zap_client.rs` stands up an HTTP server speaking ZAP's API, so the real
client's URL building, API-key handling, replacer installation, and alert
parsing are covered without Docker.

## Output examples

### Terminal

```
──────────────────────────────────────────────────────────
  ⚠  MOCK ENGINE — THESE FINDINGS ARE FAKE
     No scan was performed against the target.
     Use --engine zap for a real scan.
──────────────────────────────────────────────────────────

Vulnerability Summary
  Total Issues: 6
  Critical: 1
  High: 1
  Medium: 2
  Low: 1
  Info: 1
```

### JSON report

```json
{
  "target": "https://example.com",
  "timestamp": "2026-02-01T10:30:00+00:00",
  "engine": "mock",
  "alerts": [
    {
      "pluginid": "40018",
      "alert": "SQL Injection",
      "severity": "critical",
      "riskcode": "3",
      "riskdesc": "High",
      "confidence": "Confirmed",
      "cvss_score": 9.0,
      "cvss_estimated": true,
      "url": "https://example.com/search",
      "instances": [...]
    }
  ]
}
```

## Benefits

- **No external dependencies** — no Docker, no network, no target
- **Fast** — completes in under a second
- **Deterministic** — same findings every run, so baseline diffs are empty
- **Honest** — every output path labels itself as fabricated
