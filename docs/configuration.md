# Configuration

## Configuration file

Generate a template:

```bash
tsun init --config tsun.yaml
```

Then pass it with `--config`:

```bash
tsun scan --target https://example.com --config tsun.yaml
```

```yaml
zap:
  host: http://localhost:8080
  api_key: null

policies:
  - default

# Credentials injected into requests ZAP sends to the target.
# See docs/authentication.md
auth:
  method: bearer
  credentials:
    token: eyJhbGciOiJIUzI1NiIs...

# Findings to suppress. See "Ignore rules" below.
ignore:
  - plugin: "10038"
    reason: CSP is set at the CDN

# Timeout in seconds (default: 1800 = 30 minutes)
timeout: 1800
```

**Note:** with the default `--engine zap`, Tsun manages ZAP via Docker and
`zap.host` is ignored. `host` applies only when you point Tsun at an external
ZAP server.

## Severity levels

Tsun uses five levels. ZAP itself has four — it has no "Critical" — so Tsun
promotes a High-risk finding to Critical when ZAP rates its confidence High or
Confirmed.

| Tsun | From ZAP |
|------|----------|
| `critical` | High risk, High/Confirmed confidence |
| `high` | High risk, Medium/Low confidence |
| `medium` | Medium risk |
| `low` | Low risk |
| `info` | Informational |

Informational findings are their own level rather than being folded into Low,
so `--min-severity low` excludes them.

Severity flags take names only (`critical`, `high`, `medium`, `low`, `info`).
Numeric codes are rejected: ZAP's wire format and Tsun's legacy `riskcode`
number their levels differently, so a bare `2` would be ambiguous.

### CVSS scores

ZAP does not emit CVSS scores. Tsun derives an estimate from risk and
confidence so that scores sort consistently and baseline trends mean something.
Every estimated score is flagged `cvss_estimated: true` in the report — treat
them as ordering hints, not vendor-assigned scores.

## Ignore rules

Suppress findings you have reviewed and accepted. Suppressed findings stay in
the report under `suppressed` and are excluded from counts and exit-code
gating — they are never silently discarded.

### In the config file

```yaml
ignore:
  - plugin: "10038"
    reason: CSP is set at the CDN
  - alert: "Cookie*"
    url: "*/legacy/*"
    reason: legacy app, scheduled for removal 2026-Q3
  - url: "*/static/*"
    reason: static assets are served by a third party
```

### In a separate file

```bash
tsun scan --target https://example.com --ignore-file .tsun-ignore.yaml
```

The file may be a bare list or wrapped in `ignore:`, so the same file works
either way.

### On the command line

```bash
tsun scan --target https://example.com \
  --ignore plugin:10038 \
  --ignore "url:*/static/*"
```

Clauses can be combined with commas:

```bash
--ignore "plugin:10038,url:*/legacy/*,reason:accepted"
```

### Matching

| Field | Match |
|-------|-------|
| `plugin` | exact ZAP plugin id |
| `alert` | alert name, `*` wildcards, case-insensitive |
| `url` | URL, `*` wildcards, case-insensitive |
| `reason` | not matched — documentation for reviewers |

A rule matches only when **every** field it specifies matches, so
`plugin` + `url` is narrower than either alone. A rule specifying none of
`plugin`, `alert`, or `url` is rejected, since it would hide everything.

Rules from the config file, `--ignore-file`, and `--ignore` are all applied.

## Usage

```bash
# Docker-managed ZAP (default)
tsun scan --target https://example.com --profile ci

# Mock mode — fabricated findings, no Docker, no network
tsun scan --target https://example.com --engine mock

# HTML report
tsun scan --target https://example.com --format html --output report.html

# Verbose logging
tsun scan --target https://example.com --verbose
```

### Check an external ZAP server

```bash
tsun status --host http://localhost:8080
```

### Diagnose your setup

```bash
tsun doctor
```

## ZAP API key

Tsun's managed container generates a per-run API key and binds ZAP's API to
loopback, so nothing else on the machine or network can drive it.

For an **external** ZAP, supply its key:

```bash
tsun scan --target https://example.com --zap-api-key "$ZAP_KEY"

# or via environment
export TSUN_ZAP_API_KEY=...

# or in tsun.yaml
zap:
  api_key: ...
```

Precedence: `--zap-api-key` > `TSUN_ZAP_API_KEY` > config file.

## Requirements

- **Default (`--engine zap`):** Docker installed and running
- **`--engine mock`:** no external dependencies
- **Building from source:** Rust 1.70+

## Build from source

```bash
git clone https://github.com/tsun-dev/tsun.git
cd tsun
cargo build --release
sudo cp target/release/tsun /usr/local/bin/
```
