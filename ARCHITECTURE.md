# Development Architecture

## Module Overview

### `main.rs`
Entry point for the CLI application using `clap` for command parsing. Commands:
- `scan`: Execute security scans
- `init`: Generate configuration templates
- `status`: Check ZAP server connectivity
- `doctor`: Diagnose the local setup
- `upload-sarif`: Push a SARIF report to GitHub Code Scanning

Also owns exit-code gating (`determine_exit_code`), which decides whether a
build fails on all findings (`--exit-on-severity`) or only on ones new since a
baseline (`--fail-on-new`).

### `scanner.rs`
Core orchestration logic that:
- Initializes the ZAP client (real or mock)
- Starts and monitors scan progress
- Collects and returns scan results

### `zap.rs`
The real ZAP HTTP client. Engines are selected through the `ScanEngine` trait,
so `Scanner` holds an `Arc<dyn ScanEngine>` and neither knows nor cares which
implementation it has:

```rust
#[async_trait]
pub trait ScanEngine: Send + Sync + Debug {
    async fn check_health(&self) -> Result<()>;
    async fn start_scan(&self, target: &str, max_urls: Option<u32>,
                        attack_strength: Option<&str>,
                        alert_threshold: Option<&str>) -> Result<String>;
    async fn wait_for_scan(&self, scan_id: &str, timeout_secs: u64) -> Result<()>;
    async fn get_alerts(&self, target: &str) -> Result<Vec<Alert>>;
}
```

Two responsibilities worth knowing about:

- **`install_auth_rules()`** installs `--header`/`--cookies` credentials as ZAP
  *Replacer* rules before scanning. This is what makes them reach the target:
  setting them on our own HTTP client would only authenticate us to ZAP's API.
- **`api_get` / `api_get_raw`** are the single path for every ZAP call, so the
  API key is attached consistently and a 401/403 turns into an actionable
  error rather than a bare status code.

### `severity.rs`
Classification and CVSS estimation. ZAP has no "Critical" level, so a High-risk
finding with High/Confirmed confidence is promoted; Informational stays its own
level instead of collapsing into Low. Also the only place CVSS scores come
from — ZAP emits none, so they are estimates and flagged as such.

Three different numeric risk scales exist in this codebase (ZAP's wire format,
Tsun's legacy `riskcode`, and this enum). The module documents which function
reads which; user-facing severity input accepts names only.

### `fingerprint.rs`
Stable identity for findings across scans. Normalizes URLs into templates —
numeric ids, UUIDs, and content hashes become `{id}`, query values are dropped
while names are kept — then hashes that with the plugin and injection point.
Used by baseline comparison and SARIF fingerprints.

### `ignore.rs`
Suppression rules from config, `--ignore-file`, or `--ignore`. A rule matches
when every field it specifies matches. Suppressed findings move to
`ScanReport::suppressed` rather than being discarded.

### `zap_mock.rs`
Mock engine returning fabricated findings. Six entries spanning every severity
including Critical and Info, so gating and filtering are exercised end to end.
Reports are stamped `engine: "mock"` and every output path says the findings
are fake.

### `config.rs`
Configuration management:
- YAML file parsing (including `auth:` and `ignore:` blocks)
- Default configuration and template generation
- `resolve_profile()` — merges profile defaults with CLI overrides

### `report.rs`
Report models and baseline comparison:
- `Alert::from_zap()` — the single construction point, so the real and mock
  engines cannot drift apart in how they classify findings
- Severity aggregation, filtering, and suppression
- `ReportComparison` — fingerprint-based new/fixed/unchanged diffing
- Export to JSON, YAML, HTML, SARIF

`Alert::severity` is an `Option`, so reports written before the field existed
still load and fall back to the legacy `riskcode`.

### `lib.rs`
Library interface exposing public modules for:
- Unit testing
- Integration testing
- External crate consumption

## Mock vs Real Flow

### Real ZAP Flow
```
CLI args
  ↓
Scanner::new(target, config, use_mock=false)
  ↓
ZapClient::new(&config.zap.host)
  ↓
RealZapClient { client, base_url }
  ↓
HTTP calls to ZAP REST API
  ↓
Parse JSON responses
  ↓
Return Alert structures
```

### Mock Flow
```
CLI args
  ↓
Scanner::new(target, config, use_mock=true)
  ↓
ZapClient::mock()
  ↓
MockZapClient
  ↓
Generate fake alerts
  ↓
Return Alert structures
```

## Testing Strategy

### Unit tests
Alongside the code they cover, in each module.

### `tests/zap_client.rs`
HTTP-level tests against a fake ZAP (wiremock). Covers what the mock engine
cannot: URL building, API-key propagation, replacer rule installation, health
checking, and alert parsing across ZAP schema variations.

### `tests/cli.rs`
Runs the real binary with the mock engine (assert_cmd). Covers argument
parsing, validation, suppression, report contents, and exit codes — no Docker
or network needed.

### `scripts/qa_smoke.sh`
Binary-level smoke tests, with real-ZAP checks behind `TSUN_RUN_ZAP=1`.

### Manual Testing
```bash
# Quick mock scan
cargo run -- scan --target https://example.com --mock

# With JSON output
cargo run -- scan --target https://example.com --mock --output test.json

# Verbose debugging
RUST_LOG=debug cargo run -- scan --target https://example.com --mock --verbose
```

## Adding New Features

### Adding a New Scan Option

1. Update `Scan` command in `main.rs`:
```rust
#[arg(short, long)]
my_option: bool,
```

2. Pass to `run_scan()`:
```rust
fn run_scan(..., my_option: bool) -> anyhow::Result<()>
```

3. Pass to Scanner:
```rust
scanner.set_option(my_option);
```

4. Implement in `scanner.rs`:
```rust
pub fn set_option(&mut self, option: bool) {
    // Handle option
}
```

### Adding New Mock Vulnerabilities

Add a `MockFinding` to `generate_mock_alerts()` in `zap_mock.rs`. Give it ZAP's
wire values — risk and confidence as words — and let `Alert::from_zap` derive
severity and CVSS, so the mock stays consistent with the real engine:

```rust
MockFinding {
    plugin_id: "99999",
    name: "My Vulnerability",
    risk: "High",
    confidence: "Medium",
    // ... more fields
}
```

### Adding a Real ZAP API Call

Go through `api_get` (or `api_get_raw` when you need the status), never
`self.client` directly — that is what attaches the API key and produces
consistent errors:

```rust
async fn my_method(&self) -> Result<T> {
    let body = self
        .api_get("/JSON/path/view/thing/", &[("param", value.to_string())])
        .await?;
    Ok(serde_json::from_str(&body)?)
}
```

If the call belongs on the engine interface, add it to the `ScanEngine` trait
and implement it for `MockZapClient` too.

## Dependencies

- **clap**: CLI argument parsing
- **maud**: HTML report templating
- **wiremock / assert_cmd**: integration testing (dev)
- **tokio**: Async runtime
- **reqwest**: HTTP client
- **serde/serde_yaml**: Serialization
- **tracing**: Logging framework
- **colored**: Terminal colors
- **anyhow**: Error handling

## Error Handling

Uses `anyhow::Result<T>` throughout for:
- Clean error propagation with `?`
- Detailed error context
- Easy debugging with `.context()`

```rust
pub async fn operation() -> anyhow::Result<()> {
    zap_client.check_health().await
        .context("Failed to connect to ZAP")?;
    Ok(())
}
```
