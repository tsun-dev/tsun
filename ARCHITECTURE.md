# Development Architecture

## Module Overview

### `main.rs`
Entry point for the CLI application using `clap` for command parsing. Handles three commands:
- `scan`: Execute security scans
- `init`: Generate configuration templates
- `status`: Check ZAP server connectivity

### `scanner.rs`
Core orchestration logic that:
- Initializes the ZAP client (real or mock)
- Starts and monitors scan progress
- Collects and returns scan results

### `zap.rs`
Abstraction layer providing both real and mock ZAP clients through an enum-based interface:

```rust
pub enum ZapClient {
    Real(RealZapClient),      // HTTP client to real ZAP server
    Mock(MockZapClient),       // In-memory mock for testing
}
```

Key methods:
- `new()`: Create real ZAP client
- `mock()`: Create mock ZAP client
- `start_scan()`: Initiate a security scan
- `wait_for_scan()`: Poll scan progress
- `get_alerts()`: Retrieve vulnerabilities

### `zap_mock.rs`
Mock implementation returning realistic test data:
- 6 different vulnerability types
- Varying severity levels (Critical, High, Medium, Low)
- Realistic alert structures matching ZAP API format

### `config.rs`
Configuration management:
- YAML file parsing
- Default configuration
- Template generation

### `report.rs`
Result reporting with:
- Alert severity aggregation
- Multiple export formats (JSON, YAML)
- Summary generation

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

### Unit Tests
Located in `lib.rs`:
- Config default values
- Config template generation
- Mock scan execution
- Severity counting

### Integration Tests
Full end-to-end with mock client:
```rust
let scanner = Scanner::new(target, config, true);
let report = scanner.run().await;
assert!(report.vulnerability_count() > 0);
```

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

Edit `generate_mock_alerts()` in `zap_mock.rs`:
```rust
Alert {
    pluginid: "99999".to_string(),
    alert: "My Vulnerability".to_string(),
    riskcode: "2".to_string(),  // Risk level
    // ... more fields
}
```

### Adding a Real ZAP API Call

1. Add method to `RealZapClient`:
```rust
pub async fn my_method(&self) -> Result<T> {
    let url = format!("{}/JSON/path/action/", self.base_url);
    self.client.get(&url).send().await?.json().await
}
```

2. Add wrapper to `ZapClient` enum:
```rust
pub async fn my_method(&self) -> Result<T> {
    match self {
        ZapClient::Real(c) => c.my_method().await,
        ZapClient::Mock(_) => Ok(/* mock result */),
    }
}
```

## Dependencies

- **clap**: CLI argument parsing
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
