# Contributing

Contributions welcome! Please follow these guidelines:

## Getting Started

1. Fork the repository
2. Create a feature branch
3. **Run the git hook setup script:**
   ```bash
   ./scripts/setup-git-hooks.sh
   ```

## Development Workflow

Make your changes following these quality checks:

```bash
# Format code
cargo fmt

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test --lib
```

## Submitting Changes

1. Add tests for new functionality
2. Ensure all quality checks pass
3. Submit a pull request

The pre-push hook will automatically run these checks before each push.

## Architecture

See [ARCHITECTURE.md](../ARCHITECTURE.md) for design details.

## Code Structure

Tsun uses a modular architecture for flexibility and testability:

- **[src/main.rs](../src/main.rs)**: CLI argument parsing and command orchestration
- **[src/scanner.rs](../src/scanner.rs)**: Core scanning logic and ZAP client coordination
- **[src/zap.rs](../src/zap.rs)**: Real ZAP API client (scan/progress/alerts)
- **[src/zap_mock.rs](../src/zap_mock.rs)**: Mock ZAP client for testing without ZAP server
- **[src/zap_managed.rs](../src/zap_managed.rs)**: Docker-managed ZAP lifecycle
- **[src/config.rs](../src/config.rs)**: YAML configuration management
- **[src/report.rs](../src/report.rs)**: Report models, severity filtering, baseline comparison
- **[src/html.rs](../src/html.rs)**: HTML report generation with styling
- **[src/sarif.rs](../src/sarif.rs)**: SARIF 2.1.0 export for GitHub Code Scanning
- **[src/auth.rs](../src/auth.rs)**: Header and cookie parsing/loading
- **[src/display.rs](../src/display.rs)**: Terminal UI (spinners, progress, colors)
- **[src/validation.rs](../src/validation.rs)**: Input validation
