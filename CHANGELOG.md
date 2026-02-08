# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-07

### Changed
- **Internal refactoring**: Improved code maintainability and cross-platform support
  - Replaced 20-parameter function with `ScanOptions` struct
  - Extracted profile resolution into testable `resolve_profile()` function
  - Decomposed monolithic scan orchestration into 5 focused phase functions
  - Replaced concrete `ZapClient` enum with extensible `ScanEngine` trait
  - Added platform-aware shell command execution for Windows compatibility

## [0.2.0] - 2026-02-04

### Added
- **Scan profiles**: CI (15min) and Deep (2hr) profiles with recommended defaults
- **Docker-managed ZAP**: Automatic ZAP container lifecycle via `--engine zap`
- **Configurable scan parameters**: `--timeout`, `--max-urls`, `--attack-strength`, `--alert-threshold`
- **Real-time progress**: Plugin-level progress with overall percentage and heartbeat output
- **Authentication support**: `--header`, `--cookies`, and `--login-command` flags
- **Baseline comparison**: Track vulnerability changes with `--baseline` flag
- **SARIF output**: GitHub Code Scanning integration via SARIF 2.1.0 format
- **Exit code gating**: `--exit-on-severity` to fail builds on high/critical findings
- **Mock engine**: Fast testing mode without ZAP server via `--engine mock`
- GitHub Actions release workflow (binaries for linux/mac x86_64 and aarch64)
- Installation script for one-command setup
- CI workflow for automated testing

### Changed
- Default timeout increased from 300s to 1800s (30 minutes)
- Progress calculation uses overall plugin percentage instead of completed count only
- Scan completion requires all plugins finished (not just "0 active")
- Progress output uses stdout (not stderr) to avoid spinner conflicts
- ZAP alert parsing hardened to handle schema variations (`pluginId` vs `pluginid`, `risk` vs `riskcode`)

### Fixed
- Progress reporting no longer gets overwritten by spinner
- Scan parameters now properly passed to ZAP API (`maxChildren`, `attackStrength`, `alertThreshold`)
- Early scan termination bug fixed (now waits for pending plugins)
- Alert parsing handles both numeric and string risk codes

## [0.1.0] - 2026-01-15

### Added
- Initial CLI implementation
- Commands: `scan`, `init`, `status`, `upload-sarif`
- Multiple report formats: JSON, HTML, YAML
- YAML-based configuration
- Severity filtering
- Mock mode for development
