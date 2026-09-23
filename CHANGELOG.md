# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-09-22

Correctness and hardening release. Several long-standing defects meant Tsun
reported less than it appeared to; the fixes below change behavior, so read
"Changed" and "Breaking" before upgrading in CI.

### Fixed
- **Authenticated scanning actually authenticates.** `--header` and `--cookies`
  were applied to the HTTP client that talks to ZAP's *own API*, so they never
  reached the scanned application — every "authenticated" scan ran anonymously.
  Credentials are now installed as ZAP Replacer rules before scanning, so they
  ride on every request ZAP sends to the target. A ZAP build without the
  Replacer add-on now fails loudly instead of scanning anonymously.
- **`--exit-on-severity critical` can fire.** ZAP emits no Critical risk, and
  nothing in the pipeline ever produced one, so the gate was unreachable.
- **CVSS scores are no longer always 0.0** for real scans, which had also made
  the baseline `is_improvement` calculation structurally meaningless.
- **Baseline comparison no longer re-flags unchanged findings.** Matching was
  keyed on the exact URL, so any session id, row id, or cache-buster made a
  known finding look new on every run.
- **`tsun status` no longer reports any responding socket as healthy** — it
  ignored the HTTP status entirely and never checked the response was ZAP.
- **`--version` reports the right version.** `Cargo.toml` said 0.2.0 while the
  project was at 0.5.0.
- HTML reports labelled every finding's confidence "Low", having matched only
  ZAP's numeric confidence values while the API returns words.
- Alert parsing no longer fails the whole scan when ZAP omits `alertRef`,
  `pluginId`, or other optional fields.

### Added
- **`--fail-on-new`**: gate the build on findings new since `--baseline`, not on
  the inherited backlog. Combine with `--exit-on-severity` to gate on new
  findings at or above a severity. Requires `--baseline`, and fails rather than
  silently passing if the baseline cannot be read.
- **Ignore rules**, previously advertised but unimplemented. Suppress findings
  by plugin id, alert name glob, or URL glob — from `tsun.yaml`, an
  `--ignore-file`, or repeatable `--ignore` flags. Suppressed findings stay in
  the report under `suppressed` with the rule that hid them, and are excluded
  from counts and gating. A rule with no criteria is rejected.
- **Config-file authentication**, previously parsed and then ignored. `auth:`
  supports `basic`, `bearer`, and `custom` methods; an explicit `--header`
  overrides a config header of the same name.
- **ZAP API key support** via `--zap-api-key`, `TSUN_ZAP_API_KEY`, or
  `zap.api_key`, for external ZAP instances. The key is attached to every API
  call, and a 401/403 produces an actionable error.
- **Info severity level**, so informational findings are no longer counted as
  Low.
- SARIF results now carry stable `partialFingerprints`, so GitHub tracks an
  alert across runs instead of reopening it when a URL id changes. Rules gained
  `helpUri`, CWE tags for recognized plugins, and `security-severity`.
- Integration tests: `tests/zap_client.rs` exercises the real ZAP client
  against a fake ZAP over HTTP (wiremock); `tests/cli.rs` runs the binary
  end to end (assert_cmd). Test count went from 65 to 222.
- `tsun doctor` and `--fail-on-new` documented; new troubleshooting entries.

### Changed
- **`--engine` now defaults to `zap` instead of `mock`.** A bare
  `tsun scan --target ...` previously returned six fabricated findings while
  the README described a real scan.
- **The mock engine announces itself.** Terminal banner, `"engine": "mock"` in
  every report, and a warning in HTML output. Its fixture now spans every
  severity including Critical and Info.
- **Severity is derived from ZAP risk *and* confidence.** High risk at
  High/Confirmed confidence is promoted to Critical; everything else keeps
  ZAP's level.
- CVSS scores are estimated from risk and confidence and flagged
  `cvss_estimated: true`. They are ordering hints, not vendor scores.
- Baseline findings are matched by fingerprint — plugin, injection point, and a
  normalized URL — rather than by exact URL.
- `is_improvement` now requires that no new findings appeared, and weights
  severity, so trading one critical for two lows still reads as progress.
- SARIF rule ids are `ZAP-<plugin>` rather than the misleading `OWASP-<plugin>`.
- Managed ZAP is hardened: the API binds to `127.0.0.1` instead of `0.0.0.0`
  and always requires an API key (generated per run) instead of
  `api.disablekey=true`. With host networking, the previous configuration
  exposed an unauthenticated ZAP — which can be driven to attack arbitrary
  hosts — to everything on the network, which matters most on shared CI
  runners. Container readiness now waits for a real version response rather
  than any open socket.
- Invalid `--profile` values are rejected instead of silently falling back to
  the custom defaults, and severity flags are validated before the scan starts
  rather than after it.

### Removed
- `features.rs`, the vestigial feature-flag module left over from the paywall,
  along with the unreachable "Pro required" branch in report saving and the
  `check_profile_access` no-op.
- Numeric severity codes in CLI flags (`--min-severity 2`). ZAP's wire format
  and Tsun's legacy `riskcode` number their levels differently, so a bare
  number was ambiguous; names are required.

### Breaking
- `--engine` defaults to `zap`; pass `--engine mock` explicitly for the old
  default.
- `--min-severity low` now excludes informational findings, which previously
  collapsed into Low. Use `--min-severity info` for the old behavior.
- Severity flags no longer accept numeric codes — use names.
- Reports gained `engine`, `severity`, `cvss_estimated`, and `suppressed`
  fields. Reports written by older versions still load: a missing `severity`
  falls back to `riskcode`.
- Findings previously reported as High may now be Critical, so an
  `--exit-on-severity critical` gate that never fired may begin to.

## [0.5.0] - 2026-03-09

### Changed
- **Complete open source transition**: Removed all monetization and licensing features
  - Eliminated Pro/Free tier distinctions entirely
  - Removed license management system and CLI commands
  - All features now available without restrictions or paywalls
  - Deleted licensing documentation and pricing references

### Removed
- **License system**: Complete removal of license validation, JWT tokens, and feature gating
  - Removed `license.rs` module and all license-related code
  - Removed `tsun license` CLI command and subcommands
  - Eliminated license status checking and upgrade prompts
- **Pro-only features**: All previously gated features now freely available
  - Baseline comparisons, deep/custom profiles, HTML/YAML/SARIF outputs
  - GitHub SARIF upload functionality
  - Advanced scan configurations and reporting
- **Documentation cleanup**: Removed all references to paid tiers and licensing
  - Updated README.md, CI templates, and workflow files
  - Cleaned up GitLab CI and GitHub Actions examples

## [0.4.0] - 2026-02-08

### Added
- **QA automation infrastructure**: Comprehensive smoke test suite with 21 automated tests
  - `scripts/qa_smoke.sh` with deterministic checks for features, auth, exit-codes, and validation
  - Environment-gated real ZAP tests behind `TSUN_RUN_ZAP=1` flag
  - Vendored SARIF 2.1.0 schema (111KB) for offline validation
  - PR/push CI workflow (`.github/workflows/smoke-tests.yml`) with fast mock-only tests
  - Nightly/manual workflow (`.github/workflows/smoke-tests-nightly.yml`) with real ZAP tests
  - Release workflow artifact validation (binary version check and help text verification)
- Cargo config (`.cargo/config.toml`) to set `OPENSSL_NO_VENDOR=1` globally for project

### Fixed
- **CLI help accuracy**: Removed unsupported "xml" format from `--format` help text
  - Help now correctly lists only supported formats: json, yaml, html, sarif
  - Validation logic was already correct, only help text needed update
- **Build compatibility**: OpenSSL build errors resolved across all cargo commands and CI workflows
  - Added `OPENSSL_NO_VENDOR=1` to all CI workflow build steps
  - Eliminates perl FindBin.pm module dependency errors

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
