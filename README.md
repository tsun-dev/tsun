# Tsun

**Developer-first DAST for CI pipelines.**

Tsun makes OWASP ZAP usable in real-world CI by handling authentication, baselines, and scan noise by default.

→ **[https://use-tsun.dev](https://use-tsun.dev)**

---

## Why Tsun

- **Built for CI** — predictable runtimes and exit-code gating
- **Authenticated scanning** — headers, cookies, login commands
- **Noise reduction** — baseline comparison and change tracking
- **No ZAP babysitting** — Docker-managed lifecycle
- **Developer-friendly output** — JSON, SARIF, HTML

---

## Installation

Download pre-built binaries from:

**[https://github.com/tsun-dev/tsun/releases](https://github.com/tsun-dev/tsun/releases)**

If installation fails, verify your platform matches the asset name or download directly from the Releases page.

```bash
# Linux x86_64
curl -fL https://github.com/tsun-dev/tsun/releases/latest/download/tsun-linux-x86_64.tar.gz | tar xz
sudo install -m 0755 tsun /usr/local/bin/tsun

# macOS (Intel)
curl -fL https://github.com/tsun-dev/tsun/releases/latest/download/tsun-macos-x86_64.tar.gz | tar xz
sudo install -m 0755 tsun /usr/local/bin/tsun

# macOS (Apple Silicon)
curl -fL https://github.com/tsun-dev/tsun/releases/latest/download/tsun-macos-aarch64.tar.gz | tar xz
sudo install -m 0755 tsun /usr/local/bin/tsun

# Verify installation
tsun --version
```

---

## Quick Start

Tsun automatically starts and manages a ZAP container.

```bash
tsun scan --target https://testphp.vulnweb.com
```

**Requirements:**
- Docker running

Check your setup first with `tsun doctor`.

To exercise the CLI without Docker or a target, `--engine mock` fabricates
findings. It labels every report as fake — never use it as a stand-in for a
scan.

---

## CI Example (GitHub Actions)

```yaml
- name: Run security scan
  run: |
    tsun scan \
      --target https://staging.example.com \
      --exit-on-severity high
```

Scanning an existing application surfaces its whole backlog, which fails every
build. Gate on what the change introduced instead:

```yaml
- name: Run security scan
  run: |
    tsun scan \
      --target https://staging.example.com \
      --baseline baseline.json \
      --fail-on-new \
      --exit-on-severity high
```

---

## Features

- **Authenticated scans** — headers, cookies, login commands, or credentials
  from config. Injected into ZAP's outbound requests, so they reach the target.
- **Scan profiles** — CI (10-15 min), Deep (60-120 min), and Custom
- **Output formats** — JSON, SARIF, HTML, YAML
- **Baseline comparisons** — findings matched by fingerprint, so volatile URL
  ids and rebuilt asset hashes don't look like regressions
- **`--fail-on-new`** — fail the build only on what this change introduced
- **Ignore rules** — retire accepted findings from config, a file, or the CLI;
  suppressed findings stay in the report for review
- **Five severity levels** — including Critical (which ZAP has no concept of)
  and Info as a level of its own
- **GitHub SARIF upload** — with stable fingerprints and CWE tags, so alerts
  track across runs
- **Hardened by default** — managed ZAP binds to loopback with a per-run API key

---

## Security note

Tsun's managed ZAP container binds its API to loopback and requires a per-run
generated API key. ZAP's API can drive requests to arbitrary hosts, so it is
never left open — this matters most on shared CI runners.

## Documentation

- [Getting started in CI](docs/getting-started-ci.md)
- [Authentication examples](docs/authentication.md)
- [Baseline comparisons](docs/baseline-comparison.md)
- [Configuration reference](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [SARIF & GitHub Code Scanning](docs/sarif.md)
- [Contributing](docs/contributing.md)

---

## License

MIT
