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

---

## CI Example (GitHub Actions)

```yaml
- name: Run security scan
  run: |
    tsun scan \
      --target https://staging.example.com \
      --exit-on-severity high
```

---

## Free vs Pro

**Free:**
- Authenticated scans
- CI profile (10–15 min)
- JSON + SARIF output
- Exit-code gating

**Pro:**
- Baseline comparisons (new/fixed/unchanged)
- Deep scans (60–120 min)
- HTML/YAML reports
- GitHub SARIF upload
- CI noise reduction

**Details:** [LICENSING.md](LICENSING.md)

---

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
