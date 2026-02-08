# Baseline Comparison

Track vulnerability changes over time by comparing scans against a baseline.

## Usage

### Establish Baseline

Run your first scan and save the results:

```bash
tsun scan --target https://staging.example.com --engine zap --output baseline.json --format json
```

### Compare Against Baseline

Run subsequent scans and compare:

```bash
tsun scan --target https://staging.example.com --engine zap --baseline baseline.json --exit-on-severity high
```

## Comparison Report

The comparison shows:

- **New vulnerabilities** - Issues introduced since baseline
- **Fixed vulnerabilities** - Issues resolved since baseline
- **Overall trend** - Improving/degrading/unchanged

## CI Integration

Use baseline comparison to fail builds only on new issues:

```yaml
- name: Run security scan with baseline
  run: |
    tsun scan \
      --target https://staging.example.com \
      --engine zap \
      --baseline previous-scan.json \
      --exit-on-severity medium
```

This approach reduces noise in CI by focusing on changes rather than the full vulnerability list.

## Pro Feature

Baseline comparison is available in the Pro tier. See [LICENSING.md](../LICENSING.md) for details.
