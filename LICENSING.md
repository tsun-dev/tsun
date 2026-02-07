# Rukn Pro - Licensing Guide

## Overview

Rukn offers a **Free tier** for basic security scanning and a **Pro tier** for teams that need advanced features like baseline comparison, deep scanning, and noise reduction.

## License Plans

### Free (Default)
- ✅ CI-optimized scans (10-15 min)
- ✅ Authenticated scanning (headers, cookies, login commands)
- ✅ JSON and SARIF output
- ✅ Basic exit code gating
- ✅ Managed ZAP Docker lifecycle
- ✅ Mock testing mode

### Pro ($49/month per team)
Everything in Free, plus:
- ✅ **Baseline Comparison** - See only NEW/FIXED vulnerabilities
- ✅ **Deep Profile** - Thorough scans (60-120 min)
- ✅ **HTML Reports** - Beautiful, shareable documentation
- ✅ **YAML Output** - Easy integration with custom tools
- ✅ **GitHub SARIF Upload** - Automated Code Scanning integration
- ✅ **Ignore Rules** - Reduce false positives (coming soon)
- ✅ **Priority Support**

### Pro Plus ($149/month per team)
Everything in Pro, plus:
- ✅ **Custom Scan Policies** - Fine-tune attack strength per vulnerability type
- ✅ **Advanced Auth Strategies** - OAuth, SAML, multi-step flows
- ✅ **Team Collaboration** - Shared baselines and ignore rules
- ✅ **SLA Support** - 24-hour response time

## Managing Your License

### Check Current License Status

```bash
rukn license status
```

Output:
```
━━ License Status ━━
  Plan: Free
  Customer ID: free
  Issued: 2026-02-07T00:00:00Z
  Expires: 9999-12-31T23:59:59Z
✓ License is active

📋 Available features:
  ✓ Basic Scanning
  ✓ CI Profile
  ✓ Auth Headers
  ✗ Baseline Comparison
  ✗ Deep Profile
  ✗ HTML Reports
```

### Activate Pro License

After purchasing, you'll receive a license key. Activate it:

```bash
# From string
rukn license set "eyJwbGFuIjoicHJvIi..."

# From file
rukn license set /path/to/license.txt
```

Your license is stored locally at `~/.config/rukn/license` (XDG-compliant).

### CI/CD Integration

Store your license key as a secret and activate before scanning:

#### GitHub Actions
```yaml
- name: Activate Rukn Pro
  if: ${{ secrets.ARETE_LICENSE != '' }}
  run: echo "${{ secrets.ARETE_LICENSE }}" | rukn license set -
```

#### GitLab CI
```yaml
before_script:
  - if [ -n "$ARETE_LICENSE" ]; then echo "$ARETE_LICENSE" | rukn license set -; fi
```

## License Expiration

### Grace Period
- When your license expires, you have a **7-day grace period**
- Pro features continue to work during this time
- You'll see warnings about the expiration

### After Grace Period
- Pro features are automatically disabled
- Free tier features continue to work
- No data loss - your scans and baselines are preserved
- Renew anytime to regain Pro access

### Example: Expired License

```bash
rukn license status
```

Output:
```
━━ License Status ━━
  Plan: Pro
  Customer ID: demo_customer
  Issued: 2025-01-01T00:00:00Z
  Expires: 2026-01-01T00:00:00Z
⚠️  EXPIRED (grace period: 5 days remaining)
ℹ Pro features will be disabled after grace period ends
```

## Feature Gating

When you try to use a Pro feature without a valid license:

```bash
rukn scan --target https://example.com --profile deep --format html
```

Output:
```
⚠️  Deep Profile is part of Rukn Pro

Deep profile enables thorough security scans for production releases.

Upgrade: https://rukn.dev/pricing
Or run: rukn license set <your_license>

ℹ Falling back to 'ci' profile
```

The scan **continues with Free tier defaults** - no hard failures.

## Pricing

> **Note**: Rukn Pro is currently in early access. To get a Pro license, open a GitHub issue with the "Pro License Request" label or check the README for the latest instructions.

### For Individuals & Bootstrapped Startups
- **Free**: $0/month - Perfect for side projects and CI basics
- **Pro**: $49/month per team - Noise reduction, baselines, deep scans

### For Teams (5-50 engineers)
- **Pro**: $49/month per team (flat rate, unlimited scans)
- **Pro Plus**: $149/month per team (advanced features + SLA)

### Enterprise (50+ engineers)
- Custom pricing
- SSO, audit logs, dedicated support
- Open a GitHub issue for enterprise inquiries

## Why Pro?

The biggest pain points in DAST adoption:
1. **Noise in CI** - Pro's baseline comparison shows only NEW issues
2. **Can't scan complex apps** - Pro's deep profile finds more vulnerabilities
3. **Hard to share results** - Pro's HTML reports are executive-ready
4. **Vendor lock-in** - Rukn is CLI-first, runs anywhere

## FAQ

### Do I need Pro for CI/CD?
No! The Free tier is designed for CI/CD with the `ci` profile (10-15 min scans).

Pro is for teams that want:
- **Baseline comparison** (reduce PR noise)
- **Deep scans** (pre-release verification)
- **Better reporting** (HTML for stakeholders)

### What happens if I downgrade?
- Your existing reports and baselines are preserved
- Pro features stop working immediately
- Free features continue working
- You can re-upgrade anytime

### Can I trial Pro?
Yes! Open a GitHub issue or check the README for trial license instructions.

### How is this different from SaaS DAST tools?
- **No per-scan pricing** - Unlimited scans on Pro
- **No data upload** - Everything runs locally
- **No vendor lock-in** - Standard ZAP engine underneath
- **Developer-friendly** - CLI-first, not web-first

### Do you offer volume discounts?
Yes! For teams with 10+ developers, open a GitHub issue to discuss.

## Support

- **Free**: Community support via GitHub Issues
- **Pro**: GitHub Issues with priority response
- **Pro Plus**: GitHub Issues + direct email access to maintainer

Rukn is founder-built and maintained. Questions or feedback? Open a GitHub issue.

## Next Steps

1. Try Free tier: `rukn scan --target <url>`
2. Check features: `rukn license status`
3. See pricing: Check the README on GitHub
4. Questions: Open a GitHub issue
