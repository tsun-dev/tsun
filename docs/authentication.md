# Authentication

Tsun supports multiple authentication methods for scanning protected applications.

## Static Headers

```bash
# Single header
tsun scan --target https://example.com --engine zap --header "Authorization: Bearer TOKEN"

# Multiple headers
tsun scan --target https://example.com --engine zap --header "X-API-Key: key123,Authorization: Bearer TOKEN"
```

## Cookies

### From File (Netscape format or JSON)

```bash
tsun scan --target https://example.com --engine zap --cookies cookies.txt
```

### Pre-scan Login Command

Generate cookies using a login command before the scan:

```bash
tsun scan --target https://example.com --engine zap \
  --login-command "curl -c cookies.txt https://example.com/login -d 'user=admin&pass=secret'" \
  --cookies cookies.txt
```

## Complete Example

```bash
# Authenticate with both headers and cookies
tsun scan \
  --target https://staging.example.com \
  --engine zap \
  --header "X-API-Key: abc123" \
  --cookies session-cookies.txt \
  --profile ci \
  --format sarif \
  --output report.sarif
```
