# Authentication

Tsun scans protected applications by injecting your credentials into the
requests ZAP sends to the target.

## How it works

Credentials are installed as ZAP **Replacer** rules before the scan starts, so
every request ZAP makes — spider and active scan alike — carries them. This
matters: setting a header on the client that talks to ZAP's own API would
authenticate you to ZAP, not to the application under test.

The Replacer add-on ships with `zaproxy/zap-stable`. If you point Tsun at a ZAP
build without it, the scan fails with a clear error rather than silently
scanning unauthenticated.

## Static headers

```bash
# Single header
tsun scan --target https://example.com --header "Authorization: Bearer TOKEN"

# Multiple headers
tsun scan --target https://example.com \
  --header "X-API-Key: key123" \
  --header "Authorization: Bearer TOKEN"
```

## Cookies

### From a file (Netscape `cookies.txt` or JSON)

```bash
tsun scan --target https://example.com --cookies cookies.txt
```

Cookies are combined into a single `Cookie` header.

### Pre-scan login command

Run a command to obtain a session before scanning:

```bash
tsun scan --target https://example.com \
  --login-command "curl -c cookies.txt https://example.com/login -d 'user=admin&pass=secret'" \
  --cookies cookies.txt
```

The login command runs first; `--cookies` then reads whatever it wrote.

## From the configuration file

Credentials can live in `tsun.yaml` instead of the command line, which keeps
them out of your shell history and CI logs:

```yaml
auth:
  method: basic
  credentials:
    username: scanner
    password: ${SCANNER_PASSWORD}
```

Supported methods:

| Method | Credentials | Produces |
|--------|-------------|----------|
| `basic` | `username`, `password` | `Authorization: Basic <base64>` |
| `bearer` | `token` | `Authorization: Bearer <token>` |
| `custom` | any header names | those headers verbatim |

```yaml
# Bearer token
auth:
  method: bearer
  credentials:
    token: eyJhbGciOiJIUzI1NiIs...

# Arbitrary headers
auth:
  method: custom
  credentials:
    X-API-Key: abc123
    X-Tenant: acme
```

An explicit `--header` on the command line overrides a config-file header of
the same name.

## Complete example

```bash
tsun scan \
  --target https://staging.example.com \
  --header "X-API-Key: abc123" \
  --cookies session-cookies.txt \
  --profile ci \
  --format sarif \
  --output report.sarif
```

## Verifying authentication worked

An authenticated scan should reach more of the application than an anonymous
one. If the two produce identical findings, the credentials probably are not
being accepted:

```bash
tsun scan --target https://staging.example.com --output anon.json
tsun scan --target https://staging.example.com --header "Authorization: Bearer $TOKEN" --output authed.json
```

Run with `--verbose` to see each header as it is installed:

```
INFO tsun::zap: Installed auth header 'Authorization' for scan traffic
```

## Notes

- The mock engine ignores credentials; it never contacts the target. Tsun warns
  when you pass auth flags with `--engine mock`.
- Tsun does not yet drive form-based login inside ZAP (ZAP authentication
  contexts). Use `--login-command` to obtain a session externally, then pass it
  in with `--cookies` or `--header`.
