# Baseline Comparison

Compare a scan against a previous one so CI reports what *this change*
introduced rather than the whole backlog.

## Establish a baseline

```bash
tsun scan --target https://staging.example.com --output baseline.json --format json
```

Commit `baseline.json`, or store it as a CI artifact from your main branch.

## Compare against it

```bash
tsun scan --target https://staging.example.com --baseline baseline.json
```

The comparison reports:

- **New** — findings absent from the baseline
- **Fixed** — baseline findings that are gone
- **Unchanged** — findings present in both

## Failing the build on new findings only

`--baseline` alone only *prints* a comparison; exit codes still consider every
finding. Add `--fail-on-new` to gate on the delta:

```bash
# Fail if this change introduced anything at all
tsun scan --target https://staging.example.com \
  --baseline baseline.json \
  --fail-on-new

# Fail only if it introduced something high or worse
tsun scan --target https://staging.example.com \
  --baseline baseline.json \
  --fail-on-new \
  --exit-on-severity high
```

| Flags | Build fails when |
|-------|------------------|
| `--exit-on-severity high` | *any* finding is high or critical |
| `--fail-on-new` | *any* finding is new since the baseline |
| `--fail-on-new --exit-on-severity high` | a *new* finding is high or critical |

`--fail-on-new` requires `--baseline`. If the baseline cannot be read, the scan
fails loudly rather than passing a build it was never able to gate.

## How findings are matched

Findings are matched by a fingerprint of the plugin id, the alert name, the
injection point, and a **normalized** URL — not by exact URL. Normalization
collapses the parts of a URL that change between runs:

| Raw URL | Normalized |
|---------|------------|
| `/users/12345/orders/6` | `/users/{id}/orders/{id}` |
| `/o/550e8400-e29b-41d4-a716-446655440000` | `/o/{id}` |
| `/assets/d41d8cd98f00b204e9800998ecf8427e.js` | `/assets/{id}.js` |
| `/search?q=hello&page=2` | `/search?page&q` |
| `/search?q=a&_=1699999999&sid=abc` | `/search?q` |

So a finding on `/users/41/profile` and the same finding on `/users/99/profile`
count as one, and a rebuilt asset hash does not make every deploy look like a
regression. Query *names* are kept, because a finding on `?q=` is a different
finding from one on `?id=`.

Severity is deliberately not part of the fingerprint: if a finding's severity
changes, it is reported as the same finding, not as one fixed plus one new.

## CI integration

```yaml
- name: Restore baseline from main
  uses: actions/download-artifact@v4
  with:
    name: security-baseline
  continue-on-error: true

- name: Scan
  run: |
    tsun scan \
      --target https://staging.example.com \
      --profile ci \
      --baseline baseline.json \
      --fail-on-new \
      --exit-on-severity medium \
      --format sarif \
      --output report.sarif

- name: Publish new baseline
  if: github.ref == 'refs/heads/main'
  uses: actions/upload-artifact@v4
  with:
    name: security-baseline
    path: report.sarif
```

Refresh the baseline from your main branch only, so pull requests are always
measured against the same reference point.

## Related

- [Ignore rules](configuration.md#ignore-rules) retire findings you have judged
  and accepted — a permanent decision, where a baseline is a moving reference.
