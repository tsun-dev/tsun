# Troubleshooting

## Common Issues

### "ZAP's Replacer add-on is not available"

`--header` and `--cookies` are applied through ZAP's Replacer add-on. A ZAP
image without it cannot authenticate scan traffic, so Tsun stops rather than
silently scanning anonymously. Use `zaproxy/zap-stable` (which bundles it), or
drop the auth flags.

### "ZAP rejected the request ... Check the ZAP API key"

Tsun's managed container generates its own key, so this normally means you are
pointing at an **external** ZAP whose key was not supplied. Pass
`--zap-api-key`, set `TSUN_ZAP_API_KEY`, or put it in `tsun.yaml` under
`zap.api_key`.

### "Endpoint responded but does not look like ZAP"

Something answered on that port but did not return a ZAP version — often
another service on the port, or a proxy in front of it. Check with
`tsun status --host <url>`.

### "--fail-on-new requires --baseline"

`--fail-on-new` gates on the difference from a previous scan, so it needs one
to compare against. See [baseline comparison](baseline-comparison.md).

### "Invalid severity level: 2"

Severity flags take names, not numbers: `critical`, `high`, `medium`, `low`,
`info`. Numeric codes are rejected because ZAP and Tsun's legacy report format
number their levels differently.

### Findings I already accepted keep failing the build

Use [ignore rules](configuration.md#ignore-rules) to retire them, or
`--fail-on-new` to gate only on what a change introduced.

### "Port 8080 already in use"

Tsun automatically selects a free port if the default is busy:

```bash
# Specify a custom port
tsun scan --target URL --engine zap --zap-port 8080
# Will use an ephemeral port if 8080 is busy
```

### "Permission denied" (Docker)

Add your user to the docker group (Linux):

```bash
sudo usermod -aG docker $USER
# Then log out and back in
```

### Scan times out before completion

Increase the timeout:

```bash
# Increase timeout to 1 hour
tsun scan --target URL --engine zap --timeout 3600

# Or use deep profile (2 hours)
tsun scan --target URL --engine zap --profile deep
```

### ZAP container not cleaned up

Manually remove ZAP containers:

```bash
docker rm -f $(docker ps -aq --filter ancestor=zaproxy/zap-stable)
```

## ZAP Container Cleanup

Tsun automatically cleans up ZAP containers in all scenarios to prevent port conflicts:

- **Normal completion**: Graceful 10-second shutdown, then force removal
- **Ctrl+C / SIGINT**: Emergency cleanup, exit code 130
- **Panic / crash**: Emergency cleanup before exiting
- **Startup failure**: Immediate cleanup if ZAP container fails health checks

Containers are tracked in a global registry and removed even if tsun is interrupted.

### Debugging with `--keep-zap`

Use the `--keep-zap` flag to keep the container running for debugging:

```bash
tsun scan --target URL --engine zap --keep-zap
# Container stays running after scan - useful for inspecting ZAP UI or logs
docker ps  # See the running container
docker logs <container_id>  # View ZAP logs
docker rm -f <container_id>  # Manual cleanup when done
```

### Verify no orphaned containers

```bash
docker ps --filter ancestor=owasp/zap2docker-stable
# Should show nothing after a completed scan
```
