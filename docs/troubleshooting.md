# Troubleshooting

## Common Issues

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
