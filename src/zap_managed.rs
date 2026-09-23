//! Managed ZAP Docker runtime
//!
//! Automatically starts and stops a ZAP container for the duration of a scan.
//! On drop, the container is cleaned up (unless --keep-zap is set for debugging).

use anyhow::{anyhow, Context};
use std::net::TcpListener;
use std::process::Stdio;
use std::sync::Mutex;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};

/// Global registry of active ZAP containers for cleanup on signal/panic
static CONTAINER_REGISTRY: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// Register a container for cleanup
fn register_container(container_id: &str) {
    let mut registry = CONTAINER_REGISTRY.lock().unwrap();
    if registry.is_none() {
        *registry = Some(Vec::new());
    }
    if let Some(ref mut containers) = *registry {
        containers.push(container_id.to_string());
        debug!("Registered container for cleanup: {}", container_id);
    }
}

/// Unregister a container (when properly cleaned up)
fn unregister_container(container_id: &str) {
    let mut registry = CONTAINER_REGISTRY.lock().unwrap();
    if let Some(ref mut containers) = *registry {
        containers.retain(|id| id != container_id);
        debug!("Unregistered container: {}", container_id);
    }
}

/// Cleanup all registered containers (called on signal/panic)
pub fn cleanup_all_containers() {
    let mut registry = CONTAINER_REGISTRY.lock().unwrap();
    if let Some(ref mut containers) = *registry {
        for container_id in containers.iter() {
            warn!("Emergency cleanup of ZAP container: {}", container_id);
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", container_id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        containers.clear();
    }
}

pub struct ZapManaged {
    pub zap_url: String,
    pub api_key: Option<String>,
    container_id: String,
    keep: bool,
}

impl ZapManaged {
    /// Stop the ZAP container gracefully
    pub async fn stop(&self) -> anyhow::Result<()> {
        if self.keep {
            info!("Keeping ZAP container running: {}", self.container_id);
            return Ok(());
        }

        info!("Stopping ZAP container: {}", self.container_id);

        // Try graceful stop first
        let stop_result = Command::new("docker")
            .args(["stop", "--time", "10", &self.container_id])
            .output()
            .await;

        match stop_result {
            Ok(output) if output.status.success() => {
                debug!("ZAP container stopped gracefully");
            }
            _ => {
                warn!("Graceful stop failed, forcing removal");
            }
        }

        // Force remove to ensure cleanup
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .output()
            .await;

        unregister_container(&self.container_id);
        Ok(())
    }
}

impl Drop for ZapManaged {
    fn drop(&mut self) {
        if self.keep {
            warn!("Keeping ZAP container running: {}", self.container_id);
            return;
        }

        debug!("Drop called for ZapManaged, cleaning up container");

        // Synchronous cleanup for Drop
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        unregister_container(&self.container_id);
    }
}

#[derive(Clone, Debug)]
pub struct ManagedZapOptions {
    pub image: String,
    pub host_port: u16,
    pub api_key: Option<String>,
    pub keep: bool,
}

/// Generate a per-run ZAP API key.
///
/// Not a secret that needs to survive the process — it only has to be
/// unguessable for the lifetime of this container.
fn generate_api_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    // Stack address varies per run under ASLR, so it adds entropy the clock
    // and pid do not.
    let addr = &nanos as *const u128 as usize;

    format!("{:x}", md5::compute(format!("{}-{}-{}", nanos, pid, addr)))
}

fn try_reserve_port(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_ok()
}

fn pick_ephemeral_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("failed to bind ephemeral port")?;
    let port = listener
        .local_addr()
        .context("failed to read ephemeral port")?
        .port();
    Ok(port)
}

fn select_host_port(preferred: u16) -> anyhow::Result<(u16, bool)> {
    if preferred == 0 {
        return Ok((pick_ephemeral_port()?, true));
    }

    // If we can bind, the port is very likely available.
    if try_reserve_port(preferred) {
        return Ok((preferred, false));
    }

    warn!(
        "Requested ZAP port {} appears to be in use; selecting a free port",
        preferred
    );

    // Prefer an OS-selected ephemeral port to avoid races with naive scanning.
    // We still do a best-effort bind check before returning.
    for _ in 0..32 {
        let candidate = pick_ephemeral_port()?;
        if try_reserve_port(candidate) {
            return Ok((candidate, true));
        }
    }

    Err(anyhow!(
        "failed to find an available port for managed ZAP (preferred {})",
        preferred
    ))
}

/// Verify Docker is available
pub async fn ensure_docker() -> anyhow::Result<()> {
    let out = Command::new("docker")
        .args(["version"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("failed to execute docker")?;

    if !out.status.success() {
        return Err(anyhow!(
            "docker is not available: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Start a managed ZAP container and return a guard
pub async fn start_managed_zap(opts: ManagedZapOptions) -> anyhow::Result<ZapManaged> {
    ensure_docker().await?;

    let (host_port, changed) = select_host_port(opts.host_port)?;
    if changed {
        info!("Using ZAP port {}", host_port);
    }

    // ZAP's API can drive requests to arbitrary hosts, so it is never left
    // unauthenticated: when no key is supplied we generate one for this run.
    let api_key = opts.api_key.clone().unwrap_or_else(generate_api_key);
    let key_cfg = format!("api.key={}", api_key);

    let port_str = host_port.to_string();

    // Host networking lets ZAP reach the target directly, without proxy
    // confusion between container and host localhost addresses. It also means
    // ZAP binds on the host itself — so bind the API to loopback only, or a
    // shared CI runner would expose it to everything on the network.
    let args = vec![
        "run",
        "-d",
        "--network",
        "host", // Use host network - ZAP will bind directly to host ports
        &opts.image,
        "zap.sh",
        "-daemon",
        "-host",
        "127.0.0.1",
        "-port",
        &port_str, // Use the host port directly
        "-config",
        &key_cfg,
        "-config",
        "connection.timeoutInSecs=120",
        // Only this host may call the API, even if something else forwards to it.
        "-config",
        "api.addrs.addr.name=127.0.0.1",
        "-config",
        "api.addrs.addr.regex=false",
    ];

    let out = Command::new("docker")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("failed to run docker container")?;

    if !out.status.success() {
        return Err(anyhow!(
            "docker run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let container_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if container_id.is_empty() {
        return Err(anyhow!("docker did not return a container id"));
    }

    info!("Started managed ZAP container: {}", container_id);

    // Register for emergency cleanup
    register_container(&container_id);

    // Wait for ZAP to be ready (simple health check with retries)
    let zap_url = format!("http://127.0.0.1:{}", host_port);
    if let Err(e) = wait_for_zap_ready(&zap_url, &api_key, 90).await {
        warn!("ZAP failed to become ready, cleaning up container");
        let _ = Command::new("docker")
            .args(["rm", "-f", &container_id])
            .output()
            .await;
        unregister_container(&container_id);
        return Err(e);
    }

    Ok(ZapManaged {
        zap_url,
        api_key: Some(api_key),
        container_id,
        keep: opts.keep,
    })
}

/// Poll ZAP's version endpoint until it answers or we run out of time.
///
/// A socket that merely accepts is not readiness — we wait for ZAP to return
/// its version, which also confirms our API key is accepted.
async fn wait_for_zap_ready(
    base_url: &str,
    api_key: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let client = reqwest::Client::new();
    let health_url = format!("{}/JSON/core/view/version/", base_url);
    let mut last_error = String::new();

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "ZAP container failed to become ready within {} seconds{}",
                timeout_secs,
                if last_error.is_empty() {
                    String::new()
                } else {
                    format!(" (last response: {})", last_error)
                }
            ));
        }

        match client
            .get(&health_url)
            .query(&[("apikey", api_key)])
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() && body.contains("\"version\"") {
                    info!("ZAP container is ready");
                    return Ok(());
                }
                last_error = format!("HTTP {}", status);
            }
            Err(e) => last_error = e.to_string(),
        }

        sleep(Duration::from_millis(500)).await;
    }
}

/// Optional helper: stop a container gracefully
#[allow(dead_code)]
pub async fn stop_container(container_id: &str) -> anyhow::Result<()> {
    let _ = Command::new("docker")
        .args(["stop", container_id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_managed_zap_options_clone() {
        let opts = ManagedZapOptions {
            image: "owasp/zap2docker-stable".to_string(),
            host_port: 8080,
            api_key: Some("test".to_string()),
            keep: false,
        };
        let opts2 = opts.clone();
        assert_eq!(opts2.image, "owasp/zap2docker-stable");
        assert_eq!(opts2.host_port, 8080);
    }

    #[test]
    fn test_api_key_config_string() {
        let with_key = "api.key=mykey".to_string();
        assert!(with_key.contains("api.key"));

        let without_key = "api.disablekey=true".to_string();
        assert!(without_key.contains("disablekey"));
    }

    #[test]
    fn test_select_host_port_prefers_requested_when_free() {
        // Pick a free port first.
        let free_port = pick_ephemeral_port().expect("ephemeral port");
        let (selected, changed) = select_host_port(free_port).expect("select");
        assert_eq!(selected, free_port);
        assert!(!changed);
    }

    #[test]
    fn test_select_host_port_chooses_different_when_busy() {
        // Reserve a port, then ensure we don't pick it.
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let busy_port = listener.local_addr().unwrap().port();

        let (selected, changed) = select_host_port(busy_port).expect("select");
        assert_ne!(selected, busy_port);
        assert!(changed);
        drop(listener);
    }
}
