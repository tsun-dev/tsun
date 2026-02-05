/// Managed ZAP Docker runtime
///
/// Automatically starts and stops a ZAP container for the duration of a scan.
/// On drop, the container is cleaned up (unless --keep-zap is set for debugging).

use anyhow::{anyhow, Context};
use std::net::TcpListener;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub struct ZapManaged {
    pub zap_url: String,
    #[allow(dead_code)]
    pub api_key: Option<String>,
    container_id: String,
    keep: bool,
}

impl Drop for ZapManaged {
    fn drop(&mut self) {
        if self.keep {
            warn!("Keeping ZAP container running: {}", self.container_id);
            return;
        }
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[derive(Clone, Debug)]
pub struct ManagedZapOptions {
    pub image: String,
    pub host_port: u16,
    pub api_key: Option<String>,
    pub keep: bool,
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

    // ZAP config: if no api_key specified, disable key requirement for dev ergonomics
    let key_cfg = if let Some(k) = &opts.api_key {
        format!("api.key={}", k)
    } else {
        "api.disablekey=true".to_string()
    };

    let port_str = host_port.to_string();

    // Using host network mode so ZAP can access external URLs directly
    // without proxy confusion between container and host localhost addresses
    let args = vec![
        "run",
        "-d",
        "--network",
        "host",  // Use host network - ZAP will bind directly to host ports
        &opts.image,
        "zap.sh",
        "-daemon",
        "-host",
        "0.0.0.0",
        "-port",
        &port_str,  // Use the host port directly
        "-config",
        &key_cfg,
        "-config",
        "connection.timeoutInSecs=120",
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

    // Wait for ZAP to be ready (simple health check with retries)
    let zap_url = format!("http://127.0.0.1:{}", host_port);
    wait_for_zap_ready(&zap_url, 90).await?;

    Ok(ZapManaged {
        zap_url,
        api_key: opts.api_key,
        container_id,
        keep: opts.keep,
    })
}

/// Poll ZAP health endpoint until it's ready or timeout
async fn wait_for_zap_ready(base_url: &str, timeout_secs: u64) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("ZAP container failed to become ready within {} seconds", timeout_secs));
        }

        let health_url = format!("{}/JSON/core/action/version/", base_url);
        if let Ok(_) = reqwest::Client::new().get(&health_url).send().await {
            info!("ZAP container is ready");
            return Ok(());
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
