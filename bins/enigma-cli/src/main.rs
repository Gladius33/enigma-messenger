use clap::{Parser, Subcommand, ValueEnum};
use enigma_daemon::config::{load_config, ApiConfig, EnigmaConfig};
use reqwest::Url;
use serde_json::Value;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

#[derive(Parser)]
#[command(name = "enigma-cli")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Doctor(DoctorArgs),
    PrintDefaultConfig(PrintDefaultConfigArgs),
}

#[derive(Parser)]
struct DoctorArgs {
    #[arg(long, default_value = "/etc/enigma/daemon.toml")]
    config: PathBuf,
    #[arg(long)]
    health_url: Option<String>,
}

#[derive(Parser)]
struct PrintDefaultConfigArgs {
    #[arg(long, value_enum, default_value = "daemon")]
    service: TemplateKind,
}

#[derive(Copy, Clone, ValueEnum)]
enum TemplateKind {
    Daemon,
    Registry,
    Relay,
    Sfu,
    All,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("config {path}: {message}")]
    Config { path: String, message: String },
    #[error("io {path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("permissions {path}: {message}")]
    Permissions { path: String, message: String },
    #[error("health {url}: {message}")]
    Health { url: String, message: String },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Doctor(args) => run_doctor(args).await,
        Command::PrintDefaultConfig(args) => print_default_config(args),
    };
    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

async fn run_doctor(args: DoctorArgs) -> Result<(), CliError> {
    let cfg = read_config(&args.config)?;
    check_config_permissions(&args.config)?;
    check_data_dir_permissions(&cfg.data_dir)?;
    let health_url = derive_health_url(&cfg.api, args.health_url.as_deref())?;
    probe_health(&health_url).await?;
    println!("config: ok ({})", args.config.display());
    println!("data_dir: ok ({})", cfg.data_dir.display());
    println!("health: ok ({})", health_url);
    Ok(())
}

fn print_default_config(args: PrintDefaultConfigArgs) -> Result<(), CliError> {
    match args.service {
        TemplateKind::Daemon => {
            println!("{}", daemon_template());
        }
        TemplateKind::Registry => {
            println!("{}", registry_template());
        }
        TemplateKind::Relay => {
            println!("{}", relay_template());
        }
        TemplateKind::Sfu => {
            println!("{}", sfu_template());
        }
        TemplateKind::All => {
            println!("{}", daemon_template());
            println!("{}", registry_template());
            println!("{}", relay_template());
            println!("{}", sfu_template());
        }
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<EnigmaConfig, CliError> {
    load_config(path).map_err(|err| CliError::Config {
        path: path_display(path),
        message: err.to_string(),
    })
}

fn derive_health_url(api: &ApiConfig, override_url: Option<&str>) -> Result<Url, CliError> {
    if let Some(raw) = override_url {
        return Url::parse(raw).map_err(|err| CliError::Health {
            url: raw.to_string(),
            message: err.to_string(),
        });
    }
    let addr = api.socket_addr().map_err(|err| CliError::Config {
        path: "api".to_string(),
        message: err.to_string(),
    })?;
    let url = format!("http://{}/api/v1/health", addr);
    Url::parse(&url).map_err(|err| CliError::Health {
        url,
        message: err.to_string(),
    })
}

async fn probe_health(url: &Url) -> Result<(), CliError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| CliError::Health {
            url: url.to_string(),
            message: err.to_string(),
        })?;
    let mut request = client.get(url.clone());
    if let Ok(token) = env::var("ENIGMA_UI_TOKEN") {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|err| CliError::Health {
        url: url.to_string(),
        message: err.to_string(),
    })?;
    if !response.status().is_success() {
        return Err(CliError::Health {
            url: url.to_string(),
            message: format!("status {}", response.status()),
        });
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(|err| CliError::Health {
            url: url.to_string(),
            message: err.to_string(),
        })?;
    let status_ok = body
        .get("status")
        .and_then(|v| v.as_str())
        .map(|v| v.eq_ignore_ascii_case("ok"))
        .unwrap_or(false);
    if !status_ok {
        return Err(CliError::Health {
            url: url.to_string(),
            message: "unexpected response".to_string(),
        });
    }
    Ok(())
}

fn check_config_permissions(path: &Path) -> Result<(), CliError> {
    let meta = fs::metadata(path).map_err(|err| CliError::Io {
        path: path_display(path),
        source: err,
    })?;
    if !meta.is_file() {
        return Err(CliError::Permissions {
            path: path_display(path),
            message: "config is not a file".to_string(),
        });
    }
    let mode = mode_bits(&meta);
    if mode & 0o022 != 0 {
        return Err(CliError::Permissions {
            path: path_display(path),
            message: format!("config permissions too open (mode {:03o})", mode & 0o777),
        });
    }
    Ok(())
}

fn check_data_dir_permissions(path: &Path) -> Result<(), CliError> {
    let meta = fs::metadata(path).map_err(|err| CliError::Io {
        path: path_display(path),
        source: err,
    })?;
    if !meta.is_dir() {
        return Err(CliError::Permissions {
            path: path_display(path),
            message: "data_dir is not a directory".to_string(),
        });
    }
    let mode = mode_bits(&meta);
    if mode & 0o022 != 0 || mode & 0o004 != 0 {
        return Err(CliError::Permissions {
            path: path_display(path),
            message: format!("data_dir permissions too open (mode {:03o})", mode & 0o777),
        });
    }
    Ok(())
}

fn daemon_template() -> &'static str {
    include_str!("../../../deployment/etc/enigma/daemon.toml")
}

fn registry_template() -> &'static str {
    include_str!("../../../deployment/etc/enigma/registry.toml")
}

fn relay_template() -> &'static str {
    include_str!("../../../deployment/etc/enigma/relay.toml")
}

fn sfu_template() -> &'static str {
    include_str!("../../../deployment/etc/enigma/sfu.toml")
}

fn path_display(path: &Path) -> String {
    path.display().to_string()
}

fn mode_bits(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[tokio::test]
    async fn doctor_checks_config_and_health() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("state");
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o700)).unwrap();
        let template =
            daemon_template().replace("/var/lib/enigma/daemon", data_dir.to_str().unwrap());
        let config_path = dir.path().join("daemon.toml");
        fs::write(&config_path, template).unwrap();
        fs::set_permissions(&config_path, Permissions::from_mode(0o640)).unwrap();
        let (health_url, server) = match start_health_server().await {
            Some(server) => server,
            None => return,
        };
        let args = DoctorArgs {
            config: config_path.clone(),
            health_url: Some(health_url),
        };
        let result = run_doctor(args).await;
        server.abort();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn doctor_rejects_open_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("state");
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o755)).unwrap();
        let template =
            daemon_template().replace("/var/lib/enigma/daemon", data_dir.to_str().unwrap());
        let config_path = dir.path().join("daemon.toml");
        fs::write(&config_path, template).unwrap();
        let args = DoctorArgs {
            config: config_path.clone(),
            health_url: Some("http://127.0.0.1:0/api/v1/health".to_string()),
        };
        let result = run_doctor(args).await;
        assert!(result.is_err());
    }

    #[test]
    fn default_daemon_template_matches_expected() {
        let expected = r#"data_dir = "/var/lib/enigma/daemon"

[identity]
user_handle = "daemon"
device_name = "daemon"

[policy]
max_text_bytes = 262144
max_message_rate_per_minute = 600
max_inline_media_bytes = 67108864
max_attachment_chunk_bytes = 1048576
max_attachment_parallel_chunks = 4
max_group_name_len = 64
max_channel_name_len = 64
max_membership_changes_per_minute = 120
max_retry_window_secs = 3600
backoff_initial_ms = 500
backoff_max_ms = 60000
outbox_batch_send = 32
directory_ttl_secs = 3600
directory_refresh_on_send = true
receipt_aggregation = "Any"
group_crypto_mode = "Fanout"
sender_keys_rotate_every_msgs = 1000
sender_keys_rotate_on_membership_change = true

[registry]
enabled = true
base_url = "http://127.0.0.1:9000"
mode = "http"
pepper_hex = "0000000000000000000000000000000000000000000000000000000000000000"
key_cache_ttl_secs = 300

[registry.http]
timeout_secs = 10
connect_timeout_secs = 5
read_timeout_secs = 10
retry_attempts = 3
retry_backoff_ms = 200

[registry.pow]
enabled = false
max_solve_ms = 1500
retry_attempts = 2

[relay]
enabled = true
base_url = "http://127.0.0.1:9100"
mode = "http"

[relay.http]
timeout_secs = 10
connect_timeout_secs = 5
read_timeout_secs = 10
retry_attempts = 3
retry_backoff_ms = 200

[transport.webrtc]
enabled = false
stun_servers = []

[sfu]
enabled = false

[calls]
enabled = false
max_publish_tracks_per_participant = 4
max_subscriptions_per_participant = 16

[api]
bind_addr = "127.0.0.1:9171"

[logging]
level = "info""#;
        assert_eq!(daemon_template().trim_end(), expected.trim_end());
    }

    async fn start_health_server() -> Option<(String, JoinHandle<()>)> {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(_) => return None,
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(_) => return None,
        };
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 512];
                let _ = stream.read(&mut buf).await;
                let body = r#"{"status":"ok"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: application/json\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Some((format!("http://{}/api/v1/health", addr), handle))
    }
}
