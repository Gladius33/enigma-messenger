use clap::{Parser, Subcommand, ValueEnum};
use enigma_core::migrations::{MigrationPlan, MigrationReport, StoreVersions};
use enigma_core::CORE_VERSION;
use enigma_daemon::config::{load_config, ApiConfig, EnigmaConfig};
use enigma_daemon::DAEMON_VERSION;
use enigma_storage::key_provider::{KeyProvider, MasterKey};
use enigma_storage::{EncryptedStore, EnigmaStorageError};
use reqwest::Url;
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
const UI_API_VERSION: &str = "v1";
const REGISTRY_VERSION: &str = "0.0.2";
const RELAY_VERSION: &str = "0.0.3";

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
    Migrate(MigrateArgs),
    PrintDefaultConfig(PrintDefaultConfigArgs),
}

#[derive(Parser)]
struct DoctorArgs {
    #[arg(long, default_value = "/etc/enigma/daemon.toml")]
    config: PathBuf,
    #[arg(long)]
    health_url: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct MigrateArgs {
    #[arg(long, default_value = "/etc/enigma/daemon.toml")]
    config: PathBuf,
    #[arg(long)]
    apply: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    json: bool,
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
    #[error("storage {message}")]
    Storage { message: String },
    #[error("health {url}: {message}")]
    Health { url: String, message: String },
    #[error("migration: {message}")]
    Migration { message: String },
    #[error("confirmation required: re-run with --yes")]
    ConfirmationRequired,
}

#[derive(Serialize)]
struct DoctorReport {
    config_path: String,
    data_dir: String,
    config_valid: bool,
    data_dir_permissions_ok: bool,
    migration: MigrationReport,
    store_versions: StoreVersions,
    protocol: ProtocolReport,
    dependencies: DependencyReport,
    health: HealthReport,
}

#[derive(Serialize)]
struct MigrationCliReport {
    config_path: String,
    mode: MigrationMode,
    result: MigrationReport,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum MigrationMode {
    DryRun,
    Apply,
}

#[derive(Serialize)]
struct HealthReport {
    url: String,
    status: String,
}

#[derive(Serialize)]
struct ProtocolReport {
    ui_api: String,
    proto_v1: bool,
    proto_v2: bool,
}

#[derive(Serialize)]
struct DependencyReport {
    cli: String,
    core: String,
    daemon: String,
    ui_api: String,
    relay: String,
    registry: String,
}

#[derive(Clone)]
struct DoctorKey;

impl KeyProvider for DoctorKey {
    fn get_or_create_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        load_master_key()
    }

    fn get_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        load_master_key()
    }
}

fn load_master_key() -> Result<MasterKey, EnigmaStorageError> {
    if let Ok(path) = env::var("ENIGMA_MASTER_KEY_PATH") {
        let value = fs::read_to_string(path)
            .map_err(|err| EnigmaStorageError::KeyProviderError(err.to_string()))?;
        return parse_master_key(&value);
    }
    if let Ok(value) = env::var("ENIGMA_MASTER_KEY_HEX") {
        return parse_master_key(&value);
    }
    Ok(MasterKey::new([2u8; 32]))
}

fn parse_master_key(value: &str) -> Result<MasterKey, EnigmaStorageError> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| EnigmaStorageError::KeyProviderError("invalid master key".to_string()))?;
    if bytes.len() != 32 {
        return Err(EnigmaStorageError::InvalidKey);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(MasterKey::new(key))
}

#[derive(Serialize)]
#[serde(tag = "command", content = "report")]
enum Report {
    Doctor(Box<DoctorReport>),
    Migrate(MigrationCliReport),
}

struct CommandResult {
    payload: Report,
    json: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let (json_flag, outcome) = match cli.command {
        Command::Doctor(args) => (args.json, run_doctor(args).await),
        Command::Migrate(args) => (args.json, run_migrate(args).await),
        Command::PrintDefaultConfig(args) => {
            if let Err(err) = print_default_config(args) {
                eprintln!("{}", err);
                std::process::exit(1);
            }
            return;
        }
    };

    match outcome {
        Ok(CommandResult { payload, json }) => {
            if json {
                print_json(&payload);
            } else {
                print_text(&payload);
            }
        }
        Err(err) => {
            print_error(&err, json_flag);
            std::process::exit(1);
        }
    }
}

async fn run_doctor(args: DoctorArgs) -> Result<CommandResult, CliError> {
    let cfg = read_config(&args.config)?;
    check_config_permissions(&args.config)?;
    check_data_dir_permissions(&cfg.data_dir)?;
    let store = open_store(&cfg)?;

    let plan = MigrationPlan::new(store.clone());
    let migration = plan.dry_run().await.map_err(|err| CliError::Migration {
        message: err.to_string(),
    })?;

    let health_url = derive_health_url(&cfg.api, args.health_url.as_deref())?;
    let health = probe_health(&health_url).await?;

    let report = DoctorReport {
        config_path: path_display(&args.config),
        data_dir: cfg.data_dir.display().to_string(),
        config_valid: true,
        data_dir_permissions_ok: true,
        store_versions: migration.detected.clone(),
        migration,
        protocol: protocol_report(),
        dependencies: dependencies_report(),
        health,
    };

    Ok(CommandResult {
        payload: Report::Doctor(Box::new(report)),
        json: args.json,
    })
}

async fn run_migrate(args: MigrateArgs) -> Result<CommandResult, CliError> {
    let cfg = read_config(&args.config)?;
    check_config_permissions(&args.config)?;
    check_data_dir_permissions(&cfg.data_dir)?;
    let store = open_store(&cfg)?;
    let plan = MigrationPlan::new(store);

    let mode = if args.apply {
        if !args.yes {
            return Err(CliError::ConfirmationRequired);
        }
        MigrationMode::Apply
    } else {
        MigrationMode::DryRun
    };

    let result = match mode {
        MigrationMode::DryRun => plan.dry_run().await,
        MigrationMode::Apply => plan.apply().await,
    }
    .map_err(|err| CliError::Migration {
        message: err.to_string(),
    })?;

    let report = MigrationCliReport {
        config_path: path_display(&args.config),
        mode,
        result,
    };

    Ok(CommandResult {
        payload: Report::Migrate(report),
        json: args.json,
    })
}

fn print_default_config(args: PrintDefaultConfigArgs) -> Result<(), CliError> {
    match args.service {
        TemplateKind::Daemon => println!("{}", daemon_template()),
        TemplateKind::Registry => println!("{}", registry_template()),
        TemplateKind::Relay => println!("{}", relay_template()),
        TemplateKind::Sfu => println!("{}", sfu_template()),
        TemplateKind::All => {
            println!("{}", daemon_template());
            println!("{}", registry_template());
            println!("{}", relay_template());
            println!("{}", sfu_template());
        }
    }
    Ok(())
}

fn print_text<T: Serialize>(payload: &T) {
    let mut buffer = Vec::new();
    if serde_json::to_writer(&mut buffer, payload).is_ok() {
        if let Ok(value) = serde_json::from_slice::<Value>(&buffer) {
            if let Some(obj) = value.as_object() {
                for (key, v) in obj {
                    if v.is_object() || v.is_array() {
                        let s = serde_json::to_string(v).unwrap_or_default();
                        println!("{}: {}", key, s);
                    } else {
                        println!("{}: {}", key, v);
                    }
                }
            }
        }
    }
}

fn print_json<T: Serialize>(payload: &T) {
    match serde_json::to_string_pretty(payload) {
        Ok(serialized) => println!("{}", serialized),
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }
}

fn print_error(err: &CliError, json: bool) {
    if json {
        let value = serde_json::json!({
            "error": {
                "message": err.to_string()
            }
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    } else {
        eprintln!("{}", err);
    }
}

fn read_config(path: &Path) -> Result<EnigmaConfig, CliError> {
    load_config(path).map_err(|err| CliError::Config {
        path: path_display(path),
        message: err.to_string(),
    })
}

fn open_store(cfg: &EnigmaConfig) -> Result<Arc<Mutex<EncryptedStore>>, CliError> {
    let path = cfg.data_dir.join("core");
    let namespace = format!("daemon-{}", cfg.identity.user_handle);

    let path_str = path
        .to_str()
        .ok_or_else(|| CliError::Storage {
            message: "invalid data_dir".to_string(),
        })?
        .to_string();

    let store = EncryptedStore::open(&path_str, &namespace, &DoctorKey).map_err(|err| {
        CliError::Storage {
            message: err.to_string(),
        }
    })?;

    Ok(Arc::new(Mutex::new(store)))
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

async fn probe_health(url: &Url) -> Result<HealthReport, CliError> {
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

    Ok(HealthReport {
        url: url.to_string(),
        status: "ok".to_string(),
    })
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

fn protocol_report() -> ProtocolReport {
    ProtocolReport {
        ui_api: UI_API_VERSION.to_string(),
        proto_v1: true,
        proto_v2: true,
    }
}

fn dependencies_report() -> DependencyReport {
    DependencyReport {
        cli: CLI_VERSION.to_string(),
        core: CORE_VERSION.to_string(),
        daemon: DAEMON_VERSION.to_string(),
        ui_api: format!("{} (dto)", enigma_ui_api::API_VERSION),
        relay: RELAY_VERSION.to_string(),
        registry: REGISTRY_VERSION.to_string(),
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
            json: true,
        };

        let result = run_doctor(args).await.unwrap();
        let Report::Doctor(report) = result.payload else {
            panic!("unexpected report type");
        };

        server.abort();

        assert!(
            report.migration.needs_migration
                || report.migration.target.identity == report.migration.detected.identity
        );
    }

    #[tokio::test]
    async fn migrate_dry_run_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("state");
        fs::create_dir_all(&data_dir).unwrap();
        fs::set_permissions(&data_dir, Permissions::from_mode(0o700)).unwrap();

        let template =
            daemon_template().replace("/var/lib/enigma/daemon", data_dir.to_str().unwrap());
        let config_path = dir.path().join("daemon.toml");
        fs::write(&config_path, template).unwrap();
        fs::set_permissions(&config_path, Permissions::from_mode(0o640)).unwrap();

        let args = MigrateArgs {
            config: config_path,
            apply: false,
            yes: false,
            json: true,
        };

        let result = run_migrate(args).await.unwrap();
        let Report::Migrate(report) = result.payload else {
            panic!("unexpected report type");
        };

        assert!(report.result.detected.identity >= 1);
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
