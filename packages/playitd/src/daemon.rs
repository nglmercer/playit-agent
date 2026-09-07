use std::path::{Path, PathBuf};

use playit_agent_core::agent_control::platform::current_platform;
use playit_api_client::api::Platform;
use playit_ipc::ipc::IpcError;
use playit_runtime::{
    PlayitRuntime, RuntimeError, RuntimeOptions, VersionDetails, VersionOverrideFile,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

use crate::ipc_server::IpcServer;
use crate::logging::{IpcBroadcastLayer, log_rate_limit_filter};

#[cfg(target_os = "windows")]
const WINDOWS_LOG_MAX_FILE_SIZE_BYTES: u64 = 5 * 1024 * 1024;
#[cfg(target_os = "windows")]
const WINDOWS_LOG_MAX_TOTAL_FILES: usize = 3;
#[cfg(target_os = "windows")]
const WINDOWS_LOG_MAX_ROTATED_FILES: usize = WINDOWS_LOG_MAX_TOTAL_FILES - 1;

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub secret: Option<String>,
    pub secret_path: Option<PathBuf>,
    pub socket_path: Option<String>,
    pub log_path: Option<PathBuf>,
    pub platform_docker: bool,
    pub version: VersionDetails,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            secret: None,
            secret_path: Some(crate::paths::default_secret_path()),
            socket_path: None,
            log_path: None,
            platform_docker: false,
            version: VersionDetails::from_cargo_package()
                .expect("Cargo package version must be a valid semver triplet"),
        }
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Ipc(IpcError),
    Runtime(RuntimeError),
    SetupError(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipc(error) => write!(f, "IPC error: {error}"),
            Self::Runtime(error) => write!(f, "Runtime error: {error}"),
            Self::SetupError(error) => write!(f, "Setup error: {error}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<IpcError> for DaemonError {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

impl From<RuntimeError> for DaemonError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

pub async fn load_version_overrides(path: &Path) -> Result<VersionOverrideFile, String> {
    let content = tokio::fs::read_to_string(path).await.map_err(|error| {
        format!(
            "Failed to read version override file {}: {error}",
            path.display()
        )
    })?;

    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => serde_json::from_str(&content)
            .map_err(|error| format!("Invalid JSON in {}: {error}", path.display())),
        Some("yaml") | Some("yml") => serde_yml::from_str(&content)
            .map_err(|error| format!("Invalid YAML in {}: {error}", path.display())),
        _ => Err(format!(
            "Unsupported version override file format for {}. Use .json, .yaml, or .yml",
            path.display()
        )),
    }
}

pub async fn run_daemon(options: DaemonOptions) -> Result<(), DaemonError> {
    let runtime_options = RuntimeOptions {
        secret_path: options
            .secret_path
            .clone()
            .unwrap_or_else(crate::paths::default_secret_path),
        secret: options.secret.clone(),
        version: options.version.clone(),
        platform_docker: options.platform_docker,
        api_base: api_base(),
    };

    let platform = if options.platform_docker {
        Platform::Docker
    } else {
        current_platform()
    };
    let log_filter =
        EnvFilter::try_from_env("PLAYIT_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let (event_tx, _) = tokio::sync::broadcast::channel(256);
    let log_guard = match init_tracing(
        log_filter,
        matches!(platform, Platform::Linux | Platform::Docker),
        event_tx.clone(),
        options.log_path.as_deref(),
    ) {
        Ok(guard) => guard,
        Err(error) => {
            return Err(DaemonError::SetupError(error));
        }
    };

    let (mut runtime, handle) =
        PlayitRuntime::start_with_event_sender(runtime_options, event_tx).await?;

    tracing::info!(
        socket_path = ?options.socket_path,
        secret_path = ?handle.secret_path(),
        version = %options.version.version_string(),
        "Starting playitd"
    );

    let host_shutdown = CancellationToken::new();
    let server =
        match IpcServer::new(handle, options.socket_path.clone(), host_shutdown.clone()).await {
            Ok(server) => std::sync::Arc::new(server),
            Err(error) => {
                let _ = runtime.shutdown().await;
                return Err(DaemonError::Ipc(error));
            }
        };
    let listener = match server.bind_listener().await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = runtime.shutdown().await;
            return Err(DaemonError::Ipc(error));
        }
    };
    let mut ipc_task: JoinHandle<Result<(), IpcError>> = {
        let server = server.clone();
        tokio::spawn(async move { server.run(listener).await })
    };

    let result = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down");
            Ok(())
        }
        _ = host_shutdown.cancelled() => Ok(()),
        runtime_result = runtime.wait() => runtime_result.map_err(DaemonError::Runtime),
        ipc_result = &mut ipc_task => {
            ipc_result
                .map_err(|error| DaemonError::SetupError(format!("IPC task failed: {error}")))?
                .map_err(DaemonError::Ipc)
        }
    };

    host_shutdown.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut ipc_task).await;
    let shutdown_result = runtime.shutdown().await.map_err(DaemonError::Runtime);

    match (result, shutdown_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => {
            tracing::info!("playitd shutdown complete");
            drop(log_guard);
            Ok(())
        }
    }
}

fn api_base() -> String {
    dotenv::var("API_BASE").unwrap_or_else(|_| "https://api.playit.gg".to_string())
}

pub use playit_runtime::setup_error_user_message;

fn init_tracing(
    log_filter: EnvFilter,
    use_ansi: bool,
    event_tx: tokio::sync::broadcast::Sender<playit_ipc::model::ServiceUpdate>,
    log_path: Option<&Path>,
) -> Result<Option<WorkerGuard>, String> {
    match log_path {
        Some(path) => {
            let writer = log_file_writer(path)?;
            let (non_blocking, guard) = tracing_appender::non_blocking(writer);

            tracing_subscriber::registry()
                .with(log_filter)
                .with(
                    IpcBroadcastLayer::new(event_tx)
                        .and_then(
                            tracing_subscriber::fmt::layer()
                                .with_ansi(use_ansi)
                                .with_writer(non_blocking),
                        )
                        .with_filter(log_rate_limit_filter()),
                )
                .init();

            Ok(Some(guard))
        }
        None => {
            tracing_subscriber::registry()
                .with(log_filter)
                .with(
                    IpcBroadcastLayer::new(event_tx)
                        .and_then(
                            tracing_subscriber::fmt::layer()
                                .with_ansi(use_ansi)
                                .with_writer(std::io::stderr),
                        )
                        .with_filter(log_rate_limit_filter()),
                )
                .init();

            Ok(None)
        }
    }
}

#[cfg(target_os = "windows")]
fn log_file_writer(path: &Path) -> Result<tracing_rolling_file::RollingFileAppenderBase, String> {
    windows_log_file_writer_with_limits(
        path,
        WINDOWS_LOG_MAX_FILE_SIZE_BYTES,
        WINDOWS_LOG_MAX_ROTATED_FILES,
    )
}

#[cfg(target_os = "windows")]
fn windows_log_file_writer_with_limits(
    path: &Path,
    max_file_size_bytes: u64,
    max_rotated_files: usize,
) -> Result<tracing_rolling_file::RollingFileAppenderBase, String> {
    create_log_parent_dir(path)?;

    tracing_rolling_file::RollingFileAppenderBase::builder()
        .filename(path.display().to_string())
        .max_filecount(max_rotated_files)
        .condition_max_file_size(max_file_size_bytes)
        .build()
        .map_err(|error| {
            format!(
                "Failed to create log file writer {}: {error}",
                path.display()
            )
        })
}

#[cfg(not(target_os = "windows"))]
fn log_file_writer(path: &Path) -> Result<tracing_appender::rolling::RollingFileAppender, String> {
    create_log_parent_dir(path)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|file| file.to_str())
        .ok_or_else(|| format!("Invalid --log-path {}", path.display()))?;

    Ok(tracing_appender::rolling::never(parent, file_name))
}

fn create_log_parent_dir(path: &Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| {
        format!(
            "Failed to create log directory {}: {error}",
            parent.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{DaemonOptions, run_daemon, setup_error_user_message};
    use playit_agent_core::agent_control::errors::{SetupError, TimeoutSource};
    use playit_api_client::api::{ApiResponseError, AuthError, ProtoRegisterError};
    use playit_ipc::ipc::IpcClient;
    use playit_ipc::model::{AgentLifecycle, ServicePhase};

    fn unique_test_path(name: &str, extension: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "playitd-{name}-{}-{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            extension,
        ))
    }

    fn unique_socket_path(name: &str) -> String {
        let unique = format!(
            "playitd-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        #[cfg(target_os = "windows")]
        {
            format!(r"\\.\pipe\{unique}")
        }

        #[cfg(not(target_os = "windows"))]
        {
            std::env::temp_dir()
                .join(format!("{unique}.sock"))
                .display()
                .to_string()
        }
    }

    #[test]
    fn setup_error_message_handles_connection_failure() {
        let message = setup_error_user_message(&SetupError::FailedToConnect);
        assert!(message.contains("Could not connect to Playit tunnel servers"));
        assert!(message.contains("retry automatically"));
        assert!(message.contains("firewall"));
    }

    #[test]
    fn setup_error_message_handles_timeout() {
        let message = setup_error_user_message(&SetupError::Timeout(TimeoutSource {
            file_name: "test.rs",
            line_no: 1,
        }));
        assert!(message.contains("Timed out while connecting to Playit"));
        assert!(message.contains("retry automatically"));
    }

    #[test]
    fn setup_error_message_handles_io_error() {
        let message = setup_error_user_message(&SetupError::IoError(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "address already in use",
        )));
        assert!(message.contains("Could not open a required network socket"));
        assert!(message.contains("address already in use"));
    }

    #[test]
    fn setup_error_message_handles_invalid_secret() {
        let message = setup_error_user_message(&SetupError::ApiError(ApiResponseError::Auth(
            AuthError::NoLongerValid,
        )));
        assert!(message.contains("secret is no longer valid"));
        assert!(message.contains("playit setup"));
    }

    #[test]
    fn setup_error_message_handles_agent_limit() {
        let payload = serde_json::to_string(&ProtoRegisterError::AgentDisabledOverLimit).unwrap();
        let message = setup_error_user_message(&SetupError::ApiFail(payload));
        assert!(message.contains("over the agent limit"));
    }

    async fn wait_for_waiting_for_secret(socket_path: &str) -> IpcClient {
        let mut last_lifecycle = None;

        for _ in 0..50 {
            match IpcClient::connect_with_path(socket_path).await {
                Ok(mut client) => match client.lifecycle().await {
                    Ok(AgentLifecycle::WaitingForSecret) => return client,
                    Ok(lifecycle) => last_lifecycle = Some(format!("{lifecycle:?}")),
                    Err(error) => last_lifecycle = Some(format!("lifecycle error: {error}")),
                },
                Err(error) => last_lifecycle = Some(format!("connect error: {error}")),
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        panic!(
            "daemon did not report WaitingForSecret over IPC; last observed state: {}",
            last_lifecycle.unwrap_or_else(|| "none".to_string())
        );
    }

    #[tokio::test]
    async fn missing_file_secret_reports_waiting_for_secret() {
        let secret_path = unique_test_path("missing-secret", "toml");
        let socket_path = unique_socket_path("missing-secret");
        let _ = std::fs::remove_file(&secret_path);
        let _ = std::fs::remove_file(&socket_path);

        let daemon_handle = tokio::spawn(run_daemon(DaemonOptions {
            secret: None,
            secret_path: Some(secret_path.clone()),
            socket_path: Some(socket_path.clone()),
            log_path: None,
            platform_docker: false,
            ..DaemonOptions::default()
        }));

        let mut client = wait_for_waiting_for_secret(&socket_path).await;
        let status = client.status().await.unwrap();
        let expected_secret_path = secret_path.display().to_string();

        assert!(matches!(status.phase, ServicePhase::WaitingForSecret));
        assert!(!status.has_secret);
        assert_eq!(
            status.secret_path.as_deref(),
            Some(expected_secret_path.as_str())
        );

        let stop_response = client.stop().await.unwrap();
        assert!(stop_response.accepted);

        let daemon_result = tokio::time::timeout(Duration::from_secs(5), daemon_handle)
            .await
            .expect("daemon did not stop after IPC stop request")
            .expect("daemon task panicked");
        assert!(daemon_result.is_ok());

        let _ = std::fs::remove_file(&secret_path);
        let _ = std::fs::remove_file(&socket_path);
    }
}
