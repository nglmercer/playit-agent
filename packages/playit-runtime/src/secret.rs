use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::error::RuntimeError;
use crate::options::RuntimeOptions;

pub(crate) struct SecretProvisionRequest {
    pub(crate) secret: String,
    pub(crate) response_tx: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug, Clone)]
pub(crate) enum SecretSource {
    Inline { secret: String },
    File { path: PathBuf },
}

impl SecretSource {
    pub(crate) fn from_options(options: &RuntimeOptions) -> Self {
        match options.secret.clone() {
            Some(secret) => Self::Inline { secret },
            None => Self::File {
                path: options.secret_path.clone(),
            },
        }
    }

    pub(crate) fn secret_path(&self) -> Option<&Path> {
        match self {
            Self::Inline { .. } => None,
            Self::File { path } => Some(path.as_path()),
        }
    }

    pub(crate) fn allows_provisioning(&self) -> bool {
        matches!(self, Self::File { .. })
    }

    pub(crate) async fn load(&self) -> LoadedSecret {
        match self {
            Self::Inline { secret } => match validate_secret(secret.trim()) {
                Ok(secret) => LoadedSecret::Ready(secret),
                Err(error) => LoadedSecret::Invalid(format!(
                    "Invalid secret passed via inline configuration: {error}"
                )),
            },
            Self::File { path } => load_secret_from_path(path).await,
        }
    }

    pub(crate) fn provisioning_error(&self) -> RuntimeError {
        match self {
            Self::Inline { .. } => RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretPinned,
                "Secret provisioning is unavailable because the runtime was started with an inline secret.",
                false,
            ),
            Self::File { .. } => RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::ProvisioningUnavailable,
                "Secret provisioning is unavailable.",
                true,
            ),
        }
    }

    pub(crate) fn reset_error(&self) -> RuntimeError {
        match self {
            Self::Inline { .. } => RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretPinned,
                "Secret reset is unavailable because the runtime was started with an inline secret.",
                false,
            ),
            Self::File { path } => RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!("Failed to access secret file {}", path.display()),
                true,
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum LoadedSecret {
    Ready(String),
    Missing,
    Invalid(String),
}

pub(crate) async fn wait_for_provisioned_secret(
    secret_path: &Path,
    provision_rx: &mut mpsc::Receiver<SecretProvisionRequest>,
    cancel_token: &CancellationToken,
) -> Result<Option<String>, RuntimeError> {
    tracing::info!(
        secret_path = %secret_path.display(),
        "Waiting for Playit secret provisioning"
    );

    loop {
        tokio::select! {
            maybe_request = provision_rx.recv() => {
                let Some(request) = maybe_request else {
                    return Err(RuntimeError::secret(
                        playit_ipc::model::ServiceErrorCode::ProvisioningUnavailable,
                        "Secret provisioning channel closed.",
                        true,
                    ));
                };

                let result = persist_secret_file(secret_path, &request.secret).await;
                let ack = result.as_ref().map(|_| ()).map_err(ToString::to_string);
                let _ = request.response_tx.send(ack);

                match result {
                    Ok(secret) => {
                        tracing::info!(secret_path = %secret_path.display(), "Secret provisioned successfully");
                        return Ok(Some(secret));
                    }
                    Err(error) => {
                        tracing::error!(secret_path = %secret_path.display(), %error, "Secret provisioning failed");
                    }
                }
            }
            _ = cancel_token.cancelled() => return Ok(None),
        }
    }
}

pub(crate) async fn persist_secret_file(path: &Path, secret: &str) -> Result<String, RuntimeError> {
    let secret = validate_secret(secret.trim()).map_err(|error| {
        RuntimeError::secret(
            playit_ipc::model::ServiceErrorCode::InvalidSecret,
            error,
            false,
        )
    })?;

    ensure_secret_parent(path).await?;

    let content = if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
        toml::to_string(&SecretConfig {
            secret_key: secret.clone(),
        })
        .map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to serialize secret file {}: {error}",
                    path.display()
                ),
                true,
            )
        })?
    } else {
        secret.clone()
    };

    secure_write_secret_file(path, content.as_bytes()).await?;
    Ok(secret)
}

pub(crate) async fn reset_secret_file(path: &Path) -> Result<String, RuntimeError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(format!(
            "Deleted secret file at {}. Start the runtime again to reprovision a new secret.",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(format!(
            "Secret file was already absent at {}.",
            path.display()
        )),
        Err(error) => Err(RuntimeError::secret(
            playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
            format!("Failed to delete secret file {}: {error}", path.display()),
            true,
        )),
    }
}

pub fn validate_secret(secret: &str) -> Result<String, String> {
    if secret.is_empty() {
        return Err(
            "The secret is empty. It should be the key generated by playit setup.".to_string(),
        );
    }

    hex::decode(secret)
        .map(|_| secret.to_string())
        .map_err(|_| {
            "The secret is not valid. It should be the key generated by playit setup.".to_string()
        })
}

async fn load_secret_from_path(path: &Path) -> LoadedSecret {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return LoadedSecret::Missing,
        Err(error) => {
            return LoadedSecret::Invalid(format!(
                "Failed to read secret file {}: {error}",
                path.display()
            ));
        }
    };

    match parse_secret_file(&content) {
        Ok(secret) => LoadedSecret::Ready(secret),
        Err(()) => LoadedSecret::Invalid(format!(
            "Invalid secret file at {}. Remove or replace it with a valid secret.",
            path.display()
        )),
    }
}

async fn ensure_secret_parent(path: &Path) -> Result<(), RuntimeError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };

    let mut new_directories = Vec::new();
    let mut current = parent.to_path_buf();
    loop {
        match tokio::fs::metadata(&current).await {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(RuntimeError::secret(
                    playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                    format!(
                        "Secret path parent {} is not a directory",
                        current.display()
                    ),
                    true,
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                new_directories.push(current.clone());
                let Some(next) = current.parent() else { break };
                if next == current {
                    break;
                }
                current = next.to_path_buf();
            }
            Err(error) => {
                return Err(RuntimeError::secret(
                    playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                    format!(
                        "Failed to inspect secret directory {}: {error}",
                        current.display()
                    ),
                    true,
                ));
            }
        }
    }

    tokio::fs::create_dir_all(parent).await.map_err(|error| {
        RuntimeError::secret(
            playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
            format!(
                "Failed to create secret directory {}: {error}",
                parent.display()
            ),
            true,
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in new_directories {
            tokio::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|error| {
                    RuntimeError::secret(
                        playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                        format!(
                            "Failed to secure secret directory {}: {error}",
                            directory.display()
                        ),
                        true,
                    )
                })?;
        }
    }

    #[cfg(windows)]
    {
        for directory in new_directories {
            crate::windows_secret::protect_path_async(&directory)
                .await
                .map_err(|error| {
                    RuntimeError::secret(
                        playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                        format!(
                            "Failed to secure secret directory {}: {error}",
                            directory.display()
                        ),
                        true,
                    )
                })?;
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn secure_write_secret_file(path: &Path, content: &[u8]) -> Result<(), RuntimeError> {
    let path = path.to_path_buf();
    let content = content.to_vec();

    tokio::task::spawn_blocking(move || secure_write_secret_file_blocking(&path, &content))
        .await
        .map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!("Failed to join secret file writer task: {error}"),
                true,
            )
        })?
}

#[cfg(unix)]
fn secure_write_secret_file_blocking(path: &Path, content: &[u8]) -> Result<(), RuntimeError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("playit.toml");
    let mut suffix = [0u8; 8];
    rand::rng().fill(&mut suffix);
    let tmp_path = parent.join(format!(
        ".{file_name}.tmp-{}-{}-{}",
        std::process::id(),
        crate::options::DEFAULT_VARIANT_ID,
        hex::encode(suffix)
    ));

    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|error| {
                RuntimeError::secret(
                    playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                    format!(
                        "Failed to create temporary secret file {}: {error}",
                        tmp_path.display()
                    ),
                    true,
                )
            })?;

        file.write_all(content).map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to write temporary secret file {}: {error}",
                    tmp_path.display()
                ),
                true,
            )
        })?;
        file.sync_all().map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to sync temporary secret file {}: {error}",
                    tmp_path.display()
                ),
                true,
            )
        })?;
        drop(file);

        std::fs::rename(&tmp_path, path).map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to replace secret file {} with {}: {error}",
                    path.display(),
                    tmp_path.display()
                ),
                true,
            )
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                RuntimeError::secret(
                    playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                    format!(
                        "Failed to set secret file permissions on {}: {error}",
                        path.display()
                    ),
                    true,
                )
            },
        )?;

        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }

    result
}

#[cfg(windows)]
async fn secure_write_secret_file(path: &Path, content: &[u8]) -> Result<(), RuntimeError> {
    let path = path.to_path_buf();
    let content = content.to_vec();

    tokio::task::spawn_blocking(move || secure_write_secret_file_blocking(&path, &content))
        .await
        .map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!("Failed to join secret file writer task: {error}"),
                true,
            )
        })?
}

#[cfg(windows)]
fn secure_write_secret_file_blocking(path: &Path, content: &[u8]) -> Result<(), RuntimeError> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("playit.toml");
    let mut suffix = [0u8; 8];
    rand::rng().fill(&mut suffix);
    let tmp_path = parent.join(format!(
        ".{file_name}.tmp-{}-{}-{}",
        std::process::id(),
        crate::options::DEFAULT_VARIANT_ID,
        hex::encode(suffix)
    ));

    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|error| {
                RuntimeError::secret(
                    playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                    format!(
                        "Failed to create temporary secret file {}: {error}",
                        tmp_path.display()
                    ),
                    true,
                )
            })?;

        crate::windows_secret::protect_path(&tmp_path).map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to secure temporary secret file {}: {error}",
                    tmp_path.display()
                ),
                true,
            )
        })?;

        file.write_all(content).map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to write temporary secret file {}: {error}",
                    tmp_path.display()
                ),
                true,
            )
        })?;
        file.sync_all().map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to sync temporary secret file {}: {error}",
                    tmp_path.display()
                ),
                true,
            )
        })?;
        drop(file);

        crate::windows_secret::replace_file(&tmp_path, path).map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!(
                    "Failed to replace secret file {} with {}: {error}",
                    path.display(),
                    tmp_path.display()
                ),
                true,
            )
        })?;

        crate::windows_secret::protect_path(path).map_err(|error| {
            RuntimeError::secret(
                playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
                format!("Failed to secure secret file {}: {error}", path.display()),
                true,
            )
        })?;

        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }

    result
}

#[cfg(all(not(unix), not(windows)))]
async fn secure_write_secret_file(path: &Path, content: &[u8]) -> Result<(), RuntimeError> {
    tokio::fs::write(path, content).await.map_err(|error| {
        RuntimeError::secret(
            playit_ipc::model::ServiceErrorCode::SecretWriteFailed,
            format!("Failed to write secret file {}: {error}", path.display()),
            true,
        )
    })
}

fn parse_secret_file(content: &str) -> Result<String, ()> {
    let trimmed = content.trim();
    if let Ok(secret) = validate_secret(trimmed) {
        return Ok(secret);
    }

    let config = toml::from_str::<SecretConfig>(content).map_err(|_| ())?;
    validate_secret(config.secret_key.trim()).map_err(|_| ())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SecretConfig {
    secret_key: String,
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::{
        LoadedSecret, SecretSource, load_secret_from_path, persist_secret_file, reset_secret_file,
        validate_secret,
    };

    #[test]
    fn validates_hex_secrets_and_rejects_empty_values() {
        assert_eq!(validate_secret("deadbeef").unwrap(), "deadbeef");
        assert!(validate_secret("").is_err());
        assert!(validate_secret("not-hex").is_err());
    }

    #[tokio::test]
    async fn persists_loads_and_resets_a_dedicated_secret_file() {
        let directory = std::env::temp_dir().join(format!(
            "playit-runtime-secret-{}-{}",
            std::process::id(),
            unique_test_suffix()
        ));
        let path = directory.join("nested").join("secret.toml");

        assert_eq!(
            persist_secret_file(&path, " deadbeef ").await.unwrap(),
            "deadbeef"
        );

        assert!(matches!(
            load_secret_from_path(&path).await,
            LoadedSecret::Ready(secret) if secret == "deadbeef"
        ));

        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }

        assert!(
            reset_secret_file(&path)
                .await
                .unwrap()
                .contains("Deleted secret file")
        );
        assert!(matches!(
            SecretSource::File { path: path.clone() }.load().await,
            LoadedSecret::Missing
        ));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn invalid_stored_secret_is_reported_without_being_accepted() {
        let path = std::env::temp_dir().join(format!(
            "playit-runtime-invalid-secret-{}-{}.toml",
            std::process::id(),
            unique_test_suffix()
        ));
        tokio::fs::write(&path, "secret_key = \"not-hex\"\n")
            .await
            .unwrap();

        assert!(matches!(
            load_secret_from_path(&path).await,
            LoadedSecret::Invalid(message) if message.contains("Invalid secret file")
        ));
        let _ = tokio::fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn invalid_replacement_does_not_change_an_existing_secret() {
        let directory = std::env::temp_dir().join(format!(
            "playit-runtime-secret-existing-{}-{}",
            std::process::id(),
            unique_test_suffix()
        ));
        let path = directory.join("secret.toml");

        persist_secret_file(&path, "deadbeef").await.unwrap();
        assert!(persist_secret_file(&path, "not-hex").await.is_err());
        assert!(matches!(
            load_secret_from_path(&path).await,
            LoadedSecret::Ready(secret) if secret == "deadbeef"
        ));
        let _ = std::fs::remove_dir_all(directory);
    }

    fn unique_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    }
}
