//! Account session storage behind an explicit trait.
//!
//! Only the authenticated session is ever persisted — never the password
//! (which [`crate::auth::sign_in`] drops after the request) and never a TOTP
//! code. Two backends exist: an ephemeral in-memory store and a file store
//! that restricts Unix permissions to the owner. Neither encrypts at rest;
//! prefer the memory store wherever persistence across restarts is not
//! explicitly required.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::auth::AccountSession;

/// Storage format version for [`PersistedSession`].
pub const SESSION_FORMAT_VERSION: u32 = 1;

/// A serializable account session, ready for a storage backend.
///
/// `session_key` is a secret with the same handling rules as the live
/// session: never log it, never put it in an error message.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedSession {
    /// Format version for future migration.
    pub version: u32,
    /// The API base URL the session was issued against.
    pub api_base: String,
    /// The secret session key. Handle with care.
    pub session_key: String,
    /// The account id from the session token, for display/matching only.
    pub account_id: u64,
    /// Unix seconds when this snapshot was saved.
    pub saved_at_unix: u64,
}

impl std::fmt::Debug for PersistedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistedSession")
            .field("version", &self.version)
            .field("api_base", &self.api_base)
            .field("session_key", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("saved_at_unix", &self.saved_at_unix)
            .finish()
    }
}

impl PersistedSession {
    /// Snapshot a live [`AccountSession`] for storage.
    pub fn from_account_session(session: &AccountSession) -> Self {
        Self {
            version: SESSION_FORMAT_VERSION,
            api_base: session.api_base().to_owned(),
            session_key: session.session().session_key.clone(),
            account_id: session.account_id(),
            saved_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

/// Storage for at most one account session.
///
/// Methods return `Send` futures so stores remain usable from any async
/// runtime thread. Implementations may still use `async fn`.
pub trait SessionStore: Send + Sync {
    /// Persist `session`, replacing any previously stored session.
    fn save(
        &self,
        session: PersistedSession,
    ) -> impl std::future::Future<Output = Result<(), SessionStoreError>> + Send;
    /// Load the stored session, if any.
    fn load(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<PersistedSession>, SessionStoreError>> + Send;
    /// Delete any stored session material.
    fn clear(&self) -> impl std::future::Future<Output = Result<(), SessionStoreError>> + Send;
}

/// A failed session-store operation.
#[derive(Debug)]
pub enum SessionStoreError {
    /// The backend is unavailable or refused the operation.
    Unavailable(String),
}

impl std::fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(error) => write!(f, "session store unavailable: {error}"),
        }
    }
}

impl std::error::Error for SessionStoreError {}

/// Ephemeral in-memory session storage.
///
/// Sessions live only as long as this value. This is the default until an
/// encrypted durable backend exists; prefer it wherever persistence across
/// restarts is not explicitly required.
#[derive(Debug, Default)]
pub struct MemorySessionStore {
    inner: RwLock<Option<PersistedSession>>,
}

impl MemorySessionStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    async fn save(&self, session: PersistedSession) -> Result<(), SessionStoreError> {
        *self.inner.write().await = Some(session);
        Ok(())
    }

    async fn load(&self) -> Result<Option<PersistedSession>, SessionStoreError> {
        Ok(self.inner.read().await.clone())
    }

    async fn clear(&self) -> Result<(), SessionStoreError> {
        *self.inner.write().await = None;
        Ok(())
    }
}

/// File-backed session storage as JSON.
///
/// The file is created with owner-only permissions on Unix; group/other
/// access on Windows remains the administrator's responsibility. The payload
/// is not encrypted: anyone who can read the file as your user gets the
/// session. `clear` deletes the file.
#[derive(Debug, Clone)]
pub struct FileSessionStore {
    path: PathBuf,
}

impl FileSessionStore {
    /// Store the session at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SessionStore for FileSessionStore {
    async fn save(&self, session: PersistedSession) -> Result<(), SessionStoreError> {
        let body = serde_json::to_string_pretty(&session)
            .map_err(|error| SessionStoreError::Unavailable(error.to_string()))?;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(io_unavailable)?;
        }
        tokio::fs::write(&self.path, body)
            .await
            .map_err(io_unavailable)?;
        restrict_to_owner(&self.path).await?;
        Ok(())
    }

    async fn load(&self) -> Result<Option<PersistedSession>, SessionStoreError> {
        let body = match tokio::fs::read(&self.path).await {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_unavailable(error)),
        };
        if body.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(None);
        }
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|error| SessionStoreError::Unavailable(error.to_string()))
    }

    async fn clear(&self) -> Result<(), SessionStoreError> {
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_unavailable(error)),
        }
    }
}

fn io_unavailable(error: std::io::Error) -> SessionStoreError {
    SessionStoreError::Unavailable(error.to_string())
}

/// Restrict an existing file to owner read/write on Unix. Best effort
/// elsewhere, where portable mode bits do not exist.
async fn restrict_to_owner(path: &Path) -> Result<(), SessionStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(io_unavailable)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AccountStatus, TotpStatus, WebAuthToken, WebSession};

    fn persisted() -> PersistedSession {
        PersistedSession::from_account_session(&AccountSession::new(
            "https://api.playit.gg",
            WebSession {
                session_key: "super-secret-session-key".into(),
                auth: WebAuthToken {
                    update_version: 1,
                    account_id: 42,
                    timestamp: 1,
                    account_status: AccountStatus::Verified,
                    totp_status: TotpStatus::NotSetup,
                    admin_id: None,
                    admin_review_id: None,
                    read_only: false,
                    show_admin: false,
                },
            },
        ))
    }

    fn scratch_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "playit-session-{}-{}-{}.json",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must be after the Unix epoch")
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn memory_store_roundtrips_and_clears() {
        let store = MemorySessionStore::new();
        assert!(store.load().await.unwrap().is_none());

        store.save(persisted()).await.unwrap();
        let loaded = store.load().await.unwrap().expect("session saved");
        assert_eq!(loaded.session_key, "super-secret-session-key");
        assert_eq!(loaded.account_id, 42);
        assert_eq!(loaded.version, SESSION_FORMAT_VERSION);

        let mut second = persisted();
        second.account_id = 7;
        store.save(second).await.unwrap();
        assert_eq!(store.load().await.unwrap().unwrap().account_id, 7);

        store.clear().await.unwrap();
        assert!(store.load().await.unwrap().is_none());
    }

    #[test]
    fn persisted_debug_never_exposes_the_session_key() {
        let rendered = format!("{:?}", persisted());
        assert!(
            !rendered.contains("super-secret-session-key"),
            "Debug must not leak the session key: {rendered}"
        );
        assert!(rendered.contains("42"));
    }

    #[tokio::test]
    async fn file_store_roundtrips_and_clears() {
        let path = scratch_path("roundtrip");
        let store = FileSessionStore::new(&path);
        assert!(store.load().await.unwrap().is_none());

        store.save(persisted()).await.unwrap();
        let loaded = store.load().await.unwrap().expect("session saved");
        assert_eq!(loaded.session_key, "super-secret-session-key");
        assert_eq!(loaded.account_id, 42);

        store.clear().await.unwrap();
        assert!(store.load().await.unwrap().is_none());
        assert!(!path.exists());
        store.clear().await.unwrap();
    }

    #[tokio::test]
    async fn file_store_rejects_corrupt_content() {
        let path = scratch_path("corrupt");
        let store = FileSessionStore::new(&path);
        tokio::fs::write(&path, "{not json").await.unwrap();
        assert!(store.load().await.is_err());
        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_store_restricts_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = scratch_path("perms");
        let store = FileSessionStore::new(&path);
        store.save(persisted()).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "session file must be owner-only");
        store.clear().await.unwrap();
    }
}
