//! `playit account login/logout/status`: direct account auth without a browser.
//!
//! Sign-in exchanges an email + password for a [`playit_api_client`] account
//! session over HTTPS and stores it under the per-user config directory. The
//! password is never stored; only the returned session is written to disk,
//! with owner-only Unix permissions. See `docs/auth-flow.md`.

use std::path::PathBuf;

use playit_api_client::PlayitApi;
use playit_api_client::auth::{self, AccountSession};
use playit_api_client::session::{FileSessionStore, PersistedSession, SessionStore};

use crate::ui::ConsoleUi;
use crate::{API_BASE, CliError};

/// Where `login` stores the account session.
fn session_file() -> Result<PathBuf, CliError> {
    dirs::config_dir()
        .map(|dir| dir.join("playit-cli").join("account-session.json"))
        .ok_or_else(|| CliError::SessionError("could not locate the user config directory".into()))
}

/// Sign in and store the session for later `status` and account API use.
pub async fn run_account_login(
    console: &mut ConsoleUi,
    email: Option<String>,
    password_stdin: bool,
) -> Result<(), CliError> {
    let email = match email {
        Some(email) => email,
        None => read_line("playit.gg email").await?,
    };
    let password = read_password(password_stdin).await?;
    let session = auth::sign_in(&API_BASE, email.trim(), &password)
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?;
    let session = if session.requires_totp() {
        console
            .write_screen("this account requires a TOTP code")
            .await;
        let code = read_line("TOTP code").await?;
        auth::complete_totp(&session, code.trim())
            .await
            .map_err(|error| CliError::SessionError(error.to_string()))?
    } else {
        session
    };
    report_session(console, &session).await;
    FileSessionStore::new(session_file()?)
        .save(PersistedSession::from_account_session(&session))
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?;
    console.write_screen("account session stored").await;
    Ok(())
}

/// Show the stored session's non-secret account details.
pub async fn run_account_status(console: &mut ConsoleUi) -> Result<(), CliError> {
    let stored = load_stored_session().await?;
    console
        .write_screen(format!(
            "account {} ({}), saved at unix {}",
            stored.account_id, stored.api_base, stored.saved_at_unix
        ))
        .await;
    Ok(())
}

/// Validate the stored session with a harmless read (`POST /tunnels/list`).
///
/// Only non-secret account details are reported. A missing or expired
/// session is an error, never a silent re-login: credentials are not stored.
pub async fn run_account_validate(console: &mut ConsoleUi) -> Result<(), CliError> {
    let stored = load_stored_session().await?;
    playit_api_client::web_api::validate_with_key(&stored.api_base, &stored.session_key)
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?;
    console
        .write_screen(format!(
            "account {} session is valid ({})",
            stored.account_id, stored.api_base
        ))
        .await;
    Ok(())
}

/// Ensure a stored session exists and is still accepted by the API.
///
/// Used by `playit setup --direct` before starting the claim flow.
pub async fn require_valid_stored_session(console: &mut ConsoleUi) -> Result<(), CliError> {
    let stored = load_stored_session().await?;
    playit_api_client::web_api::validate_with_key(&stored.api_base, &stored.session_key)
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?;
    console
        .write_screen(format!(
            "using stored account {} ({})",
            stored.account_id, stored.api_base
        ))
        .await;
    Ok(())
}

/// Build an account-authenticated API client from a stored session.
pub fn stored_account_client(stored: &PersistedSession) -> PlayitApi {
    playit_api_client::PlayitApiBuilder::new(stored.api_base.clone())
        .bearer(stored.session_key.clone())
        .build()
}

/// Load the stored session and build its account-authenticated client.
pub async fn stored_client() -> Result<(PersistedSession, PlayitApi), CliError> {
    let stored = load_stored_session().await?;
    let api = stored_account_client(&stored);
    Ok((stored, api))
}

/// Prompt for one line (agent names, TOTP codes).
pub(crate) async fn prompt_line(prompt: &str) -> Result<String, CliError> {
    read_line(prompt).await
}

/// Load the stored session or explain that login is required.
async fn load_stored_session() -> Result<PersistedSession, CliError> {
    FileSessionStore::new(session_file()?)
        .load()
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?
        .ok_or_else(|| {
            CliError::SessionError("not logged in; run `playit account login` first".into())
        })
}

/// Delete the stored session. Bearer sessions have no server-side logout;
/// discarding the file ends the local session.
pub async fn run_account_logout(console: &mut ConsoleUi) -> Result<(), CliError> {
    FileSessionStore::new(session_file()?)
        .clear()
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?;
    console.write_screen("account session cleared").await;
    Ok(())
}

async fn report_session(console: &mut ConsoleUi, session: &AccountSession) {
    console
        .write_screen(format!(
            "signed in as account {} ({:?})",
            session.account_id(),
            session.account_status()
        ))
        .await;
    if session.requires_totp() {
        console
            .write_screen(
                "the stored session still requires a TOTP code; \
                run `playit account login` again to complete it.",
            )
            .await;
    }
}

async fn read_password(password_stdin: bool) -> Result<String, CliError> {
    if password_stdin {
        return read_stdin_line().await;
    }
    if let Ok(password) = std::env::var("PLAYIT_PASSWORD") {
        if password.is_empty() {
            return Err(CliError::SessionError(
                "PLAYIT_PASSWORD is set but empty".into(),
            ));
        }
        return Ok(password);
    }
    eprintln!("password input is echoed; prefer PLAYIT_PASSWORD or --password-stdin");
    read_stdin_line().await
}

async fn read_stdin_line() -> Result<String, CliError> {
    tokio::task::spawn_blocking(|| -> Result<String, CliError> {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(CliError::RenderError)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    })
    .await
    .map_err(|_| CliError::AnswerNotProvided)?
}

async fn read_line(prompt: &str) -> Result<String, CliError> {
    let prompt = format!("{prompt}: ");
    tokio::task::spawn_blocking(move || -> Result<String, CliError> {
        use std::io::Write;
        print!("{prompt}");
        std::io::stdout().flush().map_err(CliError::RenderError)?;
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(CliError::RenderError)?;
        Ok(line.trim().to_owned())
    })
    .await
    .map_err(|_| CliError::AnswerNotProvided)?
}
