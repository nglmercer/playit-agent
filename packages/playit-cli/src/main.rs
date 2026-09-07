use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::LazyLock;
use std::time::Duration;

use clap::{Parser, Subcommand};
use client::{
    AttachMode, CliTarget, ensure_service_waiting_for_secret, provision_service_secret,
    run_account_login_url_command, run_attach_command, run_auto_command, run_reset_command,
    run_secret_path_command, run_start_command, run_status_command, run_stop_command,
};
use playit_agent_core::agent_control::platform::current_platform;
use playit_agent_core::agent_control::version::{help_register_version, register_platform};
use rand::Rng;
use service::ServiceManagerMode;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use playit_agent_core::agent_control::errors::SetupError;
use playit_agent_core::utils::now_milli;
use playit_api_client::http_client::HttpClientError;
use playit_api_client::{PlayitApi, api::*, web_api};

use crate::signal_handle::get_signal_handle;
use crate::ui::{ConsoleUi, UISettings};

pub static API_BASE: LazyLock<String> =
    LazyLock::new(|| dotenv::var("API_BASE").unwrap_or("https://api.playit.gg".to_string()));

mod account;
mod client;
#[cfg(target_os = "linux")]
mod linux;
mod service;
pub mod signal_handle;
pub mod ui;
pub mod util;

#[derive(Parser)]
#[command(name = "playit-cli")]
struct Cli {
    /// Prints logs to stdout
    #[arg(short = 's', long)]
    stdout: bool,

    /// Override the IPC socket or named pipe used to reach playitd
    #[arg(long)]
    socket_path: Option<String>,

    #[cfg(target_os = "linux")]
    #[arg(long, conflicts_with = "openrc")]
    systemd: bool,

    #[cfg(target_os = "linux")]
    #[arg(long, conflicts_with = "systemd")]
    openrc: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Print version information
    Version,

    /// Attach to a running playitd service
    Attach {
        /// Print logs to stdout instead of using TUI
        #[arg(short = 's', long)]
        stdout: bool,
    },

    /// Start the installed playitd service
    Start,

    /// Stop the installed playitd service
    Stop,

    /// Show the status of the installed playitd service
    Status,

    /// Removes the secret key on your system so the playit agent can be re-claimed
    Reset,

    /// Shows the file path where the playit secret can be found
    SecretPath,

    /// Setup playit by provisioning a new secret to playitd
    Setup {
        /// Run the whole claim with the stored account session: validate it,
        /// approve the claim directly, exchange it, and provision playitd.
        /// No browser needed.
        #[arg(long)]
        direct: bool,
        /// Agent name for `--direct` (prompted when omitted).
        #[arg(long)]
        name: Option<String>,
    },

    /// Account agent management over the direct API (stored session).
    Agents {
        #[command(subcommand)]
        command: AgentCommands,
    },

    /// Account management commands
    Account {
        #[command(subcommand)]
        command: AccountCommands,
    },

    /// Setting up a new playit agent
    #[command(
        about = "Setting up a new playit agent",
        long_about = "Provides a URL that can be visited to claim the agent and generate a secret key"
    )]
    Claim {
        #[command(subcommand)]
        command: ClaimCommands,
    },
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Generates a link to allow user to login
    LoginUrl,
    /// Sign in with a playit.gg email + password and store the session.
    ///
    /// The password comes from --password-stdin, the PLAYIT_PASSWORD
    /// environment variable, or an interactive stdin prompt. It is never
    /// stored; only the returned session is written to disk.
    Login {
        /// The playit.gg account email (prompted when omitted).
        #[arg(long)]
        email: Option<String>,
        /// Read the password from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Delete the stored account session.
    Logout,
    /// Show the stored session's non-secret account details.
    Status,
    /// Validate the stored session with a harmless authenticated read.
    Validate,
}

#[derive(Subcommand)]
enum ClaimCommands {
    /// Generates a random claim code
    Generate,

    /// Print a claim URL given the code and options
    Url {
        /// Claim code
        claim_code: String,

        /// Name for the agent
        #[arg(long, default_value = "from-cli")]
        name: String,

        /// The agent type
        #[arg(long, default_value = "self-managed")]
        r#type: String,
    },

    /// Exchanges the claim for the secret key
    Exchange {
        /// Claim code (see "claim generate")
        claim_code: String,

        /// Number of seconds to wait (0=infinite)
        #[arg(long, default_value = "0")]
        wait: u32,
    },

    /// Show the current machine-side status of a claim code (direct API).
    Inspect {
        /// Claim code (see "claim generate")
        claim_code: String,
    },

    /// Approve a claim with the stored account session (direct API).
    Approve {
        /// Claim code (see "claim generate")
        claim_code: String,

        /// Agent name (prompted when omitted).
        #[arg(long)]
        name: Option<String>,

        /// Agent type: `assignable` or `self-managed` (default self-managed).
        #[arg(long)]
        agent_type: Option<String>,
    },

    /// Reject a claim with the stored account session (direct API).
    Reject {
        /// Claim code (see "claim generate")
        claim_code: String,
    },
}

#[derive(Subcommand)]
enum AgentCommands {
    /// List the account's agents.
    List,

    /// Delete an agent. Its tunnels are unassigned unless
    /// `--move-tunnels-to` names another agent.
    Delete {
        /// Agent UUID.
        agent_id: String,

        /// Move the agent's tunnels to this agent instead of unassigning.
        #[arg(long)]
        move_tunnels_to: Option<String>,

        /// Disable the affected tunnels.
        #[arg(long)]
        disable_tunnels: bool,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run_cli().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run_cli() -> Result<std::process::ExitCode, CliError> {
    let cli = Cli::parse();

    /* register docker */
    {
        let platform = current_platform();

        register_platform(platform);

        help_register_version(
            env!("CARGO_PKG_VERSION"),
            "308943e8-faef-4835-a2ba-270351f72aa3",
        );
    }

    let target = CliTarget::from_socket_path(cli.socket_path.clone());
    let service_manager = service_manager_mode(&cli);
    let attach_stdout = matches!(&cli.command, Some(Commands::Attach { stdout: true, .. }));
    let stdout_mode = cli.stdout || attach_stdout;
    let attach_mode = if stdout_mode {
        AttachMode::Stdout
    } else {
        AttachMode::Interactive
    };

    let _guard = if stdout_mode {
        Some(init_stdout_tracing())
    } else {
        None
    };

    let mut console = ConsoleUi::new(UISettings { auto_answer: None });

    match cli.command {
        None => {
            run_auto_command(&mut console, &target, attach_mode, service_manager).await?;
        }
        Some(Commands::Attach { stdout }) => {
            let attach_mode = if cli.stdout || stdout {
                AttachMode::Stdout
            } else {
                AttachMode::Interactive
            };
            run_attach_command(&target, attach_mode).await?;
        }
        Some(Commands::Start) => {
            run_start_command(&mut console, &target, service_manager).await?;
        }
        Some(Commands::Stop) => {
            run_stop_command(&target, service_manager).await?;
        }
        Some(Commands::Status) => {
            run_status_command(&target).await?;
        }
        Some(Commands::Version) => println!("{}", env!("CARGO_PKG_VERSION")),
        Some(Commands::Setup { direct, name }) => {
            run_setup_flow(&mut console, &target, service_manager, direct, name).await?;
        }
        Some(Commands::Agents { command }) => match command {
            AgentCommands::List => {
                agents_list(&mut console).await?;
            }
            AgentCommands::Delete {
                agent_id,
                move_tunnels_to,
                disable_tunnels,
            } => {
                agents_delete(&mut console, &agent_id, move_tunnels_to, disable_tunnels).await?;
            }
        },
        Some(Commands::Reset) => {
            run_reset_command(&target).await?;
        }
        Some(Commands::SecretPath) => {
            run_secret_path_command(&target).await?;
        }
        Some(Commands::Account { ref command }) => match command {
            AccountCommands::LoginUrl => {
                run_account_login_url_command(&target).await?;
            }
            AccountCommands::Login {
                email,
                password_stdin,
            } => {
                crate::account::run_account_login(&mut console, email.clone(), *password_stdin)
                    .await?;
            }
            AccountCommands::Logout => {
                crate::account::run_account_logout(&mut console).await?;
            }
            AccountCommands::Status => {
                crate::account::run_account_status(&mut console).await?;
            }
            AccountCommands::Validate => {
                crate::account::run_account_validate(&mut console).await?;
            }
        },
        Some(Commands::Claim { command }) => match command {
            ClaimCommands::Generate => {
                console.write_screen(claim_generate()).await;
            }
            ClaimCommands::Url { claim_code, .. } => {
                console
                    .write_screen(claim_url(&claim_code)?.to_string())
                    .await;
            }
            ClaimCommands::Exchange { claim_code, wait } => {
                let secret_key =
                    claim_exchange(&mut console, &claim_code, ClaimAgentType::SelfManaged, wait)
                        .await?;
                console.write_screen(secret_key).await;
            }
            ClaimCommands::Inspect { claim_code } => {
                claim_inspect(&mut console, &claim_code).await?;
            }
            ClaimCommands::Approve {
                claim_code,
                name,
                agent_type,
            } => {
                claim_approve(&mut console, &claim_code, name, agent_type).await?;
            }
            ClaimCommands::Reject { claim_code } => {
                claim_reject(&mut console, &claim_code).await?;
            }
        },
    }

    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(target_os = "linux")]
fn service_manager_mode(cli: &Cli) -> ServiceManagerMode {
    match (cli.systemd, cli.openrc) {
        (true, false) => ServiceManagerMode::Systemd,
        (false, true) => ServiceManagerMode::OpenRc,
        (false, false) => ServiceManagerMode::None,
        (true, true) => unreachable!("clap conflicts_with prevents this"),
    }
}

#[cfg(target_os = "windows")]
fn service_manager_mode(_cli: &Cli) -> ServiceManagerMode {
    ServiceManagerMode::WindowsService
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn service_manager_mode(_cli: &Cli) -> ServiceManagerMode {
    ServiceManagerMode::Native
}

fn init_stdout_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let log_filter =
        EnvFilter::try_from_env("PLAYIT_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_ansi(current_platform() == Platform::Linux)
        .with_writer(non_blocking)
        .with_env_filter(log_filter)
        .init();
    guard
}

pub async fn run_setup_flow(
    console: &mut ConsoleUi,
    target: &CliTarget,
    service_manager: ServiceManagerMode,
    direct: bool,
    name: Option<String>,
) -> Result<(), CliError> {
    if direct {
        crate::account::require_valid_stored_session(console).await?;
        ensure_service_waiting_for_secret(console, target, service_manager).await?;
        let claim_code = claim_generate();
        claim_approve(console, &claim_code, name, None).await?;
        let key = claim_exchange(console, &claim_code, ClaimAgentType::Assignable, 0).await?;
        provision_service_secret(console, target, &key, service_manager).await?;
        console
            .write_screen("playit setup is complete. The background service is ready.")
            .await;
        return Ok(());
    }
    ensure_service_waiting_for_secret(console, target, service_manager).await?;

    let claim_code = claim_generate();
    console
        .write_screen(format!(
            "Open this link to finish setting up playit:\n{}",
            claim_url(&claim_code)?
        ))
        .await;

    let key = claim_exchange(console, &claim_code, ClaimAgentType::Assignable, 0).await?;
    provision_service_secret(console, target, &key, service_manager).await?;

    if !direct {
        let api = PlayitApi::create(API_BASE.to_string(), Some(key));
        if let Ok(session) = api.login_guest().await {
            console
                .write_screen(format!(
                    "Guest login:\nhttps://playit.gg/login/guest-account/{}",
                    session.session_key
                ))
                .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    console
        .write_screen("playit setup is complete. The background service is ready.")
        .await;
    Ok(())
}

/// Report the current machine-side status of a claim code (direct API).
///
/// This performs a single `/claim/setup` status poll — the same request the
/// exchange loop sends while waiting — without starting an exchange.
pub async fn claim_inspect(console: &mut ConsoleUi, claim_code: &str) -> Result<(), CliError> {
    let api = PlayitApi::create(API_BASE.to_string(), None);
    let setup = api
        .claim_setup(ReqClaimSetup {
            code: claim_code.to_string(),
            agent_type: ClaimAgentType::SelfManaged,
            version: format!("playit {}", env!("CARGO_PKG_VERSION")),
        })
        .await?;
    console
        .write_screen(format!("claim {claim_code}: {setup:?}"))
        .await;
    Ok(())
}

/// Parse a `--agent-type` flag into the API enum.
fn parse_claim_agent_type(value: Option<String>) -> Result<ClaimAgentType, CliError> {
    match value.as_deref().map(str::trim) {
        None | Some("") | Some("self-managed") => Ok(ClaimAgentType::SelfManaged),
        Some("assignable") => Ok(ClaimAgentType::Assignable),
        Some(other) => Err(CliError::ApiFail(format!(
            "invalid --agent-type {other:?}: expected `assignable` or `self-managed`"
        ))),
    }
}

/// Announce a claim from the machine side and wait until the account side
/// can see it (`POST /claim/details` success).
///
/// Each round sends one anonymous `/claim/setup` poll (the same request the
/// exchange loop sends) and then looks the code up. `WaitingForAgent`
/// retries; any other failure is terminal for this code.
async fn await_claim_details(
    api: &PlayitApi,
    claim_code: &str,
) -> Result<web_api::ClaimDetails, CliError> {
    let anon = PlayitApi::create(API_BASE.to_string(), None);
    for _ in 0..40 {
        let _ = anon
            .claim_setup(ReqClaimSetup {
                code: claim_code.to_string(),
                agent_type: ClaimAgentType::SelfManaged,
                version: format!("playit {}", env!("CARGO_PKG_VERSION")),
            })
            .await;
        match web_api::claim_details(api, claim_code)
            .await
            .map_err(|error| CliError::SessionError(error.to_string()))?
        {
            ApiResult::Success(details) => return Ok(details),
            ApiResult::Fail(web_api::ClaimDetailsFail::WaitingForAgent) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ApiResult::Fail(fail) => {
                return Err(CliError::ApiFail(format!(
                    "cannot use claim {claim_code}: {fail:?}"
                )));
            }
            ApiResult::Error(error) => return Err(CliError::ApiError(error)),
        }
    }
    Err(CliError::ApiFail(format!(
        "timed out waiting for claim {claim_code} to become visible; \
        is the machine polling this code?"
    )))
}

/// Approve a claim as the stored account (`POST /claim/accept`).
pub async fn claim_approve(
    console: &mut ConsoleUi,
    claim_code: &str,
    name: Option<String>,
    agent_type: Option<String>,
) -> Result<(), CliError> {
    claim_url(claim_code)?;
    let (_stored, api) = crate::account::stored_client().await?;
    let details = await_claim_details(&api, claim_code).await?;
    console
        .write_screen(format!(
            "claim {claim_code}: {:?} named {:?}",
            details.agent_type, details.name
        ))
        .await;
    let name = match name {
        Some(name) if !name.trim().is_empty() => name,
        _ => crate::account::prompt_line("agent name").await?,
    };
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err(CliError::ApiFail(
            "agent name must not be empty".to_string(),
        ));
    }
    let agent_type = parse_claim_agent_type(agent_type)?;
    match web_api::accept_claim(&api, claim_code, &name, agent_type)
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?
    {
        ApiResult::Success(accepted) => {
            console
                .write_screen(format!(
                    "claim approved, agent {} ({name})",
                    accepted.agent_id
                ))
                .await;
            console
                .write_screen(format!(
                    "run `claim exchange {claim_code}` to fetch the agent secret"
                ))
                .await;
        }
        ApiResult::Fail(fail) => {
            return Err(CliError::ApiFail(format!(
                "claim {claim_code} was not approved: {fail:?}"
            )));
        }
        ApiResult::Error(error) => return Err(CliError::ApiError(error)),
    }
    Ok(())
}

/// Reject a claim as the stored account (`POST /claim/reject`).
pub async fn claim_reject(console: &mut ConsoleUi, claim_code: &str) -> Result<(), CliError> {
    claim_url(claim_code)?;
    let (_stored, api) = crate::account::stored_client().await?;
    match web_api::reject_claim(&api, claim_code)
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?
    {
        ApiResult::Success(()) => {
            console
                .write_screen(format!("claim {claim_code} rejected"))
                .await;
        }
        ApiResult::Fail(fail) => {
            return Err(CliError::ApiFail(format!(
                "claim {claim_code} was not rejected: {fail:?}"
            )));
        }
        ApiResult::Error(error) => return Err(CliError::ApiError(error)),
    }
    Ok(())
}

/// List the account's agents (`POST /agents/list`).
pub async fn agents_list(console: &mut ConsoleUi) -> Result<(), CliError> {
    let (_stored, api) = crate::account::stored_client().await?;
    match web_api::list_agents(&api)
        .await
        .map_err(|error| CliError::SessionError(error.to_string()))?
    {
        ApiResult::Success(list) => {
            if list.agents.is_empty() {
                console.write_screen("no agents").await;
            }
            for agent in &list.agents {
                console
                    .write_screen(format!("{} {}", agent.id, agent.name))
                    .await;
            }
        }
        ApiResult::Fail(fail) => {
            return Err(CliError::ApiFail(format!(
                "agents list failed: {}",
                serde_json::to_string(&fail).unwrap_or_else(|_| "{unserializable}".to_string())
            )));
        }
        ApiResult::Error(error) => return Err(CliError::ApiError(error)),
    }
    Ok(())
}

/// Delete an agent (`POST /agents/delete`).
pub async fn agents_delete(
    console: &mut ConsoleUi,
    agent_id: &str,
    move_tunnels_to: Option<String>,
    disable_tunnels: bool,
) -> Result<(), CliError> {
    let agent_id: Uuid = agent_id
        .trim()
        .parse()
        .map_err(|_| CliError::ApiFail(format!("invalid agent id: {agent_id}")))?;
    let move_to: Option<Uuid> = move_tunnels_to
        .map(|id| {
            id.trim()
                .parse()
                .map_err(|_| CliError::ApiFail(format!("invalid --move-tunnels-to agent id: {id}")))
        })
        .transpose()?;
    let (_stored, api) = crate::account::stored_client().await?;
    match web_api::delete_agent(
        &api,
        web_api::ReqAgentsDelete {
            agent_id,
            tunnels_strategy: web_api::TunnelsStrategy::MoveToAgent(
                web_api::AgentDeleteMoveDetails {
                    agent_id: move_to,
                    disable_tunnels,
                },
            ),
        },
    )
    .await
    .map_err(|error| CliError::SessionError(error.to_string()))?
    {
        ApiResult::Success(()) => {
            console
                .write_screen(format!("agent {agent_id} deleted"))
                .await;
        }
        ApiResult::Fail(fail) => {
            return Err(CliError::ApiFail(format!(
                "agent {agent_id} was not deleted: {}",
                serde_json::to_string(&fail).unwrap_or_else(|_| "{unserializable}".to_string())
            )));
        }
        ApiResult::Error(error) => return Err(CliError::ApiError(error)),
    }
    Ok(())
}

pub fn claim_generate() -> String {
    let mut buffer = [0u8; 5];
    rand::rng().fill(&mut buffer);
    hex::encode(&buffer)
}

pub fn claim_url(code: &str) -> Result<String, CliError> {
    if hex::decode(code).is_err() {
        return Err(CliError::InvalidClaimCode);
    }

    Ok(format!("https://playit.gg/claim/{}", code,))
}

pub async fn claim_exchange(
    console: &mut ConsoleUi,
    claim_code: &str,
    agent_type: ClaimAgentType,
    wait_sec: u32,
) -> Result<String, CliError> {
    let api = PlayitApi::create(API_BASE.to_string(), None);

    let end_at = if wait_sec == 0 {
        u64::MAX
    } else {
        now_milli() + (wait_sec as u64) * 1000
    };

    {
        let _close_guard = get_signal_handle().close_guard();
        let mut last_message = "Preparing setup...".to_string();

        loop {
            let setup_res = api
                .claim_setup(ReqClaimSetup {
                    code: claim_code.to_string(),
                    agent_type,
                    version: format!("playit {}", env!("CARGO_PKG_VERSION")),
                })
                .await;

            let setup = match setup_res {
                Ok(v) => v,
                Err(error) => {
                    tracing::error!(?error, "Failed loading claim setup");
                    console
                        .write_screen(format!("{}\n\nError: {:?}", last_message, error))
                        .await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            last_message = match setup {
                ClaimSetupResponse::WaitingForUserVisit => {
                    format!(
                        "Open this link to finish setting up playit:\n{}",
                        claim_url(claim_code)?
                    )
                }
                ClaimSetupResponse::WaitingForUser => {
                    format!(
                        "Approve this program in your browser:\n{}",
                        claim_url(claim_code)?
                    )
                }
                ClaimSetupResponse::UserAccepted => {
                    console
                        .write_screen("Program approved. Finishing setup...")
                        .await;
                    break;
                }
                ClaimSetupResponse::UserRejected => {
                    console
                        .write_screen("Setup was not approved in the browser.")
                        .await;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    return Err(CliError::AgentClaimRejected);
                }
            };

            console.write_screen(&last_message).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    let secret_key = loop {
        match api
            .claim_exchange(ReqClaimExchange {
                code: claim_code.to_string(),
            })
            .await
        {
            Ok(res) => break res.secret_key,
            Err(ApiError::Fail(status)) => {
                let msg = format!(
                    "Waiting for claim code \"{}\" to be approved: {:?}",
                    claim_code, status
                );
                console.write_screen(msg).await;
            }
            Err(error) => return Err(error.into()),
        };

        if now_milli() > end_at {
            console
                .write_screen("Setup timed out before the program was approved.")
                .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            return Err(CliError::TimedOut);
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    Ok(secret_key)
}

#[derive(Debug)]
pub enum CliError {
    InvalidClaimCode,
    NotImplemented,
    MissingSecret,
    MalformedSecret,
    InvalidSecret,
    RenderError(std::io::Error),
    SecretFileLoadError,
    SecretFileWriteError(std::io::Error),
    SecretFilePathMissing,
    InvalidPortType,
    InvalidPortCount,
    InvalidMappingOverride,
    AgentClaimRejected,
    InvalidConfigFile,
    TunnelNotFound(Uuid),
    TimedOut,
    AnswerNotProvided,
    SessionError(String),
    TunnelOverwrittenAlready(Uuid),
    ResourceNotFoundAfterCreate(Uuid),
    RequestError(HttpClientError),
    ApiError(ApiResponseError),
    ApiFail(String),
    TunnelSetupError(SetupError),
    ServiceError(String),
    IpcError(String),
}

impl Error for CliError {}

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceError(message)
            | Self::IpcError(message)
            | Self::ApiFail(message)
            | Self::SessionError(message) => {
                write!(f, "{message}")
            }
            _ => write!(f, "{:?}", self),
        }
    }
}

impl<F: serde::Serialize> From<ApiError<F, HttpClientError>> for CliError {
    fn from(e: ApiError<F, HttpClientError>) -> Self {
        match e {
            ApiError::ApiError(e) => CliError::ApiError(e),
            ApiError::ClientError(e) => CliError::RequestError(e),
            ApiError::Fail(fail) => CliError::ApiFail(serde_json::to_string(&fail).unwrap()),
        }
    }
}

impl From<ApiErrorNoFail<HttpClientError>> for CliError {
    fn from(e: ApiErrorNoFail<HttpClientError>) -> Self {
        match e {
            ApiErrorNoFail::UnexpectedFail => {
                CliError::ApiFail("unexpected API fail response".to_string())
            }
            ApiErrorNoFail::ApiError(e) => CliError::ApiError(e),
            ApiErrorNoFail::ClientError(e) => CliError::RequestError(e),
        }
    }
}

impl From<SetupError> for CliError {
    fn from(e: SetupError) -> Self {
        CliError::TunnelSetupError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_manager_mode_defaults_to_none() {
        let cli = Cli::try_parse_from(["playit-cli"]).unwrap();

        assert_eq!(service_manager_mode(&cli), ServiceManagerMode::None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_manager_mode_accepts_systemd() {
        let cli = Cli::try_parse_from(["playit-cli", "--systemd"]).unwrap();

        assert_eq!(service_manager_mode(&cli), ServiceManagerMode::Systemd);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_manager_mode_accepts_openrc() {
        let cli = Cli::try_parse_from(["playit-cli", "--openrc"]).unwrap();

        assert_eq!(service_manager_mode(&cli), ServiceManagerMode::OpenRc);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_manager_flags_conflict() {
        let error = match Cli::try_parse_from(["playit-cli", "--systemd", "--openrc"]) {
            Ok(_) => panic!("expected --systemd and --openrc to conflict"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_service_manager_mode_uses_windows_service() {
        let cli = Cli::try_parse_from(["playit-cli"]).unwrap();

        assert_eq!(
            service_manager_mode(&cli),
            ServiceManagerMode::WindowsService
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_does_not_accept_linux_service_manager_flags() {
        assert!(Cli::try_parse_from(["playit-cli", "--systemd"]).is_err());
        assert!(Cli::try_parse_from(["playit-cli", "--openrc"]).is_err());
    }
}
