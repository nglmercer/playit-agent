//! Live end-to-end verification against the real Playit API.
//!
//! These tests run ONLY when a gitignored `.env` file (workspace root or
//! `packages/api_client/.env`) provides `PLAYIT_TEST_EMAIL` and
//! `PLAYIT_TEST_PASSWORD`. Without credentials every test passes trivially
//! with a skip notice, so plain `cargo test` and CI stay green.
//!
//! Use a disposable test account. Real environment variables win over
//! `.env` values. Mutations are limited to self-restoring round-trips:
//!
//! - `POST /claim/setup` with a fresh random code (anonymous, no side
//!   effects; ends at `WaitingForUserVisit`).
//! - Tunnel rename round-trip, only when `PLAYIT_TEST_TUNNEL_ID` names a
//!   tunnel (restores the original name afterwards).
//! - Tunnel create/delete lifecycle, only when `PLAYIT_TEST_AGENT_ID`
//!   names an agent (deletes what it creates).
//!
//! Never commit `.env`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use playit_api_client::api::{
    ApiResult, AssignedAgentCreate, ClaimAgentType, ClaimSetupResponse, PortType, ReqClaimExchange,
    ReqClaimSetup, ReqTunnelsCreate, ReqTunnelsDelete, ReqTunnelsList, ReqTunnelsRename,
    TunnelOriginCreate, TunnelType,
};
use playit_api_client::{PlayitApi, auth, web_api};

/// Credentials and optional mutation targets loaded from `.env`/env.
struct LiveConfig {
    api_base: String,
    email: String,
    password: String,
    tunnel_id: Option<uuid::Uuid>,
    agent_id: Option<uuid::Uuid>,
}

/// Parse a dotenv-style file (`KEY=value`, `#` comments, blank lines).
fn parse_dotenv(path: &PathBuf, into: &mut HashMap<String, String>) {
    let Ok(body) = std::fs::read_to_string(path) else {
        return;
    };
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (key, mut value) = line.split_once('=').expect("contains '='");
        value = value.trim();
        if value.len() >= 2 && value.starts_with(['"', '\'']) && value.ends_with(['"', '\'']) {
            value = &value[1..value.len() - 1];
        }
        into.entry(key.trim().to_owned())
            .or_insert_with(|| value.to_owned());
    }
}

/// Load `.env` (workspace root, then package dir) overlaid by real env.
///
/// Returns `None` when no email/password is configured: callers must pass
/// the test with a skip notice instead of failing.
fn live_config() -> Option<LiveConfig> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut file_vars = HashMap::new();
    if let Some(root) = manifest.parent().and_then(|p| p.parent()) {
        parse_dotenv(&root.join(".env"), &mut file_vars);
    }
    parse_dotenv(&manifest.join(".env"), &mut file_vars);

    let get = |key: &str| {
        std::env::var(key)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| file_vars.get(key).cloned())
    };
    Some(LiveConfig {
        api_base: get("PLAYIT_TEST_API_BASE")
            .unwrap_or_else(|| "https://api.playit.gg".to_string()),
        email: get("PLAYIT_TEST_EMAIL")?,
        password: get("PLAYIT_TEST_PASSWORD")?,
        tunnel_id: get("PLAYIT_TEST_TUNNEL_ID").and_then(|v| v.parse().ok()),
        agent_id: get("PLAYIT_TEST_AGENT_ID").and_then(|v| v.parse().ok()),
    })
}

static CLAIM_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn fresh_claim_code() -> String {
    // 10 hex chars, matching the CLI's 5-byte claim codes. The sequence
    // counter makes parallel tests unique; the timestamp keeps runs apart.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = CLAIM_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mixed = nanos.wrapping_add(seq.wrapping_mul(0x9E3779B97F4A7C15));
    let hex = format!("{mixed:016x}");
    format!("e2e{}", &hex[hex.len() - 7..])
}

#[tokio::test]
async fn e2e_signin_validate_and_reads() {
    let Some(config) = live_config() else {
        println!("skipping live e2e: set PLAYIT_TEST_EMAIL/PLAYIT_TEST_PASSWORD in .env");
        return;
    };
    let session = auth::sign_in(&config.api_base, &config.email, &config.password)
        .await
        .expect("live sign-in succeeds");
    if session.requires_totp() {
        println!("skipping live e2e: test account requires TOTP");
        return;
    }
    session.validate().await.expect("session validates");
    let tunnels = playit_api_client::web_api::list_tunnels(&session)
        .await
        .expect("tunnels list");
    println!("live account tunnels: {}", tunnels.tunnels.len());
    playit_api_client::web_api::list_domains(&session)
        .await
        .expect("domains list");
}

#[tokio::test]
async fn e2e_claim_setup_waits_for_user() {
    let Some(config) = live_config() else {
        println!("skipping live e2e: set PLAYIT_TEST_EMAIL/PLAYIT_TEST_PASSWORD in .env");
        return;
    };
    let api = PlayitApi::create(config.api_base, None);
    let setup = api
        .claim_setup(ReqClaimSetup {
            code: fresh_claim_code(),
            agent_type: ClaimAgentType::SelfManaged,
            version: "e2e-verify".to_string(),
        })
        .await
        .expect("claim setup");
    assert!(
        matches!(
            setup,
            ClaimSetupResponse::WaitingForUserVisit | ClaimSetupResponse::WaitingForUser
        ),
        "fresh code waits for the user, got {setup:?}"
    );
    // A fresh code is never approved: exchange must report NotAccepted.
    let exchange = api
        .claim_exchange(ReqClaimExchange {
            code: fresh_claim_code(),
            // NOTE: a different fresh code is used on purpose; the setup
            // code above is left untouched for manual approval if desired.
        })
        .await;
    assert!(exchange.is_err(), "unapproved code must not exchange");
}

#[tokio::test]
async fn e2e_tunnel_rename_roundtrip() {
    let Some(config) = live_config() else {
        println!("skipping live e2e: set PLAYIT_TEST_EMAIL/PLAYIT_TEST_PASSWORD in .env");
        return;
    };
    let Some(tunnel_id) = config.tunnel_id else {
        println!("skipping rename e2e: set PLAYIT_TEST_TUNNEL_ID in .env");
        return;
    };
    let session = auth::sign_in(&config.api_base, &config.email, &config.password)
        .await
        .expect("live sign-in succeeds");
    if session.requires_totp() {
        println!("skipping rename e2e: test account requires TOTP");
        return;
    }
    let api = session.account_client();
    let list = api
        .tunnels_list(ReqTunnelsList {
            tunnel_id: Some(tunnel_id),
            agent_id: None,
        })
        .await
        .expect("tunnel lookup");
    let original = list
        .tunnels
        .first()
        .and_then(|t| t.name.clone())
        .unwrap_or_default();
    api.tunnels_rename(ReqTunnelsRename {
        tunnel_id,
        name: "e2e-tmp-rename".to_string(),
    })
    .await
    .expect("rename to temp name");
    let renamed = api
        .tunnels_list(ReqTunnelsList {
            tunnel_id: Some(tunnel_id),
            agent_id: None,
        })
        .await
        .expect("tunnel re-lookup");
    assert_eq!(
        renamed.tunnels.first().and_then(|t| t.name.as_deref()),
        Some("e2e-tmp-rename")
    );
    api.tunnels_rename(ReqTunnelsRename {
        tunnel_id,
        name: original.clone(),
    })
    .await
    .expect("rename restores original name");
    let restored = api
        .tunnels_list(ReqTunnelsList {
            tunnel_id: Some(tunnel_id),
            agent_id: None,
        })
        .await
        .expect("tunnel final lookup");
    assert_eq!(
        restored.tunnels.first().and_then(|t| t.name.clone()),
        Some(original)
    );
}

#[tokio::test]
async fn e2e_tunnel_create_delete_lifecycle() {
    let Some(config) = live_config() else {
        println!("skipping live e2e: set PLAYIT_TEST_EMAIL/PLAYIT_TEST_PASSWORD in .env");
        return;
    };
    let Some(agent_id) = config.agent_id else {
        println!("skipping lifecycle e2e: set PLAYIT_TEST_AGENT_ID in .env");
        return;
    };
    let session = auth::sign_in(&config.api_base, &config.email, &config.password)
        .await
        .expect("live sign-in succeeds");
    if session.requires_totp() {
        println!("skipping lifecycle e2e: test account requires TOTP");
        return;
    }
    let api = session.account_client();
    let created = api
        .tunnels_create(ReqTunnelsCreate {
            name: Some("e2e-tmp-lifecycle".to_string()),
            tunnel_type: Some(TunnelType::MinecraftJava),
            port_type: PortType::Tcp,
            port_count: 1,
            origin: TunnelOriginCreate::Agent(AssignedAgentCreate {
                agent_id,
                local_ip: "127.0.0.1".parse().expect("loopback parses"),
                local_port: Some(25566),
            }),
            enabled: true,
            alloc: None,
            firewall_id: None,
            proxy_protocol: None,
        })
        .await
        .expect("tunnel create");
    // Best-effort cleanup: whatever happens below, the temp tunnel goes.
    let list = api
        .tunnels_list(ReqTunnelsList {
            tunnel_id: Some(created.id),
            agent_id: None,
        })
        .await
        .expect("created tunnel is listed");
    if !list.tunnels.iter().any(|t| t.id == created.id) {
        let _ = api
            .tunnels_delete(ReqTunnelsDelete {
                tunnel_id: created.id,
            })
            .await;
        panic!("created tunnel missing from list");
    }
    api.tunnels_delete(ReqTunnelsDelete {
        tunnel_id: created.id,
    })
    .await
    .expect("tunnel delete");
    let after = api
        .tunnels_list(ReqTunnelsList {
            tunnel_id: Some(created.id),
            agent_id: None,
        })
        .await
        .expect("post-delete list");
    assert!(
        after.tunnels.iter().all(|t| t.id != created.id),
        "deleted tunnel is gone"
    );
}

/// Announce a fresh claim from the machine side until the account side
/// sees it, mirroring the CLI's approve flow.
async fn await_claim_details(api_base: &str, api: &PlayitApi, code: &str) -> web_api::ClaimDetails {
    let anon = PlayitApi::create(api_base.to_owned(), None);
    for _ in 0..20 {
        let _ = anon
            .claim_setup(ReqClaimSetup {
                code: code.to_owned(),
                agent_type: ClaimAgentType::SelfManaged,
                version: "e2e-verify".to_string(),
            })
            .await;
        match web_api::claim_details(api, code).await {
            Ok(ApiResult::Success(details)) => return details,
            Ok(ApiResult::Fail(web_api::ClaimDetailsFail::WaitingForAgent)) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Ok(other) => panic!("claim details terminal outcome: {other:?}"),
            Err(error) => panic!("claim details transport failure: {error}"),
        }
    }
    panic!("claim {code} never became visible to the account");
}

async fn signed_in_session(config: &LiveConfig) -> Option<auth::AccountSession> {
    let session = auth::sign_in(&config.api_base, &config.email, &config.password)
        .await
        .expect("live sign-in succeeds");
    if session.requires_totp() {
        println!("skipping live e2e: test account requires TOTP");
        return None;
    }
    Some(session)
}

#[tokio::test]
async fn e2e_agents_list() {
    let Some(config) = live_config() else {
        println!("skipping live e2e: set PLAYIT_TEST_EMAIL/PLAYIT_TEST_PASSWORD in .env");
        return;
    };
    let Some(session) = signed_in_session(&config).await else {
        return;
    };
    match web_api::list_agents(&session.account_client())
        .await
        .expect("agents list call completes")
    {
        ApiResult::Success(list) => println!("live account agents: {}", list.agents.len()),
        ApiResult::Fail(fail) => panic!("agents list fail: {fail:?}"),
        ApiResult::Error(error) => panic!("agents list error: {error:?}"),
    }
}

#[tokio::test]
async fn e2e_claim_reject_lifecycle() {
    let Some(config) = live_config() else {
        println!("skipping live e2e: set PLAYIT_TEST_EMAIL/PLAYIT_TEST_PASSWORD in .env");
        return;
    };
    let Some(session) = signed_in_session(&config).await else {
        return;
    };
    let api = session.account_client();
    let code = fresh_claim_code();
    let details = await_claim_details(&config.api_base, &api, &code).await;
    assert_eq!(details.agent_type, ClaimAgentType::SelfManaged);
    match web_api::reject_claim(&api, &code)
        .await
        .expect("reject call completes")
    {
        ApiResult::Success(()) => {}
        other => panic!("reject failed: {other:?}"),
    }
    match web_api::claim_details(&api, &code)
        .await
        .expect("details call completes")
    {
        ApiResult::Fail(web_api::ClaimDetailsFail::AlreadyRejected) => {}
        other => panic!("expected AlreadyRejected after reject, got {other:?}"),
    }
}

#[tokio::test]
async fn e2e_claim_accept_delete_lifecycle() {
    let Some(config) = live_config() else {
        println!("skipping live e2e: set PLAYIT_TEST_EMAIL/PLAYIT_TEST_PASSWORD in .env");
        return;
    };
    if std::env::var("PLAYIT_TEST_AGENT_CREATE").as_deref() != Ok("1") {
        println!("skipping agent-create e2e: set PLAYIT_TEST_AGENT_CREATE=1 in .env");
        return;
    }
    let Some(session) = signed_in_session(&config).await else {
        return;
    };
    let api = session.account_client();
    let code = fresh_claim_code();
    await_claim_details(&config.api_base, &api, &code).await;
    let agent_id =
        match web_api::accept_claim(&api, &code, "e2e-tmp-agent", ClaimAgentType::SelfManaged)
            .await
            .expect("accept call completes")
        {
            ApiResult::Success(accepted) => accepted.agent_id,
            other => panic!("accept failed: {other:?}"),
        };
    // Best-effort cleanup: the temp agent goes whatever happens below.
    let delete = || async {
        web_api::delete_agent(
            &api,
            web_api::ReqAgentsDelete {
                agent_id,
                tunnels_strategy: web_api::TunnelsStrategy::MoveToAgent(
                    web_api::AgentDeleteMoveDetails {
                        agent_id: None,
                        disable_tunnels: false,
                    },
                ),
            },
        )
        .await
    };
    let listed = match web_api::list_agents(&api)
        .await
        .expect("list call completes")
    {
        ApiResult::Success(list) => list.agents.iter().any(|a| a.id == agent_id),
        other => {
            let _ = delete().await;
            panic!("list failed: {other:?}");
        }
    };
    if !listed {
        let _ = delete().await;
        panic!("accepted agent missing from list");
    }
    match delete().await.expect("delete call completes") {
        ApiResult::Success(()) => {}
        other => panic!("delete failed: {other:?}"),
    }
    match web_api::list_agents(&api)
        .await
        .expect("final list completes")
    {
        ApiResult::Success(list) => assert!(
            list.agents.iter().all(|a| a.id != agent_id),
            "deleted agent is gone"
        ),
        other => panic!("final list failed: {other:?}"),
    }
}
