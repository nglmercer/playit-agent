//! Direct, embeddable Playit agent runtime.
//!
//! `PlayitRuntime` is intended to run inside an existing Tokio application. It
//! owns the Playit agent, account/claim/tunnel operations, secret persistence,
//! and state publication. It does not create an IPC endpoint, install a
//! service, install signal handlers, or initialize a tracing subscriber.

mod claim;
mod error;
mod handle;
mod options;
mod runtime;
mod secret;
mod state;
mod tunnels;

#[cfg(windows)]
mod windows_secret;

pub use error::RuntimeError;
pub use handle::PlayitHandle;
pub use options::{DEFAULT_VARIANT_ID, RuntimeOptions, VersionDetails, VersionOverrideFile};
pub use runtime::{PlayitRuntime, setup_error_user_message};

pub use playit_ipc::model::{
    AccountLoginUrlResponse, AccountResponse, AccountTunnelListResponse, AccountTunnelState,
    AgentLifecycle, AgentState, ClaimResponse, CommandResponse, ConnectionStats, NoticeState,
    PendingTunnelState, ProtocolInfo, ServiceError, ServiceErrorCode, ServicePhase, ServiceStatus,
    ServiceUpdate, SubscribeResponse, SubscriptionSnapshot, TunnelCreateResponse,
    TunnelListResponse, TunnelProtocol, TunnelState,
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::sync::broadcast;

    use super::{AgentLifecycle, PlayitRuntime, RuntimeOptions, ServiceUpdate};

    #[tokio::test]
    async fn starts_without_a_secret_and_can_be_stopped_without_ipc() {
        let secret_path = std::env::temp_dir().join(format!(
            "playit-runtime-test-{}-{}.toml",
            std::process::id(),
            unique_test_suffix()
        ));

        let options = RuntimeOptions {
            secret_path: secret_path.clone(),
            ..RuntimeOptions::default()
        };
        let (runtime, handle) = PlayitRuntime::start(options).await.unwrap();

        for _ in 0..50 {
            if matches!(handle.lifecycle().await, AgentLifecycle::WaitingForSecret) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(matches!(
            handle.lifecycle().await,
            AgentLifecycle::WaitingForSecret
        ));

        runtime.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(secret_path).await;
    }

    #[tokio::test]
    async fn direct_runtime_publishes_events_and_never_owns_an_ipc_endpoint() {
        let secret_path = std::env::temp_dir().join(format!(
            "playit-runtime-events-{}-{}.toml",
            std::process::id(),
            unique_test_suffix()
        ));
        let (runtime, handle) = PlayitRuntime::start(RuntimeOptions {
            secret_path: secret_path.clone(),
            ..RuntimeOptions::default()
        })
        .await
        .unwrap();
        let mut events = handle.subscribe();

        assert!(handle.status().await.socket_path.is_empty());
        assert!(matches!(
            handle.lifecycle().await,
            AgentLifecycle::Starting | AgentLifecycle::WaitingForSecret
        ));

        let mut saw_waiting = false;
        for _ in 0..4 {
            if let Ok(Ok(ServiceUpdate::Lifecycle(AgentLifecycle::WaitingForSecret))) =
                tokio::time::timeout(Duration::from_secs(1), events.recv()).await
            {
                saw_waiting = true;
                break;
            }
        }
        assert!(saw_waiting);

        runtime.shutdown().await.unwrap();
        assert!(matches!(handle.lifecycle().await, AgentLifecycle::Stopping));
        let _ = tokio::fs::remove_file(secret_path).await;
    }

    #[tokio::test]
    async fn host_event_sender_receives_startup_events_before_start_returns() {
        let secret_path = std::env::temp_dir().join(format!(
            "playit-runtime-host-events-{}-{}.toml",
            std::process::id(),
            unique_test_suffix()
        ));
        let (event_tx, mut events) = broadcast::channel(8);
        let (runtime, _handle) = PlayitRuntime::start_with_event_sender(
            RuntimeOptions {
                secret_path: secret_path.clone(),
                ..RuntimeOptions::default()
            },
            event_tx,
        )
        .await
        .unwrap();

        assert!(matches!(
            events.recv().await.unwrap(),
            ServiceUpdate::Status(status) if matches!(status.phase, super::ServicePhase::Starting)
        ));

        runtime.shutdown().await.unwrap();
        let _ = tokio::fs::remove_file(secret_path).await;
    }

    #[tokio::test]
    async fn claim_start_is_direct_idempotent_and_cancellable() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let api_base = format!("http://{}", listener.local_addr().unwrap());
        let server_cancel = tokio_util::sync::CancellationToken::new();
        let server_cancel_task = server_cancel.clone();
        let server_task = tokio::spawn(async move {
            let mut connections = Vec::new();
            loop {
                tokio::select! {
                    _ = server_cancel_task.cancelled() => break,
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted {
                            connections.push(stream);
                        }
                    }
                }
            }
            drop(connections);
        });

        let secret_path = std::env::temp_dir().join(format!(
            "playit-runtime-claim-{}-{}.toml",
            std::process::id(),
            unique_test_suffix()
        ));
        let (runtime, handle) = PlayitRuntime::start(RuntimeOptions {
            secret_path: secret_path.clone(),
            api_base,
            ..RuntimeOptions::default()
        })
        .await
        .unwrap();

        wait_until_waiting(&handle).await;
        let first = handle.start_claim().await.unwrap();
        let second = handle.start_claim().await.unwrap();
        assert_eq!(first.claim_url, second.claim_url);

        runtime.shutdown().await.unwrap();
        server_cancel.cancel();
        server_task.await.unwrap();
        let _ = tokio::fs::remove_file(secret_path).await;
    }

    #[tokio::test]
    async fn reset_secret_removes_the_file_and_requests_shutdown() {
        let secret_path = std::env::temp_dir().join(format!(
            "playit-runtime-reset-{}-{}.toml",
            std::process::id(),
            unique_test_suffix()
        ));
        let (runtime, handle) = PlayitRuntime::start(RuntimeOptions {
            secret_path: secret_path.clone(),
            ..RuntimeOptions::default()
        })
        .await
        .unwrap();
        wait_until_waiting(&handle).await;

        tokio::fs::write(&secret_path, "secret_key = \"deadbeef\"\n")
            .await
            .unwrap();
        let response = handle.reset_secret().await.unwrap();
        assert!(response.accepted);
        assert!(!secret_path.exists());

        runtime.shutdown().await.unwrap();
    }

    async fn wait_until_waiting(handle: &super::PlayitHandle) {
        for _ in 0..100 {
            if matches!(handle.lifecycle().await, AgentLifecycle::WaitingForSecret) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("runtime did not reach WaitingForSecret");
    }

    fn unique_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos()
    }
}
