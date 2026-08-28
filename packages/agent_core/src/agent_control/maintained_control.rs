use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use playit_agent_proto::control_feed::{ControlFeed, NewClient};
use playit_agent_proto::control_messages::{ControlResponse, UdpChannelDetails};
use tokio::sync::watch;

use crate::agent_control::errors::TryTimeoutHelper;
use crate::agent_control::established_control::EstablishedControl;
use crate::utils::now_milli;

use super::address_selector::AddressSelector;
use super::connected_control::ConnectedControl;
use super::errors::SetupError;
use super::{AuthResource, PacketIO};

const HARD_RECONNECT_FAILURE_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlConnectionState {
    Connected,
    Reconnecting,
}

pub struct MaintainedControl<I: PacketIO, A: AuthResource> {
    control: EstablishedControl<A, I>,
    last_keep_alive: u64,
    last_ping: u64,
    last_pong: u64,
    last_udp_auth: u64,
    last_control_targets: Vec<SocketAddr>,
    control_state: watch::Sender<ControlConnectionState>,
    soft_reconnect_failures: u32,
    hard_reconnect_requested: bool,
}

impl<I: PacketIO, A: AuthResource> MaintainedControl<I, A> {
    pub async fn setup(io: I, auth: A) -> Result<Self, SetupError> {
        let addresses = auth.get_control_addresses().await?;
        let setup = AddressSelector::new(addresses.clone(), io)
            .connect_to_first()
            .try_timeout(Duration::from_secs(10))
            .await?;

        let control_channel = setup
            .auth_into_established(auth)
            .try_timeout(Duration::from_secs(10))
            .await?;
        let (control_state, _) = watch::channel(ControlConnectionState::Connected);

        Ok(MaintainedControl {
            control: control_channel,
            last_keep_alive: 0,
            last_ping: 0,
            last_pong: now_milli(),
            last_udp_auth: 0,
            last_control_targets: addresses,
            control_state,
            soft_reconnect_failures: 0,
            hard_reconnect_requested: false,
        })
    }

    pub fn subscribe_control_state(&self) -> watch::Receiver<ControlConnectionState> {
        self.control_state.subscribe()
    }

    pub fn take_hard_reconnect_request(&mut self) -> bool {
        let requested = self.hard_reconnect_requested;
        self.hard_reconnect_requested = false;
        requested
    }

    pub async fn reload_control_addr<E: Into<SetupError>, C: Future<Output = Result<I, E>>>(
        &mut self,
        create_io: C,
        force: bool,
    ) -> Result<bool, SetupError> {
        if force {
            self.set_control_state(ControlConnectionState::Reconnecting);
        }

        let addresses = self
            .control
            .auth
            .get_control_addresses()
            .try_timeout(Duration::from_secs(5))
            .await?;

        if !force && self.last_control_targets == addresses {
            return Ok(false);
        }

        self.set_control_state(ControlConnectionState::Reconnecting);

        let new_io = async { create_io.await.map_err(|e| e.into()) }
            .try_timeout(Duration::from_secs(5))
            .await?;

        let connected = AddressSelector::new(addresses.clone(), new_io)
            .connect_to_first()
            .try_timeout(Duration::from_secs(10))
            .await?;

        let updated = self
            .replace_connection(connected, force)
            .try_timeout(Duration::from_secs(5))
            .await?;

        self.last_control_targets = addresses;
        self.last_pong = now_milli();
        self.last_ping = 0;
        self.last_keep_alive = 0;
        self.last_udp_auth = 0;
        self.soft_reconnect_failures = 0;
        self.hard_reconnect_requested = false;
        self.set_control_state(ControlConnectionState::Connected);
        Ok(updated)
    }

    pub async fn replace_connection(
        &mut self,
        mut connected: ConnectedControl<I>,
        force: bool,
    ) -> Result<bool, SetupError> {
        if !force
            && self.control.conn.pong_latest.client_addr.ip()
                == connected.pong_latest.client_addr.ip()
            && self.control.conn.pong_latest.tunnel_addr == connected.pong_latest.tunnel_addr
        {
            return Ok(false);
        }

        self.set_control_state(ControlConnectionState::Reconnecting);

        let registered = connected
            .authenticate(&self.control.auth)
            .try_timeout(Duration::from_secs(10))
            .await?;

        tracing::info!(old = %self.control.conn.pong_latest.tunnel_addr, new = %connected.pong_latest.tunnel_addr, "update control address");
        connected.reset_established(&mut self.control, registered);
        self.last_pong = now_milli();
        self.last_ping = 0;
        self.last_keep_alive = 0;
        self.last_udp_auth = 0;
        self.soft_reconnect_failures = 0;
        self.hard_reconnect_requested = false;
        self.set_control_state(ControlConnectionState::Connected);

        Ok(true)
    }

    pub async fn send_udp_session_auth(&mut self, now_ms: u64, min_wait_ms: u64) -> bool {
        if now_ms < self.last_udp_auth + min_wait_ms {
            return false;
        }

        self.last_udp_auth = now_ms;
        if let Err(error) = self
            .control
            .send_setup_udp_channel(1)
            .try_timeout(Duration::from_secs(5))
            .await
        {
            tracing::debug!(?error, "failed to send setup udp channel request");
            self.note_control_failure();
            self.control.set_expired();
        }

        true
    }

    pub async fn update(&mut self) -> Option<TunnelControlEvent> {
        if let Some(reason) = self.control.is_expired() {
            self.set_control_state(ControlConnectionState::Reconnecting);

            if let Err(error) = self
                .control
                .authenticate()
                .try_timeout(Duration::from_secs(5))
                .await
            {
                let failures = self.note_control_failure();
                if failures >= HARD_RECONNECT_FAILURE_THRESHOLD {
                    tracing::warn!(
                        ?error,
                        failures,
                        ?reason,
                        "control reauthentication failed; will refresh the UDP socket"
                    );
                } else {
                    tracing::debug!(?error, failures, ?reason, "control reauthentication failed");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                return None;
            }

            self.soft_reconnect_failures = 0;
            self.hard_reconnect_requested = false;
            self.last_pong = now_milli();
            self.set_control_state(ControlConnectionState::Connected);
        }

        let now = now_milli();
        if now - self.last_ping > 1_000 {
            self.last_ping = now;

            if let Err(error) = self
                .control
                .send_ping(200, now)
                .try_timeout(Duration::from_secs(1))
                .await
            {
                tracing::debug!(?error, "failed to send ping");
                self.note_control_failure();
                self.control.set_expired();
            }
        }

        let time_till_expire = self.control.get_expire_at().max(now) - now;
        tracing::trace!(time_till_expire, "time till expire");

        /* keep alive every 60s or every 10s if expiring soon */
        let interval = if time_till_expire < 30_000 {
            10_000
        } else {
            60_000
        };

        if interval < now - self.last_keep_alive {
            self.last_keep_alive = now;

            tracing::debug!(time_till_expire, "send KeepAlive");
            if let Err(error) = self
                .control
                .send_keep_alive(100)
                .try_timeout(Duration::from_secs(1))
                .await
            {
                tracing::debug!(?error, "failed to send KeepAlive");
                self.note_control_failure();
                self.control.set_expired();
            }
        }

        let mut timeouts = 0;

        for _ in 0..30 {
            match tokio::time::timeout(Duration::from_millis(100), self.control.recv_feed_msg())
                .await
            {
                Ok(Ok(ControlFeed::NewClient(new_client))) => {
                    return Some(TunnelControlEvent::NewClient(new_client));
                }
                Ok(Ok(ControlFeed::NewClientOld(new_client))) => {
                    return Some(TunnelControlEvent::NewClient(new_client.into()));
                }
                Ok(Ok(ControlFeed::Response(msg))) => match msg.content {
                    ControlResponse::UdpChannelDetails(details) => {
                        return Some(TunnelControlEvent::UdpChannelDetails(details));
                    }
                    ControlResponse::Unauthorized => {
                        tracing::debug!("session no longer authorized");
                        self.set_control_state(ControlConnectionState::Reconnecting);
                        self.control.set_expired();
                    }
                    ControlResponse::Pong(pong) => {
                        self.last_pong = now_milli();

                        if pong.client_addr != self.control.pong_at_auth.client_addr {
                            tracing::debug!(
                                new_client = %pong.client_addr,
                                old_client = %self.control.pong_at_auth.client_addr,
                                "client ip changed"
                            );
                        }
                    }
                    msg => {
                        tracing::debug!(?msg, "got response");
                    }
                },
                Ok(Err(error)) => {
                    tracing::debug!(?error, "failed to parse response");
                }
                Err(_) => {
                    timeouts += 1;

                    if timeouts >= 10 {
                        tracing::trace!("feed recv timeout");
                        break;
                    }
                }
            }
        }

        if self.last_pong != 0 && now_milli() - self.last_pong > 6_000 {
            tracing::debug!("control endpoint stopped responding; reconnecting");

            self.last_pong = 0;
            self.set_control_state(ControlConnectionState::Reconnecting);
            self.note_control_failure();
            self.control.set_expired();
        }

        None
    }

    fn set_control_state(&self, state: ControlConnectionState) {
        if *self.control_state.borrow() != state {
            tracing::info!(?state, "playit control connection state changed");
            let _ = self.control_state.send(state);
        }
    }

    fn note_control_failure(&mut self) -> u32 {
        self.soft_reconnect_failures = self.soft_reconnect_failures.saturating_add(1);
        if self.soft_reconnect_failures >= HARD_RECONNECT_FAILURE_THRESHOLD {
            self.hard_reconnect_requested = true;
        }
        self.soft_reconnect_failures
    }
}

pub enum TunnelControlEvent {
    NewClient(NewClient),
    UdpChannelDetails(UdpChannelDetails),
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    use playit_agent_proto::{
        AgentSessionId,
        control_messages::{AgentRegistered, Pong},
    };
    use playit_api_client::api::SignedAgentKey;
    use tokio::sync::watch;

    use super::*;
    use crate::agent_control::established_control::MtuData;

    #[derive(Clone)]
    struct TestAuth;

    impl AuthResource for TestAuth {
        async fn authenticate(&self, _: &Pong) -> Result<SignedAgentKey, SetupError> {
            panic!("authentication is not used by this test");
        }

        async fn get_control_addresses(&self) -> Result<Vec<SocketAddr>, SetupError> {
            Ok(Vec::new())
        }
    }

    struct TestPacketIo;

    impl PacketIO for TestPacketIo {
        async fn send_to(&self, buf: &[u8], _: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }

        async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "test queue empty",
            ))
        }
    }

    fn test_control() -> MaintainedControl<TestPacketIo, TestAuth> {
        let now = crate::utils::now_milli();
        let pong = Pong {
            request_now: now,
            server_now: now,
            server_id: 1,
            data_center_id: 1,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000),
            tunnel_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9_999),
            session_expire_at: Some(now + 60_000),
        };
        let (control_state, _) = watch::channel(ControlConnectionState::Connected);

        MaintainedControl {
            control: EstablishedControl {
                auth: TestAuth,
                conn: ConnectedControl::new(pong.tunnel_addr, TestPacketIo, pong.clone()),
                pong_at_auth: pong,
                session_setup_deadline: None,
                registered: AgentRegistered {
                    id: AgentSessionId {
                        session_id: 1,
                        account_id: 1,
                        agent_id: 1,
                    },
                    expires_at: now + 60_000,
                },
                current_ping: None,
                clock_offset: 0,
                force_expired: false,
                pending_mtu_data: MtuData::default(),
                known_mtu_data: MtuData::default(),
            },
            last_keep_alive: 0,
            last_ping: 0,
            last_pong: now,
            last_udp_auth: 0,
            last_control_targets: Vec::new(),
            control_state,
            soft_reconnect_failures: 0,
            hard_reconnect_requested: false,
        }
    }

    #[test]
    fn three_control_failures_request_a_hard_reconnect() {
        let mut control = test_control();

        assert_eq!(control.note_control_failure(), 1);
        assert!(!control.take_hard_reconnect_request());
        assert_eq!(control.note_control_failure(), 2);
        assert!(!control.take_hard_reconnect_request());
        assert_eq!(control.note_control_failure(), 3);
        assert!(control.take_hard_reconnect_request());
        assert!(!control.take_hard_reconnect_request());
    }
}
