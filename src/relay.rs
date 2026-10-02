use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use quinn::{Connecting, Connection, Endpoint, crypto::rustls::QuicServerConfig};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit},
    task::JoinSet,
    time::{Instant, interval_at, timeout, timeout_at},
};

use crate::{
    config::RelayConfig,
    credentials::{self, AccessToken},
    error::{RunError, SocketOperation},
    protocol::{
        self, ALPN, AUTH_REJECTED, AuthRequest, AuthResponse, MAX_DATAGRAM, PROTOCOL_ERROR,
        SERVER_BUSY, VERSION,
    },
    transport::{self, CloseOnDrop, ControlStream, SessionEnd, Stats},
};

struct State {
    exit_addr: SocketAddr,
    token: AccessToken,
    active: Semaphore,
    stats: Stats,
}

pub async fn run(config: RelayConfig) -> Result<(), RunError> {
    let token = AccessToken::load(config.token_file())?;
    let certs = credentials::certificates(config.cert_file())?;
    let key = credentials::private_key(config.key_file())?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    quic.transport_config(transport::transport_config(
        config.limits().idle_timeout(),
        None,
    ));
    quic.max_incoming(config.limits().pending());
    quic.incoming_buffer_size(transport::DATAGRAM_BUFFER as u64);
    quic.incoming_buffer_size_total(
        (config.limits().pending() * transport::DATAGRAM_BUFFER) as u64,
    );
    let endpoint = Endpoint::server(quic, config.listen())
        .map_err(|error| SocketOperation::BindQuic.error(error))?;
    tracing::info!(listen = %endpoint.local_addr().map_err(|error| SocketOperation::InspectQuic.error(error))?, "relay listening");

    let state = Arc::new(State {
        exit_addr: config.exit_addr(),
        token,
        active: Semaphore::new(config.limits().active()),
        stats: Stats::default(),
    });
    let pending = Arc::new(Semaphore::new(config.limits().pending()));
    let max_connections = config.limits().active() + config.limits().pending();
    let setup_timeout = config.limits().setup_timeout();
    let mut sessions = JoinSet::new();
    let mut session_id = 0_u64;
    let shutdown = transport::shutdown();
    tokio::pin!(shutdown);
    let mut report = interval_at(
        Instant::now() + transport::REPORT_INTERVAL,
        transport::REPORT_INTERVAL,
    );
    let result = loop {
        tokio::select! {
            biased;
            result = &mut shutdown => break result.map_err(RunError::Signal),
            completed = sessions.join_next(), if !sessions.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    tracing::error!("relay session task failed");
                }
                report_resources(&state, &pending, &config, &sessions, &endpoint);
            }
            _ = report.tick() => {
                state.stats.report("relay");
                report_resources(&state, &pending, &config, &sessions, &endpoint);
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break Ok(()); };
                // Include closing/draining transport state in the bound during rapid churn.
                let permit = if endpoint.open_connections() < max_connections {
                    pending.clone().try_acquire_owned().ok()
                } else {
                    None
                };
                let Some(permit) = permit else {
                    incoming.refuse();
                    state.stats.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(reason = "pending_or_transport_limit", "relay connection rejected");
                    continue;
                };
                // Accept synchronously so the next admission check includes this connection.
                let connecting = match incoming.accept() {
                    Ok(connecting) => connecting,
                    Err(_) => {
                        state.stats.setup_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(reason = "handshake_start_failed", "relay setup failed");
                        continue;
                    }
                };
                session_id += 1;
                sessions.spawn(run_session(connecting, state.clone(), permit, Instant::now() + setup_timeout, session_id));
            }
        }
    };

    endpoint.close(0_u32.into(), b"relay stopped");
    if timeout(Duration::from_secs(1), async {
        while sessions.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
    }
    transport::close_endpoint(&endpoint).await;
    state.stats.report("relay");
    report_resources(&state, &pending, &config, &sessions, &endpoint);
    tracing::info!("relay stopped");
    result
}

fn report_resources(
    state: &State,
    pending: &Semaphore,
    config: &RelayConfig,
    sessions: &JoinSet<()>,
    endpoint: &Endpoint,
) {
    tracing::info!(
        pending = config.limits().pending() - pending.available_permits(),
        active = config.limits().active() - state.active.available_permits(),
        tasks = sessions.len(),
        connections = endpoint.open_connections(),
        "relay resources"
    );
}

// Construction is private to setup. Forwarding always retains the authenticated
// connection, both control halves, the connected upstream socket, and its permit.
struct ReadySession<'a> {
    connection: CloseOnDrop,
    control: ControlStream,
    upstream: UdpSocket,
    _active: SemaphorePermit<'a>,
}

impl ReadySession<'_> {
    async fn forward(&mut self, stats: &Stats) -> SessionEnd {
        let mut buffer = transport::udp_buffer();
        transport::forward_session(
            &self.connection.0,
            &self.upstream,
            &mut self.control,
            stats,
            &mut buffer,
        )
        .await
    }
}

#[derive(Debug, Clone, Copy)]
enum SetupError {
    HandshakeFailed,
    ControlStreamFailed,
    InvalidControlMessage,
    UnsupportedVersion,
    AuthenticationRejected,
    InsufficientDatagramBudget,
    ActiveLimit,
    ExitSocketBindFailed,
    ExitSocketConnectFailed,
    ControlResponseFailed,
    Timeout,
}

impl SetupError {
    fn reason(self) -> &'static str {
        match self {
            Self::HandshakeFailed => "handshake_failed",
            Self::ControlStreamFailed => "control_stream_failed",
            Self::InvalidControlMessage => "invalid_control_message",
            Self::UnsupportedVersion => "unsupported_version",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::InsufficientDatagramBudget => "insufficient_datagram_budget",
            Self::ActiveLimit => "active_limit",
            Self::ExitSocketBindFailed => "exit_socket_bind_failed",
            Self::ExitSocketConnectFailed => "exit_socket_connect_failed",
            Self::ControlResponseFailed => "control_response_failed",
            Self::Timeout => "setup_timeout",
        }
    }

    // The failure variant determines its wire code, so they cannot disagree.
    fn reject(self, connection: &Connection) -> Self {
        let code = match self {
            Self::AuthenticationRejected => AUTH_REJECTED,
            Self::ActiveLimit => SERVER_BUSY,
            Self::InvalidControlMessage
            | Self::UnsupportedVersion
            | Self::InsufficientDatagramBudget => PROTOCOL_ERROR,
            Self::HandshakeFailed
            | Self::ControlStreamFailed
            | Self::ExitSocketBindFailed
            | Self::ExitSocketConnectFailed
            | Self::ControlResponseFailed
            | Self::Timeout => return self,
        };
        connection.close(code.into(), self.reason().as_bytes());
        self
    }
}

async fn run_session(
    connecting: Connecting,
    state: Arc<State>,
    pending: OwnedSemaphorePermit,
    deadline: Instant,
    session_id: u64,
) {
    let started = Instant::now();
    // One deadline covers both TLS and application authentication/socket setup.
    let setup = async {
        let connection = CloseOnDrop(connecting.await.map_err(|_| SetupError::HandshakeFailed)?);
        setup(connection, &state).await
    };
    let result = timeout_at(deadline, setup)
        .await
        .unwrap_or(Err(SetupError::Timeout));
    let reason = match result {
        Ok(mut session) => {
            drop(pending);
            tracing::info!(session_id, "relay session ready");
            session.forward(&state.stats).await.reason()
        }
        Err(error) => {
            state.stats.setup_errors.fetch_add(1, Ordering::Relaxed);
            error.reason()
        }
    };
    tracing::info!(
        session_id,
        reason,
        duration_ms = started.elapsed().as_millis() as u64,
        "relay session ended"
    );
}

async fn setup(connection: CloseOnDrop, state: &State) -> Result<ReadySession<'_>, SetupError> {
    let (mut send, mut recv) = connection
        .0
        .accept_bi()
        .await
        .map_err(|_| SetupError::ControlStreamFailed)?;
    let request: AuthRequest = protocol::read_frame(&mut recv)
        .await
        .map_err(|_| SetupError::InvalidControlMessage.reject(&connection.0))?;
    if request.version != VERSION {
        return Err(SetupError::UnsupportedVersion.reject(&connection.0));
    }
    if !state.token.matches(&request.token) {
        return Err(SetupError::AuthenticationRejected.reject(&connection.0));
    }
    if !transport::supports_datagrams(&connection.0) {
        return Err(SetupError::InsufficientDatagramBudget.reject(&connection.0));
    }
    let active = state.active.try_acquire().map_err(|_| {
        state.stats.rejected.fetch_add(1, Ordering::Relaxed);
        SetupError::ActiveLimit.reject(&connection.0)
    })?;
    // Authentication and capacity reservation precede upstream socket allocation.
    let upstream = UdpSocket::bind(transport::wildcard(state.exit_addr))
        .await
        .map_err(|_| SetupError::ExitSocketBindFailed)?;
    upstream
        .connect(state.exit_addr)
        .await
        .map_err(|_| SetupError::ExitSocketConnectFailed)?;
    protocol::write_frame(
        &mut send,
        &AuthResponse {
            version: VERSION,
            max_datagram_size: MAX_DATAGRAM,
        },
    )
    .await
    .map_err(|_| SetupError::ControlResponseFailed)?;
    Ok(ReadySession {
        connection,
        control: ControlStream::new(send, recv),
        upstream,
        _active: active,
    })
}
