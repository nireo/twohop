use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use quinn::{ConnectionError, Endpoint, crypto::rustls::QuicClientConfig};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    time::{Instant, interval_at, sleep, timeout_at},
};

use crate::{
    config::ClientConfig,
    credentials::{self, AccessToken},
    error::{RunError, SocketOperation},
    protocol::{
        self, ALPN, AUTH_REJECTED, AuthRequest, AuthResponse, MAX_DATAGRAM, PROTOCOL_ERROR,
        SERVER_BUSY, VERSION,
    },
    transport::{self, CloseOnDrop, ControlStream, SessionEnd, Stats, UdpBuffer},
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const STABLE_SESSION: Duration = Duration::from_secs(30);

// Only connect constructs a ready session, after authentication and budget checks.
struct ReadySession {
    connection: CloseOnDrop,
    control: ControlStream,
}

impl ReadySession {
    async fn forward(
        &mut self,
        local: &UdpSocket,
        stats: &Stats,
        buffer: &mut UdpBuffer,
    ) -> SessionEnd {
        transport::forward_session(&self.connection.0, local, &mut self.control, stats, buffer)
            .await
    }

    fn protocol_rejected(&self) -> bool {
        matches!(self.connection.0.close_reason(), Some(ConnectionError::ApplicationClosed(close)) if close.error_code == PROTOCOL_ERROR.into())
    }
}

#[derive(Debug, Clone, Copy, Error)]
pub enum SetupError {
    #[error("invalid_relay_configuration")]
    InvalidRelayConfiguration,
    #[error("setup_timeout")]
    Timeout,
    #[error("authentication_rejected")]
    AuthenticationRejected,
    #[error("protocol_rejected")]
    ProtocolRejected,
    #[error("relay_busy")]
    RelayBusy,
    #[error("tls_or_transport_rejected")]
    TransportRejected,
    #[error("relay_disconnected")]
    Disconnected,
    #[error("invalid_control_exchange")]
    InvalidControlExchange,
    #[error("unsupported_relay_response")]
    UnsupportedResponse,
    #[error("insufficient_datagram_budget")]
    InsufficientDatagramBudget,
    #[error("local_udp_receive_failed")]
    LocalReceiveFailed,
}

impl SetupError {
    fn retryable(self) -> bool {
        match self {
            Self::Timeout | Self::RelayBusy | Self::Disconnected => true,
            Self::InvalidRelayConfiguration
            | Self::AuthenticationRejected
            | Self::ProtocolRejected
            | Self::TransportRejected
            | Self::InvalidControlExchange
            | Self::UnsupportedResponse
            | Self::InsufficientDatagramBudget
            | Self::LocalReceiveFailed => false,
        }
    }
}

impl From<protocol::FrameError> for SetupError {
    fn from(error: protocol::FrameError) -> Self {
        error
            .connection_error()
            .map(classify)
            .unwrap_or(Self::InvalidControlExchange)
    }
}

pub async fn run(config: ClientConfig) -> Result<(), RunError> {
    let token = AccessToken::load(config.token_file())?;
    let roots = credentials::roots(config.ca_cert_file())?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    quic.transport_config(transport::transport_config(
        transport::client_idle_timeout(),
        Some(transport::KEEPALIVE),
    ));
    let mut endpoint = Endpoint::client(transport::wildcard(config.relay_addr()))
        .map_err(|error| SocketOperation::BindQuic.error(error))?;
    endpoint.set_default_client_config(quic);

    let local = UdpSocket::bind(config.local_bind())
        .await
        .map_err(|error| SocketOperation::BindLocal.error(error))?;
    local
        .connect(config.wireguard_addr())
        .await
        .map_err(|error| SocketOperation::ConnectLocal.error(error))?;
    let local_addr = local
        .local_addr()
        .map_err(|error| SocketOperation::InspectLocal.error(error))?;
    if local_addr.port() == config.wireguard_addr().port() {
        return Err(RunError::LocalPortConflict);
    }
    tracing::info!(local = %local_addr, "client listening");

    let stats = Stats::default();
    let result = {
        let work = run_sessions(&endpoint, &local, &config, &token, &stats);
        let shutdown = transport::shutdown();
        tokio::pin!(work, shutdown);
        let mut report = interval_at(
            Instant::now() + transport::REPORT_INTERVAL,
            transport::REPORT_INTERVAL,
        );
        loop {
            tokio::select! {
                result = &mut work => break result,
                result = &mut shutdown => break result.map_err(RunError::Signal),
                _ = report.tick() => stats.report("client"),
            }
        }
    };
    // Session futures have dropped before draining, including on signal shutdown.
    transport::close_endpoint(&endpoint).await;
    stats.report("client");
    tracing::info!("client stopped");
    result
}

async fn run_sessions(
    endpoint: &Endpoint,
    local: &UdpSocket,
    config: &ClientConfig,
    token: &AccessToken,
    stats: &Stats,
) -> Result<(), RunError> {
    let mut backoff = INITIAL_BACKOFF;
    // One heap buffer serves discard, draining, and forwarding across reconnects.
    let mut buffer = transport::udp_buffer();
    let mut session_id = 0_u64;
    loop {
        session_id += 1;
        tracing::info!(session_id, "client connecting");
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let result = tokio::select! {
            result = timeout_at(deadline, connect(endpoint, config, token)) => result.unwrap_or(Err(SetupError::Timeout)),
            result = discard_local(local, stats, &mut buffer) => return result,
        };
        let result = match result {
            Ok(session) => {
                // Discard is cancelled before draining. Both phases share the same buffer,
                // and TLS, authentication, and draining still use one setup deadline.
                timeout_at(deadline, drain_local(local, stats, &mut buffer))
                    .await
                    .map_err(|_| SetupError::Timeout)
                    .and_then(|result| result.map_err(|_| SetupError::LocalReceiveFailed))
                    .map(|()| session)
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(mut session) => {
                tracing::info!(session_id, "client session ready");
                let started = Instant::now();
                let reason = session.forward(local, stats, &mut buffer).await;
                tracing::info!(
                    session_id,
                    reason = reason.reason(),
                    duration_ms = started.elapsed().as_millis() as u64,
                    "client session ended"
                );
                if reason.is_protocol_error() {
                    return Err(RunError::ProtocolViolation);
                }
                if session.protocol_rejected() {
                    return Err(RunError::ProtocolRejected);
                }
                if started.elapsed() >= STABLE_SESSION {
                    backoff = INITIAL_BACKOFF;
                }
            }
            Err(failure) => {
                stats.setup_errors.fetch_add(1, Ordering::Relaxed);
                if !failure.retryable() {
                    return Err(failure.into());
                }
                tracing::warn!(
                    session_id,
                    reason = failure.to_string().as_str(),
                    "client setup failed"
                );
            }
        }
        let delay = jitter(backoff);
        tracing::info!(
            delay_ms = delay.as_millis() as u64,
            "client reconnect scheduled"
        );
        tokio::select! {
            _ = sleep(delay) => {},
            result = discard_local(local, stats, &mut buffer) => return result,
        }
        stats.reconnects.fetch_add(1, Ordering::Relaxed);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn connect(
    endpoint: &Endpoint,
    config: &ClientConfig,
    token: &AccessToken,
) -> Result<ReadySession, SetupError> {
    let connecting = endpoint
        .connect(config.relay_addr(), config.server_name())
        .map_err(|_| SetupError::InvalidRelayConfiguration)?;
    let connection = CloseOnDrop(connecting.await.map_err(|error| classify(&error))?);
    let (mut send, mut recv) = connection
        .0
        .open_bi()
        .await
        .map_err(|error| classify(&error))?;
    protocol::write_frame(
        &mut send,
        &AuthRequest {
            version: VERSION,
            token: token.as_str(),
        },
    )
    .await?;
    let response: AuthResponse = protocol::read_frame(&mut recv).await?;
    if response.version != VERSION || response.max_datagram_size != MAX_DATAGRAM {
        return Err(SetupError::UnsupportedResponse);
    }
    if !transport::supports_datagrams(&connection.0) {
        return Err(SetupError::InsufficientDatagramBudget);
    }
    Ok(ReadySession {
        connection,
        control: ControlStream::new(send, recv),
    })
}

fn classify(error: &ConnectionError) -> SetupError {
    match error {
        ConnectionError::ApplicationClosed(close) if close.error_code == AUTH_REJECTED.into() => {
            SetupError::AuthenticationRejected
        }
        ConnectionError::ApplicationClosed(close) if close.error_code == PROTOCOL_ERROR.into() => {
            SetupError::ProtocolRejected
        }
        ConnectionError::ApplicationClosed(close) if close.error_code == SERVER_BUSY.into() => {
            SetupError::RelayBusy
        }
        ConnectionError::TransportError(error)
            if error.code == quinn::TransportErrorCode::CONNECTION_REFUSED =>
        {
            SetupError::RelayBusy
        }
        ConnectionError::ConnectionClosed(close)
            if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED =>
        {
            SetupError::RelayBusy
        }
        ConnectionError::TransportError(_)
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::VersionMismatch => SetupError::TransportRejected,
        ConnectionError::ApplicationClosed(_)
        | ConnectionError::Reset
        | ConnectionError::TimedOut
        | ConnectionError::LocallyClosed
        | ConnectionError::CidsExhausted => SetupError::Disconnected,
    }
}

async fn discard_local(
    local: &UdpSocket,
    stats: &Stats,
    buffer: &mut UdpBuffer,
) -> Result<(), RunError> {
    loop {
        local
            .recv(&mut buffer[..])
            .await
            .map_err(|error| SocketOperation::DiscardLocal.error(error))?;
        stats.disconnected_drops.fetch_add(1, Ordering::Relaxed);
    }
}

async fn drain_local(
    local: &UdpSocket,
    stats: &Stats,
    buffer: &mut UdpBuffer,
) -> std::io::Result<()> {
    let mut drained = 0;
    loop {
        match local.try_recv(&mut buffer[..]) {
            Ok(_) => {
                stats.disconnected_drops.fetch_add(1, Ordering::Relaxed);
                drained += 1;
                // Keep shutdown and setup deadlines responsive under sustained local traffic.
                if drained % 64 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn jitter(backoff: Duration) -> Duration {
    let millis = backoff.as_millis() as u64;
    Duration::from_millis(rand::random_range(millis / 2..=millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delays_stay_bounded() {
        for backoff in [INITIAL_BACKOFF, MAX_BACKOFF] {
            for _ in 0..100 {
                let delay = jitter(backoff);
                assert!(delay >= backoff / 2 && delay <= backoff);
            }
        }
    }
}
