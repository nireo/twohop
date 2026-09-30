use std::{net::Ipv4Addr, sync::Arc, sync::atomic::Ordering, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use quinn::{ConnectionError, Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use tokio::{
    net::UdpSocket,
    time::{Instant, interval_at, sleep, timeout},
};

use crate::{
    config::ClientConfig,
    protocol::{
        self, ALPN, AUTH_REJECTED, AuthRequest, AuthResponse, MAX_DATAGRAM, PROTOCOL_ERROR,
        SERVER_BUSY, VERSION,
    },
    transport::{self, CloseOnDrop, Stats, UDP_BUFFER},
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const STABLE_SESSION: Duration = Duration::from_secs(30);

type Session = (CloseOnDrop, SendStream, RecvStream);

struct SetupFailure {
    retry: bool,
    reason: &'static str,
}

pub async fn run(config: ClientConfig) -> Result<()> {
    let token = protocol::load_token(&config.token_file)?;
    let mut roots = RootCertStore::empty();
    for cert in
        CertificateDer::pem_file_iter(&config.ca_cert_file).context("cannot open CA certificate")?
    {
        roots.add(cert.context("invalid CA certificate PEM")?)?;
    }
    ensure!(!roots.is_empty(), "CA certificate file has no certificates");
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    quic.transport_config(transport::transport_config(
        transport::IDLE_TIMEOUT,
        Some(transport::KEEPALIVE),
    )?);
    let mut endpoint = Endpoint::client(transport::wildcard(config.relay_addr))?;
    endpoint.set_default_client_config(quic);

    let local = UdpSocket::bind(config.local_bind)
        .await
        .context("cannot bind local UDP socket")?;
    local
        .connect((Ipv4Addr::LOCALHOST, config.wireguard_port))
        .await
        .context("cannot connect local WireGuard socket")?;

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
                result = &mut shutdown => break result,
                _ = report.tick() => stats.report("client"),
            }
        }
    };
    // The session future has dropped before draining, including on signal shutdown.
    transport::close_endpoint(&endpoint).await;
    stats.report("client");
    tracing::info!("client stopped");
    result
}

async fn run_sessions(
    endpoint: &Endpoint,
    local: &UdpSocket,
    config: &ClientConfig,
    token: &str,
    stats: &Stats,
) -> Result<()> {
    let mut backoff = INITIAL_BACKOFF;
    let mut session_id = 0_u64;
    loop {
        session_id += 1;
        tracing::info!(session_id, "client connecting");
        let setup = timeout(
            SETUP_TIMEOUT,
            connect(endpoint, local, config, token, stats),
        );
        let result = tokio::select! {
            result = setup => result.unwrap_or(Err(SetupFailure { retry: true, reason: "setup_timeout" })),
            result = discard_local(local, stats) => return result,
        };
        match result {
            Ok((connection, _send, mut recv)) => {
                tracing::info!(session_id, "client session ready");
                let started = Instant::now();
                let reason =
                    transport::forward_session(&connection.0, local, &mut recv, stats).await;
                tracing::info!(
                    session_id,
                    reason,
                    duration_ms = started.elapsed().as_millis() as u64,
                    "client session ended"
                );
                if matches!(
                    reason,
                    "unexpected_control_data" | "unexpected_control_stream"
                ) {
                    bail!("relay violated the session protocol");
                }
                if matches!(connection.0.close_reason(), Some(ConnectionError::ApplicationClosed(ref close)) if close.error_code == PROTOCOL_ERROR.into())
                {
                    bail!("relay rejected the session protocol");
                }
                if started.elapsed() >= STABLE_SESSION {
                    backoff = INITIAL_BACKOFF;
                }
            }
            Err(failure) => {
                stats.setup_errors.fetch_add(1, Ordering::Relaxed);
                if !failure.retry {
                    bail!("client setup failed: {}", failure.reason);
                }
                tracing::warn!(session_id, reason = failure.reason, "client setup failed");
            }
        }
        let delay = jitter(backoff);
        tracing::info!(
            delay_ms = delay.as_millis() as u64,
            "client reconnect scheduled"
        );
        tokio::select! {
            _ = sleep(delay) => {},
            result = discard_local(local, stats) => return result,
        }
        stats.reconnects.fetch_add(1, Ordering::Relaxed);
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn connect(
    endpoint: &Endpoint,
    local: &UdpSocket,
    config: &ClientConfig,
    token: &str,
    stats: &Stats,
) -> Result<Session, SetupFailure> {
    let connecting = endpoint
        .connect(config.relay_addr, &config.server_name)
        .map_err(|_| SetupFailure {
            retry: false,
            reason: "invalid_relay_configuration",
        })?;
    let connection = CloseOnDrop(connecting.await.map_err(|error| classify(error.into()))?);
    let (mut send, mut recv) = connection
        .0
        .open_bi()
        .await
        .map_err(|error| classify(error.into()))?;
    protocol::write_frame(
        &mut send,
        &AuthRequest {
            version: VERSION,
            token: token.to_owned(),
        },
    )
    .await
    .map_err(classify)?;
    let response: AuthResponse = protocol::read_frame(&mut recv).await.map_err(classify)?;
    if response.version != VERSION || response.max_datagram_size != MAX_DATAGRAM {
        return Err(SetupFailure {
            retry: false,
            reason: "unsupported_relay_response",
        });
    }
    transport::check_datagram_budget(&connection.0).map_err(|_| SetupFailure {
        retry: false,
        reason: "insufficient_datagram_budget",
    })?;
    // Empty the kernel's receive backlog before this session starts forwarding.
    drain_local(local, stats).await.map_err(|_| SetupFailure {
        retry: false,
        reason: "local_udp_receive_failed",
    })?;
    Ok((connection, send, recv))
}

fn classify(error: anyhow::Error) -> SetupFailure {
    let connection_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ConnectionError>());
    let (retry, reason) = match connection_error {
        Some(ConnectionError::ApplicationClosed(close))
            if close.error_code == AUTH_REJECTED.into() =>
        {
            (false, "authentication_rejected")
        }
        Some(ConnectionError::ApplicationClosed(close))
            if close.error_code == PROTOCOL_ERROR.into() =>
        {
            (false, "protocol_rejected")
        }
        Some(ConnectionError::ApplicationClosed(close))
            if close.error_code == SERVER_BUSY.into() =>
        {
            (true, "relay_busy")
        }
        Some(ConnectionError::TransportError(error))
            if error.code == quinn::TransportErrorCode::CONNECTION_REFUSED =>
        {
            (true, "relay_busy")
        }
        Some(ConnectionError::ConnectionClosed(close))
            if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED =>
        {
            (true, "relay_busy")
        }
        Some(ConnectionError::TransportError(_))
        | Some(ConnectionError::ConnectionClosed(_))
        | Some(ConnectionError::VersionMismatch) => (false, "tls_or_transport_rejected"),
        Some(_) => (true, "relay_disconnected"),
        None => (false, "invalid_control_exchange"),
    };
    SetupFailure { retry, reason }
}

async fn discard_local(local: &UdpSocket, stats: &Stats) -> Result<()> {
    let mut buffer = vec![0_u8; UDP_BUFFER];
    loop {
        local
            .recv(&mut buffer)
            .await
            .context("cannot discard local UDP traffic")?;
        stats.disconnected_drops.fetch_add(1, Ordering::Relaxed);
    }
}

async fn drain_local(local: &UdpSocket, stats: &Stats) -> std::io::Result<()> {
    let mut buffer = vec![0_u8; UDP_BUFFER];
    let mut drained = 0;
    loop {
        match local.try_recv(&mut buffer) {
            Ok(_) => {
                stats.disconnected_drops.fetch_add(1, Ordering::Relaxed);
                drained += 1;
                // Keep shutdown and the setup deadline responsive under sustained local traffic.
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
