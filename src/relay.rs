use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use quinn::{
    Connecting, Connection, Endpoint, RecvStream, SendStream, crypto::rustls::QuicServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit},
    task::JoinSet,
    time::{Instant, interval_at, timeout, timeout_at},
};

use crate::{
    config::RelayConfig,
    protocol::{
        self, ALPN, AUTH_REJECTED, AuthRequest, AuthResponse, MAX_DATAGRAM, PROTOCOL_ERROR,
        SERVER_BUSY, VERSION,
    },
    transport::{self, CloseOnDrop, Stats},
};

struct State {
    exit_addr: SocketAddr,
    token: String,
    active: Semaphore,
    stats: Stats,
}

pub async fn run(config: RelayConfig) -> Result<()> {
    let token = protocol::load_token(&config.token_file)?;
    let certs = CertificateDer::pem_file_iter(&config.cert_file)
        .context("cannot open relay certificate")?
        .collect::<Result<Vec<_>, _>>()
        .context("invalid relay certificate PEM")?;
    ensure!(
        !certs.is_empty(),
        "relay certificate file has no certificates"
    );
    let key =
        PrivateKeyDer::from_pem_file(&config.key_file).context("invalid relay private key PEM")?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut quic = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    quic.transport_config(transport::transport_config(
        Duration::from_secs(config.limits.idle_timeout_secs),
        None,
    )?);
    quic.max_incoming(config.limits.max_pending_handshakes);
    quic.incoming_buffer_size(transport::DATAGRAM_BUFFER as u64);
    quic.incoming_buffer_size_total(
        (config.limits.max_pending_handshakes * transport::DATAGRAM_BUFFER) as u64,
    );
    let endpoint =
        Endpoint::server(quic, config.listen).context("cannot bind relay QUIC socket")?;
    tracing::info!(listen = %endpoint.local_addr()?, "relay listening");

    let state = Arc::new(State {
        exit_addr: config.exit_addr,
        token,
        active: Semaphore::new(config.limits.max_active_sessions),
        stats: Stats::default(),
    });
    let pending = Arc::new(Semaphore::new(config.limits.max_pending_handshakes));
    let max_connections = config.limits.max_active_sessions + config.limits.max_pending_handshakes;
    let setup_timeout = Duration::from_secs(config.limits.setup_timeout_secs);
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
            result = &mut shutdown => break result,
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
        pending = config.limits.max_pending_handshakes - pending.available_permits(),
        active = config.limits.max_active_sessions - state.active.available_permits(),
        tasks = sessions.len(),
        connections = endpoint.open_connections(),
        "relay resources"
    );
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
        let connection = CloseOnDrop(connecting.await.map_err(|_| "handshake_failed")?);
        let (send, recv, upstream, active) = setup(&connection.0, &state).await?;
        Ok::<_, &'static str>((connection, send, recv, upstream, active))
    };
    let reason = match timeout_at(deadline, setup).await {
        Ok(Ok((connection, _send, mut recv, upstream, _active))) => {
            drop(pending);
            tracing::info!(session_id, "relay session ready");
            transport::forward_session(&connection.0, &upstream, &mut recv, &state.stats).await
        }
        Ok(Err(reason)) => {
            state.stats.setup_errors.fetch_add(1, Ordering::Relaxed);
            reason
        }
        Err(_) => {
            state.stats.setup_errors.fetch_add(1, Ordering::Relaxed);
            "setup_timeout"
        }
    };
    tracing::info!(
        session_id,
        reason,
        duration_ms = started.elapsed().as_millis() as u64,
        "relay session ended"
    );
}

async fn setup<'a>(
    connection: &Connection,
    state: &'a State,
) -> Result<(SendStream, RecvStream, UdpSocket, SemaphorePermit<'a>), &'static str> {
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|_| "control_stream_failed")?;
    let request: AuthRequest = protocol::read_frame(&mut recv)
        .await
        .map_err(|_| reject(connection, PROTOCOL_ERROR, "invalid_control_message"))?;
    if request.version != VERSION {
        return Err(reject(connection, PROTOCOL_ERROR, "unsupported_version"));
    }
    if !bool::from(request.token.as_bytes().ct_eq(state.token.as_bytes())) {
        return Err(reject(connection, AUTH_REJECTED, "authentication_rejected"));
    }
    transport::check_datagram_budget(connection)
        .map_err(|_| reject(connection, PROTOCOL_ERROR, "insufficient_datagram_budget"))?;
    let active = state.active.try_acquire().map_err(|_| {
        state.stats.rejected.fetch_add(1, Ordering::Relaxed);
        reject(connection, SERVER_BUSY, "active_limit")
    })?;
    // Authentication and capacity reservation precede upstream socket allocation.
    let upstream = UdpSocket::bind(transport::wildcard(state.exit_addr))
        .await
        .map_err(|_| "exit_socket_bind_failed")?;
    upstream
        .connect(state.exit_addr)
        .await
        .map_err(|_| "exit_socket_connect_failed")?;
    protocol::write_frame(
        &mut send,
        &AuthResponse {
            version: VERSION,
            max_datagram_size: MAX_DATAGRAM,
        },
    )
    .await
    .map_err(|_| "control_response_failed")?;
    Ok((send, recv, upstream, active))
}

fn reject(connection: &Connection, code: u32, reason: &'static str) -> &'static str {
    connection.close(code.into(), reason.as_bytes());
    reason
}
