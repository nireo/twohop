use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use quinn::{
    Connection, Endpoint, RecvStream, SendStream, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use subtle::ConstantTimeEq;
use tokio::{net::UdpSocket, time::timeout};

use crate::{
    config::{ClientConfig, RelayConfig},
    protocol::{self, ALPN, AuthRequest, AuthResponse, MAX_DATAGRAM, VERSION},
};

const DATAGRAM_BUFFER: usize = 64 * 1024;
const UDP_BUFFER: usize = 65_536;

pub async fn run_client(config: ClientConfig) -> Result<()> {
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
    quic.transport_config(transport_config());

    let bind_addr = match config.relay_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(quic);

    let local = UdpSocket::bind(config.local_bind)
        .await
        .context("cannot bind local UDP socket")?;

    local
        .connect(SocketAddr::new(
            Ipv4Addr::LOCALHOST.into(),
            config.wireguard_port,
        ))
        .await
        .context("cannot connect local WireGuard socket")?;

    let connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(config.relay_addr, &config.server_name)?,
    )
    .await
    .context("relay connection timed out")??;

    let result = client_session(&connection, &local, token).await;
    connection.close(0_u32.into(), b"session ended");
    endpoint.wait_idle().await;

    result
}

async fn client_session(connection: &Connection, local: &UdpSocket, token: String) -> Result<()> {
    let (mut control_send, mut control_recv) = connection.open_bi().await?;
    protocol::write_frame(
        &mut control_send,
        &AuthRequest {
            version: VERSION,
            token,
        },
    )
    .await?;

    let response: AuthResponse = timeout(
        Duration::from_secs(10),
        protocol::read_frame(&mut control_recv),
    )
    .await
    .context("relay authentication timed out")??;

    ensure!(
        response.version == VERSION,
        "relay returned an unsupported version"
    );
    ensure!(
        response.max_datagram_size == MAX_DATAGRAM,
        "relay returned an unsupported datagram size"
    );

    check_datagram_budget(connection)?;
    eprintln!("client session ready");
    forward_session(connection, local, &mut control_recv).await
}

pub async fn run_relay(config: RelayConfig) -> Result<()> {
    let token = Arc::new(protocol::load_token(&config.token_file)?);
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
    quic.transport_config(transport_config());

    let endpoint =
        Endpoint::server(quic, config.listen).context("cannot bind relay QUIC socket")?;
    eprintln!("relay listening on {}", endpoint.local_addr()?);

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                let token = token.clone();
                let exit_addr = config.exit_addr;
                let setup_timeout = Duration::from_secs(config.limits.setup_timeout_secs);
                tokio::spawn(async move {
                    match timeout(setup_timeout, incoming).await {
                        Ok(Ok(connection)) => {
                            match timeout(setup_timeout, relay_setup(&connection, exit_addr, &token)).await {
                                Ok(Ok((_control_send, mut control_recv, upstream))) => {
                                    eprintln!("relay session ready");
                                    if let Err(error) = forward_session(&connection, &upstream, &mut control_recv).await {
                                        eprintln!("relay session ended: {error:#}");
                                    }
                                    connection.close(0_u32.into(), b"session ended");
                                }
                                Ok(Err(error)) => {
                                    eprintln!("relay session setup failed: {error:#}");
                                    connection.close(1_u32.into(), b"session rejected");
                                }
                                Err(_) => {
                                    eprintln!("relay session setup timed out");
                                    connection.close(1_u32.into(), b"session rejected");
                                }
                            }
                        }
                        Ok(Err(error)) => eprintln!("relay handshake failed: {error}"),
                        Err(_) => eprintln!("relay handshake timed out"),
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    endpoint.close(0_u32.into(), b"relay stopped");
    endpoint.wait_idle().await;
    Ok(())
}

async fn relay_setup(
    connection: &Connection,
    exit_addr: SocketAddr,
    expected_token: &str,
) -> Result<(SendStream, RecvStream, UdpSocket)> {
    let (mut control_send, mut control_recv) = connection.accept_bi().await?;
    let request: AuthRequest = protocol::read_frame(&mut control_recv).await?;
    ensure!(
        request.version == VERSION
            && bool::from(request.token.as_bytes().ct_eq(expected_token.as_bytes())),
        "authentication failed"
    );
    check_datagram_budget(connection)?;

    let bind_addr = match exit_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    let upstream = UdpSocket::bind(bind_addr)
        .await
        .context("cannot bind exit UDP socket")?;
    upstream
        .connect(exit_addr)
        .await
        .context("cannot connect exit UDP socket")?;

    protocol::write_frame(
        &mut control_send,
        &AuthResponse {
            version: VERSION,
            max_datagram_size: MAX_DATAGRAM,
        },
    )
    .await?;
    Ok((control_send, control_recv, upstream))
}

fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(1_u8.into());
    config.max_concurrent_uni_streams(0_u8.into());
    config.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    config.datagram_send_buffer_size(DATAGRAM_BUFFER);
    Arc::new(config)
}

fn check_datagram_budget(connection: &Connection) -> Result<()> {
    ensure!(
        connection
            .max_datagram_size()
            .is_some_and(|size| size >= MAX_DATAGRAM),
        "QUIC path cannot send {MAX_DATAGRAM}-byte datagrams"
    );
    Ok(())
}

async fn forward_session(
    connection: &Connection,
    socket: &UdpSocket,
    control: &mut RecvStream,
) -> Result<()> {
    let oversized = AtomicU64::new(0);
    let result = tokio::select! {
        result = udp_to_quic(socket, connection, &oversized) => result,
        result = quic_to_udp(connection, socket, &oversized) => result,
        result = watch_control(control) => result,
        result = connection.accept_bi() => match result {
            Ok(_) => Err(anyhow::anyhow!("unexpected control stream")),
            Err(error) => Err(error.into()),
        },
        result = connection.accept_uni() => match result {
            Ok(_) => Err(anyhow::anyhow!("unexpected unidirectional stream")),
            Err(error) => Err(error.into()),
        },
    };
    let dropped = oversized.load(Ordering::Relaxed);
    if dropped > 0 {
        eprintln!("session oversized datagrams dropped: {dropped}");
    }
    result
}

async fn udp_to_quic(
    socket: &UdpSocket,
    connection: &Connection,
    oversized: &AtomicU64,
) -> Result<()> {
    let mut buffer = vec![0_u8; UDP_BUFFER];
    loop {
        let size = socket.recv(&mut buffer).await?;
        if size > MAX_DATAGRAM {
            oversized.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        check_datagram_budget(connection)?;
        connection.send_datagram(Bytes::copy_from_slice(&buffer[..size]))?;
    }
}

async fn quic_to_udp(
    connection: &Connection,
    socket: &UdpSocket,
    oversized: &AtomicU64,
) -> Result<()> {
    loop {
        let datagram = connection.read_datagram().await?;
        if datagram.len() > MAX_DATAGRAM {
            oversized.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        socket.send(&datagram).await?;
    }
}

async fn watch_control(stream: &mut RecvStream) -> Result<()> {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte).await? {
        Some(_) => bail!("unexpected control data"),
        None => bail!("control stream closed"),
    }
}
