use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use tokio::{net::UdpSocket, time::timeout};

use crate::protocol::{MAX_DATAGRAM, MAX_FRAME, PROTOCOL_ERROR};

pub const DATAGRAM_BUFFER: usize = 64 * 1024;
pub const UDP_BUFFER: usize = 65_536;
// The receive APIs require this full buffer, preventing oversized UDP packets
// from being silently truncated into apparently valid protocol datagrams.
pub type UdpBuffer = [u8; UDP_BUFFER];

pub fn udp_buffer() -> Box<UdpBuffer> {
    vec![0; UDP_BUFFER]
        .into_boxed_slice()
        .try_into()
        .expect("fixed UDP buffer length")
}
pub fn client_idle_timeout() -> quinn::IdleTimeout {
    quinn::VarInt::from_u32(60_000).into()
}
pub const KEEPALIVE: Duration = Duration::from_secs(20);
pub const REPORT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Traffic {
    packets: AtomicU64,
    bytes: AtomicU64,
    oversized: AtomicU64,
}

#[derive(Default)]
pub struct Stats {
    udp_to_quic: Traffic,
    quic_to_udp: Traffic,
    pub disconnected_drops: AtomicU64,
    pub reconnects: AtomicU64,
    pub setup_errors: AtomicU64,
    pub session_errors: AtomicU64,
    pub rejected: AtomicU64,
}

impl Stats {
    pub fn report(&self, role: &'static str) {
        tracing::info!(
            role,
            udp_to_quic_packets = self.udp_to_quic.packets.load(Ordering::Relaxed),
            udp_to_quic_bytes = self.udp_to_quic.bytes.load(Ordering::Relaxed),
            udp_to_quic_oversized = self.udp_to_quic.oversized.load(Ordering::Relaxed),
            quic_to_udp_packets = self.quic_to_udp.packets.load(Ordering::Relaxed),
            quic_to_udp_bytes = self.quic_to_udp.bytes.load(Ordering::Relaxed),
            quic_to_udp_oversized = self.quic_to_udp.oversized.load(Ordering::Relaxed),
            disconnected_drops = self.disconnected_drops.load(Ordering::Relaxed),
            reconnects = self.reconnects.load(Ordering::Relaxed),
            setup_errors = self.setup_errors.load(Ordering::Relaxed),
            session_errors = self.session_errors.load(Ordering::Relaxed),
            rejected = self.rejected.load(Ordering::Relaxed),
            "traffic counters"
        );
    }
}

// Closing on drop also covers cancelled and timed-out setup futures.
pub struct CloseOnDrop(pub Connection);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(0_u32.into(), b"session ended");
    }
}

pub fn wildcard(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(
        match addr.ip() {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        },
        0,
    )
}

pub fn transport_config(
    idle_timeout: quinn::IdleTimeout,
    keepalive: Option<Duration>,
) -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_idle_timeout(Some(idle_timeout));
    config.keep_alive_interval(keepalive);
    config.max_concurrent_bidi_streams(1_u8.into());
    config.max_concurrent_uni_streams(0_u8.into());
    // One bounded control frame, with room for its prefix and protocol violation detection.
    let control_window = (MAX_FRAME + 4 + 1) as u32;
    config.stream_receive_window(control_window.into());
    config.receive_window(control_window.into());
    config.send_window(u64::from(control_window));
    config.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    config.datagram_send_buffer_size(DATAGRAM_BUFFER);
    Arc::new(config)
}

pub fn supports_datagrams(connection: &Connection) -> bool {
    connection
        .max_datagram_size()
        .is_some_and(|size| size >= MAX_DATAGRAM)
}

// Owning the send half prevents an accidental FIN while the receive half is monitored.
pub struct ControlStream {
    _send: SendStream,
    recv: RecvStream,
}

impl ControlStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { _send: send, recv }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    UnexpectedControlData,
    UnexpectedControlStream,
    ControlClosed,
    TransportClosed,
    UdpReceiveFailed,
    UdpSendFailed,
    DatagramBudgetLost,
    QuicSendFailed,
}

impl SessionEnd {
    pub fn reason(self) -> &'static str {
        match self {
            Self::UnexpectedControlData => "unexpected_control_data",
            Self::UnexpectedControlStream => "unexpected_control_stream",
            Self::ControlClosed => "control_closed",
            Self::TransportClosed => "transport_closed",
            Self::UdpReceiveFailed => "udp_receive_failed",
            Self::UdpSendFailed => "udp_send_failed",
            Self::DatagramBudgetLost => "datagram_budget_lost",
            Self::QuicSendFailed => "quic_send_failed",
        }
    }

    pub fn is_protocol_error(self) -> bool {
        matches!(
            self,
            Self::UnexpectedControlData | Self::UnexpectedControlStream
        )
    }
}

pub async fn forward_session(
    connection: &Connection,
    socket: &UdpSocket,
    control: &mut ControlStream,
    stats: &Stats,
    buffer: &mut UdpBuffer,
) -> SessionEnd {
    let mut control_byte = [0_u8; 1];
    let reason = tokio::select! {
        reason = udp_to_quic(socket, connection, &stats.udp_to_quic, buffer) => reason,
        reason = quic_to_udp(connection, socket, &stats.quic_to_udp) => reason,
        result = control.recv.read(&mut control_byte) => match result {
            Ok(Some(_)) => SessionEnd::UnexpectedControlData,
            _ => SessionEnd::ControlClosed,
        },
        result = connection.accept_bi() => if result.is_ok() {
            SessionEnd::UnexpectedControlStream
        } else {
            SessionEnd::TransportClosed
        },
        result = connection.accept_uni() => if result.is_ok() {
            SessionEnd::UnexpectedControlStream
        } else {
            SessionEnd::TransportClosed
        },
        _ = connection.closed() => SessionEnd::TransportClosed,
    };
    let protocol_error = reason.is_protocol_error();
    let normal_close = match connection.close_reason() {
        Some(quinn::ConnectionError::LocallyClosed) => true,
        Some(quinn::ConnectionError::ApplicationClosed(close)) => close.error_code == 0_u32.into(),
        _ => false,
    };
    if protocol_error {
        connection.close(PROTOCOL_ERROR.into(), b"protocol error");
    }
    if protocol_error || !normal_close {
        stats.session_errors.fetch_add(1, Ordering::Relaxed);
    }
    reason
}

async fn udp_to_quic(
    socket: &UdpSocket,
    connection: &Connection,
    stats: &Traffic,
    buffer: &mut UdpBuffer,
) -> SessionEnd {
    loop {
        let size = match socket.recv(&mut buffer[..]).await {
            Ok(size) => size,
            Err(_) => return SessionEnd::UdpReceiveFailed,
        };
        if size > MAX_DATAGRAM {
            stats.oversized.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if !supports_datagrams(connection) {
            return SessionEnd::DatagramBudgetLost;
        }
        if connection
            .send_datagram(Bytes::copy_from_slice(&buffer[..size]))
            .is_err()
        {
            return SessionEnd::QuicSendFailed;
        }
        stats.packets.fetch_add(1, Ordering::Relaxed);
        stats.bytes.fetch_add(size as u64, Ordering::Relaxed);
    }
}

async fn quic_to_udp(connection: &Connection, socket: &UdpSocket, stats: &Traffic) -> SessionEnd {
    loop {
        let datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(_) => return SessionEnd::TransportClosed,
        };
        if datagram.len() > MAX_DATAGRAM {
            stats.oversized.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if socket.send(&datagram).await.is_err() {
            return SessionEnd::UdpSendFailed;
        }
        stats.packets.fetch_add(1, Ordering::Relaxed);
        stats
            .bytes
            .fetch_add(datagram.len() as u64, Ordering::Relaxed);
    }
}

pub async fn shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

pub async fn close_endpoint(endpoint: &Endpoint) {
    endpoint.close(0_u32.into(), b"shutdown");
    if timeout(Duration::from_secs(3), endpoint.wait_idle())
        .await
        .is_err()
    {
        tracing::warn!("transport drain timed out");
    }
}
