use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Run(#[from] RunError),
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error(transparent)]
    Credential(#[from] crate::credentials::CredentialError),
    #[error("cannot configure TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("TLS configuration has no QUIC-compatible initial cipher suite")]
    QuicCrypto(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    #[error("cannot {operation}: {source}")]
    Socket {
        operation: SocketOperation,
        #[source]
        source: io::Error,
    },
    #[error("cannot handle shutdown signals: {0}")]
    Signal(#[source] io::Error),
    #[error("client setup failed: {0}")]
    Setup(#[from] crate::client::SetupError),
    #[error("local UDP port conflicts with wireguard_port")]
    LocalPortConflict,
    #[error("relay violated the session protocol")]
    ProtocolViolation,
    #[error("relay rejected the session protocol")]
    ProtocolRejected,
}

#[derive(Debug, Clone, Copy)]
pub enum SocketOperation {
    BindQuic,
    InspectQuic,
    BindLocal,
    InspectLocal,
    ConnectLocal,
    DiscardLocal,
}

impl std::fmt::Display for SocketOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BindQuic => "bind QUIC socket",
            Self::InspectQuic => "inspect QUIC socket",
            Self::InspectLocal => "inspect local UDP socket",
            Self::BindLocal => "bind local UDP socket",
            Self::ConnectLocal => "connect local WireGuard socket",
            Self::DiscardLocal => "discard local UDP traffic",
        })
    }
}

impl SocketOperation {
    pub fn error(self, source: io::Error) -> RunError {
        RunError::Socket {
            operation: self,
            source,
        }
    }
}
