use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid configuration {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("local_bind must use an IPv4 loopback address")]
    LocalBind,
    #[error("wireguard_port must be nonzero and differ from local_bind's port")]
    WireguardPort,
    #[error("{field} must use a nonzero port")]
    PeerPort { field: &'static str },
    #[error("server_name must be a valid ASCII DNS name")]
    ServerName,
    #[error("{field} must be between 1 and 32")]
    SessionLimit { field: &'static str },
    #[error("setup_timeout_secs must be nonzero and fit within the clock limit")]
    SetupTimeout,
    #[error("idle_timeout_secs must be nonzero and fit within the QUIC transport limit")]
    IdleTimeout,
}

// Only raw input is deserializable. Private fields/constructors make it impossible
// for the rest of the application to construct or mutate an unvalidated config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientConfig {
    local_bind: SocketAddr,
    wireguard_port: u16,
    relay_addr: SocketAddr,
    server_name: String,
    ca_cert_file: PathBuf,
    token_file: PathBuf,
}

#[derive(Debug)]
pub struct ClientConfig(RawClientConfig);

impl ClientConfig {
    pub fn local_bind(&self) -> SocketAddr {
        self.0.local_bind
    }
    pub fn wireguard_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.0.wireguard_port))
    }
    pub fn relay_addr(&self) -> SocketAddr {
        self.0.relay_addr
    }
    pub fn server_name(&self) -> &str {
        &self.0.server_name
    }
    pub fn ca_cert_file(&self) -> &Path {
        &self.0.ca_cert_file
    }
    pub fn token_file(&self) -> &Path {
        &self.0.token_file
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayConfig {
    listen: SocketAddr,
    exit_addr: SocketAddr,
    cert_file: PathBuf,
    key_file: PathBuf,
    token_file: PathBuf,
    limits: RawRelayLimits,
}

#[derive(Debug)]
pub struct RelayConfig {
    listen: SocketAddr,
    exit_addr: SocketAddr,
    cert_file: PathBuf,
    key_file: PathBuf,
    token_file: PathBuf,
    limits: RelayLimits,
}

impl RelayConfig {
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }
    pub fn exit_addr(&self) -> SocketAddr {
        self.exit_addr
    }
    pub fn cert_file(&self) -> &Path {
        &self.cert_file
    }
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }
    pub fn token_file(&self) -> &Path {
        &self.token_file
    }
    pub fn limits(&self) -> &RelayLimits {
        &self.limits
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelayLimits {
    max_active_sessions: usize,
    max_pending_handshakes: usize,
    setup_timeout_secs: u64,
    idle_timeout_secs: u64,
}

#[derive(Debug)]
pub struct RelayLimits {
    active: usize,
    pending: usize,
    setup: Duration,
    idle: quinn::IdleTimeout,
}

impl RelayLimits {
    pub fn active(&self) -> usize {
        self.active
    }
    pub fn pending(&self) -> usize {
        self.pending
    }
    pub fn setup_timeout(&self) -> Duration {
        self.setup
    }
    pub fn idle_timeout(&self) -> quinn::IdleTimeout {
        self.idle
    }
}

impl TryFrom<RawRelayLimits> for RelayLimits {
    type Error = ConfigError;

    fn try_from(raw: RawRelayLimits) -> Result<Self, Self::Error> {
        for (field, value) in [
            ("max_active_sessions", raw.max_active_sessions),
            ("max_pending_handshakes", raw.max_pending_handshakes),
        ] {
            if !(1..=32).contains(&value) {
                return Err(ConfigError::SessionLimit { field });
            }
        }
        let setup = Duration::from_secs(raw.setup_timeout_secs);
        if setup.is_zero() || std::time::Instant::now().checked_add(setup).is_none() {
            return Err(ConfigError::SetupTimeout);
        }
        let idle = Duration::from_secs(raw.idle_timeout_secs);
        if idle.is_zero() {
            return Err(ConfigError::IdleTimeout);
        }
        let idle = idle.try_into().map_err(|_| ConfigError::IdleTimeout)?;
        Ok(Self {
            active: raw.max_active_sessions,
            pending: raw.max_pending_handshakes,
            setup,
            idle,
        })
    }
}

pub fn load_client(path: &Path) -> Result<ClientConfig, ConfigError> {
    let raw: RawClientConfig = load(path)?;
    if !matches!(raw.local_bind.ip(), IpAddr::V4(ip) if ip.is_loopback()) {
        return Err(ConfigError::LocalBind);
    }
    if raw.wireguard_port == 0 || raw.wireguard_port == raw.local_bind.port() {
        return Err(ConfigError::WireguardPort);
    }
    require_peer_port(raw.relay_addr, "relay_addr")?;
    if !valid_server_name(&raw.server_name) {
        return Err(ConfigError::ServerName);
    }
    Ok(ClientConfig(raw))
}

pub fn load_relay(path: &Path) -> Result<RelayConfig, ConfigError> {
    let raw: RawRelayConfig = load(path)?;
    require_peer_port(raw.exit_addr, "exit_addr")?;
    let limits = raw.limits.try_into()?;
    Ok(RelayConfig {
        listen: raw.listen,
        exit_addr: raw.exit_addr,
        cert_file: raw.cert_file,
        key_file: raw.key_file,
        token_file: raw.token_file,
        limits,
    })
}

fn require_peer_port(addr: SocketAddr, field: &'static str) -> Result<(), ConfigError> {
    if addr.port() == 0 {
        Err(ConfigError::PeerPort { field })
    } else {
        Ok(())
    }
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn load<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.into(),
        source,
    })?;
    toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.into(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_invalid_counts_and_timeouts() {
        let raw = RawRelayLimits {
            max_active_sessions: 1,
            max_pending_handshakes: 1,
            setup_timeout_secs: 10,
            idle_timeout_secs: 60,
        };
        assert!(RelayLimits::try_from(raw).is_ok());
        for value in [0, u64::MAX] {
            assert!(matches!(
                RelayLimits::try_from(RawRelayLimits {
                    setup_timeout_secs: value,
                    ..raw
                }),
                Err(ConfigError::SetupTimeout)
            ));
            assert!(matches!(
                RelayLimits::try_from(RawRelayLimits {
                    idle_timeout_secs: value,
                    ..raw
                }),
                Err(ConfigError::IdleTimeout)
            ));
        }
        for value in [0, 33] {
            assert!(matches!(
                RelayLimits::try_from(RawRelayLimits {
                    max_active_sessions: value,
                    ..raw
                }),
                Err(ConfigError::SessionLimit { .. })
            ));
            assert!(matches!(
                RelayLimits::try_from(RawRelayLimits {
                    max_pending_handshakes: value,
                    ..raw
                }),
                Err(ConfigError::SessionLimit { .. })
            ));
        }
    }
}
