use std::{
    fs::{self, File},
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use serde::{Deserialize, de::DeserializeOwned};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub local_bind: SocketAddr,
    pub wireguard_port: u16,
    pub relay_addr: SocketAddr,
    pub server_name: String,
    pub ca_cert_file: PathBuf,
    pub token_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub listen: SocketAddr,
    pub exit_addr: SocketAddr,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub token_file: PathBuf,
    pub limits: RelayLimits,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLimits {
    pub max_active_sessions: usize,
    pub max_pending_handshakes: usize,
    pub setup_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

pub fn load_client(path: &Path) -> Result<ClientConfig, String> {
    let config: ClientConfig = load(path)?;
    config.validate()?;
    Ok(config)
}

pub fn load_relay(path: &Path) -> Result<RelayConfig, String> {
    let config: RelayConfig = load(path)?;
    config.validate()?;
    Ok(config)
}

impl ClientConfig {
    fn validate(&self) -> Result<(), String> {
        if !matches!(self.local_bind.ip(), IpAddr::V4(ip) if ip.is_loopback()) {
            return Err("local_bind must use an IPv4 loopback address".into());
        }
        require_port(self.local_bind, "local_bind")?;
        if self.wireguard_port == 0 || self.wireguard_port == self.local_bind.port() {
            return Err("wireguard_port must be nonzero and differ from local_bind's port".into());
        }
        require_port(self.relay_addr, "relay_addr")?;
        if !valid_server_name(&self.server_name) {
            return Err("server_name must be a valid ASCII DNS name".into());
        }
        require_nonempty_file(&self.ca_cert_file, "ca_cert_file")?;
        require_nonempty_file(&self.token_file, "token_file")
    }
}

impl RelayConfig {
    fn validate(&self) -> Result<(), String> {
        require_port(self.listen, "listen")?;
        require_port(self.exit_addr, "exit_addr")?;
        require_nonempty_file(&self.cert_file, "cert_file")?;
        require_nonempty_file(&self.key_file, "key_file")?;
        require_nonempty_file(&self.token_file, "token_file")?;
        self.limits.validate()
    }
}

impl RelayLimits {
    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("max_active_sessions", self.max_active_sessions),
            ("max_pending_handshakes", self.max_pending_handshakes),
        ] {
            if !(1..=32).contains(&value) {
                return Err(format!("{name} must be between 1 and 32"));
            }
        }
        if self.setup_timeout_secs == 0 || self.idle_timeout_secs == 0 {
            return Err("setup_timeout_secs and idle_timeout_secs must be nonzero".into());
        }
        if std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(self.setup_timeout_secs))
            .is_none()
        {
            return Err("setup_timeout_secs exceeds the clock limit".into());
        }
        if quinn::IdleTimeout::try_from(std::time::Duration::from_secs(self.idle_timeout_secs))
            .is_err()
        {
            return Err("idle_timeout_secs exceeds the QUIC transport limit".into());
        }
        Ok(())
    }
}

fn require_port(addr: SocketAddr, name: &str) -> Result<(), String> {
    if addr.port() == 0 {
        Err(format!("{name} must use a nonzero port"))
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

fn require_nonempty_file(path: &Path, name: &str) -> Result<(), String> {
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open {name} {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {name} {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{name} must be a regular file: {}", path.display()));
    }
    if file
        .read(&mut [0])
        .map_err(|error| format!("cannot read {name} {}: {error}", path.display()))?
        == 0
    {
        return Err(format!("{name} must not be empty: {}", path.display()));
    }
    Ok(())
}

fn load<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("cannot read configuration {}: {error}", path.display()))?;

    toml::from_str(&contents).map_err(|error: toml::de::Error| {
        format!(
            "invalid configuration {}: {}",
            path.display(),
            error.message()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unrepresentable_timeouts_before_startup() {
        let mut limits = RelayLimits {
            max_active_sessions: 1,
            max_pending_handshakes: 1,
            setup_timeout_secs: 10,
            idle_timeout_secs: 60,
        };
        assert!(limits.validate().is_ok());
        limits.setup_timeout_secs = u64::MAX;
        assert_eq!(
            limits.validate().unwrap_err(),
            "setup_timeout_secs exceeds the clock limit"
        );
        limits.setup_timeout_secs = 10;
        limits.idle_timeout_secs = u64::MAX;
        assert_eq!(
            limits.validate().unwrap_err(),
            "idle_timeout_secs exceeds the QUIC transport limit"
        );
    }
}
