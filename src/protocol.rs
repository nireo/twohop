use std::{fs, path::Path};

use anyhow::{Context, Result, ensure};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const ALPN: &[u8] = b"twohop/1";
pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 4096;
pub const MAX_DATAGRAM: usize = 1040;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRequest {
    pub version: u8,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthResponse {
    pub version: u8,
    pub max_datagram_size: usize,
}

pub fn load_token(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("cannot read token file {}", path.display()))?;
    let token = contents.strip_suffix('\n').unwrap_or(&contents);
    ensure!(
        token.len() == 64
            && token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "token file must contain 64 lowercase hex characters, with an optional final newline"
    );
    Ok(token.to_owned())
}

pub async fn write_frame<T: Serialize>(stream: &mut SendStream, message: &T) -> Result<()> {
    let payload = serde_json::to_vec(message)?;
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_FRAME,
        "control message is too large"
    );
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&payload).await?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .context("cannot read control length")?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        length > 0 && length <= MAX_FRAME,
        "invalid control message length"
    );
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .context("cannot read control message")?;
    serde_json::from_slice(&payload).context("invalid control message JSON")
}
