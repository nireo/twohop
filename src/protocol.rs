use quinn::{ConnectionError, ReadError, ReadExactError, RecvStream, SendStream, WriteError};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const ALPN: &[u8] = b"twohop/1";
pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 4096;
pub const MAX_DATAGRAM: usize = 1040;

// Application close codes; reasons are fixed strings, never peer-provided data.
pub const AUTH_REJECTED: u32 = 1;
pub const PROTOCOL_ERROR: u32 = 2;
pub const SERVER_BUSY: u32 = 3;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRequest<T = String> {
    pub version: u8,
    pub token: T,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthResponse {
    pub version: u8,
    pub max_datagram_size: usize,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("invalid control message length: {0}")]
    Length(usize),
    #[error("cannot write control message")]
    Write(#[from] WriteError),
    #[error("cannot read control message")]
    Read(#[from] ReadExactError),
    // The source remains available for programmatic inspection; callers log fixed reasons.
    #[error("invalid control message JSON")]
    Json(#[from] serde_json::Error),
}

impl FrameError {
    pub fn connection_error(&self) -> Option<&ConnectionError> {
        match self {
            Self::Write(WriteError::ConnectionLost(error))
            | Self::Read(ReadExactError::ReadError(ReadError::ConnectionLost(error))) => {
                Some(error)
            }
            _ => None,
        }
    }
}

// A length can only be constructed after checking bounds, before allocation.
struct FrameLength(usize);

impl TryFrom<usize> for FrameLength {
    type Error = FrameError;

    fn try_from(length: usize) -> Result<Self, Self::Error> {
        if (1..=MAX_FRAME).contains(&length) {
            Ok(Self(length))
        } else {
            Err(FrameError::Length(length))
        }
    }
}

pub async fn write_frame<T: Serialize>(
    stream: &mut SendStream,
    message: &T,
) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(message)?;
    let length = FrameLength::try_from(payload.len())?;
    stream.write_all(&(length.0 as u32).to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T, FrameError> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).await?;
    let length = FrameLength::try_from(u32::from_be_bytes(length) as usize)?;
    let mut payload = vec![0_u8; length.0];
    stream.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}
