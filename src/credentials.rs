use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use rustls::{
    RootCertStore,
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{self, PemObject},
    },
};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("cannot read credential file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("credential must be a regular file: {}", .0.display())]
    NotRegular(PathBuf),
    #[error("credential file must not be empty: {}", .0.display())]
    Empty(PathBuf),
    #[error("invalid PEM in {}: {source}", path.display())]
    Pem {
        path: PathBuf,
        #[source]
        source: pem::Error,
    },
    #[error("certificate file has no certificates: {}", .0.display())]
    NoCertificates(PathBuf),
    #[error("invalid CA certificate: {0}")]
    Certificate(#[from] rustls::Error),
    #[error("token file must contain 64 lowercase hex characters, with an optional final newline")]
    InvalidToken,
}

// No Debug/Serialize implementation: secrets must never appear in diagnostics.
// Construction guarantees the exact token format used on the wire.
pub struct AccessToken([u8; 64]);

impl AccessToken {
    fn parse(contents: &[u8]) -> Result<Self, CredentialError> {
        let bytes = contents.strip_suffix(b"\n").unwrap_or(contents);
        let token: [u8; 64] = bytes
            .try_into()
            .map_err(|_| CredentialError::InvalidToken)?;
        if !token
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(CredentialError::InvalidToken);
        }
        Ok(Self(token))
    }

    pub fn load(path: &Path) -> Result<Self, CredentialError> {
        Self::parse(&read(path)?)
    }

    pub fn as_str(&self) -> &str {
        // parse accepts only ASCII. Keep the conversion safe rather than using unchecked UTF-8.
        std::str::from_utf8(&self.0).expect("validated ASCII token")
    }

    pub fn matches(&self, supplied: &str) -> bool {
        bool::from(self.0.as_slice().ct_eq(supplied.as_bytes()))
    }
}

pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, CredentialError> {
    let contents = read(path)?;
    let certs = CertificateDer::pem_slice_iter(&contents)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CredentialError::Pem {
            path: path.into(),
            source,
        })?;
    if certs.is_empty() {
        return Err(CredentialError::NoCertificates(path.into()));
    }
    Ok(certs)
}

pub fn roots(path: &Path) -> Result<RootCertStore, CredentialError> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(path)? {
        roots.add(cert)?;
    }
    Ok(roots)
}

pub fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>, CredentialError> {
    PrivateKeyDer::from_pem_slice(&read(path)?).map_err(|source| CredentialError::Pem {
        path: path.into(),
        source,
    })
}

fn read(path: &Path) -> Result<Vec<u8>, CredentialError> {
    let io_error = |source| CredentialError::Io {
        path: path.into(),
        source,
    };
    let mut file = File::open(path).map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(CredentialError::NotRegular(path.into()));
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).map_err(io_error)?;
    if contents.is_empty() {
        return Err(CredentialError::Empty(path.into()));
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_format_and_comparison() {
        let valid = "a0".repeat(32);
        for text in [valid.clone(), format!("{valid}\n")] {
            let token = AccessToken::parse(text.as_bytes()).unwrap();
            assert_eq!(token.as_str(), valid);
            assert!(token.matches(&valid));
            assert!(!token.matches(&"b0".repeat(32)));
        }
        for text in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            format!("{valid}\r\n"),
            format!("{valid}\n\n"),
        ] {
            assert!(matches!(
                AccessToken::parse(text.as_bytes()),
                Err(CredentialError::InvalidToken)
            ));
        }
    }
}
