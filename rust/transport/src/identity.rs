use futures_util::future::BoxFuture;
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_encoding::{Decode, Encode};
use ssh_key::{certificate::CertType, Algorithm, Certificate, PrivateKey, PublicKey, Signature};

use crate::{wire::Reader, Error, Result};

/// Policy invoked for every upstream key exchange, after signature verification.
pub trait HostKeyVerifier: Send + Sync {
    fn verify<'a>(&'a self, key: &'a [u8]) -> BoxFuture<'a, Result<()>>;
}

impl HostKeyVerifier for PublicKey {
    fn verify<'a>(&'a self, key: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if public_key(key)?.key_data() != self.key_data() {
                return Err(Error::HostKey);
            }
            Ok(())
        })
    }
}

/// A private host key and, optionally, its matching OpenSSH host certificate.
#[derive(Clone)]
pub struct HostIdentity {
    pub(crate) private: PrivateKey,
    certificate: Option<Certificate>,
}

impl HostIdentity {
    pub fn new(private: PrivateKey, certificate: Option<Certificate>) -> Result<Self> {
        if private.is_encrypted() {
            return Err(Error::Protocol("host key is encrypted"));
        }
        if !matches!(
            private.algorithm(),
            Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. }
        ) {
            return Err(Error::Protocol("unsupported host key algorithm"));
        }
        if let Some(cert) = &certificate {
            if cert.cert_type() != CertType::Host
                || cert.public_key() != private.public_key().key_data()
            {
                return Err(Error::Protocol("host certificate does not match host key"));
            }
        }
        Ok(Self {
            private,
            certificate,
        })
    }

    pub fn algorithms(&self) -> Vec<String> {
        let names = if self.private.algorithm().is_rsa() {
            vec!["rsa-sha2-512".to_owned(), "rsa-sha2-256".to_owned()]
        } else {
            vec![self.private.algorithm().as_str().to_owned()]
        };
        if self.certificate.is_some() {
            names
                .into_iter()
                .map(|name| format!("{name}-cert-v01@openssh.com"))
                .collect()
        } else {
            names
        }
    }

    pub(crate) fn encoded(&self) -> Result<Vec<u8>> {
        Ok(match &self.certificate {
            Some(cert) => cert.to_bytes()?,
            None => self.private.public_key().to_bytes()?,
        })
    }
}

pub fn signature_algorithm(algorithm: &str) -> &str {
    algorithm
        .strip_suffix("-cert-v01@openssh.com")
        .unwrap_or(algorithm)
}

/// Decode the signing key without making a trust decision about a certificate.
pub fn public_key(encoded: &[u8]) -> Result<PublicKey> {
    if Reader(encoded).text()?.ends_with("-cert-v01@openssh.com") {
        let cert = Certificate::from_bytes(encoded)?;
        Ok(PublicKey::new(cert.public_key().clone(), ""))
    } else {
        Ok(PublicKey::from_bytes(encoded)?)
    }
}

pub fn sign(key: &PrivateKey, message: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    let algorithm = signature_algorithm(algorithm);
    let signature: Signature = if algorithm == "rsa-sha2-256" {
        let pair = key
            .key_data()
            .rsa()
            .ok_or(Error::Protocol("RSA signature requires an RSA key"))?;
        let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::try_from(pair)?;
        Signature::new(
            Algorithm::new(algorithm)?,
            signing.try_sign(message)?.to_vec(),
        )?
    } else {
        key.try_sign(message)?
    };
    if signature.algorithm().as_str() != algorithm {
        return Err(Error::Protocol(
            "signature algorithm does not match request",
        ));
    }
    let mut encoded = Vec::new();
    signature.encode(&mut encoded)?;
    Ok(encoded)
}

pub fn verify_signature(
    key: &PublicKey,
    message: &[u8],
    encoded: &[u8],
    algorithm: &str,
) -> Result<()> {
    let mut reader = encoded;
    let signature = Signature::decode(&mut reader)?;
    if !reader.is_empty() || signature.algorithm().as_str() != signature_algorithm(algorithm) {
        return Err(Error::Protocol("invalid signature encoding or algorithm"));
    }
    Verifier::verify(key, message, &signature)?;
    Ok(())
}
