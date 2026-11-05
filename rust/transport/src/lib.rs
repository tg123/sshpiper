//! SSH packet transport used by the Rust-native sshpiperd daemon.
//!
//! Owns the SSH transport protocol, using unmodified cryptographic crates.
//! Authentication and connection payloads remain opaque, including unknown
//! channel types and extensions. Supports ML-KEM768/X25519 and Curve25519,
//! Ed25519/RSA-SHA2/ECDSA host signatures, host certificates, AES-128/256-GCM
//! and uncompressed traffic.
//!
//! Operations must be serialized. Cancelling an operation poisons the transport:
//! drop it rather than attempting to resume a partially completed key exchange.
//! Callers must impose connection/handshake deadlines.
//!
//! ```
//! use rand_core::OsRng;
//! use ssh_key::{Algorithm, PrivateKey};
//! use sshpiper_transport::Transport;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
//! let trusted_key = host_key.public_key().clone();
//! let (downstream, client) = tokio::io::duplex(65536);
//! let (server, client) = tokio::try_join!(
//!     Transport::accept(downstream, host_key),
//!     Transport::connect(client, trusted_key),
//! )?;
//! assert_eq!(server.session_id(), client.session_id());
//! // User authentication must still complete before any channel is relayed.
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod certificate;
mod codec;
mod connection;
mod identity;
mod kex;
mod transport;
pub mod wire;

pub use certificate::Certificate;
pub use connection::{PacketReceiver, PacketSender};
pub use identity::{
    public_key, sign, signature_algorithm, verify_signature, HostIdentity, HostKeyVerifier,
};
pub use kex::Algorithms;
pub use transport::{relay, Transport};

/// Maximum complete SSH binary packet length, excluding its authentication tag.
/// Includes the length field and cipher-dependent padding, not just the payload.
pub const MAX_PACKET: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("SSH protocol error: {0}")]
    Protocol(&'static str),
    #[error("SSH packet authentication failed")]
    Authentication,
    #[error("upstream host key does not match the trusted key")]
    HostKey,
    #[error("upstream host verification failed: {0}")]
    HostVerification(String),
    #[error("peer disconnected")]
    Disconnected,
    #[error("transport is unusable after an error or cancelled operation")]
    Poisoned,
    #[error("transport driver failed: {0}")]
    Driver(String),
    #[error(transparent)]
    Key(#[from] ssh_key::Error),
    #[error(transparent)]
    Encoding(#[from] ssh_encoding::Error),
    #[error(transparent)]
    Signature(#[from] signature::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
