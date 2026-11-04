//! Experimental SSH packet transport, not a replacement daemon.
//!
//! Owns the SSH transport protocol, using unmodified cryptographic crates.
//! Authentication and connection payloads remain opaque, including unknown
//! channel types and extensions. Only Curve25519, Ed25519, AES-256-GCM and
//! uncompressed traffic are supported at this stage.
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

mod codec;
mod connection;
mod kex;
mod transport;
mod wire;

pub use connection::{PacketReceiver, PacketSender};
pub use transport::{relay, Transport};

/// Maximum complete SSH binary packet length, excluding its authentication tag.
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
