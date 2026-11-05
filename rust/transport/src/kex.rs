use bytes::Bytes;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as EphemeralPublic};
use zeroize::Zeroizing;

use crate::{
    codec::Cipher,
    wire::{mpint, string, Reader},
    Error, Result,
};

const KEY_EXCHANGES: &str = "curve25519-sha256,curve25519-sha256@libssh.org";
pub(crate) const HOST_KEYS: &str = "ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521";
const CIPHERS: &str = "aes256-gcm@openssh.com,aes128-gcm@openssh.com";
const MACS: &str = "hmac-sha2-256,hmac-sha2-512";

#[derive(Clone, Debug)]
pub struct Algorithms {
    key_exchanges: String,
    ciphers: String,
    macs: String,
}

impl Algorithms {
    /// Preserve configured ordering, using defaults only for omitted lists.
    /// Unsupported names are rejected rather than silently broadening policy.
    pub fn new(key_exchanges: &[String], ciphers: &[String], macs: &[String]) -> Result<Self> {
        fn list(configured: &[String], supported: &str) -> Result<String> {
            if configured.is_empty() {
                return Ok(supported.to_owned());
            }
            if configured
                .iter()
                .any(|name| !supported.split(',').any(|allowed| allowed == name))
            {
                return Err(Error::Protocol(
                    "configured transport algorithm is unsupported",
                ));
            }
            Ok(configured.join(","))
        }
        Ok(Self {
            key_exchanges: list(key_exchanges, KEY_EXCHANGES)?,
            ciphers: list(ciphers, CIPHERS)?,
            macs: list(macs, MACS)?,
        })
    }
}

impl Default for Algorithms {
    fn default() -> Self {
        Self {
            key_exchanges: KEY_EXCHANGES.to_owned(),
            ciphers: CIPHERS.to_owned(),
            macs: MACS.to_owned(),
        }
    }
}

pub(crate) fn init(server: bool, host_keys: &str, initial: bool, algorithms: &Algorithms) -> Bytes {
    use rand_core::RngCore;
    let mut out = vec![20; 17];
    OsRng.fill_bytes(&mut out[1..]);
    let mut exchanges = algorithms.key_exchanges.clone();
    exchanges.push_str(if server {
        ",kex-strict-s-v00@openssh.com"
    } else {
        ",kex-strict-c-v00@openssh.com"
    });
    if initial {
        exchanges.push_str(if server { ",ext-info-s" } else { ",ext-info-c" });
    }
    string(&mut out, exchanges.as_bytes());
    for name in [
        host_keys.as_bytes(),
        algorithms.ciphers.as_bytes(),
        algorithms.ciphers.as_bytes(),
        algorithms.macs.as_bytes(),
        algorithms.macs.as_bytes(),
        b"none",
        b"none",
        b"",
        b"",
    ] {
        string(&mut out, name);
    }
    out.extend_from_slice(&[0; 5]);
    out.into()
}

pub(crate) struct Negotiated {
    pub strict: bool,
    pub discard_guess: bool,
    pub host_key: String,
    pub c2s_aes128: bool,
    pub s2c_aes128: bool,
    pub extensions: bool,
}

fn lists(peer: &[u8]) -> Result<(Vec<&[u8]>, bool)> {
    let mut reader = Reader(peer);
    if reader.byte()? != 20 {
        return Err(Error::Protocol("expected KEXINIT"));
    }
    reader.take(16)?;
    let mut lists = Vec::with_capacity(10);
    for _ in 0..10 {
        let list = reader.string()?;
        if !list.is_ascii() || list.contains(&0) {
            return Err(Error::Protocol("invalid algorithm name-list"));
        }
        lists.push(list);
    }
    let guess = match reader.byte()? {
        0 => false,
        1 => true,
        _ => return Err(Error::Protocol("invalid first_kex_packet_follows")),
    };
    if reader.uint()? != 0 {
        return Err(Error::Protocol("nonzero KEXINIT reserved field"));
    }
    reader.end()?;
    Ok((lists, guess))
}

pub(crate) fn negotiate(peer: &[u8], local: &[u8], server: bool) -> Result<Negotiated> {
    let (peer, guess) = lists(peer)?;
    let (local, _) = lists(local)?;
    let (client, server_lists) = if server {
        (&peer, &local)
    } else {
        (&local, &peer)
    };
    let choose = |index: usize| -> Result<&[u8]> {
        client[index]
            .split(|b| *b == b',')
            .find(|name| {
                server_lists[index]
                    .split(|b| *b == b',')
                    .any(|candidate| candidate == *name)
            })
            .ok_or(Error::Protocol("no supported transport algorithm"))
    };
    let key_exchange = choose(0)?;
    if !KEY_EXCHANGES
        .split(',')
        .any(|algorithm| algorithm.as_bytes() == key_exchange)
        || choose(6)? != b"none"
        || choose(7)? != b"none"
    {
        return Err(Error::Protocol("unsupported key exchange or compression"));
    }
    let host_key = choose(1)?;
    let c2s_aes128 = choose(2)? == b"aes128-gcm@openssh.com";
    let s2c_aes128 = choose(3)? == b"aes128-gcm@openssh.com";
    let strict_name: &[u8] = if server {
        b"kex-strict-c-v00@openssh.com"
    } else {
        b"kex-strict-s-v00@openssh.com"
    };
    Ok(Negotiated {
        strict: peer[0]
            .split(|b| *b == b',')
            .any(|name| name == strict_name),
        discard_guess: guess
            && (peer[0].split(|b| *b == b',').next() != Some(key_exchange)
                || peer[1].split(|b| *b == b',').next() != Some(host_key)),
        host_key: String::from_utf8(host_key.to_vec())
            .map_err(|_| Error::Protocol("invalid host key algorithm"))?,
        c2s_aes128,
        s2c_aes128,
        extensions: peer[0]
            .split(|b| *b == b',')
            .any(|name| name == if server { b"ext-info-c" } else { b"ext-info-s" }),
    })
}

pub(crate) struct Exchange {
    secret: EphemeralSecret,
    pub public: [u8; 32],
}

impl Exchange {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = EphemeralPublic::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn finish(self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::Protocol("invalid Curve25519 public key length"))?;
        let shared = self.secret.diffie_hellman(&EphemeralPublic::from(peer));
        if !shared.was_contributory() {
            return Err(Error::Protocol("non-contributory Curve25519 public key"));
        }
        let mut encoded = Zeroizing::new(Vec::new());
        mpint(&mut encoded, shared.as_bytes());
        Ok(encoded)
    }
}

pub(crate) fn hash(fields: [&[u8]; 7], shared: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field);
    }
    digest.update(shared);
    digest.finalize().into()
}

pub(crate) fn derive(
    shared: &[u8],
    hash: &[u8; 32],
    session_id: &[u8; 32],
    client_to_server: bool,
    aes128: bool,
) -> Cipher {
    let expand = |letter| {
        let mut digest = Sha256::new();
        digest.update(shared);
        digest.update(hash);
        digest.update([letter]);
        digest.update(session_id);
        Zeroizing::new(<[u8; 32]>::from(digest.finalize()))
    };
    let iv = expand(if client_to_server { b'A' } else { b'B' });
    let key = expand(if client_to_server { b'C' } else { b'D' });
    let iv = iv[..12].try_into().expect("derived IV length");
    if aes128 {
        Cipher::aes128(key[..16].try_into().expect("derived key length"), iv)
    } else {
        Cipher::new(&key, iv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_exchange_secrets() {
        let left = Exchange::new();
        let right = Exchange::new();
        let left_public = left.public;
        let right_public = right.public;
        assert_eq!(
            left.finish(&right_public).unwrap(),
            right.finish(&left_public).unwrap()
        );
    }

    #[test]
    fn zero_shared_secret_is_rejected() {
        assert!(Exchange::new().finish(&[0; 32]).is_err());
    }

    #[test]
    fn negotiation_and_trailing_data() {
        for server in [false, true] {
            let local = init(server, HOST_KEYS, true, &Algorithms::default());
            assert!(
                negotiate(
                    &init(!server, HOST_KEYS, true, &Algorithms::default()),
                    &local,
                    server
                )
                .unwrap()
                .strict
            );
            let mut malformed = init(!server, HOST_KEYS, true, &Algorithms::default()).to_vec();
            malformed.push(0);
            assert!(negotiate(&malformed, &local, server).is_err());
        }
    }

    #[test]
    fn every_truncated_kexinit_is_rejected() {
        let message = init(true, HOST_KEYS, true, &Algorithms::default());
        for length in 0..message.len() {
            assert!(negotiate(
                &message[..length],
                &init(false, HOST_KEYS, true, &Algorithms::default()),
                false
            )
            .is_err());
        }
    }

    #[test]
    fn configured_algorithms_are_not_broadened_during_negotiation() {
        let policy = Algorithms::new(
            &["curve25519-sha256@libssh.org".into()],
            &["aes128-gcm@openssh.com".into()],
            &["hmac-sha2-512".into()],
        )
        .unwrap();
        for initial in [true, false] {
            let peer = init(false, HOST_KEYS, initial, &Algorithms::default());
            let local = init(true, HOST_KEYS, initial, &policy);
            let negotiated = negotiate(&peer, &local, true).unwrap();
            assert!(negotiated.c2s_aes128 && negotiated.s2c_aes128);
            let (lists, _) = lists(&local).unwrap();
            assert!(!lists[0]
                .split(|byte| *byte == b',')
                .any(|name| name == b"curve25519-sha256"));
            assert_eq!(lists[2], b"aes128-gcm@openssh.com");
            assert_eq!(lists[4], b"hmac-sha2-512");
        }
        assert!(Algorithms::new(&["unknown".into()], &[], &[]).is_err());
        assert!(Algorithms::new(&[], &["aes256-ctr".into()], &[]).is_err());
        assert!(Algorithms::new(&[], &[], &["hmac-sha1".into()]).is_err());
    }

    #[test]
    fn altered_exchange_hash_invalidates_signature() {
        let key = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let signature = crate::sign(&key, &[1; 32], "ssh-ed25519").unwrap();
        crate::verify_signature(key.public_key(), &[1; 32], &signature, "ssh-ed25519").unwrap();
        assert!(
            crate::verify_signature(key.public_key(), &[2; 32], &signature, "ssh-ed25519").is_err()
        );
    }
}
