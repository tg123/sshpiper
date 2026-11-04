use bytes::Bytes;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use ssh_encoding::{Decode, Encode};
use ssh_key::{PrivateKey, PublicKey, Signature};
use x25519_dalek::{EphemeralSecret, PublicKey as EphemeralPublic};
use zeroize::Zeroizing;

use crate::{
    codec::Cipher,
    wire::{mpint, string, Reader},
    Error, Result,
};

const KEX: &[u8] = b"curve25519-sha256";
const HOST_KEY: &[u8] = b"ssh-ed25519";
const CIPHER: &[u8] = b"aes256-gcm@openssh.com";

pub(crate) fn init(server: bool) -> Bytes {
    use rand_core::RngCore;
    let mut out = vec![20; 17];
    OsRng.fill_bytes(&mut out[1..]);
    string(
        &mut out,
        if server {
            b"curve25519-sha256,kex-strict-s-v00@openssh.com"
        } else {
            b"curve25519-sha256,kex-strict-c-v00@openssh.com"
        },
    );
    for name in [
        HOST_KEY,
        CIPHER,
        CIPHER,
        b"hmac-sha2-256",
        b"hmac-sha2-256",
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
}

pub(crate) fn negotiate(peer: &[u8], server: bool) -> Result<Negotiated> {
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
    for (index, required) in [
        (0, KEX),
        (1, HOST_KEY),
        (2, CIPHER),
        (3, CIPHER),
        (6, &b"none"[..]),
        (7, &b"none"[..]),
    ] {
        if !lists[index]
            .split(|b| *b == b',')
            .any(|name| name == required)
        {
            return Err(Error::Protocol("no supported transport algorithm"));
        }
    }
    let strict_name: &[u8] = if server {
        b"kex-strict-c-v00@openssh.com"
    } else {
        b"kex-strict-s-v00@openssh.com"
    };
    Ok(Negotiated {
        strict: lists[0]
            .split(|b| *b == b',')
            .any(|name| name == strict_name),
        discard_guess: guess
            && (lists[0].split(|b| *b == b',').next() != Some(KEX)
                || lists[1].split(|b| *b == b',').next() != Some(HOST_KEY)),
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

pub(crate) fn sign(key: &PrivateKey, hash: &[u8]) -> Result<Vec<u8>> {
    let signature: Signature = key.try_sign(hash)?;
    let mut encoded = Vec::new();
    signature.encode(&mut encoded)?;
    Ok(encoded)
}

pub(crate) fn verify(trusted: &PublicKey, key: &[u8], hash: &[u8], signature: &[u8]) -> Result<()> {
    let presented = PublicKey::from_bytes(key)?;
    if presented.key_data() != trusted.key_data() {
        return Err(Error::HostKey);
    }
    let mut reader = signature;
    let signature = Signature::decode(&mut reader)?;
    if !reader.is_empty() {
        return Err(Error::Protocol("trailing signature data"));
    }
    Verifier::verify(&presented, hash, &signature)?;
    Ok(())
}

pub(crate) fn derive(
    shared: &[u8],
    hash: &[u8; 32],
    session_id: &[u8; 32],
    client_to_server: bool,
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
    Cipher::new(&key, iv[..12].try_into().expect("derived IV length"))
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
            assert!(negotiate(&init(!server), server).unwrap().strict);
            let mut malformed = init(!server).to_vec();
            malformed.push(0);
            assert!(negotiate(&malformed, server).is_err());
        }
    }

    #[test]
    fn every_truncated_kexinit_is_rejected() {
        let message = init(true);
        for length in 0..message.len() {
            assert!(negotiate(&message[..length], false).is_err());
        }
    }

    #[test]
    fn altered_exchange_hash_invalidates_signature() {
        let key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let encoded_key = key.public_key().to_bytes().unwrap();
        let signature = sign(&key, &[1; 32]).unwrap();
        verify(key.public_key(), &encoded_key, &[1; 32], &signature).unwrap();
        assert!(verify(key.public_key(), &encoded_key, &[2; 32], &signature).is_err());
    }
}
