use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce, Tag,
};
use bytes::{BufMut, Bytes, BytesMut};
use rand_core::{OsRng, RngCore};
use tokio_util::codec::{Decoder, Encoder};

use crate::{Error, Result, MAX_PACKET};

pub(crate) struct Cipher {
    key: Key,
    iv: [u8; 12],
    exhausted: bool,
}

enum Key {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl Cipher {
    pub fn new(key: &[u8; 32], iv: [u8; 12]) -> Self {
        Self {
            key: Key::Aes256(Box::new(Aes256Gcm::new(key.into()))),
            iv,
            exhausted: false,
        }
    }

    pub fn aes128(key: &[u8; 16], iv: [u8; 12]) -> Self {
        Self {
            key: Key::Aes128(Box::new(Aes128Gcm::new(key.into()))),
            iv,
            exhausted: false,
        }
    }

    fn decrypt(&self, aad: &[u8], data: &mut [u8], tag: &Tag) -> Result<()> {
        let nonce = Nonce::from_slice(&self.iv);
        match &self.key {
            Key::Aes128(key) => key.decrypt_in_place_detached(nonce, aad, data, tag),
            Key::Aes256(key) => key.decrypt_in_place_detached(nonce, aad, data, tag),
        }
        .map_err(|_| Error::Authentication)
    }

    fn encrypt(&self, aad: &[u8], data: &mut [u8]) -> Result<Tag> {
        let nonce = Nonce::from_slice(&self.iv);
        match &self.key {
            Key::Aes128(key) => key.encrypt_in_place_detached(nonce, aad, data),
            Key::Aes256(key) => key.encrypt_in_place_detached(nonce, aad, data),
        }
        .map_err(|_| Error::Authentication)
    }

    fn advance(&mut self) {
        let counter = u64::from_be_bytes(self.iv[4..].try_into().expect("fixed nonce"));
        match counter.checked_add(1) {
            Some(counter) => self.iv[4..].copy_from_slice(&counter.to_be_bytes()),
            None => self.exhausted = true,
        }
    }
}

#[derive(Default)]
pub(crate) struct Codec {
    pub rx: Option<Cipher>,
    pub tx: Option<Cipher>,
    pub rx_sequence: u32,
    pub tx_sequence: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl Decoder for Codec {
    type Item = Bytes;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Bytes>> {
        if src.len() < 4 {
            return Ok(None);
        }
        let length = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
        if !(6..=MAX_PACKET - 4).contains(&length) {
            return Err(Error::Protocol("invalid packet length"));
        }
        let encrypted = self.rx.is_some();
        let alignment = if encrypted {
            length % 16
        } else {
            (length + 4) % 8
        };
        if alignment != 0 {
            return Err(Error::Protocol("invalid packet alignment"));
        }
        let total = 4 + length + if encrypted { 16 } else { 0 };
        if src.len() < total {
            return Ok(None);
        }
        let mut packet = src.split_to(total);
        if let Some(cipher) = &mut self.rx {
            if cipher.exhausted {
                return Err(Error::Protocol("receive nonce exhausted"));
            }
            let aad: [u8; 4] = packet[..4].try_into().expect("validated packet length");
            let tag = Tag::clone_from_slice(&packet[4 + length..]);
            cipher.decrypt(&aad, &mut packet[4..4 + length], &tag)?;
            cipher.advance();
        }
        let padding = packet[4] as usize;
        if padding < 4 || padding + 1 >= length {
            return Err(Error::Protocol("invalid padding length"));
        }
        self.rx_sequence = self.rx_sequence.wrapping_add(1);
        self.rx_bytes += total as u64;
        Ok(Some(packet.freeze().slice(5..4 + length - padding)))
    }
}

impl Encoder<Bytes> for Codec {
    type Error = Error;

    fn encode(&mut self, payload: Bytes, dst: &mut BytesMut) -> Result<()> {
        // Bound the payload before padding arithmetic, then check the padded packet.
        if payload.is_empty() || payload.len() > MAX_PACKET - 4 {
            return Err(Error::Protocol("invalid payload length"));
        }
        let encrypted = self.tx.is_some();
        let block = if encrypted { 16 } else { 8 };
        let prefix = if encrypted { 1 } else { 5 };
        let mut padding = block - (prefix + payload.len()) % block;
        if padding < 4 {
            padding += block;
        }
        let length = 1 + payload.len() + padding;
        if length > MAX_PACKET - 4 {
            return Err(Error::Protocol("invalid payload length"));
        }
        let start = dst.len();
        dst.put_u32(length as u32);
        dst.put_u8(padding as u8);
        dst.extend_from_slice(&payload);
        let padding_start = dst.len();
        dst.resize(padding_start + padding, 0);
        OsRng.fill_bytes(&mut dst[padding_start..]);
        if let Some(cipher) = &mut self.tx {
            if cipher.exhausted {
                return Err(Error::Protocol("send nonce exhausted"));
            }
            let tag = cipher.encrypt(&(length as u32).to_be_bytes(), &mut dst[start + 4..])?;
            dst.extend_from_slice(&tag);
            cipher.advance();
        }
        self.tx_sequence = self.tx_sequence.wrapping_add(1);
        self.tx_bytes += (dst.len() - start) as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Codec, Codec) {
        (
            Codec {
                tx: Some(Cipher::new(&[7; 32], [3; 12])),
                ..Codec::default()
            },
            Codec {
                rx: Some(Cipher::new(&[7; 32], [3; 12])),
                ..Codec::default()
            },
        )
    }

    #[test]
    fn fragmented_packets_and_opaque_payloads() {
        for encrypted in [false, true] {
            let (mut tx, mut rx) = if encrypted {
                pair()
            } else {
                (Codec::default(), Codec::default())
            };
            for size in [1, 2, 15, 16, 17, 255, 32768, MAX_PACKET - 32] {
                let payload = Bytes::from((0..size).map(|n| (n % 256) as u8).collect::<Vec<_>>());
                let mut encoded = BytesMut::new();
                tx.encode(payload.clone(), &mut encoded).unwrap();
                let mut input = BytesMut::new();
                for byte in &encoded[..encoded.len() - 1] {
                    input.extend_from_slice(&[*byte]);
                    assert!(rx.decode(&mut input).unwrap().is_none());
                }
                input.extend_from_slice(&encoded[encoded.len() - 1..]);
                assert_eq!(rx.decode(&mut input).unwrap(), Some(payload));
                assert!(input.is_empty());
            }
        }
    }

    #[test]
    fn packet_size_boundaries_match_decoder() {
        for (tx_cipher, rx_cipher, max_payload, max_packet) in [
            (None, None, MAX_PACKET - 9, MAX_PACKET),
            (
                Some(Cipher::aes128(&[7; 16], [3; 12])),
                Some(Cipher::aes128(&[7; 16], [3; 12])),
                MAX_PACKET - 21,
                MAX_PACKET - 12,
            ),
            (
                Some(Cipher::new(&[7; 32], [3; 12])),
                Some(Cipher::new(&[7; 32], [3; 12])),
                MAX_PACKET - 21,
                MAX_PACKET - 12,
            ),
        ] {
            let encrypted = tx_cipher.is_some();
            let mut tx = Codec {
                tx: tx_cipher,
                ..Codec::default()
            };
            let mut rx = Codec {
                rx: rx_cipher,
                ..Codec::default()
            };
            for size in max_payload - 20..=max_payload {
                let payload = Bytes::from(vec![0x5e; size]);
                let mut encoded = BytesMut::new();
                tx.encode(payload.clone(), &mut encoded).unwrap();
                let length = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
                assert!(length <= MAX_PACKET - 4);
                if size == max_payload {
                    assert_eq!(length + 4, max_packet);
                    assert_eq!(encoded.len(), max_packet + if encrypted { 16 } else { 0 });
                }
                assert_eq!(rx.decode(&mut encoded).unwrap(), Some(payload));
                assert!(encoded.is_empty());
            }

            for size in [
                0,
                max_payload + 1,
                MAX_PACKET - 4,
                MAX_PACKET,
                MAX_PACKET + 1,
            ] {
                let mut encoded = BytesMut::from(&b"prefix"[..]);
                let sequence = tx.tx_sequence;
                let bytes = tx.tx_bytes;
                assert!(matches!(
                    tx.encode(Bytes::from(vec![0x5e; size]), &mut encoded),
                    Err(Error::Protocol("invalid payload length"))
                ));
                assert_eq!(encoded.as_ref(), b"prefix");
                assert_eq!(tx.tx_sequence, sequence);
                assert_eq!(tx.tx_bytes, bytes);
            }

            let rejected_length = (max_packet - 4 + if encrypted { 16 } else { 8 }) as u32;
            let mut input = BytesMut::from(&rejected_length.to_be_bytes()[..]);
            assert!(matches!(
                rx.decode(&mut input),
                Err(Error::Protocol("invalid packet length"))
            ));

            let payload = Bytes::from_static(b"\x5eafter rejected packets");
            let mut encoded = BytesMut::new();
            tx.encode(payload.clone(), &mut encoded).unwrap();
            assert_eq!(rx.decode(&mut encoded).unwrap(), Some(payload));
        }
    }

    #[test]
    fn tampering_is_rejected_before_payload_delivery() {
        for position in [4, 5, 20, 35] {
            let (mut tx, mut rx) = pair();
            let mut encoded = BytesMut::new();
            tx.encode(
                Bytes::from_static(b"\x5eprivate channel payload"),
                &mut encoded,
            )
            .unwrap();
            encoded[position] ^= 1;
            assert!(matches!(
                rx.decode(&mut encoded),
                Err(Error::Authentication)
            ));
        }
    }

    #[test]
    fn invalid_lengths_do_not_require_buffering_the_body() {
        for length in [0_u32, 5, MAX_PACKET as u32, u32::MAX] {
            let mut input = BytesMut::from(&length.to_be_bytes()[..]);
            assert!(Codec::default().decode(&mut input).is_err());
        }
    }

    #[test]
    fn nonce_wrap_is_terminal() {
        let (mut tx, mut rx) = pair();
        tx.tx.as_mut().unwrap().iv[4..].fill(255);
        rx.rx.as_mut().unwrap().iv[4..].fill(255);
        let mut encoded = BytesMut::new();
        tx.encode(Bytes::from_static(b"\x5ehello"), &mut encoded)
            .unwrap();
        assert!(rx.decode(&mut encoded).unwrap().is_some());
        assert!(tx
            .encode(Bytes::from_static(b"\x5eagain"), &mut encoded)
            .is_err());
    }
}
