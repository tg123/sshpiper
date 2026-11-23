use bytes::{BufMut, Bytes, BytesMut};
use rand_core::{OsRng, RngCore};
use ring::aead::{self, Aad, LessSafeKey, Nonce, Tag, UnboundKey};
use tokio_util::codec::{Decoder, Encoder};

use crate::{Error, Result, MAX_PACKET};

pub(crate) struct Cipher {
    // Codec owns SSH's per-direction nonce sequence; this cipher must not be cloned.
    key: Box<LessSafeKey>,
    iv: [u8; 12],
    exhausted: bool,
}

impl Cipher {
    pub fn new(key: &[u8; 32], iv: [u8; 12]) -> Self {
        Self {
            key: Box::new(LessSafeKey::new(
                UnboundKey::new(&aead::AES_256_GCM, key).expect("fixed AES-256 key length"),
            )),
            iv,
            exhausted: false,
        }
    }

    pub fn aes128(key: &[u8; 16], iv: [u8; 12]) -> Self {
        Self {
            key: Box::new(LessSafeKey::new(
                UnboundKey::new(&aead::AES_128_GCM, key).expect("fixed AES-128 key length"),
            )),
            iv,
            exhausted: false,
        }
    }

    fn decrypt(&self, aad: &[u8], data: &mut [u8], tag: Tag) -> Result<()> {
        self.key
            .open_in_place_separate_tag(
                Nonce::assume_unique_for_key(self.iv),
                Aad::from(aad),
                tag,
                data,
                0..,
            )
            .map(|_| ())
            .map_err(|_| Error::Authentication)
    }

    fn encrypt(&self, aad: &[u8], data: &mut [u8]) -> Result<Tag> {
        self.key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(self.iv), Aad::from(aad), data)
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
            let tag = Tag::try_from(&packet[4 + length..]).expect("validated GCM tag length");
            cipher.decrypt(&aad, &mut packet[4..4 + length], tag)?;
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
            dst.extend_from_slice(tag.as_ref());
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
    use aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes128Gcm, Aes256Gcm,
    };

    #[test]
    fn aes_gcm_matches_independent_provider_in_both_directions() {
        for aes128 in [true, false] {
            let cipher = || {
                if aes128 {
                    Cipher::aes128(&[7; 16], [3; 12])
                } else {
                    Cipher::new(&[7; 32], [3; 12])
                }
            };
            let mut tx = Codec {
                tx: Some(cipher()),
                ..Codec::default()
            };
            let mut rx = Codec {
                rx: Some(cipher()),
                ..Codec::default()
            };
            let key128 = Aes128Gcm::new_from_slice(&[7; 16]).unwrap();
            let key256 = Aes256Gcm::new_from_slice(&[7; 32]).unwrap();
            let mut iv = [3; 12];
            for size in [1, 16, 8192, 32768, MAX_PACKET - 21] {
                let payload = Bytes::from(vec![200; size]);
                let mut encoded = BytesMut::new();
                tx.encode(payload.clone(), &mut encoded).unwrap();
                let aad = u32::from_be_bytes(encoded[..4].try_into().unwrap()).to_be_bytes();
                let length = u32::from_be_bytes(aad) as usize;
                let tag = aes_gcm::Tag::clone_from_slice(&encoded[4 + length..]);
                let mut plaintext = encoded[4..4 + length].to_vec();
                let nonce = aes_gcm::Nonce::from_slice(&iv);
                if aes128 {
                    key128
                        .decrypt_in_place_detached(nonce, &aad, &mut plaintext, &tag)
                        .unwrap();
                } else {
                    key256
                        .decrypt_in_place_detached(nonce, &aad, &mut plaintext, &tag)
                        .unwrap();
                }
                let padding = usize::from(plaintext[0]);
                assert_eq!(&plaintext[1..length - padding], payload.as_ref());
                let tag = if aes128 {
                    key128
                        .encrypt_in_place_detached(nonce, &aad, &mut plaintext)
                        .unwrap()
                } else {
                    key256
                        .encrypt_in_place_detached(nonce, &aad, &mut plaintext)
                        .unwrap()
                };
                let mut independent = BytesMut::from(aad.as_slice());
                independent.extend_from_slice(&plaintext);
                independent.extend_from_slice(&tag);
                assert_eq!(encoded, independent);
                assert_eq!(rx.decode(&mut independent).unwrap(), Some(payload));
                assert!(independent.is_empty());
                let counter = u64::from_be_bytes(iv[4..].try_into().unwrap());
                iv[4..].copy_from_slice(&(counter + 1).to_be_bytes());
            }
        }
    }

    #[test]
    fn aes128_gcm_matches_nist_zero_key_vector() {
        let cipher = Cipher::aes128(&[0; 16], [0; 12]);
        let mut data = [0; 16];
        let tag = cipher.encrypt(&[], &mut data).unwrap();
        assert_eq!(
            data,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78,
            ]
        );
        assert_eq!(
            tag.as_ref(),
            &[
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf,
            ]
        );
        cipher.decrypt(&[], &mut data, tag).unwrap();
        assert_eq!(data, [0; 16]);
    }

    #[test]
    fn both_gcm_algorithms_reject_modified_ciphertext_and_every_tag_byte() {
        for aes128 in [true, false] {
            let cipher = || {
                if aes128 {
                    Cipher::aes128(&[7; 16], [3; 12])
                } else {
                    Cipher::new(&[7; 32], [3; 12])
                }
            };
            let mut tx = Codec {
                tx: Some(cipher()),
                ..Codec::default()
            };
            let mut encoded = BytesMut::new();
            tx.encode(
                Bytes::from_static(b"\xc8authenticated payload"),
                &mut encoded,
            )
            .unwrap();
            for position in (4..encoded.len()).chain([0, 1, 2, 3]) {
                let mut packet = encoded.clone();
                packet[position] ^= 1;
                let mut rx = Codec {
                    rx: Some(cipher()),
                    ..Codec::default()
                };
                assert!(
                    !matches!(rx.decode(&mut packet), Ok(Some(_))),
                    "tampered byte {position}"
                );
            }
        }
    }

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
        for aes128 in [true, false] {
            let (mut tx, mut rx) = pair();
            if aes128 {
                tx.tx = Some(Cipher::aes128(&[7; 16], [3; 12]));
                rx.rx = Some(Cipher::aes128(&[7; 16], [3; 12]));
            }
            tx.tx.as_mut().unwrap().iv[4..].fill(255);
            rx.rx.as_mut().unwrap().iv[4..].fill(255);
            let mut encoded = BytesMut::new();
            tx.encode(Bytes::from_static(b"\x5ehello"), &mut encoded)
                .unwrap();
            let mut replay = encoded.clone();
            assert!(rx.decode(&mut encoded).unwrap().is_some());
            assert!(matches!(
                rx.decode(&mut replay),
                Err(Error::Protocol("receive nonce exhausted"))
            ));
            assert!(tx
                .encode(Bytes::from_static(b"\x5eagain"), &mut encoded)
                .is_err());
        }
    }
}
