use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use ssh_key::{certificate::CertType, public::KeyData, Algorithm, PublicKey};

use crate::{
    wire::{string, Reader},
    Error, Result, MAX_PACKET,
};

/// OpenSSH certificate wire data. Validity is kept as unsigned SSH timestamps,
/// including the `u64::MAX` no-expiry sentinel, rather than platform SystemTime.
#[derive(Clone)]
pub struct Certificate {
    encoded: Vec<u8>,
    key: PublicKey,
    kind: CertType,
    principals: Vec<String>,
    valid_after: u64,
    valid_before: u64,
    critical: BTreeMap<String, Vec<u8>>,
    authority: PublicKey,
    signed_len: usize,
    signature: Vec<u8>,
}

impl Certificate {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.len() > MAX_PACKET {
            return Err(Error::Protocol("certificate exceeds maximum packet length"));
        }
        let mut reader = Reader(encoded);
        let certificate_algorithm = reader.text()?;
        let algorithm = certificate_algorithm
            .strip_suffix("-cert-v01@openssh.com")
            .ok_or(Error::Protocol("expected OpenSSH certificate algorithm"))?;
        let fields = match algorithm {
            "ssh-ed25519" => 1,
            "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => 2,
            _ => return Err(Error::Protocol("unsupported certificate key algorithm")),
        };
        reader.string()?; // Nonce.
        let mut key = Vec::new();
        string(&mut key, algorithm.as_bytes());
        for _ in 0..fields {
            string(&mut key, reader.string()?);
        }
        let key = PublicKey::from_bytes(&key)?;
        reader.uint64()?; // Serial number.
        let kind = match reader.uint()? {
            1 => CertType::User,
            2 => CertType::Host,
            _ => return Err(Error::Protocol("invalid certificate type")),
        };
        reader.string()?; // Key identifier.
        let mut principal_data = Reader(reader.string()?);
        let mut principals = Vec::new();
        while !principal_data.0.is_empty() {
            principals.push(principal_data.text()?.to_owned());
        }
        let valid_after = reader.uint64()?;
        let valid_before = reader.uint64()?;
        let critical = options(reader.string()?)?;
        options(reader.string()?)?;
        reader.string()?; // Reserved.
        let authority = PublicKey::from_bytes(reader.string()?)?;
        let signed_len = encoded.len() - reader.0.len();
        let signature = reader.string()?.to_vec();
        reader.end()?;
        // Parse the signature even when a plugin will make the trust decision.
        let mut signature_reader = signature.as_slice();
        <ssh_key::Signature as ssh_encoding::Decode>::decode(&mut signature_reader)?;
        if !signature_reader.is_empty() {
            return Err(Error::Protocol("trailing certificate signature data"));
        }
        Ok(Self {
            encoded: encoded.to_vec(),
            key,
            kind,
            principals,
            valid_after,
            valid_before,
            critical,
            authority,
            signed_len,
            signature,
        })
    }

    pub fn from_openssh(text: &str) -> Result<Self> {
        let mut fields = text.split_whitespace();
        let algorithm = fields
            .next()
            .ok_or(Error::Protocol("missing certificate algorithm"))?;
        let encoded = fields
            .next()
            .ok_or(Error::Protocol("missing certificate data"))?;
        let encoded = STANDARD
            .decode(encoded)
            .map_err(|_| Error::Protocol("invalid base64 certificate"))?;
        if Reader(&encoded).text()? != algorithm {
            return Err(Error::Protocol(
                "certificate algorithm does not match wire data",
            ));
        }
        Self::from_bytes(&encoded)
    }

    pub fn public_key(&self) -> &KeyData {
        self.key.key_data()
    }

    pub fn signature_key(&self) -> &KeyData {
        self.authority.key_data()
    }

    pub fn algorithm(&self) -> Algorithm {
        self.key.algorithm()
    }

    pub fn cert_type(&self) -> CertType {
        self.kind
    }

    pub fn valid_principals(&self) -> &[String] {
        &self.principals
    }

    pub fn critical_options(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.critical
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encoded.clone()
    }

    pub fn validate(&self, authority: &PublicKey) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Protocol("system time precedes Unix epoch"))?
            .as_secs();
        self.validate_at(now, authority)
    }

    /// Verify CA authorization, signature, and validity. The caller must also
    /// enforce the certificate type, principal, and critical-option policy.
    pub fn validate_at(&self, now: u64, authority: &PublicKey) -> Result<()> {
        if self.authority.key_data() != authority.key_data() {
            return Err(Error::Protocol("certificate authority is not trusted"));
        }
        if now < self.valid_after || now >= self.valid_before {
            return Err(Error::Protocol(
                "certificate is outside its validity interval",
            ));
        }
        let algorithm = Reader(&self.signature).text()?;
        crate::verify_signature(
            authority,
            &self.encoded[..self.signed_len],
            &self.signature,
            algorithm,
        )
    }
}

fn options(data: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut reader = Reader(data);
    let mut values = BTreeMap::new();
    while !reader.0.is_empty() {
        let name = reader.text()?;
        if name.is_empty()
            || values
                .last_key_value()
                .is_some_and(|(previous, _): (&String, &Vec<u8>)| previous.as_str() >= name)
        {
            return Err(Error::Protocol(
                "certificate options are not strictly ordered",
            ));
        }
        values.insert(name.to_owned(), reader.string()?.to_vec());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use ssh_key::{certificate::Builder, EcdsaCurve, PrivateKey};

    use super::*;

    #[test]
    fn certificates_preserve_wire_signatures_and_unsigned_validity() {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Rsa { hash: None },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
        ] {
            let key = if matches!(algorithm, Algorithm::Rsa { .. }) {
                let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
                PrivateKey::new(
                    ssh_key::private::KeypairData::Rsa(key.try_into().unwrap()),
                    "",
                )
                .unwrap()
            } else {
                PrivateKey::random(&mut OsRng, algorithm).unwrap()
            };
            let mut builder =
                Builder::new(vec![1; 32], key.public_key().key_data().clone(), 100, 200).unwrap();
            builder.cert_type(CertType::Host).unwrap();
            builder.valid_principal("host").unwrap();
            let original = builder.sign(&ca).unwrap();
            let encoded = original.to_bytes().unwrap();
            let parsed = Certificate::from_bytes(&encoded).unwrap();
            assert_eq!(parsed.to_bytes(), encoded);
            assert_eq!(parsed.public_key(), key.public_key().key_data());
            assert_eq!(parsed.valid_principals(), ["host"]);
            parsed.validate_at(150, ca.public_key()).unwrap();
            assert!(parsed.validate_at(99, ca.public_key()).is_err());
            assert!(parsed.validate_at(200, ca.public_key()).is_err());
            for length in 0..encoded.len() {
                assert!(Certificate::from_bytes(&encoded[..length]).is_err());
            }
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(Certificate::from_bytes(&trailing).is_err());
            let text = original.to_openssh().unwrap();
            assert_eq!(
                Certificate::from_openssh(&text).unwrap().to_bytes(),
                encoded
            );
            let wrong_label = format!("ssh-rsa-cert-v01@openssh.com {}", STANDARD.encode(&encoded));
            if !matches!(key.algorithm(), Algorithm::Rsa { .. }) {
                assert!(Certificate::from_openssh(&wrong_label).is_err());
            }

            let mut reader = Reader(&encoded);
            reader.string().unwrap();
            reader.string().unwrap();
            let fields = if key.algorithm() == Algorithm::Ed25519 {
                1
            } else {
                2
            };
            for _ in 0..fields {
                reader.string().unwrap();
            }
            reader.uint64().unwrap();
            reader.uint().unwrap();
            reader.string().unwrap();
            reader.string().unwrap();
            reader.uint64().unwrap();
            let expiry_offset = encoded.len() - reader.0.len();
            let mut forever = encoded[..parsed.signed_len].to_vec();
            forever[expiry_offset..expiry_offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
            let signature = crate::sign(&ca, &forever, "ssh-ed25519").unwrap();
            string(&mut forever, &signature);
            let unlimited = Certificate::from_bytes(&forever).unwrap();
            unlimited.validate_at(300, ca.public_key()).unwrap();
            unlimited
                .validate_at(u64::MAX - 1, ca.public_key())
                .unwrap();
            assert_eq!(unlimited.to_bytes(), forever);
            assert!(unlimited.validate_at(u64::MAX, ca.public_key()).is_err());
            let other_ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            assert!(unlimited.validate_at(300, other_ca.public_key()).is_err());
            forever[expiry_offset] ^= 1;
            assert!(Certificate::from_bytes(&forever)
                .unwrap()
                .validate_at(300, ca.public_key())
                .is_err());
        }
    }

    #[test]
    fn certificate_option_maps_reject_duplicates_and_truncation() {
        for names in [["a", "a"], ["b", "a"]] {
            let mut encoded = Vec::new();
            for name in names {
                string(&mut encoded, name.as_bytes());
                string(&mut encoded, b"opaque");
            }
            assert!(options(&encoded).is_err());
        }
        let mut encoded = Vec::new();
        string(&mut encoded, b"option");
        string(&mut encoded, b"opaque");
        assert_eq!(options(&encoded).unwrap()["option"], b"opaque");
        for length in 1..encoded.len() {
            assert!(options(&encoded[..length]).is_err());
        }
    }
}
