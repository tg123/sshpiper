use std::{fs::OpenOptions, io::Write};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::future::BoxFuture;
use hmac::Mac;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use ssh_key::{
    certificate::CertType,
    private::{EcdsaKeypair, KeypairData},
    public::{EcdsaPublicKey, KeyData},
    Algorithm, LineEnding, PrivateKey, PublicKey,
};
use sshpiper_transport::{Certificate, HostIdentity, HostKeyVerifier};

use crate::{
    config::Config,
    plugin::Plugin,
    proto::plugin::{ConnMeta, VerifyHostKeyRequest},
};

pub fn private_key(data: &[u8]) -> Result<PrivateKey> {
    let pem = pem::parse(data)?;
    let der = pem.contents();
    let key = match pem.tag() {
        "OPENSSH PRIVATE KEY" => return Ok(PrivateKey::from_bytes(der)?),
        "RSA PRIVATE KEY" => KeypairData::Rsa(rsa::RsaPrivateKey::from_pkcs1_der(der)?.try_into()?),
        "PRIVATE KEY" => {
            let info = rsa::pkcs8::PrivateKeyInfo::try_from(der)?;
            match info.algorithm.oid.to_string().as_str() {
                "1.2.840.113549.1.1.1" => {
                    KeypairData::Rsa(rsa::RsaPrivateKey::from_pkcs8_der(der)?.try_into()?)
                }
                "1.3.101.112" => {
                    KeypairData::Ed25519(ed25519_dalek::SigningKey::from_pkcs8_der(der)?.into())
                }
                "1.2.840.10045.2.1" => {
                    ec_private_key(der, &info.algorithm.parameters_oid()?.to_string(), true)?
                }
                oid => bail!("unsupported PKCS8 private key algorithm {oid}"),
            }
        }
        "EC PRIVATE KEY" => {
            let info = sec1::EcPrivateKey::try_from(der)?;
            let curve = info
                .parameters
                .and_then(|parameters| parameters.named_curve())
                .context("EC private key has no named curve")?;
            ec_private_key(der, &curve.to_string(), false)?
        }
        kind => bail!("unsupported private key PEM type {kind}"),
    };
    Ok(PrivateKey::new(key, "")?)
}

fn ec_private_key(der: &[u8], curve: &str, pkcs8: bool) -> Result<KeypairData> {
    let key = match curve {
        "1.2.840.10045.3.1.7" => {
            let private = if pkcs8 {
                p256::SecretKey::from_pkcs8_der(der)?
            } else {
                p256::SecretKey::from_sec1_der(der)?
            };
            let public = private.public_key().into();
            EcdsaKeypair::NistP256 {
                public,
                private: private.into(),
            }
        }
        "1.3.132.0.34" => {
            let private = if pkcs8 {
                p384::SecretKey::from_pkcs8_der(der)?
            } else {
                p384::SecretKey::from_sec1_der(der)?
            };
            let public = private.public_key().into();
            EcdsaKeypair::NistP384 {
                public,
                private: private.into(),
            }
        }
        "1.3.132.0.35" => {
            let private = if pkcs8 {
                p521::SecretKey::from_pkcs8_der(der)?
            } else {
                p521::SecretKey::from_sec1_der(der)?
            };
            let public = private.public_key().into();
            EcdsaKeypair::NistP521 {
                public,
                private: private.into(),
            }
        }
        oid => bail!("unsupported EC private key curve {oid}"),
    };
    Ok(KeypairData::Ecdsa(key))
}

pub fn remote_public_key(encoding: &str, der: &[u8]) -> Result<PublicKey> {
    let key = match encoding {
        "PKCS1" => KeyData::Rsa(rsa::RsaPublicKey::from_pkcs1_der(der)?.try_into()?),
        "PKIX" => {
            let info = rsa::pkcs8::SubjectPublicKeyInfoRef::try_from(der)?;
            match info.algorithm.oid.to_string().as_str() {
                "1.2.840.113549.1.1.1" => {
                    KeyData::Rsa(rsa::RsaPublicKey::from_public_key_der(der)?.try_into()?)
                }
                "1.2.840.10045.2.1" => KeyData::Ecdsa(
                    match info.algorithm.parameters_oid()?.to_string().as_str() {
                        "1.2.840.10045.3.1.7" => EcdsaPublicKey::NistP256(
                            p256::PublicKey::from_public_key_der(der)?.to_encoded_point(false),
                        ),
                        "1.3.132.0.34" => EcdsaPublicKey::NistP384(
                            p384::PublicKey::from_public_key_der(der)?.to_encoded_point(false),
                        ),
                        "1.3.132.0.35" => EcdsaPublicKey::NistP521(
                            p521::PublicKey::from_public_key_der(der)?.to_encoded_point(false),
                        ),
                        curve => bail!("unsupported remote signer EC curve {curve}"),
                    },
                ),
                oid => bail!("unsupported remote signer public key algorithm {oid}"),
            }
        }
        kind => bail!("unsupported remote signer public key encoding {kind}"),
    };
    Ok(PublicKey::new(key, ""))
}

pub fn host_identities(config: &Config) -> Result<Vec<HostIdentity>> {
    let mut keys = Vec::new();
    if let Some(data) = config
        .server_key_data
        .as_deref()
        .filter(|data| !data.is_empty())
    {
        keys.push(private_key(&STANDARD.decode(data)?)?);
    } else {
        let mut paths =
            glob::glob(&config.server_key)?.collect::<std::result::Result<Vec<_>, _>>()?;
        if config.server_key_generate_mode == "always"
            || (paths.is_empty() && config.server_key_generate_mode == "notexist")
        {
            if config.server_key.contains(['*', '?', '[']) {
                bail!("cannot generate a host key at a glob pattern");
            }
            let path = std::path::PathBuf::from(&config.server_key);
            let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)?;
            let mut options = OpenOptions::new();
            options.write(true);
            if config.server_key_generate_mode == "always" {
                options.create(true).truncate(true);
            } else {
                options.create_new(true);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => file.write_all(key.to_openssh(LineEnding::LF)?.as_bytes())?,
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        && config.server_key_generate_mode == "notexist" => {}
                Err(error) => return Err(error).context("generating host key"),
            }
            paths = vec![path];
        }
        for path in paths {
            keys.push(private_key(&std::fs::read(&path).with_context(|| {
                format!("reading host key {}", path.display())
            })?)?);
        }
    }
    if keys.is_empty() {
        bail!("no host keys matched --server-key");
    }
    let mut certificates = Vec::new();
    let cert_data = config
        .server_cert_data
        .as_deref()
        .filter(|data| !data.is_empty());
    let cert_pattern = config
        .server_cert
        .as_deref()
        .filter(|pattern| !pattern.is_empty());
    if let Some(data) = cert_data {
        if keys.len() != 1 {
            bail!("--server-cert-data provides a single certificate; use --server-cert for multiple keys");
        }
        let data = STANDARD.decode(data)?;
        certificates.push(Certificate::from_openssh(std::str::from_utf8(&data)?)?);
    } else if let Some(pattern) = cert_pattern {
        let paths = glob::glob(pattern)?.collect::<std::result::Result<Vec<_>, _>>()?;
        if paths.is_empty() {
            bail!("--server-cert {pattern:?} matched no files");
        }
        for path in paths {
            let result: Result<Certificate> = (|| {
                let cert = Certificate::from_openssh(&std::fs::read_to_string(&path)?)?;
                if cert.cert_type() != CertType::Host {
                    bail!("not a host certificate");
                }
                Ok(cert)
            })();
            match result {
                Ok(cert) => certificates.push(cert),
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "ignoring non-host-certificate candidate")
                }
            }
        }
    }
    let mut identities = Vec::new();
    for key in keys {
        let certificate = if cert_data.is_some() || cert_pattern.is_some() {
            Some(
                certificates.iter().find(|cert| {
                    cert.cert_type() == CertType::Host
                        && cert.public_key() == key.public_key().key_data()
                })
                .context("no host certificate in --server-cert/--server-cert-data matches configured private key")?
                .clone(),
            )
        } else {
            None
        };
        identities.push(HostIdentity::new(key, certificate)?);
    }
    Ok(identities)
}

pub struct UpstreamVerifier {
    pub plugin: Plugin,
    pub meta: ConnMeta,
    pub hostname: String,
    pub netaddress: String,
    pub known_hosts: Vec<u8>,
}

impl HostKeyVerifier for UpstreamVerifier {
    fn verify<'a>(&'a self, key: &'a [u8]) -> BoxFuture<'a, sshpiper_transport::Result<()>> {
        Box::pin(async move {
            let result: Result<()> = async {
                if self.plugin.has("VerifyHostKey") {
                    let reply = self
                        .plugin
                        .client()
                        .verify_host_key(VerifyHostKeyRequest {
                            meta: Some(self.meta.clone()),
                            key: key.to_vec(),
                            hostname: self.hostname.clone(),
                            netaddress: self.netaddress.clone(),
                        })
                        .await?
                        .into_inner();
                    if !reply.verified {
                        bail!("plugin rejected upstream host key");
                    }
                } else if self.known_hosts.is_empty() {
                    tracing::warn!(
                        upstream = self.hostname,
                        "skipping upstream host key verification: known_hosts_data is empty"
                    );
                } else {
                    verify_known_hosts(&self.known_hosts, &self.hostname, &self.netaddress, key)?;
                }
                Ok(())
            }
            .await;
            result.map_err(|error| sshpiper_transport::Error::HostVerification(error.to_string()))
        })
    }
}

fn host_and_port(address: &str) -> (String, u16) {
    if let Ok(address) = address.parse::<std::net::SocketAddr>() {
        return (address.ip().to_string(), address.port());
    }
    match address.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => (
            host.trim_matches(['[', ']']).to_owned(),
            port.parse().expect("validated port"),
        ),
        _ => (address.to_owned(), 22),
    }
}

fn normalized(address: &str) -> String {
    let (host, port) = host_and_port(address);
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

fn pattern_matches(pattern: &str, hostname: &str) -> Result<bool> {
    if let Some(hashed) = pattern.strip_prefix("|1|") {
        let (salt, hash) = hashed
            .split_once('|')
            .context("invalid hashed known_hosts entry")?;
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&STANDARD.decode(salt)?)?;
        mac.update(hostname.as_bytes());
        return Ok(mac.verify_slice(&STANDARD.decode(hash)?).is_ok());
    }
    let regex = format!(
        "^{}$",
        regex::escape(pattern)
            .replace("\\*", ".*")
            .replace("\\?", ".")
    );
    Ok(regex::Regex::new(&regex)?.is_match(hostname))
}

fn host_matches(patterns: &str, names: &[String]) -> Result<bool> {
    let mut matched = false;
    for pattern in patterns.split(',') {
        let negated = pattern.starts_with('!');
        let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
        for name in names {
            if pattern_matches(pattern, name)? {
                if negated {
                    return Ok(false);
                }
                matched = true;
            }
        }
    }
    Ok(matched)
}

pub fn verify_known_hosts(
    data: &[u8],
    hostname: &str,
    netaddress: &str,
    encoded: &[u8],
) -> Result<()> {
    let presented = sshpiper_transport::public_key(encoded)?;
    let certificate = if sshpiper_transport::wire::Reader(encoded)
        .text()?
        .ends_with("-cert-v01@openssh.com")
    {
        Some(Certificate::from_bytes(encoded)?)
    } else {
        None
    };
    // Like Go's knownhosts, match the dialed hostname; a resolved address must not
    // vouch for a named upstream.
    let names = [normalized(if hostname.is_empty() {
        netaddress
    } else {
        hostname
    })];
    let mut trusted = false;
    for (line_number, line) in std::str::from_utf8(data)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let first = fields.next().context("empty known_hosts entry")?;
        let (marker, patterns) = if first.starts_with('@') {
            (
                first,
                fields
                    .next()
                    .context("known_hosts marker missing hostnames")?,
            )
        } else {
            ("", first)
        };
        let algorithm = fields.next().context("known_hosts missing algorithm")?;
        let base64 = fields.next().context("known_hosts missing key")?;
        let key = PublicKey::from_openssh(&format!("{algorithm} {base64}"))
            .with_context(|| format!("invalid known_hosts key on line {}", line_number + 1))?;
        if !host_matches(patterns, &names)? {
            continue;
        }
        let same_leaf = key.key_data() == presented.key_data();
        let same_ca = certificate
            .as_ref()
            .is_some_and(|cert| cert.signature_key() == key.key_data());
        match marker {
            "@revoked" if same_leaf || same_ca => bail!("upstream host key is revoked"),
            "@revoked" => {}
            "@cert-authority" if same_ca => {
                let cert = certificate
                    .as_ref()
                    .context("CA entry requires a host certificate")?;
                cert.validate(&key)?;
                let host = host_and_port(hostname).0;
                if cert.cert_type() != CertType::Host
                    || !cert.critical_options().is_empty()
                    || (!cert.valid_principals().is_empty()
                        && !cert.valid_principals().contains(&host))
                {
                    bail!("invalid upstream host certificate type, principal, or critical options");
                }
                trusted = true;
            }
            "@cert-authority" => {}
            "" if same_leaf && certificate.is_none() => trusted = true,
            "" => {}
            _ => bail!("unsupported known_hosts marker {marker}"),
        }
    }
    if !trusted {
        bail!("upstream host key is not trusted by known_hosts_data");
    }
    Ok(())
}
