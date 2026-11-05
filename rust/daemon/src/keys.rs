use std::{fs::OpenOptions, io::Write};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::future::BoxFuture;
use hmac::Mac;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};
use ssh_key::{
    certificate::CertType, Algorithm, Certificate, HashAlg, LineEnding, PrivateKey, PublicKey,
};
use sshpiper_transport::{HostIdentity, HostKeyVerifier};

use crate::{
    config::Config,
    plugin::Plugin,
    proto::plugin::{ConnMeta, VerifyHostKeyRequest},
};

pub fn private_key(data: &[u8]) -> Result<PrivateKey> {
    let text = std::str::from_utf8(data).context("private key is not UTF-8 PEM")?;
    if text.starts_with("-----BEGIN RSA PRIVATE KEY-----")
        || text.starts_with("-----BEGIN PRIVATE KEY-----")
    {
        let key = if text.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
            rsa::RsaPrivateKey::from_pkcs1_pem(text)?
        } else {
            rsa::RsaPrivateKey::from_pkcs8_pem(text)?
        };
        return Ok(PrivateKey::new(
            ssh_key::private::KeypairData::Rsa(key.try_into()?),
            "",
        )?);
    }
    let pem = pem::parse(data)?;
    if pem.tag() != "OPENSSH PRIVATE KEY" {
        bail!("unsupported private key PEM type {}", pem.tag());
    }
    Ok(PrivateKey::from_bytes(pem.contents())?)
}

pub fn host_identities(config: &Config) -> Result<Vec<HostIdentity>> {
    let mut keys = Vec::new();
    if let Some(data) = &config.server_key_data {
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
    if let Some(data) = &config.server_cert_data {
        let data = STANDARD.decode(data)?;
        certificates.push(Certificate::from_openssh(std::str::from_utf8(&data)?)?);
    }
    if let Some(pattern) = &config.server_cert {
        for path in glob::glob(pattern)? {
            certificates.push(Certificate::from_openssh(&std::fs::read_to_string(path?)?)?);
        }
    }
    let mut identities = Vec::new();
    for cert in certificates {
        let key = keys
            .iter()
            .find(|key| key.public_key().key_data() == cert.public_key())
            .context("host certificate does not match any configured private key")?;
        identities.push(HostIdentity::new(key.clone(), Some(cert))?);
    }
    for key in keys {
        identities.push(HostIdentity::new(key, None)?);
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
    let names = [normalized(hostname), normalized(netaddress)];
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
                cert.validate([&key.fingerprint(HashAlg::Sha256)])?;
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
