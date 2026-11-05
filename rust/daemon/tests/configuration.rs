use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use hmac::Mac;
use rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use sshpiperd::{
    config::Config,
    keys::{host_identities, private_key, verify_known_hosts},
};

#[test]
fn preserves_plugin_arguments_and_chain_separators() {
    let config = Config::try_parse_from([
        "sshpiperd",
        "--port",
        "0",
        "first plugin",
        "--port",
        "1234",
        "--",
        "second plugin",
        "--target",
        "host:22",
    ])
    .unwrap();
    assert_eq!(config.port, 0);
    let commands = config.plugin_commands().unwrap();
    let expected: Vec<Vec<std::ffi::OsString>> = vec![
        vec!["first plugin".into(), "--port".into(), "1234".into()],
        vec!["second plugin".into(), "--target".into(), "host:22".into()],
    ];
    assert_eq!(commands, expected);
}

#[test]
fn admin_requires_explicit_tls_or_insecure() {
    let config =
        Config::try_parse_from(["sshpiperd", "--admin-grpc-port", "1234", "plugin"]).unwrap();
    assert!(config.validate().is_err());
    let config = Config::try_parse_from([
        "sshpiperd",
        "--admin-grpc-port",
        "1234",
        "--admin-grpc-insecure",
        "plugin",
    ])
    .unwrap();
    config.validate().unwrap();
    let config = Config::try_parse_from([
        "sshpiperd",
        "--admin-grpc-port",
        "1234",
        "--admin-grpc-insecure",
        "--admin-grpc-tls-cert",
        "cert",
        "plugin",
    ])
    .unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn openssh_private_keys_accept_go_and_openssh_pem_wrapping() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let go_pem = pem::encode(&pem::Pem::new(
        "OPENSSH PRIVATE KEY",
        key.to_bytes().unwrap().to_vec(),
    ));
    let openssh_pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
    for pem in [go_pem.as_bytes(), openssh_pem.as_bytes()] {
        assert_eq!(private_key(pem).unwrap().public_key(), key.public_key());
    }
    assert!(private_key(b"not a private key").is_err());
    assert!(
        private_key(pem::encode(&pem::Pem::new("PUBLIC KEY", vec![1, 2, 3])).as_bytes()).is_err()
    );
}

#[test]
fn pkcs8_and_sec1_keys_preserve_algorithm_and_public_key() {
    use rsa::{
        pkcs1::EncodeRsaPrivateKey,
        pkcs8::{der::Encode, EncodePrivateKey, PrivateKeyInfo},
    };
    use ssh_key::private::{EcdsaKeypair, KeypairData};

    fn check(kind: &str, der: &[u8], expected: &PrivateKey) {
        let pem = pem::encode(&pem::Pem::new(kind, der));
        let parsed = private_key(pem.as_bytes()).unwrap();
        assert_eq!(parsed.public_key(), expected.public_key());
        let key_algorithm = expected.algorithm();
        let algorithms = if matches!(key_algorithm, Algorithm::Rsa { .. }) {
            vec!["rsa-sha2-512", "rsa-sha2-256"]
        } else {
            vec![key_algorithm.as_str()]
        };
        for algorithm in algorithms {
            let signed = sshpiper_transport::sign(&parsed, b"key format regression", algorithm)
                .unwrap_or_else(|error| panic!("{kind} {algorithm}: {error}"));
            sshpiper_transport::verify_signature(
                expected.public_key(),
                b"key format regression",
                &signed,
                algorithm,
            )
            .unwrap();
        }
    }

    let ed = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let expected = PrivateKey::new(KeypairData::Ed25519(ed.clone().into()), "").unwrap();
    check(
        "PRIVATE KEY",
        ed.to_pkcs8_der().unwrap().as_bytes(),
        &expected,
    );
    let rsa = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let expected = PrivateKey::new(KeypairData::Rsa(rsa.clone().try_into().unwrap()), "").unwrap();
    check(
        "PRIVATE KEY",
        rsa.to_pkcs8_der().unwrap().as_bytes(),
        &expected,
    );
    check(
        "RSA PRIVATE KEY",
        rsa.to_pkcs1_der().unwrap().as_bytes(),
        &expected,
    );

    macro_rules! check_ec {
        ($curve:ident, $variant:ident) => {{
            let key = $curve::SecretKey::random(&mut OsRng);
            let expected = PrivateKey::new(
                KeypairData::Ecdsa(EcdsaKeypair::$variant {
                    public: key.public_key().into(),
                    private: key.clone().into(),
                }),
                "",
            )
            .unwrap();
            check(
                "PRIVATE KEY",
                key.to_pkcs8_der().unwrap().as_bytes(),
                &expected,
            );
            let pkcs8 = key.to_pkcs8_der().unwrap();
            let curve = PrivateKeyInfo::try_from(pkcs8.as_bytes())
                .unwrap()
                .algorithm
                .parameters_oid()
                .unwrap();
            let der = key.to_sec1_der().unwrap();
            let mut sec1 = sec1::EcPrivateKey::try_from(der.as_slice()).unwrap();
            sec1.parameters = Some(sec1::EcParameters::NamedCurve(curve));
            check("EC PRIVATE KEY", &sec1.to_der().unwrap(), &expected);
        }};
    }
    check_ec!(p256, NistP256);
    check_ec!(p384, NistP384);
    check_ec!(p521, NistP521);
}

#[test]
fn known_hosts_requires_a_matching_non_revoked_key() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let encoded = key.public_key().to_bytes().unwrap();
    let trusted = key.public_key().to_openssh().unwrap();
    let entry = format!("[host]:2222 {trusted}\n");
    verify_known_hosts(entry.as_bytes(), "host:2222", "127.0.0.1:2222", &encoded).unwrap();
    assert!(
        verify_known_hosts(entry.as_bytes(), "other:2222", "127.0.0.1:2222", &encoded).is_err()
    );
    assert!(verify_known_hosts(
        entry.as_bytes(),
        "host:2222",
        "127.0.0.1:2222",
        &other.public_key().to_bytes().unwrap()
    )
    .is_err());
    let revoked = format!("{entry}@revoked [host]:2222 {trusted}\n");
    assert!(
        verify_known_hosts(revoked.as_bytes(), "host:2222", "127.0.0.1:2222", &encoded).is_err()
    );
    let excluded = format!("*,![host]:2222 {trusted}\n");
    assert!(
        verify_known_hosts(excluded.as_bytes(), "host:2222", "127.0.0.1:2222", &encoded).is_err()
    );
}

#[test]
fn known_hosts_does_not_trust_a_named_host_by_its_resolved_address() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let encoded = key.public_key().to_bytes().unwrap();
    let entry = format!(
        "dev-box,10.0.0.66 {}\n",
        key.public_key().to_openssh().unwrap()
    );
    assert!(verify_known_hosts(entry.as_bytes(), "prod-db:22", "10.0.0.66:22", &encoded).is_err());
    verify_known_hosts(entry.as_bytes(), "dev-box:22", "10.0.0.66:22", &encoded).unwrap();
    verify_known_hosts(entry.as_bytes(), "10.0.0.66:22", "10.0.0.66:22", &encoded).unwrap();
}

#[test]
fn hashed_known_hosts_entries_bind_hostname_and_port() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let salt = [7_u8; 20];
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&salt).unwrap();
    mac.update(b"[host]:2222");
    let entry = format!(
        "|1|{}|{} {}\n",
        STANDARD.encode(salt),
        STANDARD.encode(mac.finalize().into_bytes()),
        key.public_key().to_openssh().unwrap()
    );
    let encoded = key.public_key().to_bytes().unwrap();
    verify_known_hosts(entry.as_bytes(), "host:2222", "127.0.0.1:2222", &encoded).unwrap();
    assert!(verify_known_hosts(entry.as_bytes(), "host:22", "127.0.0.1:22", &encoded).is_err());
}

#[test]
fn host_certificate_selection_preserves_configuration_policy() {
    let temp = tempfile::tempdir().unwrap();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut builder = ssh_key::certificate::Builder::new(
        vec![1; 32],
        key.public_key().key_data().clone(),
        0,
        1_000_000,
    )
    .unwrap();
    builder
        .cert_type(ssh_key::certificate::CertType::Host)
        .unwrap();
    builder.valid_principal("host").unwrap();
    let certificate = builder.sign(&ca).unwrap().to_openssh().unwrap();
    let mut config = Config::try_parse_from(["sshpiperd", "plugin"]).unwrap();
    config.server_key_data =
        Some(STANDARD.encode(key.to_openssh(ssh_key::LineEnding::LF).unwrap()));
    config.server_cert = Some(temp.path().join("*.nonexistent").display().to_string());
    assert!(host_identities(&config)
        .err()
        .expect("missing certificate")
        .to_string()
        .contains("matched no files"));
    config.server_cert_data = Some(STANDARD.encode(certificate.as_bytes()));
    let identities = host_identities(&config).unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(
        identities[0].algorithms(),
        ["ssh-ed25519-cert-v01@openssh.com"]
    );

    config.server_key_data = None;
    for name in ["key-a", "key-b"] {
        std::fs::write(
            temp.path().join(name),
            key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
    }
    config.server_key = temp.path().join("key-*").display().to_string();
    assert!(host_identities(&config)
        .err()
        .expect("ambiguous certificate")
        .to_string()
        .contains("single certificate"));
    config.server_cert_data = None;
    config.server_cert = Some(temp.path().join("*.pub").display().to_string());
    std::fs::write(temp.path().join("host.pub"), certificate).unwrap();
    let identities = host_identities(&config).unwrap();
    assert_eq!(identities.len(), 2);
    assert!(identities
        .iter()
        .all(|identity| identity.algorithms()[0].contains("-cert-")));

    let unmatched = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    std::fs::write(
        temp.path().join("key-unmatched"),
        unmatched
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    assert!(host_identities(&config).is_err());
}
