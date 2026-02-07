# SSH Test Fixtures

Test keys and certificates used by the e2e test suite.

## Regenerating Host Certificate Fixtures

If you need to regenerate the host CA and certificate (e.g. to change principals
or key type), run from this directory:

```bash
# 1. generate the host CA key pair
ssh-keygen -t ed25519 -f host-ca -N "" -C "host-ca"

# 2. generate sshpiperd's host key
ssh-keygen -t ed25519 -f piper-host-key -N "" -C "piper-host"

# 3. sign the host key with the CA (creates piper-host-key-cert.pub)
ssh-keygen -s host-ca -I piper-host -h -n 127.0.0.1,localhost piper-host-key.pub
```

To add an expiry, use `-V` in step 3:

```bash
ssh-keygen -s host-ca -I piper-host -h -n 127.0.0.1,localhost -V +52w piper-host-key.pub
```

To verify the certificate contents:

```bash
ssh-keygen -L -f piper-host-key-cert.pub
```
