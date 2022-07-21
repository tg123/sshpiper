# TOTP Working Directory plugin for sshpiperd

Add TOTP 2FA to ssh, compatible with all [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238) authenticator, for example: `google authenticator`, `azure authenticator`.

the plugin is load `totp` in working directory defined in [workingdir](../workingdir/) plugin.

## Usage

```
./sshpiperd ./totp -- ./workingdir
```

the secret should be stored in `totp` file in working directory.
for example:

```
/var/sshpiper/username/totp
```