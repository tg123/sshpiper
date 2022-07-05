# Azure Device Code for sshpiperd

Support Azure AD device code grant, [More info](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)

sshpier will ask user to login using webpage

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ****** to authenticate.
```

NOTE: This is an additional challenge plugin. 🔒 you must use it with other routing plugins.

## Usage

Note: you may want to set `login-grace-time` to larger value (default: 30s) to avoid being kicked by `sshpiperd` if code was not entered in time.

```
sshpiperd --login-grace-time=2m azdevicecode --tenant-id 00000000-0000-0000-0000-000000000000 --client-id 00000000-0000-0000-0000-000000000000  -- other-plugin --other-option
```