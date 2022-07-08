# Publickey based Working Directory plugin for sshpiperd

This plugin is smilar to the [workingdir](../workingdir/) plugin, but it uses public key to route.

workingdir tree

```
├── git
│   ├── bitbucket
│   │   └── sshpiper_upstream
│   ├── github
│   │   ├── authorized_keys
│   │   ├── id_rsa
│   │   └── sshpiper_upstream
│   └── gitlab
│       └── sshpiper_upstream
├── linode....
```

The plugin will search across all sub directories of the `username` directory to see if the `downstream` key is in `authorized_keys` file.
The first matched sub directory will be used to route to the upstream.