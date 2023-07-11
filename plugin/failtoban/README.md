# fail to ban for sshpiperd

put ip to jail for a while after failed to login for several times.

## Usage

put this plugin after other plugins, like:

```
sshpiperd <main plguin> -- failtoban
```


## Configuration

 * max-failures: max failures before ban, default 5
 * ban-duration: ban duration, default 1h