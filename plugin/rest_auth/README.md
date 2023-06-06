# rest auth plugin for sshpiperd

The rest_auth plugin will get the upstream/downstream configuration from your rest backend. The auth backend only supports public key authentication!


## Usage

```
sshpiperd \
  rest_auth --url https://localhost:8443/auth
```

### options

```
  --url value URL for your rest endpoint, can be anything you like
  --insecure  allow insecure SSL (do not validate SSL certificate)
```

# process example

## Authentication backend: GET https://localhost:8443/auth/arthur
To get the upstream/downstream configuration for the user, your endpoint has to send back the following data. You can either use key authentication or password authentication.

```json
{
  "user": "root",
  "host": "192.168.1.1:22",
  "authorizedKeys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDVEvuHaktOlL+GpF+JUlcX9N2f1b36moKkck7eV8Kgj root@c8e26162952a",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\r\nQyNTUxOQAAACDacsBgzwtW0WBIVrE/ZVWFr2w2287w1MoVJMueJgog1gAAAJjLTCf6y0wn\r\n+gAAAAtzc2gtZWQyNTUxOQAAACDacsBgzwtW0WBIVrE/ZVWFr2w2287w1MoVJMueJgog1g\r\nAAAEA7WWWE4AN6UIrkjbKa51tyuBNunmGc6W1IhUH0fQ/pz9pywGDPC1bRYEhWsT9lVYWv\r\nbDbbzvDUyhUky54mCiDWAAAAEXJvb3RAODhiNTBkOGM2MDc3AQIDBA==\r\n-----END OPENSSH PRIVATE KEY-----"
}
```

### Authentication backend parameters
| Parameter | Description | Example |
| --- | --- | --- |
| `user` | The name of the upstream user | *root*, *no-standard-username@myserver* |
| `host` | IP:Port of the upstream server | *10.0.0.125:22*, *192.168.1.10:678* |
| `authorizedKeys` | A list of authorized downstream public keys (can be multiple use \r\n) | *ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AA........* |
| `privateKey` | The private key for the upstream connection | *-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNz.....* |


# Express example
```js
...
app.get('/:user', (req, res, next) => {
  res.json({hello:`Hi ${req.params.user}, what is the airspeed velocity of an unladen swallow?`});
});
app.post('/:user', (req, res, next) => {
  if(/20\.1mph|20\.1|20|32.35kmh|32.35|32/i.test(req.body.response)){
    res.json({auth:true});
  }else{
    res.json({auth:false});
  }
});
...
```