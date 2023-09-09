# MongoDB Plugin for sshpiperd

The MongoDB plugin for sshpiperd is a plugin that allows you to use a MongoDB database to configure your sshpiperd. This plugin reads from a specific MongoDB collection which contains the necessary SSH configurations.

This MongoDB collection should contain documents with the following fields:

 * `_id`: This is the username associated with the SSH connection.
 * `password`, `publicKey` and `privateKey` are used for authentication.
 * `knownHosts` provides known host information.
 * `userForUpstream` and `hostForUpstream` define the upstream SSH connection details.
 * `ignoreHostkey` can be used to skip host key verification.

## Usage

```
sshpiperd mongo --uri mongodb://user:password@host:port --database sshpiperd --collection ssh_configurations
```

### Options

```
   --uri value        MongoDB connection URI [$SSHPIPERD_MONGO_URI]
   --database value   MongoDB database name [$SSHPIPERD_MONGO_DATABASE]
   --collection value MongoDB collection name [$SSHPIPERD_MONGO_COLLECTION]
```

## Item Structure in the Collection

Your MongoDB collection should have items which follow the following structure

```json
{
  "_id": "username",
  "password": "hashed_password",
  "publicKey": "user_public_key",
  "privateKey": "user_private_key",
  "knownHosts": "known_hosts_data",
  "userForUpstream": "upstream_username",
  "hostForUpstream": "upstream_host:port",
  "ignoreHostkey": true
}
```

Where:

- `username`: This is the username associated with the SSH connection.
- `hashed_password`: This is the SHA256 hashed version of the user's password.
- `privateKey`, `publicKey`: The user's SSH private and public keys.
- `knownHosts`: Contains known host information.
- `userForUpstream` and `hostForUpstream`: Define the username and hostname (plus port) of the upstream SSH connection.
- `ignoreHostkey`: A boolean flag to skip host key verification (default `false`).

Public key is used first for authentication. If public key is not available, password is used. If neither method is provided, an error will occur.
