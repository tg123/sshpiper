# MongoDB Plugin for sshpiperd

The MongoDB plugin for sshpiperd is a plugin that you can use to configure your sshpiperd with a MongoDB database. Configurations are stored in a MongoDB collection that the plugin reads from.

This MongoDB collection should contain documents that match the newly updated schema given below:

- `from`: This field contains an array of documents, each with `username`, `username_regex_match`, `authorized_keys`, and `authorized_keys_data` fields.
- `to`: This field contains a document with the `username`, `host`, `password`, `private_key`, `private_key_data`, `known_hosts`, `known_hosts_data`, and `ignore_hostkey` fields.

## Schema

Each document requires the following structure:

```json
{
  "from": [
    {
      "username": "downstream_username",
      "username_regex_match": true/false,
      "authorized_keys": "authorized_keys info",
      "authorized_keys_data": "authorized_keys_data"
    },
    ...
  ],
  "to": {
    "username": "upstream_username",
    "host": "upstream_host:port",
    "password": "hashed_password",
    "private_key": "user_private_key",
    "private_key_data": "private_key_data",
    "known_hosts": "known_hosts_data",
    "known_hosts_data": "known_hosts_data",
    "ignore_hostkey": true/false
  }
}
```

Where:

- `from.username`: This is the username associated with the SSH connection.
- `from.username_regex_match`: This boolean field indicates whether the username is a regular expression match.
- `from.authorized_keys`: A string representation of the authorized keys (if any).
- `from.authorized_keys_data`: An optional field to provide further information about the authorized keys.
- `to.username` and `to.host`: Define the username and hostname (plus port) of the upstream SSH connection.
- `to.password`: This is the SHA256 hashed version of the user's password.
- `to.private_key` and `to.private_key_data`: The user's SSH private key and its data.
- `to.known_hosts` and `to.known_hosts_data`: Known host information.
- `to.ignore_hostkey`: A boolean flag whether to ignore host key check (default `false`).

If none of the methods for authenticating (`from.authorized_keys`, `from.authorized_keys_data`, `to.password`) are provided, an error will occur.

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