# Kubernetes upstream for SSHPiper

Kubernetes api is called to retreive sshpiper configuration.

## Usage

First install CRD

```
$ kubectl apply -f https://raw.githubusercontent.com/pockost/sshpipe-k8s-lib/v0.0.3/artifacts/sshpipe.yaml
```

You can now add a new sshpipe object

```
apiVersion: pockost.com/v1beta1
kind: SshPipe
metadata:
  name: sftp2
spec:
  users:
    - user2
  target:
    name: sftp2
```

You can find more example in [the example folder](example)

## ssh host key

If the `/etc/ssh/ssh_host_rsa_key` does not exist at startup the
sshpiper container generate one. This mean each time the `sshpiper` pod
is recreated a new `ssh_host_rsa_key` will be generated.

To prevent this you can generate a new `ssh_host_rsa_key` and store this
one in a Secret object.

```
$ docker run --rm farmer1992/sshpiperd /sshpiperd genkey > ssh_host_rsa_key
$ kubectl -n sshpiper create secret generic sshpiper --from-file ssh_host_rsa_key
```

You can now inject this secret in /etc/ssh/ssh_host_rsa_key.

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sshpiper
  namespace: sshpiper
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sshpiper
  template:
    metadata:
      labels:
        app: sshpiper
    spec:
      serviceAccountName: sshpiper
      containers:
      - name: sshpiper
        image: lermit/sshpiper
        imagePullPolicy: Always
        env:
          - name: SSHPIPERD_UPSTREAM_DRIVER
            value: kubernetes
        volumeMounts:
          - name: secrets
            mountPath: /etc/ssh/ssh_host_rsa_key
            subPath: ssh_host_rsa_key
      volumes:
        - name: secrets
          secret:
            secretName: sshpiper
```

**Note**: You can uncomment corresponding line in the example folder.
