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

You can find more example in [the example folder](sshpiperd/kubernetes/example)
