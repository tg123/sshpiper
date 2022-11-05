# kubernetes plugin for sshpiperd

The kubernetes plugin for sshpiperd provides native kubernetes CRD integretion and allow you manage sshpiper by `kubectl get pipes` and `kubectl apply -f pipe.yaml`

this plugin is inpsired by the [first version kubernetes plugin](https://github.com/pockost/sshpipe-k8s-lib/) for v0 sshpier by [pockost](https://github.com/pockost)

## Usage


### Apply CRD definition

```
kubectl apply -f https://raw.githubusercontent.com/tg123/sshpiper/master/plugin/kubernetes/crd.yaml
```

most parameters are the same as in [yaml](../yaml/)

A full sample can be found [here](sample.yaml)

### Create Service

```
# sshpiper service
---
apiVersion: v1
kind: Service
metadata:
  name: sshpiper
spec:
  selector:
    app: sshpiper
  ports:
    - protocol: TCP
      port: 2222
---
apiVersion: v1
data:
  server_key: |
    <replace with you server key>
kind: Secret
metadata:
  name: sshpiper-server-key
type: Opaque
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sshpiper-deployment
  labels:
    app: sshpiper
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
      serviceAccountName: sshpiper-account
      containers:
      - name: sshpiper
        image: farmer1992/sshpiperd:latest
        ports:
        - containerPort: 2222
        env:
        - name: PLUGIN
          value: "kubernetes"
        - name: SSHPIPERD_SERVER_KEY
          value: "/serverkey/ssh_host_rsa_key"
        - name: SSHPIPERD_LOG_LEVEL
          value: "trace"
        volumeMounts:
        - name: sshpiper-server-key
          mountPath: "/serverkey/"
          readOnly: true          
      volumes:
      - name: sshpiper-server-key
        secret:
          secretName: sshpiper-server-key
          items:
          - key: server_key
            path: ssh_host_rsa_key
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sshpiper-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
- apiGroups: ["sshpiper.com"]
  resources: ["pipes"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-sshpiper
subjects:
- kind: ServiceAccount
  name: sshpiper-account
roleRef:
  kind: Role
  name: sshpiper-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sshpiper-account
```

### Create Password Pipe

```
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: pipe-password
spec:
  from:
  - username: "password_simple"
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
```

### Create Public Key Pipe

```
---
apiVersion: v1
data:
  privatekey: |
    <base64 encoded private key>
kind: Secret
metadata:
  name: host-publickey-key
type: Opaque
---
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: pipe-publickey
  annotations:
    privatekey_field_name: privatekey # this is optional, default is privatekey  
spec:
  from:
  - username: ".*" # catch all    
    username_regex_match: true
    authorized_keys_data: "base64_authorized_keys_data"
  to:
    host: host-publickey:2222
    username: "user"
    private_key_secret:
      name: host-publickey-key
    ignore_hostkey: true
---
```