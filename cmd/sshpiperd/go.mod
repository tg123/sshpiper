module github.com/tg123/sshpiper/cmd/sshpiperd

go 1.26.0

// The forked golang.org/x/crypto (carrying sshpiper's PiperConfig/PiperConn API)
// is scoped to this module only. The root github.com/tg123/sshpiper module and
// every plugin under it build against upstream golang.org/x/crypto.
replace golang.org/x/crypto => ../../crypto

replace github.com/tg123/sshpiper => ../..

require (
	github.com/google/uuid v1.6.0
	github.com/pires/go-proxyproto v0.12.0
	github.com/ramr/go-reaper v0.3.1
	github.com/tg123/jobobject v0.1.0
	github.com/tg123/remotesigner v0.0.3
	github.com/tg123/sshpiper v0.0.0
	github.com/urfave/cli/v2 v2.27.7
	golang.org/x/crypto v0.52.0
	golang.org/x/term v0.43.0
	google.golang.org/grpc v1.81.1
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
)
