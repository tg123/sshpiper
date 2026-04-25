//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative admin.proto

// Package libadmin defines the gRPC management API exposed by sshpiperd
// (the SshPiperAdmin service) and provides a thin Go client used by the
// sshpiperd-webadmin aggregator and any future admin CLI tools.
package libadmin
