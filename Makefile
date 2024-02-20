# The Makefile is for demo purposes
SSHPIPERD_SSHD_PORT=2222
UPSTREAM_SSHD_PORT=5522
run: build build_plugins run_dummy_sshd
	./out/sshpiperd -i ssh_host_ed25519_key --port $(SSHPIPERD_SSHD_PORT) -- ./out/fixed --target=127.0.0.1:$(UPSTREAM_SSHD_PORT)
build:
	CGO_ENABLED=0 go build -o ./out/sshpiperd ./cmd/sshpiperd
build_plugins:
	CGO_ENABLED=0 go build -tags "full" -o ./out/azdevicecode ./plugin/azdevicecode
	CGO_ENABLED=0 go build -tags "full" -o ./out/docker ./plugin/docker
	CGO_ENABLED=0 go build -tags "full" -o ./out/failtoban ./plugin/failtoban
	CGO_ENABLED=0 go build -tags "full" -o ./out/fixed ./plugin/fixed
	CGO_ENABLED=0 go build -tags "full" -o ./out/kubernetes ./plugin/kubernetes
	CGO_ENABLED=0 go build -tags "full" -o ./out/simplemath ./plugin/simplemath
	CGO_ENABLED=0 go build -tags "full" -o ./out/testcaplugin ./plugin/testcaplugin
	CGO_ENABLED=0 go build -tags "full" -o ./out/totp ./plugin/totp
	CGO_ENABLED=0 go build -tags "full" -o ./out/workingdir ./plugin/workingdir
	CGO_ENABLED=0 go build -tags "full" -o ./out/workingdirbykey ./plugin/workingdirbykey
	CGO_ENABLED=0 go build -tags "full" -o ./out/yaml ./plugin/yaml
run_dummy_sshd:
	docker run -d -e USER_NAME=user -e USER_PASSWORD=pass -e PASSWORD_ACCESS=true -p 127.0.0.1:$(UPSTREAM_SSHD_PORT):2222 lscr.io/linuxserver/openssh-server

.PHONY: build build_plugins run_dummy_sshd run
