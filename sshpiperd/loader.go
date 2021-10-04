package main

import (
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/database"
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/grpcupstream"
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/kubernetes"
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/workingdir"
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/yaml"

	_ "github.com/tg123/sshpiper/sshpiperd/challenger/authy"
	_ "github.com/tg123/sshpiper/sshpiperd/challenger/azdevicecode"
	_ "github.com/tg123/sshpiper/sshpiperd/challenger/pome"

	_ "github.com/tg123/sshpiper/sshpiperd/auditor/typescriptlogger"
)
