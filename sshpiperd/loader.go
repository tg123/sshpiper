package main

import (
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/database"
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/workingdir"

	_ "github.com/tg123/sshpiper/sshpiperd/challenger/authy"
	_ "github.com/tg123/sshpiper/sshpiperd/challenger/azdevicecode"
	_ "github.com/tg123/sshpiper/sshpiperd/challenger/pam"

	_ "github.com/tg123/sshpiper/sshpiperd/auditor/typescriptlogger"
)
