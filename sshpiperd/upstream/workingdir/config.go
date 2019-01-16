package workingdir

var (
	config = struct {
		WorkingDir       string `long:"upstream-workingdir" default:"/var/sshpiper" description:"Path to working directory" env:"SSHPIPERD_UPSTREAM_WORKINGDIR" ini-name:"upstream-workingdir"`
		AllowBadUsername bool   `long:"upstream-workingdir-allowbadusername" description:"Disable username check while search the working directory" env:"SSHPIPERD_UPSTREAM_WORKINGDIR_ALLOWBADUSERNAME" ini-name:"upstream-workingdir-allowbadusername"`
		NoCheckPerm      bool   `long:"upstream-workingdir-nocheckperm" description:"Disable 0400 checking when using files in the working directory" env:"SSHPIPERD_UPSTREAM_WORKINGDIR_NOCHECKPERM" ini-name:"upstream-workingdir-nocheckperm"`
		FallbackUsername string `long:"upstream-workingdir-fallbackusername" description:"Fallback to a user when user does not exists in directory" env:"SSHPIPERD_UPSTREAM_WORKINGDIR_FALLBACKUSERNAME" ini-name:"upstream-workingdir-fallbackusername"`
		StrictHostKey    bool   `long:"upstream-workingdir-stricthostkey" description:"Upstream host public key must be in known_hosts file, otherwise drop the connection" env:"SSHPIPERD_UPSTREAM_WORKINGDIR_STRICTHOSTKEY" ini-name:"upstream-workingdir-stricthostkey"`
	}{}
)
