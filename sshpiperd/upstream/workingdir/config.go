package workingdir

var (
	config = struct {
		WorkingDir       string `long:"workingdir" default:"/var/sshpiper" description:"Path to workingdir" env:"SSHPIPERD_WORKINGDIR" ini-name:"workingdir"`
		AllowBadUsername bool   `long:"workingdir-allowbadusername" description:"Disable username check while search the working dir" env:"SSHPIPERD_WORKINGDIR_ALLOWBADUSERNAME" ini-name:"workingdir-allowbadusername"`
		NoCheckPerm      bool   `long:"workingdir-nocheckperm" description:"Disable 0400 checking when using files in the working dir" env:"SSHPIPERD_WORKINGDIR_NOCHECKPERM" ini-name:"workingdir-nocheckperm"`
		FallbackUSername string `long:"workingdir-fallbackusername" description:"Fallback to a user when user does not exists in directory" env:"SSHPIPERD_WORKINGDIR_FALLBACKUSERNAME" ini-name:"workingdir-fallbackusername"`
	}{}
)
