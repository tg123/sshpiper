// godefs -g pam pamdefs.c

// MACHINE GENERATED - DO NOT EDIT.

package pam

// Constants
const (
	SUCCESS                = 0
	OPEN_ERR               = 0x1
	SYMBOL_ERR             = 0x2
	SERVICE_ERR            = 0x3
	SYSTEM_ERR             = 0x4
	BUF_ERR                = 0x5
	PERM_DENIED            = 0x6
	AUTH_ERR               = 0x7
	CRED_INSUFFICIENT      = 0x8
	AUTHINFO_UNAVAIL       = 0x9
	USER_UNKNOWN           = 0xa
	MAXTRIES               = 0xb
	NEW_AUTHOTK_REQD       = 0xc
	ACCT_EXPIRED           = 0xd
	SESSION_ERR            = 0xe
	CRED_UNAVAIL           = 0xf
	CRED_EXPIRED           = 0x10
	CRED_ERR               = 0x11
	NO_MODULE_DATA         = 0x12
	CONV_ERR               = 0x13
	AUTHTOK_ERR            = 0x14
	AUTHTOK_RECOVERY_ERR   = 0x15
	AUTHTOK_LOCK_BUSY      = 0x16
	AUTHTOK_DISABLE_AGING  = 0x17
	TRY_AGAIN              = 0x18
	IGNORE                 = 0x19
	ABORT                  = 0x1a
	AUTHTOK_EXPIRED        = 0x1b
	MODULE_UNKNOWN         = 0x1c
	BAD_ITEM               = 0x1d
	CONV_AGAIN             = 0x1e
	INCOMPLETE             = 0x1f
	SILENT                 = 0x8000
	DISALLOW_NULL_AUTHTOK  = 0x1
	ESTABLISH_CRED         = 0x2
	DELETE_CRED            = 0x4
	REINITIALIZE_CRED      = 0x8
	REFRESH_CRED           = 0x10
	CHANGE_EXPIRED_AUTHTOK = 0x20
	SERVICE                = 0x1
	USER                   = 0x2
	TTY                    = 0x3
	RHOST                  = 0x4
	CONV                   = 0x5
	AUTHTOK                = 0x6
	OLDAUTHTOK             = 0x7
	RUSER                  = 0x8
	USER_PROMPT            = 0x9
	PROMPT_ECHO_OFF        = 0x1
	PROMPT_ECHO_ON         = 0x2
	ERROR_MSG              = 0x3
	TEXT_INFO              = 0x4
)

// Types
