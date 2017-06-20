// Package pam provides a wrapper for the application layer of the
// Pluggable Authentication Modules library.
package pam

import (
    //#include "golang-pam.h"
    //#cgo LDFLAGS: -lpam
    "C"
    "unsafe"
    "strings"
)

// Objects implementing the ConversationHandler interface can
// be registered as conversation callbacks to be used during
// PAM authentication.  RespondPAM receives a message style
// (one of PROMPT_ECHO_OFF, PROMPT_ECHO_ON, ERROR_MSG, or
// TEXT_INFO) and a message string.  It is expected to return
// a response string and a bool indicating success or failure.
type ConversationHandler interface {
    RespondPAM(msg_style int, msg string) (string,bool)
}

// ResponseFunc is an adapter to allow the use of ordinary
// functions as conversation callbacks.  ResponseFunc(f) is
// a ConversationHandler that calls f, where f must have
// the signature func(int,string)(string,bool).
type ResponseFunc func(int,string) (string,bool)
func (f ResponseFunc) RespondPAM(style int, msg string) (string,bool) {
    return f(style,msg)
}

// Internal conversation structure
type conversation struct {
    handler ConversationHandler
    cconv *C.struct_pam_conv
}

// Cosntructs a new conversation object with a given handler and a newly
// allocated pam_conv struct that uses this object as its appdata_ptr
func newConversation(handler ConversationHandler) *conversation {
    conv := &conversation{}
    conv.handler = handler
    conv.cconv = C.make_gopam_conv(unsafe.Pointer(conv))
    return conv
}

//export goPAMConv
// Go-side function for processing a single conversational message.  Ultimately
// this calls the associated ConversationHandler's ResponsePAM callback with data
// coming in from a C-side call.
func goPAMConv(msg_style C.int, msg *C.char, appdata unsafe.Pointer) (*C.char,int)  {
    conv := (*conversation)(appdata)
    resp,ok := conv.handler.RespondPAM(int(msg_style), C.GoString(msg))
    if ok {
        return C.CString(resp),SUCCESS
    }
    return nil,CONV_ERR
}

// Transaction is the application's handle for a single PAM transaction.
type Transaction struct {
    handle *C.pam_handle_t
    conv *conversation
}

// Start initiates a new PAM transaction.  serviceName is treated identically
// to how pam_start internally treats it.  The same applies to user, except that
// the empty string is passed to PAM as nil; therefore the empty string should be
// used to signal that no username is being provided.
//
// All application calls to PAM begin with Start().  The returned *Transaction
// provides an interface to the remainder of the API.
//
// The returned status int may be ABORT, BUF_ERR, SUCCESS, or SYSTEM_ERR, as per
// the official PAM documentation.
func Start(serviceName, user string, handler ConversationHandler) (*Transaction,int) {
    t := &Transaction{}
    t.conv = newConversation(handler)
    var status C.int
    if len(user) == 0 {
        status = C.pam_start(C.CString(serviceName), nil, t.conv.cconv, &t.handle)
    } else {
        status = C.pam_start(C.CString(serviceName), C.CString(user), t.conv.cconv, &t.handle)
    }

    if status != SUCCESS {
        C.free(unsafe.Pointer(t.conv.cconv))
        return nil,int(status)
    }

    return t, int(status)
}

// Ends a PAM transaction.  From Linux-PAM documentation: "The [status] argument
// should be set to the value returned by the last PAM library call."
//
// This may return SUCCESS, or SYSTEM_ERR.
//
// This *must* be called on any Transaction successfully returned by Start() or
// you will leak memory.
func (t *Transaction) End(status int) {
    C.pam_end(t.handle, C.int(status))
    C.free(unsafe.Pointer(t.conv.cconv))
}

// Sets a PAM informational item.  Legal values of itemType are listed here (excluding Linux extensions):
//
// http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-interface-by-app-expected.html#adg-pam_set_item
//
// the CONV item type is also not supported in order to simplify the Go API (and due to
// the fact that it is completely unnecessary).
func (t *Transaction) SetItem(itemType int, item string) int {
    if itemType == CONV { return BAD_ITEM }
    cs := unsafe.Pointer(C.CString(item))
    defer C.free(cs)
    return int(C.pam_set_item(t.handle, C.int(itemType), cs))
}

// Gets a PAM item.  Legal values of itemType are as specified by the documentation of SetItem.
func (t *Transaction) GetItem(itemType int) (string,int) {
    if itemType == CONV { return "",BAD_ITEM }
    result := C.pam_get_item_string(t.handle, C.int(itemType))
    return C.GoString(result.str),int(result.status)
}

// Error returns a PAM error string from a PAM error code
func (t *Transaction) Error(errnum int) string {
    return C.GoString(C.pam_strerror(t.handle, C.int(errnum)))
}

// pam_authenticate
func (t *Transaction) Authenticate(flags int) int {
    return int(C.pam_authenticate(t.handle, C.int(flags)))
}

// pam_setcred
func (t* Transaction) SetCred(flags int) int {
    return int(C.pam_setcred(t.handle, C.int(flags)))
}

// pam_acctmgmt
func (t* Transaction) AcctMgmt(flags int) int {
    return int(C.pam_acct_mgmt(t.handle, C.int(flags)))
}

// pam_chauthtok
func (t* Transaction) ChangeAuthTok(flags int) int {
    return int(C.pam_chauthtok(t.handle, C.int(flags)))
}

// pam_open_session
func (t* Transaction) OpenSession(flags int) int {
    return int(C.pam_open_session(t.handle, C.int(flags)))
}

// pam_close_session
func (t* Transaction) CloseSession(flags int) int {
    return int(C.pam_close_session(t.handle, C.int(flags)))
}

// pam_putenv
func (t* Transaction) PutEnv(nameval string) int {
    cs := C.CString(nameval)
    defer C.free(unsafe.Pointer(cs))
    return int(C.pam_putenv(t.handle, cs))
}

// pam_getenv.  Returns an additional argument indicating
// the actual existence of the given environment variable.
func (t* Transaction) GetEnv(name string) (string,bool) {
    cs := C.CString(name)
    defer C.free(unsafe.Pointer(cs))
    value := C.pam_getenv(t.handle, cs)
    if value != nil {
        return C.GoString(value),true
    }
    return "",false
}

// GetEnvList internally calls pam_getenvlist and then uses some very
// dangerous code to pull out the returned environment data and mash
// it into a map[string]string.  This call may be safe, but it hasn't
// been tested on enough platforms/architectures/PAM-implementations to
// be sure.
func (t* Transaction) GetEnvList() map[string]string {
    env := make(map[string]string)
    list := (uintptr)(unsafe.Pointer(C.pam_getenvlist(t.handle)))
    for *(*uintptr)(unsafe.Pointer(list)) != 0 {
        entry := *(*uintptr)(unsafe.Pointer(list))
        nameval := C.GoString((*C.char)(unsafe.Pointer(entry)))
        chunks := strings.SplitN(nameval, "=", 2)
        env[chunks[0]] = chunks[1]
        list += (uintptr)(unsafe.Sizeof(list))
    }
    return env
}

