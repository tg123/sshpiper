package readpass

// #cgo openbsd CFLAGS: -fpic -nopie
// #cgo openbsd LDFLAGS: -fpic
// #include <stdlib.h>
// #include "noecho.h"
import "C"
import "fmt"
import "unsafe"

// ReadPass shows the prompt, and reads the password while blanking
// the console. Most users will want to print a newline immediately
// after reading the password.
func ReadPass(prompt string) ([]byte, error) {
	fmt.Printf("%s", prompt)
	pw := C.readpass()
	if pw == nil {
		return nil, fmt.Errorf("readpass: failed to read password")
	}
	password := C.GoString(pw)
	C.free(unsafe.Pointer(pw))
	return []byte(password), nil
}
