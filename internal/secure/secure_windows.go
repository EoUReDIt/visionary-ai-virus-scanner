//go:build windows

package secure

import (
	"errors"
	"os/user"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = advapi32.NewProc("LogonUserW")
)

const (
	logonInteractive = 2
	logonNetwork     = 3
)

// CurrentUser returns the account whose password VerifyPassword checks.
func CurrentUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// verifyOSPassword asks Windows to validate the password with LogonUser. It
// needs the account password: a Windows Hello PIN is not accepted by this API.
func verifyOSPassword(pw string) error {
	name := CurrentUser()
	if name == "" {
		return errors.New("cannot determine the current Windows user")
	}
	domain := "."
	if i := strings.IndexByte(name, '\\'); i >= 0 {
		domain, name = name[:i], name[i+1:]
	}
	u, _ := windows.UTF16PtrFromString(name)
	d, _ := windows.UTF16PtrFromString(domain)
	p, err := windows.UTF16PtrFromString(pw)
	if err != nil {
		return errors.New("invalid password")
	}
	for _, typ := range []uintptr{logonInteractive, logonNetwork} {
		var token windows.Handle
		r, _, _ := procLogonUserW.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)),
			uintptr(unsafe.Pointer(p)), typ, 0, uintptr(unsafe.Pointer(&token)))
		if r != 0 {
			windows.CloseHandle(token)
			return nil
		}
	}
	return errors.New("wrong Windows password")
}

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// protect encrypts with DPAPI at machine scope so both the logged-in user and
// the service account can read the keys, while the file stays useless on any
// other computer.
func protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(plain), nil, nil, 0, nil,
		windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(enc []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(enc), nil, nil, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
