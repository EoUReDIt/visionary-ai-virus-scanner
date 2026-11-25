//go:build !windows

package secure

import (
	"crypto/subtle"
	"errors"
	"os"
	"os/user"
)

func CurrentUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// verifyOSPassword on development builds: there is no portable way to check a
// login password without cgo/PAM, so non-Windows builds compare against
// VISIONARY_DEV_PASSWORD. This file is never compiled into the Windows app.
func verifyOSPassword(pw string) error {
	want := os.Getenv("VISIONARY_DEV_PASSWORD")
	if want == "" {
		return errors.New("password verification needs Windows (set VISIONARY_DEV_PASSWORD for development)")
	}
	if subtle.ConstantTimeCompare([]byte(pw), []byte(want)) != 1 {
		return errors.New("wrong password")
	}
	return nil
}

// Development builds rely on file permissions (0600) only.
func protect(plain []byte) ([]byte, error) { return plain, nil }
func unprotect(enc []byte) ([]byte, error) { return enc, nil }
