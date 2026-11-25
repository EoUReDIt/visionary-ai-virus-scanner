//go:build !windows

package winsec

import "errors"

var errWindows = errors.New("Windows Security integration is only available on Windows")

func GetStatus() *Status {
	s := &Status{}
	s.describe()
	return s
}

func Coexist(...string) error         { return errWindows }
func SetPassive(bool) (string, error) { return "", errWindows }
func OfflineScan() error              { return errWindows }

// Defender is unavailable off Windows; New returns nil so the engine skips
// the second-opinion layer.
type Defender struct{}

func New() *Defender { return nil }

func (*Defender) ScanFile(string) (string, bool, error)   { return "", false, errWindows }
func (*Defender) ScanBuffer([]byte, string) (bool, error) { return false, errWindows }
func (*Defender) VerifyTrust(string) (bool, error)        { return false, errWindows }
