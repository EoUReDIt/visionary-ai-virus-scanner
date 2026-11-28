//go:build windows

package plat

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

const (
	afInet               = 2
	tcpTableOwnerPIDAll  = 5
	tcpStateEstablished  = 5
	errInsufficientBuffr = 122
)

// tcpRowOwnerPID mirrors MIB_TCPROW_OWNER_PID.
type tcpRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	PID        uint32
}

// OutboundConns lists established IPv4 TCP connections with their owning PIDs.
func OutboundConns() ([]Conn, error) {
	size := uint32(32 << 10)
	var buf []byte
	for try := 0; try < 5; try++ {
		buf = make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, afInet, tcpTableOwnerPIDAll, 0)
		if r == 0 {
			break
		}
		if r != errInsufficientBuffr || try == 4 {
			return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", r)
		}
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(tcpRowOwnerPID{})
	var out []Conn
	for i := uint32(0); i < n; i++ {
		off := 4 + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*tcpRowOwnerPID)(unsafe.Pointer(&buf[off]))
		if row.State != tcpStateEstablished {
			continue
		}
		a := row.RemoteAddr // network byte order: first octet is the low byte
		out = append(out, Conn{
			PID:        int(row.PID),
			RemoteIP:   fmt.Sprintf("%d.%d.%d.%d", byte(a), byte(a>>8), byte(a>>16), byte(a>>24)),
			RemotePort: int(row.RemotePort>>8&0xff | row.RemotePort<<8&0xff00),
		})
	}
	return out, nil
}
