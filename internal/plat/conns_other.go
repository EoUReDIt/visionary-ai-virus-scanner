//go:build !windows

package plat

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// OutboundConns lists established IPv4 TCP connections (PID is not resolved
// off Windows).
func OutboundConns() ([]Conn, error) {
	raw, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	return parseProcNetTCP(string(raw)), nil
}

func parseProcNetTCP(s string) []Conn {
	var out []Conn
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[3] != "01" { // 01 = ESTABLISHED
			continue
		}
		addr, port, ok := strings.Cut(f[2], ":")
		if !ok || len(addr) != 8 {
			continue
		}
		a, err1 := strconv.ParseUint(addr, 16, 32)
		p, err2 := strconv.ParseUint(port, 16, 16)
		if err1 != nil || err2 != nil {
			continue
		}
		// /proc prints the in-memory (little-endian) word: low byte is first octet.
		out = append(out, Conn{
			RemoteIP:   fmt.Sprintf("%d.%d.%d.%d", byte(a), byte(a>>8), byte(a>>16), byte(a>>24)),
			RemotePort: int(p),
		})
	}
	return out
}
