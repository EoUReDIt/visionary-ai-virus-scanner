//go:build !windows

package plat

import "testing"

func TestParseProcNetTCP(t *testing.T) {
	in := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 0100A8C0:C350 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2 1
   2: 0100A8C0:C351 0101A8C0:0050 06 00000000:00000000 00:00000000 00000000  1000        0 3 1
`
	got := parseProcNetTCP(in)
	if len(got) != 1 || got[0].RemoteIP != "8.8.8.8" || got[0].RemotePort != 443 {
		t.Fatalf("unexpected: %+v", got)
	}
}
