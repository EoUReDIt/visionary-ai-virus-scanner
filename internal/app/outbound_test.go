package app

import (
	"context"
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/risk"
)

type fakeLooker struct{ calls []string }

func (f *fakeLooker) Lookup(_ context.Context, ip string) (*risk.IPExposure, error) {
	f.calls = append(f.calls, ip)
	lvl := "low"
	if ip == "8.8.4.4" {
		lvl = "critical"
	}
	return &risk.IPExposure{IP: ip, RiskLevel: lvl}, nil
}

func TestBuildOutboundFiltersDedupesAndRanks(t *testing.T) {
	conns := []plat.Conn{
		{PID: 1, RemoteIP: "192.168.1.1", RemotePort: 80}, // private
		{PID: 1, RemoteIP: "127.0.0.1", RemotePort: 80},   // loopback
		{PID: 2, RemoteIP: "8.8.8.8", RemotePort: 443},
		{PID: 3, RemoteIP: "8.8.8.8", RemotePort: 80},
		{PID: 2, RemoteIP: "8.8.8.8", RemotePort: 443}, // duplicate
		{PID: 3, RemoteIP: "8.8.4.4", RemotePort: 443},
	}
	f := &fakeLooker{}
	res := buildOutbound(context.Background(), conns, map[int]string{2: "a.exe", 3: "b.exe"}, f)
	if res.Connections != 6 || res.PublicIPs != 2 || res.Looked != 2 || len(f.calls) != 2 {
		t.Fatalf("bad counts: %+v calls=%v", res, f.calls)
	}
	if res.Reports[0].IP != "8.8.4.4" {
		t.Fatalf("critical not ranked first: %+v", res.Reports)
	}
	r := res.Reports[1]
	if len(r.Ports) != 2 || r.Ports[0] != 80 || len(r.Processes) != 2 {
		t.Fatalf("bad merge: %+v", r)
	}
}

func TestBuildOutboundCapsLookups(t *testing.T) {
	var conns []plat.Conn
	for i := 1; i <= maxOutboundLookups+5; i++ {
		conns = append(conns, plat.Conn{RemoteIP: "8.8." + itoa(i) + ".1", RemotePort: 443})
	}
	f := &fakeLooker{}
	res := buildOutbound(context.Background(), conns, nil, f)
	if res.Looked != maxOutboundLookups || res.Skipped != 5 || len(f.calls) != maxOutboundLookups {
		t.Fatalf("cap not applied: %+v", res)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
