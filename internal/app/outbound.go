package app

import (
	"context"
	"fmt"
	"sort"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/risk"
)

// maxOutboundLookups caps how many distinct remote IPs one check sends to
// Shodan, to stay polite to the free keyless API.
const maxOutboundLookups = 25

// OutboundReport is one distinct public remote endpoint this machine is
// talking to, with the processes involved and its InternetDB exposure.
type OutboundReport struct {
	IP        string           `json:"ip"`
	Ports     []int            `json:"remote_ports"`
	Processes []string         `json:"processes,omitempty"`
	Exposure  *risk.IPExposure `json:"exposure,omitempty"`
	Error     string           `json:"error,omitempty"`
}

// OutboundResult is the outcome of CheckOutbound.
type OutboundResult struct {
	Connections int              `json:"connections"` // established connections seen
	PublicIPs   int              `json:"public_ips"`  // distinct public remote IPs
	Looked      int              `json:"looked_up"`
	Skipped     int              `json:"skipped"` // public IPs beyond the lookup cap
	Reports     []OutboundReport `json:"reports"`
}

type ipLooker interface {
	Lookup(ctx context.Context, ip string) (*risk.IPExposure, error)
}

// CheckOutbound lists established outbound TCP connections, drops private,
// loopback and other non-public destinations locally (they never leave the PC),
// and looks each distinct public remote IP up in Shodan InternetDB. Opt-in:
// every looked-up IP is sent to Shodan.
func (a *App) CheckOutbound(ctx context.Context) (*OutboundResult, error) {
	conns, err := plat.OutboundConns()
	if err != nil {
		return nil, fmt.Errorf("cannot list connections: %w", err)
	}
	names := map[int]string{}
	if procs, err := plat.ListProcesses(); err == nil {
		for _, p := range procs {
			names[p.PID] = p.Name
		}
	}
	res := buildOutbound(ctx, conns, names, risk.NewInternetDB("", a.cacheStore()))
	crit := 0
	for _, r := range res.Reports {
		if r.Exposure != nil && r.Exposure.RiskLevel == "critical" {
			crit++
		}
	}
	sev := "info"
	if crit > 0 {
		sev = "warn"
	}
	a.Log("system", sev, fmt.Sprintf("Outbound check: %d public IPs, %d looked up, %d critical", res.PublicIPs, res.Looked, crit), nil)
	return res, nil
}

func buildOutbound(ctx context.Context, conns []plat.Conn, names map[int]string, idb ipLooker) *OutboundResult {
	res := &OutboundResult{Connections: len(conns), Reports: []OutboundReport{}}
	byIP := map[string]*OutboundReport{}
	var order []string
	portSeen := map[string]map[int]bool{}
	procSeen := map[string]map[string]bool{}
	for _, c := range conns {
		ip, err := risk.ValidatePublicIP(c.RemoteIP)
		if err != nil {
			continue // private / local / reserved: never leaves the host
		}
		r := byIP[ip]
		if r == nil {
			r = &OutboundReport{IP: ip}
			byIP[ip] = r
			order = append(order, ip)
			portSeen[ip] = map[int]bool{}
			procSeen[ip] = map[string]bool{}
		}
		if !portSeen[ip][c.RemotePort] {
			portSeen[ip][c.RemotePort] = true
			r.Ports = append(r.Ports, c.RemotePort)
		}
		if n := names[c.PID]; n != "" && !procSeen[ip][n] {
			procSeen[ip][n] = true
			r.Processes = append(r.Processes, n)
		}
	}
	res.PublicIPs = len(order)
	for i, ip := range order {
		r := byIP[ip]
		sort.Ints(r.Ports)
		sort.Strings(r.Processes)
		if i < maxOutboundLookups {
			res.Looked++
			exp, err := idb.Lookup(ctx, ip)
			if err != nil {
				r.Error = err.Error()
			} else {
				r.Exposure = exp
			}
		} else {
			res.Skipped++
		}
		res.Reports = append(res.Reports, *r)
	}
	rank := func(r OutboundReport) int {
		if r.Exposure == nil {
			return 0
		}
		switch r.Exposure.RiskLevel {
		case "critical":
			return 3
		case "elevated":
			return 2
		}
		return 1
	}
	sort.SliceStable(res.Reports, func(i, j int) bool { return rank(res.Reports[i]) > rank(res.Reports[j]) })
	return res
}
