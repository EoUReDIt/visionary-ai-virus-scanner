package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/cache"
)

// DefaultInternetDBEndpoint is Shodan's free keyless InternetDB API.
const DefaultInternetDBEndpoint = "https://internetdb.shodan.io"

// ErrPrivateIP is returned whenever a caller attempts to query a private,
// loopback, link-local, or non-routable IP address. Private LAN addresses stay
// strictly behind the home router and never leave the host.
var ErrPrivateIP = errors.New("internetdb: private/local IP addresses are blocked locally (behind-home-network scope)")

var (
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
	benchPrefix = netip.MustParsePrefix("198.18.0.0/15")
	test1Prefix = netip.MustParsePrefix("192.0.2.0/24")
	test2Prefix = netip.MustParsePrefix("198.51.100.0/24")
	test3Prefix = netip.MustParsePrefix("203.0.113.0/24")
)

var riskyHomePorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	135:  "MSRPC",
	139:  "NetBIOS",
	445:  "SMB",
	1900: "UPnP",
	3389: "RDP",
	5900: "VNC",
	8080: "HTTP-Alt/Admin",
	8443: "HTTPS-Alt/Admin",
}

// IPExposure summarizes a keyless Shodan InternetDB lookup for one public IPv4.
type IPExposure struct {
	IP         string   `json:"ip"`
	Source     string   `json:"source"`
	Ports      []int    `json:"ports,omitempty"`
	RiskyPorts []string `json:"risky_ports,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Vulns      []string `json:"vulns,omitempty"`
	Hostnames  []string `json:"hostnames,omitempty"`
	RiskLevel  string   `json:"risk_level"` // low | elevated | critical
	Summary    string   `json:"summary"`
	Cached     bool     `json:"cached,omitempty"`
}

// ValidatePublicIP parses raw as a globally routable IPv4 address and strictly
// rejects RFC 1918 private LANs, loopback, link-local, CGNAT, multicast, and
// documentation ranges before any network request is made.
func ValidatePublicIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("internetdb: invalid IP address %q", raw)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.Is4() {
		return "", errors.New("internetdb: only public IPv4 addresses are supported")
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() ||
		cgnatPrefix.Contains(addr) || benchPrefix.Contains(addr) ||
		test1Prefix.Contains(addr) || test2Prefix.Contains(addr) || test3Prefix.Contains(addr) {
		return "", ErrPrivateIP
	}
	return addr.String(), nil
}

// InternetDB queries Shodan's free keyless InternetDB endpoint with strict
// private-IP blocking and local cache reuse.
type InternetDB struct {
	Endpoint string
	Cache    cache.Store
}

func NewInternetDB(endpoint string, st cache.Store) *InternetDB {
	ep := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if ep == "" {
		ep = DefaultInternetDBEndpoint
	}
	return &InternetDB{Endpoint: ep, Cache: st}
}

// Lookup queries Shodan InternetDB for one public IPv4 address (e.g. an opt-in
// check of the user's router WAN IP or an outbound remote IP).
func (idb *InternetDB) Lookup(ctx context.Context, rawIP string) (*IPExposure, error) {
	ip, err := ValidatePublicIP(rawIP)
	if err != nil {
		return nil, err
	}
	if idb.Cache != nil {
		if rec, ok := idb.Cache.GetIPReputation(ip); ok {
			exp := buildIPExposure(ip, rec.Ports, rec.CPEs, rec.Tags, rec.Vulns, rec.Hostnames, true)
			return exp, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, idb.Endpoint+"/"+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "VisionaryAV-RiskExchange/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("internetdb request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No open ports/CVEs indexed by Shodan for this public IP — good news.
		if idb.Cache != nil {
			_ = idb.Cache.PutIPReputation(cache.IPRecord{
				IP:        ip,
				Source:    "internetdb",
				ExpiresAt: time.Now().Add(24 * time.Hour),
			})
		}
		return buildIPExposure(ip, nil, nil, nil, nil, nil, false), nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("internetdb HTTP %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	var payload struct {
		IP        string   `json:"ip"`
		Ports     []int    `json:"ports"`
		CPEs      []string `json:"cpes"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("internetdb invalid JSON: %w", err)
	}
	if idb.Cache != nil {
		_ = idb.Cache.PutIPReputation(cache.IPRecord{
			IP:        ip,
			Source:    "internetdb",
			Ports:     payload.Ports,
			CPEs:      payload.CPEs,
			Tags:      payload.Tags,
			Vulns:     payload.Vulns,
			Hostnames: payload.Hostnames,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		})
	}
	return buildIPExposure(ip, payload.Ports, payload.CPEs, payload.Tags, payload.Vulns, payload.Hostnames, false), nil
}

func buildIPExposure(ip string, ports []int, cpes, tags, vulns, hostnames []string, cached bool) *IPExposure {
	var risky []string
	for _, p := range ports {
		if name, ok := riskyHomePorts[p]; ok {
			risky = append(risky, fmt.Sprintf("%d (%s)", p, name))
		}
	}
	level := "low"
	summary := "No exposed ports or known CVEs indexed on Shodan InternetDB."
	switch {
	case len(vulns) > 0 && len(risky) > 0:
		level = "critical"
		summary = fmt.Sprintf("%d risky exposed %s (%s) and %d indexed %s — verify router firewall & port forwarding.",
			len(risky), plural(len(risky), "port", "ports"), strings.Join(risky, ", "), len(vulns), plural(len(vulns), "CVE", "CVEs"))
	case len(vulns) > 0:
		level = "elevated"
		summary = fmt.Sprintf("%d indexed %s across %d open %s on Shodan InternetDB.",
			len(vulns), plural(len(vulns), "CVE", "CVEs"), len(ports), plural(len(ports), "port", "ports"))
	case len(risky) > 0:
		level = "elevated"
		summary = fmt.Sprintf("Risky exposed %s detected (%s) — check router UPnP/port forwarding.",
			plural(len(risky), "port", "ports"), strings.Join(risky, ", "))
	case len(ports) > 0:
		level = "low"
		summary = fmt.Sprintf("%d open %s indexed, no CVEs or high-risk administrative ports.",
			len(ports), plural(len(ports), "port", "ports"))
	}
	return &IPExposure{
		IP:         ip,
		Source:     "internetdb",
		Ports:      ports,
		RiskyPorts: risky,
		CPEs:       cpes,
		Tags:       tags,
		Vulns:      vulns,
		Hostnames:  hostnames,
		RiskLevel:  level,
		Summary:    summary,
		Cached:     cached,
	}
}
