package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// DefaultCISAKEVEndpoint is CISA's static Known Exploited Vulnerabilities JSON
// catalog — zero API key, zero rate limit.
const DefaultCISAKEVEndpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// CISAKEV queries CISA's static Known Exploited Vulnerabilities JSON feed.
type CISAKEV struct {
	Endpoint string
}

func NewCISAKEV(endpoint string) *CISAKEV {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		ep = DefaultCISAKEVEndpoint
	}
	return &CISAKEV{Endpoint: ep}
}

func (c *CISAKEV) ID() string   { return "cisa-kev" }
func (c *CISAKEV) Name() string { return "CISA KEV Catalog (No Key)" }

func (c *CISAKEV) Search(ctx context.Context, opts SearchOptions) ([]Advisory, int, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, 0, errors.New("cisa-kev: endpoint must be a valid http(s) URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "VisionaryAV-RiskExchange/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("cisa-kev request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("cisa-kev HTTP %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, 0, err
	}
	var feed struct {
		Vulnerabilities []struct {
			CVEID             string   `json:"cveID"`
			VendorProject     string   `json:"vendorProject"`
			Product           string   `json:"product"`
			VulnerabilityName string   `json:"vulnerabilityName"`
			DateAdded         string   `json:"dateAdded"`
			ShortDescription  string   `json:"shortDescription"`
			RequiredAction    string   `json:"requiredAction"`
			CWEs              []string `json:"cwes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &feed); err != nil {
		return nil, 0, fmt.Errorf("cisa-kev invalid JSON: %w", err)
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	cveFilter := strings.ToUpper(strings.TrimSpace(opts.CVEID))
	kw := strings.ToLower(strings.TrimSpace(opts.Query))
	if cveFilter == "" && cveIDRe.MatchString(strings.ToUpper(kw)) {
		cveFilter = strings.ToUpper(kw)
		kw = ""
	}

	var matched []Advisory
	for _, v := range feed.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if id == "" {
			continue
		}
		if cveFilter != "" && id != cveFilter {
			continue
		}
		hay := strings.ToLower(id + " " + v.VendorProject + " " + v.Product + " " + v.VulnerabilityName + " " + v.ShortDescription)
		if kw != "" && !strings.Contains(hay, kw) {
			continue
		}
		prod := strings.TrimSpace(v.Product)
		if vp := strings.TrimSpace(v.VendorProject); vp != "" && !strings.EqualFold(vp, prod) {
			prod = vp + "/" + prod
		}
		summary := strings.TrimSpace(v.ShortDescription)
		summary = truncateRunes(summary, 260)
		adv := Advisory{
			ID:        id,
			Source:    "cisa-kev",
			Severity:  "CRITICAL",
			CVSS:      9.0,
			KEV:       true,
			KEVName:   strings.TrimSpace(v.VulnerabilityName),
			Summary:   summary,
			Published: v.DateAdded,
			Products:  []string{prod},
			CWEs:      v.CWEs,
			URL:       "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(id),
		}
		adv.ScanHints = MatchHints(adv)
		matched = append(matched, adv)
	}
	// The catalog is not newest-first; show the most recently added entries.
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].Published > matched[j].Published })
	total := len(matched)
	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched, total, nil
}
