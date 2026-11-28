package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultNVDEndpoint is NIST's free National Vulnerability Database CVE 2.0 REST API.
const DefaultNVDEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

var (
	httpClient = &http.Client{Timeout: 30 * time.Second}
	cveIDRe    = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
)

// NVD queries NIST NVD CVE 2.0 (or a compatible custom HTTP/JSON endpoint).
type NVD struct {
	Endpoint string
	APIKey   string // optional free NIST API key (lifts 5 req/30s -> 50 req/30s)
	Custom   bool
}

func NewNVD(apiKey, endpoint string, custom bool) *NVD {
	ep := strings.TrimSpace(endpoint)
	if ep == "" && !custom {
		ep = DefaultNVDEndpoint
	}
	return &NVD{
		Endpoint: ep,
		APIKey:   strings.TrimSpace(apiKey),
		Custom:   custom,
	}
}

func (n *NVD) ID() string {
	if n.Custom {
		return "custom"
	}
	return "nvd"
}

func (n *NVD) Name() string {
	if n.Custom {
		return "Custom HTTP/JSON Risk Feed"
	}
	return "NIST NVD CVE 2.0"
}

// Search queries NIST NVD 2.0 (or a custom HTTP/JSON feed) using compact
// resultsPerPage pagination to respect free API rate limits.
func (n *NVD) Search(ctx context.Context, opts SearchOptions) ([]Advisory, int, error) {
	if n.Endpoint == "" {
		return nil, 0, errors.New("risk exchange: endpoint URL is required")
	}
	u, err := url.Parse(n.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, 0, errors.New("risk exchange: endpoint must be a valid http(s) URL")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}

	q := u.Query()
	cveID := strings.ToUpper(strings.TrimSpace(opts.CVEID))
	kw := strings.TrimSpace(opts.Query)
	if cveID == "" && cveIDRe.MatchString(strings.ToUpper(kw)) {
		cveID = strings.ToUpper(kw)
		kw = ""
	}

	if cveID != "" {
		if !cveIDRe.MatchString(cveID) {
			return nil, 0, fmt.Errorf("invalid CVE ID %q (expected CVE-YYYY-NNNN)", cveID)
		}
		q.Set("cveId", cveID)
	} else {
		q.Set("resultsPerPage", strconv.Itoa(limit))
		if kw != "" {
			q.Set("keywordSearch", kw)
		}
		if opts.KEVOnly {
			q.Set("hasKev", "")
		}
		if sev := normalizeSeverity(opts.Severity); sev != "" {
			q.Set("cvssV3Severity", sev)
		}
	}
	// NVD expects bare `hasKev` (without `=`) or `hasKev=` — both work, and
	// trimming `=` keeps URLs canonical to NIST documentation.
	u.RawQuery = strings.ReplaceAll(q.Encode(), "hasKev=", "hasKev")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "VisionaryAV-RiskExchange/1.0")
	if n.APIKey != "" {
		req.Header.Set("apiKey", n.APIKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("risk exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, 0, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, 0, errors.New("NVD rate limit reached (free tier allows 5 req/30s; add a free NIST API key for 50 req/30s)")
	case http.StatusNotFound:
		return nil, 0, nil
	default:
		return nil, 0, fmt.Errorf("risk exchange HTTP %s", resp.Status)
	}

	return n.parsePayload(raw)
}

func (n *NVD) parsePayload(raw []byte) ([]Advisory, int, error) {
	// Primary format: NIST NVD CVE 2.0 JSON.
	var nvdResp struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID                    string `json:"id"`
				Published             string `json:"published"`
				LastModified          string `json:"lastModified"`
				CISAExploitAdd        string `json:"cisaExploitAdd"`
				CISAVulnerabilityName string `json:"cisaVulnerabilityName"`
				Descriptions          []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					V31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					V30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					V2 []struct {
						BaseSeverity string `json:"baseSeverity"`
						CVSSData     struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria   string `json:"criteria"`
							Vulnerable bool   `json:"vulnerable"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(raw, &nvdResp); err == nil && (len(nvdResp.Vulnerabilities) > 0 || nvdResp.TotalResults > 0 || strings.Contains(string(raw), `"vulnerabilities"`)) {
		out := make([]Advisory, 0, len(nvdResp.Vulnerabilities))
		for _, item := range nvdResp.Vulnerabilities {
			c := item.CVE
			if c.ID == "" {
				continue
			}
			summary := ""
			for _, d := range c.Descriptions {
				if strings.EqualFold(d.Lang, "en") {
					summary = strings.TrimSpace(d.Value)
					break
				}
				if summary == "" {
					summary = strings.TrimSpace(d.Value)
				}
			}
			summary = truncateRunes(summary, 260)
			var score float64
			sev := "UNKNOWN"
			switch {
			case len(c.Metrics.V31) > 0:
				score = c.Metrics.V31[0].CVSSData.BaseScore
				sev = strings.ToUpper(c.Metrics.V31[0].CVSSData.BaseSeverity)
			case len(c.Metrics.V30) > 0:
				score = c.Metrics.V30[0].CVSSData.BaseScore
				sev = strings.ToUpper(c.Metrics.V30[0].CVSSData.BaseSeverity)
			case len(c.Metrics.V2) > 0:
				score = c.Metrics.V2[0].CVSSData.BaseScore
				sev = strings.ToUpper(c.Metrics.V2[0].BaseSeverity)
			}
			if sev == "" {
				sev = scoreToSeverity(score)
			}

			var cwes []string
			cweSeen := map[string]bool{}
			for _, w := range c.Weaknesses {
				for _, d := range w.Description {
					v := strings.TrimSpace(d.Value)
					if strings.HasPrefix(v, "CWE-") && !cweSeen[v] {
						cweSeen[v] = true
						cwes = append(cwes, v)
					}
				}
			}

			var prods []string
			prodSeen := map[string]bool{}
			for _, cfg := range c.Configurations {
				for _, node := range cfg.Nodes {
					for _, cm := range node.CPEMatch {
						if p := cpeProduct(cm.Criteria); p != "" && !prodSeen[p] {
							prodSeen[p] = true
							prods = append(prods, p)
							if len(prods) >= 6 {
								break
							}
						}
					}
				}
			}

			adv := Advisory{
				ID:        c.ID,
				Source:    n.ID(),
				Severity:  sev,
				CVSS:      score,
				KEV:       strings.TrimSpace(c.CISAExploitAdd) != "",
				KEVName:   strings.TrimSpace(c.CISAVulnerabilityName),
				Summary:   summary,
				Published: c.Published,
				Modified:  c.LastModified,
				Products:  prods,
				CWEs:      cwes,
				URL:       "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(c.ID),
			}
			adv.ScanHints = MatchHints(adv)
			out = append(out, adv)
		}
		total := nvdResp.TotalResults
		if total == 0 {
			total = len(out)
		}
		return out, total, nil
	}

	// Custom JSON fallback: { "advisories": [...] } or bare [...]
	var wrapped struct {
		Advisories []Advisory `json:"advisories"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Advisories) > 0 {
		for i := range wrapped.Advisories {
			if wrapped.Advisories[i].Source == "" {
				wrapped.Advisories[i].Source = n.ID()
			}
			if len(wrapped.Advisories[i].ScanHints) == 0 {
				wrapped.Advisories[i].ScanHints = MatchHints(wrapped.Advisories[i])
			}
		}
		return wrapped.Advisories, len(wrapped.Advisories), nil
	}
	var bare []Advisory
	if err := json.Unmarshal(raw, &bare); err == nil {
		for i := range bare {
			if bare[i].Source == "" {
				bare[i].Source = n.ID()
			}
			if len(bare[i].ScanHints) == 0 {
				bare[i].ScanHints = MatchHints(bare[i])
			}
		}
		return bare, len(bare), nil
	}
	return nil, 0, errors.New("risk exchange: unrecognized JSON response format")
}

// cpeProduct extracts "vendor/product" from a CPE 2.3 string like
// "cpe:2.3:a:7-zip:7-zip:24.08:*:*:*:*:*:*:*".
func cpeProduct(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) < 5 || parts[0] != "cpe" {
		return ""
	}
	vendor, prod := strings.TrimSpace(parts[3]), strings.TrimSpace(parts[4])
	if prod == "" || prod == "*" || prod == "-" {
		return ""
	}
	if vendor == "" || vendor == "*" || vendor == prod {
		return prod
	}
	return vendor + "/" + prod
}

func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return strings.ToUpper(strings.TrimSpace(s))
	default:
		return ""
	}
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
