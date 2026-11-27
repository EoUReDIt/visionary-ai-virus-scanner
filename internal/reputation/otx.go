package reputation

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OTX queries the LevelBlue / AlienVault Open Threat Exchange (OTX)
// DirectConnect API v1 (https://otx.alienvault.com/api).
type OTX struct {
	Key     string
	BaseURL string
	cache   *DiskCache
}

// ExportedHash is one SHA-256 indicator pulled from OTX's compact bulk export.
type ExportedHash struct {
	SHA256 string
	Label  string
}

func NewOTX(key string) *OTX {
	return NewOTXWithCache(key, nil)
}

func NewOTXWithCache(key string, cache *DiskCache) *OTX {
	if cache == nil {
		cache = OpenCache("")
	}
	return &OTX{
		Key:     strings.TrimSpace(key),
		BaseURL: "https://otx.alienvault.com/api/v1",
		cache:   cache,
	}
}

func (o *OTX) ProviderName() string { return "AlienVault OTX" }

func (o *OTX) Lookup(ctx context.Context, sha256 string) (malicious, total int, label string, found bool, err error) {
	mal, tot, lbl, _, ok, e := o.LookupDetail(ctx, sha256)
	return mal, tot, lbl, ok, e
}

// LookupDetail queries the compact /indicators/file/{sha256}/general section.
// Results are persisted in DiskCache so each hash is queried at most once per TTL.
func (o *OTX) LookupDetail(ctx context.Context, sha256 string) (malicious, total int, label, detail string, found bool, err error) {
	h := normalizeHash(sha256)
	if !validSHA256(h) {
		return 0, 0, "", "", false, errors.New("otx: invalid SHA-256 hash")
	}
	if rec, ok := o.cache.Get("otx", h); ok {
		return rec.Mal, rec.Total, rec.Label, rec.Detail, rec.Found, nil
	}
	ep := strings.TrimRight(o.BaseURL, "/") + "/indicators/file/" + h + "/general"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
	if err != nil {
		return 0, 0, "", "", false, err
	}
	req.Header.Set("X-OTX-API-KEY", o.Key)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", "", false, err
	}
	defer resp.Body.Close()

	var rec cacheRecord
	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			Validation []struct {
				Source  string `json:"source"`
				Name    string `json:"name"`
				Message string `json:"message"`
			} `json:"validation"`
			FalsePositive []struct {
				Assessment string `json:"assessment"`
			} `json:"false_positive"`
			PulseInfo struct {
				Count  int `json:"count"`
				Pulses []struct {
					Name            string   `json:"name"`
					Adversary       string   `json:"adversary"`
					MalwareFamilies []any    `json:"malware_families"`
					Tags            []string `json:"tags"`
				} `json:"pulses"`
			} `json:"pulse_info"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
			return 0, 0, "", "", false, err
		}
		whitelisted := false
		for _, v := range body.Validation {
			low := strings.ToLower(v.Source + " " + v.Name + " " + v.Message)
			if strings.Contains(low, "whitelist") || strings.Contains(low, "false_positive") {
				whitelisted = true
				break
			}
		}
		for _, fp := range body.FalsePositive {
			if strings.EqualFold(fp.Assessment, "accepted") {
				whitelisted = true
				break
			}
		}
		pulses := body.PulseInfo.Count
		if pulses == 0 && len(body.PulseInfo.Pulses) > 0 {
			pulses = len(body.PulseInfo.Pulses)
		}
		if !whitelisted && pulses > 0 {
			lbl := extractOTXLabel(body.PulseInfo.Pulses)
			mal := pulses
			if pulses >= 3 && mal < 5 {
				// 3+ independent threat pulses on OTX count as a high-confidence hit.
				mal = 5
			}
			tot := pulses
			if tot < 10 {
				tot = 10
			}
			noun := "pulse"
			if pulses != 1 {
				noun = "pulses"
			}
			rec = cacheRecord{
				Mal:    mal,
				Total:  tot,
				Label:  lbl,
				Detail: fmt.Sprintf("%d threat %s on AlienVault OTX", pulses, noun),
				Found:  true,
			}
		}
	case http.StatusNotFound:
		// Unknown hash in OTX: cache negative lookup so it isn't re-queried.
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, 0, "", "", false, errors.New("otx: the API key was rejected")
	case http.StatusTooManyRequests:
		return 0, 0, "", "", false, errors.New("otx: rate limit reached")
	default:
		return 0, 0, "", "", false, fmt.Errorf("otx: %s", resp.Status)
	}
	o.cache.Put("otx", h, rec)
	return rec.Mal, rec.Total, rec.Label, rec.Detail, rec.Found, nil
}

// LookupBatch deduplicates hashes, satisfies cache hits with zero network
// calls, and queries only uncached hashes while stopping cleanly on rate limit.
func (o *OTX) LookupBatch(ctx context.Context, hashes []string) map[string]LookupResult {
	o.cache.BeginBatch()
	defer o.cache.EndBatch()
	out := make(map[string]LookupResult, len(hashes))
	var uncached []string
	seen := map[string]bool{}
	for _, raw := range hashes {
		h := normalizeHash(raw)
		if !validSHA256(h) || seen[h] {
			continue
		}
		seen[h] = true
		if rec, ok := o.cache.Get("otx", h); ok {
			out[h] = LookupResult{Malicious: rec.Mal, Total: rec.Total, Label: rec.Label, Detail: rec.Detail, Found: rec.Found}
			continue
		}
		uncached = append(uncached, h)
	}
	for _, h := range uncached {
		if err := ctx.Err(); err != nil {
			break
		}
		mal, tot, lbl, det, ok, err := o.LookupDetail(ctx, h)
		out[h] = LookupResult{Malicious: mal, Total: tot, Label: lbl, Detail: det, Found: ok, Err: err}
		if err != nil && strings.Contains(err.Error(), "rate limit") {
			break
		}
	}
	return out
}

// ExportSHA256 pulls subscribed SHA-256 malware indicators in bulk via OTX's
// compact /api/v1/indicators/export endpoint (hundreds of hashes per request),
// using modifiedSince for incremental delta updates.
func (o *OTX) ExportSHA256(ctx context.Context, modifiedSince time.Time, maxPages int) ([]ExportedHash, error) {
	if o.Key == "" {
		return nil, errors.New("otx: API key is required")
	}
	if maxPages <= 0 {
		maxPages = 5
	}
	base := strings.TrimRight(o.BaseURL, "/")
	q := url.Values{}
	q.Set("types", "FileHash-SHA256")
	q.Set("limit", "500")
	if !modifiedSince.IsZero() {
		q.Set("modified_since", modifiedSince.UTC().Format("2006-01-02T15:04:05"))
	}
	nextURL := base + "/indicators/export?" + q.Encode()

	seen := map[string]bool{}
	var out []ExportedHash
	for page := 0; page < maxPages && nextURL != ""; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("X-OTX-API-KEY", o.Key)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return out, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if readErr != nil {
			return out, readErr
		}
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusUnauthorized, http.StatusForbidden:
			return out, errors.New("otx: the API key was rejected")
		case http.StatusTooManyRequests:
			return out, errors.New("otx: rate limit reached")
		default:
			return out, fmt.Errorf("otx export: %s", resp.Status)
		}

		trimmed := strings.TrimSpace(string(raw))
		if strings.HasPrefix(trimmed, "{") {
			var payload struct {
				Results []struct {
					Indicator   string `json:"indicator"`
					Type        string `json:"type"`
					Title       string `json:"title"`
					Description string `json:"description"`
				} `json:"results"`
				Next string `json:"next"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				return out, fmt.Errorf("otx export: malformed JSON: %w", err)
			}
			for _, item := range payload.Results {
				h := normalizeHash(item.Indicator)
				if !validSHA256(h) || seen[h] {
					continue
				}
				seen[h] = true
				lbl := sanitizeOTXLabel(item.Title)
				if lbl == "" {
					lbl = "OTX.SubscribedIOC"
				}
				out = append(out, ExportedHash{SHA256: h, Label: lbl})
			}
			nextURL = strings.TrimSpace(payload.Next)
			if nextURL != "" && strings.HasPrefix(nextURL, "/") {
				if u, err := url.Parse(base); err == nil {
					nextURL = u.Scheme + "://" + u.Host + nextURL
				}
			}
		} else {
			// Plain-text newline-delimited fallback.
			sc := bufio.NewScanner(strings.NewReader(trimmed))
			for sc.Scan() {
				h := normalizeHash(sc.Text())
				if validSHA256(h) && !seen[h] {
					seen[h] = true
					out = append(out, ExportedHash{SHA256: h, Label: "OTX.SubscribedIOC"})
				}
			}
			nextURL = ""
		}
	}
	return out, nil
}

func extractOTXLabel(pulses []struct {
	Name            string   `json:"name"`
	Adversary       string   `json:"adversary"`
	MalwareFamilies []any    `json:"malware_families"`
	Tags            []string `json:"tags"`
}) string {
	for _, p := range pulses {
		for _, mf := range p.MalwareFamilies {
			switch v := mf.(type) {
			case string:
				if lbl := sanitizeOTXLabel(v); lbl != "" {
					return lbl
				}
			case map[string]any:
				if s, ok := v["display_name"].(string); ok {
					if lbl := sanitizeOTXLabel(s); lbl != "" {
						return lbl
					}
				}
				if s, ok := v["id"].(string); ok {
					if lbl := sanitizeOTXLabel(s); lbl != "" {
						return lbl
					}
				}
			}
		}
	}
	for _, p := range pulses {
		if lbl := sanitizeOTXLabel(p.Adversary); lbl != "" {
			return lbl
		}
	}
	for _, p := range pulses {
		if lbl := sanitizeOTXLabel(p.Name); lbl != "" {
			return lbl
		}
	}
	return "OTX.ThreatPulse"
}

func sanitizeOTXLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Strip colons/newlines so labels are safe in ClamAV-style HSB lines too.
	s = strings.NewReplacer(":", "-", "\r", " ", "\n", " ").Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 48 {
		s = strings.TrimSpace(s[:48])
	}
	if !strings.HasPrefix(strings.ToUpper(s), "OTX.") {
		s = "OTX." + s
	}
	return s
}
