package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type VirusTotal struct {
	Key       string
	BaseURL   string
	PaceDelay time.Duration // delay between live uncached batch requests (e.g. 15s for 4 req/min free tier)
	cache     *DiskCache
}

func NewVirusTotal(key string) *VirusTotal {
	return NewVirusTotalWithCache(key, nil)
}

func NewVirusTotalWithCache(key string, cache *DiskCache) *VirusTotal {
	if cache == nil {
		cache = OpenCache("")
	}
	return &VirusTotal{
		Key:       strings.TrimSpace(key),
		BaseURL:   "https://www.virustotal.com/api/v3",
		PaceDelay: 15 * time.Second,
		cache:     cache,
	}
}

func (v *VirusTotal) ProviderName() string { return "VirusTotal" }

func (v *VirusTotal) Lookup(ctx context.Context, sha256 string) (malicious, total int, label string, found bool, err error) {
	mal, tot, lbl, _, ok, e := v.LookupDetail(ctx, sha256)
	return mal, tot, lbl, ok, e
}

func (v *VirusTotal) LookupDetail(ctx context.Context, sha256 string) (malicious, total int, label, detail string, found bool, err error) {
	h := normalizeHash(sha256)
	if !validSHA256(h) {
		return 0, 0, "", "", false, errors.New("virustotal: invalid SHA-256 hash")
	}
	if rec, ok := v.cache.Get("virustotal", h); ok {
		return rec.Mal, rec.Total, rec.Label, rec.Detail, rec.Found, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(v.BaseURL, "/")+"/files/"+h, nil)
	if err != nil {
		return 0, 0, "", "", false, err
	}
	req.Header.Set("x-apikey", v.Key)
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", "", false, err
	}
	defer resp.Body.Close()
	var r cacheRecord
	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			Data struct {
				Attributes struct {
					Stats map[string]int `json:"last_analysis_stats"`
					Class struct {
						Label string `json:"suggested_threat_label"`
					} `json:"popular_threat_classification"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
			return 0, 0, "", "", false, err
		}
		a := body.Data.Attributes
		r = cacheRecord{Mal: a.Stats["malicious"], Label: a.Class.Label, Found: true}
		for k, n := range a.Stats {
			if k != "type-unsupported" && k != "timeout" && k != "failure" {
				r.Total += n
			}
		}
		r.Detail = fmt.Sprintf("%d of %d engines on VirusTotal flag this hash", r.Mal, r.Total)
	case http.StatusNotFound:
		// Unknown to VirusTotal: not evidence either way.
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, 0, "", "", false, errors.New("virustotal: the API key was rejected")
	case http.StatusTooManyRequests:
		return 0, 0, "", "", false, errors.New("virustotal: rate limit reached")
	default:
		return 0, 0, "", "", false, fmt.Errorf("virustotal: %s", resp.Status)
	}
	v.cache.Put("virustotal", h, r)
	return r.Mal, r.Total, r.Label, r.Detail, r.Found, nil
}

// LookupBatch deduplicates hashes, serves cached entries with zero requests,
// paces live requests to respect the free 4 req/min limit, and stops cleanly
// if VirusTotal returns HTTP 429 rate-limit.
func (v *VirusTotal) LookupBatch(ctx context.Context, hashes []string) map[string]LookupResult {
	out := make(map[string]LookupResult, len(hashes))
	var uncached []string
	seen := map[string]bool{}
	for _, raw := range hashes {
		h := normalizeHash(raw)
		if !validSHA256(h) || seen[h] {
			continue
		}
		seen[h] = true
		if rec, ok := v.cache.Get("virustotal", h); ok {
			out[h] = LookupResult{Malicious: rec.Mal, Total: rec.Total, Label: rec.Label, Detail: rec.Detail, Found: rec.Found}
			continue
		}
		uncached = append(uncached, h)
	}
	for i, h := range uncached {
		if i > 0 && v.PaceDelay > 0 {
			select {
			case <-ctx.Done():
				return out
			case <-time.After(v.PaceDelay):
			}
		}
		if err := ctx.Err(); err != nil {
			break
		}
		mal, tot, lbl, det, ok, err := v.LookupDetail(ctx, h)
		out[h] = LookupResult{Malicious: mal, Total: tot, Label: lbl, Detail: det, Found: ok, Err: err}
		if err != nil && strings.Contains(err.Error(), "rate limit") {
			break
		}
	}
	return out
}
