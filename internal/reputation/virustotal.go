// Package reputation looks file hashes up in VirusTotal. Only the SHA-256
// leaves the machine: files are never uploaded.
package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type VirusTotal struct {
	Key     string
	BaseURL string
	mu      sync.Mutex
	cache   map[string]vtResult
}

type vtResult struct {
	mal, total int
	label      string
	found      bool
}

func NewVirusTotal(key string) *VirusTotal {
	return &VirusTotal{Key: key, BaseURL: "https://www.virustotal.com/api/v3", cache: map[string]vtResult{}}
}

var client = &http.Client{Timeout: 30 * time.Second}

func (v *VirusTotal) Lookup(ctx context.Context, sha256 string) (malicious, total int, label string, found bool, err error) {
	v.mu.Lock()
	c, ok := v.cache[sha256]
	v.mu.Unlock()
	if ok {
		return c.mal, c.total, c.label, c.found, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.BaseURL+"/files/"+sha256, nil)
	if err != nil {
		return 0, 0, "", false, err
	}
	req.Header.Set("x-apikey", v.Key)
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", false, err
	}
	defer resp.Body.Close()
	var r vtResult
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
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return 0, 0, "", false, err
		}
		a := body.Data.Attributes
		r = vtResult{mal: a.Stats["malicious"], label: a.Class.Label, found: true}
		for k, n := range a.Stats {
			if k != "type-unsupported" && k != "timeout" && k != "failure" {
				r.total += n
			}
		}
	case http.StatusNotFound:
		// Unknown to VirusTotal: not evidence either way.
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, 0, "", false, errors.New("virustotal: the API key was rejected")
	case http.StatusTooManyRequests:
		return 0, 0, "", false, errors.New("virustotal: rate limit reached")
	default:
		return 0, 0, "", false, fmt.Errorf("virustotal: %s", resp.Status)
	}
	v.mu.Lock()
	v.cache[sha256] = r
	v.mu.Unlock()
	return r.mal, r.total, r.label, r.found, nil
}
