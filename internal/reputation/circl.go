package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultCIRCLBaseURL = "https://hashlookup.circl.lu"

// CIRCL queries CIRCL's free keyless hashlookup API (NSRL / known-good OS and
// software reference hashes) to confirm legitimate binaries and suppress
// heuristic false positives without needing any API key. Only SHA-256 hashes
// ever leave the machine.
type CIRCL struct {
	BaseURL string
	cache   *DiskCache
}

func NewCIRCL() *CIRCL {
	return NewCIRCLWithCache(nil)
}

func NewCIRCLWithCache(cache *DiskCache) *CIRCL {
	return &CIRCL{
		BaseURL: defaultCIRCLBaseURL,
		cache:   cache,
	}
}

func (c *CIRCL) ProviderName() string { return "CIRCL hashlookup (No Key)" }

func (c *CIRCL) baseURL() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultCIRCLBaseURL
}

func (c *CIRCL) Lookup(ctx context.Context, sha256 string) (malicious, total int, label string, found bool, err error) {
	mal, tot, lbl, _, ok, e := c.LookupDetail(ctx, sha256)
	return mal, tot, lbl, ok, e
}

func (c *CIRCL) LookupDetail(ctx context.Context, sha256 string) (malicious, total int, label, detail string, found bool, err error) {
	sha256 = normalizeHash(sha256)
	if !validSHA256(sha256) {
		return 0, 0, "", "", false, errors.New("invalid SHA-256 hash")
	}
	if rec, ok := c.cache.Get("circl", sha256); ok {
		return rec.Mal, rec.Total, rec.Label, rec.Detail, rec.Found, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL()+"/lookup/sha256/"+sha256, nil)
	if err != nil {
		return 0, 0, "", "", false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "VisionaryAV-ThreatExchange/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		c.cache.Put("circl", sha256, cacheRecord{Found: false})
		return 0, 0, "", "", false, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return 0, 0, "", "", false, errors.New("CIRCL hashlookup rate limit reached")
	}
	if resp.StatusCode != http.StatusOK {
		return 0, 0, "", "", false, fmt.Errorf("CIRCL hashlookup: %s", resp.Status)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, 0, "", "", false, err
	}
	var payload struct {
		FileName    string `json:"FileName"`
		ProductName string `json:"ProductName"`
		Source      string `json:"source"`
		KnownMalic  string `json:"KnownMalicious"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, 0, "", "", false, err
	}

	// CIRCL hashlookup indexes known-good NSRL/RDS files. Reporting total=100
	// with mal=0 integrates cleanly with engine.go's known-clean discount.
	label = strings.TrimSpace(payload.FileName)
	if label == "" {
		label = strings.TrimSpace(payload.ProductName)
	}
	if label == "" {
		label = "KnownGood.NSRL"
	}
	src := strings.TrimSpace(payload.Source)
	if src == "" {
		src = "NSRL/RDS"
	}
	detail = fmt.Sprintf("Known-good reference file on CIRCL hashlookup (%s)", src)
	c.cache.Put("circl", sha256, cacheRecord{
		Mal:    0,
		Total:  100,
		Label:  label,
		Detail: detail,
		Found:  true,
	})
	return 0, 100, label, detail, true, nil
}

// LookupBatch queries unique SHA-256 hashes against CIRCL hashlookup using a
// single atomic cache flush at the end.
func (c *CIRCL) LookupBatch(ctx context.Context, hashes []string) map[string]LookupResult {
	out := make(map[string]LookupResult, len(hashes))
	c.cache.BeginBatch()
	defer c.cache.EndBatch()
	seen := map[string]bool{}
	for _, raw := range hashes {
		h := normalizeHash(raw)
		if !validSHA256(h) || seen[h] {
			continue
		}
		seen[h] = true
		if ctx.Err() != nil {
			out[h] = LookupResult{Err: ctx.Err()}
			continue
		}
		mal, tot, lbl, det, ok, err := c.LookupDetail(ctx, h)
		out[h] = LookupResult{Malicious: mal, Total: tot, Label: lbl, Detail: det, Found: ok, Err: err}
	}
	return out
}
