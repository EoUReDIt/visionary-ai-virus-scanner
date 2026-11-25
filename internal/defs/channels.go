package defs

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

// Preset is a ready-made channel subscription.
type Preset struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Kind  string `json:"kind"`
	Hours int    `json:"hours"`
	About string `json:"about"`
}

var Presets = []Preset{
	{"malwarebazaar-recent", "https://bazaar.abuse.ch/export/txt/sha256/recent/", "hashes", 1,
		"abuse.ch MalwareBazaar: SHA-256 of samples seen in the last 48 hours"},
	{"malwarebazaar-recent-md5", "https://bazaar.abuse.ch/export/txt/md5/recent/", "hashes", 1,
		"abuse.ch MalwareBazaar: MD5 of samples seen in the last 48 hours"},
	{"malwarebazaar-full-csv", "https://bazaar.abuse.ch/export/csv/recent/", "hashes", 6,
		"abuse.ch MalwareBazaar: recent samples with family names"},
}

const maxDownload = 1 << 30

// ValidateChannelURL only allows transports that cannot be tampered with in
// transit: a definitions feed decides what gets quarantined.
func ValidateChannelURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https", "file":
		return nil
	case "http":
		if h := u.Hostname(); h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
		return errors.New("plain http channels are refused: use https (or a file:// path)")
	}
	return fmt.Errorf("unsupported channel URL scheme %q", u.Scheme)
}

// Due reports whether a channel should be polled now.
func Due(ch config.Channel, now time.Time) bool {
	if !ch.Enabled {
		return false
	}
	h := ch.IntervalHours
	if h <= 0 {
		h = 6
	}
	return ch.LastChecked.IsZero() || now.Sub(ch.LastChecked) >= time.Duration(h)*time.Hour
}

// UpdateChannel polls one channel. It mutates ch (ETag, status) and reports
// whether new definitions were imported.
func UpdateChannel(ch *config.Channel) (changed bool, src Source, err error) {
	ch.LastChecked = time.Now()
	defer func() {
		switch {
		case err != nil:
			ch.LastStatus = "error: " + err.Error()
		case changed:
			ch.LastStatus = fmt.Sprintf("updated: %d entries", src.Count)
		default:
			ch.LastStatus = "up to date"
		}
	}()
	if err = ValidateChannelURL(ch.URL); err != nil {
		return false, src, err
	}
	u, _ := url.Parse(ch.URL)
	srcName := "ch-" + ch.Name
	hint := path.Base(u.Path)

	if u.Scheme == "file" {
		p := u.Path
		if u.Host != "" { // file://C:/path style
			p = u.Host + u.Path
		}
		p = strings.TrimPrefix(p, "/")
		if !strings.Contains(p, ":") {
			p = "/" + p
		}
		st, err := os.Stat(p)
		if err != nil {
			return false, src, err
		}
		tag := fmt.Sprintf("%d-%d", st.Size(), st.ModTime().UnixNano())
		if tag == ch.ETag {
			return false, src, nil
		}
		if src, err = Import(p, srcName, ch.Kind, hint, ch.Name); err != nil {
			return false, src, err
		}
		ch.ETag = tag
		return true, src, nil
	}

	req, err := http.NewRequest(http.MethodGet, ch.URL, nil)
	if err != nil {
		return false, src, err
	}
	req.Header.Set("User-Agent", "visionary-av/"+config.Version)
	if ch.ETag != "" {
		req.Header.Set("If-None-Match", ch.ETag)
	}
	if ch.LastModified != "" {
		req.Header.Set("If-Modified-Since", ch.LastModified)
	}
	for _, h := range ch.Headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return false, src, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return false, src, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, src, fmt.Errorf("server answered %s", resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dir("tmp", "x")), "dl-*")
	if err != nil {
		return false, src, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownload+1))
	tmp.Close()
	if err != nil {
		return false, src, err
	}
	if n > maxDownload {
		return false, src, errors.New("download exceeds the 1 GB limit")
	}
	if src, err = Import(tmp.Name(), srcName, ch.Kind, hint, ch.Name); err != nil {
		return false, src, err
	}
	ch.ETag = resp.Header.Get("ETag")
	ch.LastModified = resp.Header.Get("Last-Modified")
	return true, src, nil
}
