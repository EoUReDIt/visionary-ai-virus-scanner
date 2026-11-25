package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// HFBase is the Hugging Face endpoint. It is a variable so tests can point it
// at a local server; users never change it.
var HFBase = "https://huggingface.co"

func init() {
	// Test hook: point at a local mock hub. Anything but loopback is ignored.
	if v := os.Getenv("VISIONARY_HF_BASE"); strings.HasPrefix(v, "http://127.0.0.1:") || strings.HasPrefix(v, "http://localhost:") {
		HFBase = strings.TrimRight(v, "/")
	}
}

// DefaultMaxDownloadGB refuses to even start downloading files that cannot be
// a model under the parameter limit (a 3B model at Q8 is about 3.3 GB).
const DefaultMaxDownloadGB = 4.5

// HFModel is one search hit.
type HFModel struct {
	ID        string  `json:"id"`
	Downloads int     `json:"downloads"`
	Likes     int     `json:"likes"`
	Gated     bool    `json:"gated"`
	ParamsB   float64 `json:"params_b,omitempty"` // 0 when the hub does not say
}

// HFFile is one downloadable GGUF file in a repository.
type HFFile struct {
	Name    string `json:"name"`
	SizeMB  int    `json:"size_mb"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256,omitempty"`
	Quant   string `json:"quant,omitempty"`
	Sharded bool   `json:"sharded,omitempty"`
}

var (
	repoRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	fileRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,200}\.gguf$`)
	quantRe = regexp.MustCompile(`(?i)(IQ\d_[A-Z]+(_[A-Z]+)?|Q\d(_K)?(_[A-Z0-9]+)?|BF16|F16|F32)`)
	shardRe = regexp.MustCompile(`(?i)-\d{5}-of-\d{5}\.gguf$`)
)

// hfClient follows redirects only to Hugging Face's own hosts (files are
// served from CDN hostnames) and never forwards the token elsewhere.
func hfClient() *http.Client {
	base, _ := url.Parse(HFBase)
	return &http.Client{
		Timeout: 0, // downloads are long; callers pass a context
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return errors.New("too many redirects")
			}
			h := strings.ToLower(r.URL.Hostname())
			okHost := h == base.Hostname() || strings.HasSuffix(h, ".huggingface.co") || strings.HasSuffix(h, ".hf.co") || h == "hf.co"
			if r.URL.Scheme != "https" && h != "127.0.0.1" && h != "localhost" {
				return errors.New("refusing redirect to a non-https address")
			}
			if !okHost && h != "127.0.0.1" && h != "localhost" {
				return fmt.Errorf("refusing redirect to %s (not a Hugging Face host)", h)
			}
			if h != base.Hostname() {
				r.Header.Del("Authorization")
			}
			return nil
		},
	}
}

func hfGet(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, HFBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "visionary-av")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hfClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("Hugging Face denied access: the model is gated or private. Accept its terms on huggingface.co and set a read token (visionary ai local hf set-token)")
	case http.StatusNotFound:
		return errors.New("not found on Hugging Face")
	default:
		return fmt.Errorf("Hugging Face: %s", resp.Status)
	}
	return json.Unmarshal(raw, out)
}

// HFSearch looks for GGUF repositories, most downloaded first.
func HFSearch(ctx context.Context, token, query string, limit int) ([]HFModel, error) {
	if limit <= 0 || limit > 50 {
		limit = 15
	}
	q := url.Values{}
	q.Set("search", query)
	q.Set("filter", "gguf")
	q.Set("sort", "downloads")
	q.Set("direction", "-1")
	q.Set("limit", fmt.Sprint(limit))
	for _, e := range []string{"downloads", "likes", "gated", "gguf"} {
		q.Add("expand[]", e)
	}
	var raw []struct {
		ID        string          `json:"id"`
		Downloads int             `json:"downloads"`
		Likes     int             `json:"likes"`
		Gated     json.RawMessage `json:"gated"`
		GGUF      *struct {
			Total uint64 `json:"total"`
		} `json:"gguf"`
	}
	if err := hfGet(ctx, token, "/api/models?"+q.Encode(), &raw); err != nil {
		return nil, err
	}
	out := make([]HFModel, 0, len(raw))
	for _, m := range raw {
		if !repoRe.MatchString(m.ID) {
			continue
		}
		hm := HFModel{ID: m.ID, Downloads: m.Downloads, Likes: m.Likes}
		if g := strings.TrimSpace(string(m.Gated)); g != "" && g != "false" && g != "null" {
			hm.Gated = true
		}
		if m.GGUF != nil {
			hm.ParamsB = float64(m.GGUF.Total) / 1e9
		}
		out = append(out, hm)
	}
	return out, nil
}

// HFFiles lists the single-file GGUFs of a repository.
func HFFiles(ctx context.Context, token, repo string) ([]HFFile, error) {
	if !repoRe.MatchString(repo) {
		return nil, fmt.Errorf("%q is not a Hugging Face repository (expected owner/name)", repo)
	}
	var tree []struct {
		Type string `json:"type"`
		Path string `json:"path"`
		Size int64  `json:"size"`
		LFS  *struct {
			OID  string `json:"oid"`
			Size int64  `json:"size"`
		} `json:"lfs"`
	}
	if err := hfGet(ctx, token, "/api/models/"+repo+"/tree/main", &tree); err != nil {
		return nil, err
	}
	var files []HFFile
	for _, t := range tree {
		if t.Type != "file" || !strings.HasSuffix(strings.ToLower(t.Path), ".gguf") || !fileRe.MatchString(t.Path) {
			continue
		}
		f := HFFile{Name: t.Path, Size: t.Size, Sharded: shardRe.MatchString(t.Path)}
		if t.LFS != nil {
			f.SHA256 = strings.ToLower(t.LFS.OID)
			if t.LFS.Size > 0 {
				f.Size = t.LFS.Size
			}
		}
		f.SizeMB = int(f.Size >> 20)
		if m := quantRe.FindString(strings.TrimSuffix(t.Path, ".gguf")); m != "" {
			f.Quant = strings.ToUpper(m)
		}
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Size < files[j].Size })
	return files, nil
}

// quantPreference is the order tried when the user names no quantisation:
// a good size/quality balance first, small CPU-friendly ones next.
var quantPreference = []string{"Q4_K_M", "Q4_K_S", "Q4_0", "Q5_K_M", "Q5_K_S", "Q6_K", "Q8_0", "IQ4_XS", "Q3_K_M"}

// PickFile chooses a file by exact name, by quantisation, or by preference.
func PickFile(files []HFFile, want string) (HFFile, error) {
	var usable []HFFile
	for _, f := range files {
		if !f.Sharded {
			usable = append(usable, f)
		}
	}
	if len(usable) == 0 {
		return HFFile{}, errors.New("the repository has no single-file GGUF (split models are not supported)")
	}
	want = strings.TrimSpace(want)
	if want != "" {
		for _, f := range usable {
			if strings.EqualFold(f.Name, want) {
				return f, nil
			}
		}
		for _, f := range usable {
			if strings.EqualFold(f.Quant, want) {
				return f, nil
			}
		}
		return HFFile{}, fmt.Errorf("no file or quantisation %q in the repository (try: visionary ai local hf files <repo>)", want)
	}
	for _, q := range quantPreference {
		for _, f := range usable {
			if f.Quant == q {
				return f, nil
			}
		}
	}
	return usable[0], nil
}

// HFRef is what the user typed, understood.
type HFRef struct{ Repo, File string }

// ParseHFRef accepts owner/repo, owner/repo:QUANT, owner/repo/file.gguf and
// huggingface.co URLs (repo page or direct file link).
func ParseHFRef(s string) (HFRef, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err != nil {
			return HFRef{}, err
		}
		h := strings.ToLower(u.Hostname())
		if h != "huggingface.co" && h != "hf.co" && h != "www.huggingface.co" {
			return HFRef{}, fmt.Errorf("only huggingface.co links are accepted, not %s", h)
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 {
			return HFRef{}, errors.New("link does not name a repository")
		}
		r := HFRef{Repo: parts[0] + "/" + parts[1]}
		if len(parts) >= 5 && (parts[2] == "resolve" || parts[2] == "blob") {
			r.File = strings.Join(parts[4:], "/")
		}
		if !repoRe.MatchString(r.Repo) {
			return HFRef{}, fmt.Errorf("%q is not a valid repository", r.Repo)
		}
		return r, nil
	}
	var r HFRef
	if i := strings.LastIndex(s, ":"); i > 0 {
		r.File, s = s[i+1:], s[:i]
	}
	parts := strings.Split(s, "/")
	switch {
	case len(parts) == 2:
		r.Repo = s
	case len(parts) == 3 && strings.HasSuffix(strings.ToLower(parts[2]), ".gguf"):
		r.Repo, r.File = parts[0]+"/"+parts[1], parts[2]
	default:
		return HFRef{}, fmt.Errorf("%q: use owner/repo, owner/repo:Q4_K_M or owner/repo/file.gguf", s)
	}
	if !repoRe.MatchString(r.Repo) {
		return HFRef{}, fmt.Errorf("%q is not a valid repository", r.Repo)
	}
	return r, nil
}

// HFDownloadOptions describes one download.
type HFDownloadOptions struct {
	Repo, File string
	Token      string
	Dir        string  // store directory
	MaxGB      float64 // size guard; 0 = DefaultMaxDownloadGB
	MaxParamsB float64 // parameter ceiling verified after download
	Progress   func(done, total int64)
}

// StoredName is the on-disk name for a downloaded file.
func StoredName(repo, file string) string {
	return strings.ReplaceAll(repo, "/", "--") + "--" + file
}

// HFDownload fetches one GGUF into the model store, resuming a partial file,
// verifying the published SHA-256 and the GGUF header, and enforcing the
// parameter ceiling by counting the real tensors. A file over the limit is
// deleted. It returns the stored model.
func HFDownload(ctx context.Context, o HFDownloadOptions) (StoredModel, error) {
	if !repoRe.MatchString(o.Repo) {
		return StoredModel{}, fmt.Errorf("invalid repository %q", o.Repo)
	}
	files, err := HFFiles(ctx, o.Token, o.Repo)
	if err != nil {
		return StoredModel{}, err
	}
	f, err := PickFile(files, o.File)
	if err != nil {
		return StoredModel{}, err
	}
	maxGB := o.MaxGB
	if maxGB <= 0 {
		maxGB = DefaultMaxDownloadGB
	}
	if float64(f.Size) > maxGB*(1<<30) {
		return StoredModel{}, fmt.Errorf("%s is %.1f GB, too large for a model under the %.1fB limit (guard: %.1f GB)",
			f.Name, float64(f.Size)/(1<<30), orDefault(o.MaxParamsB), maxGB)
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return StoredModel{}, err
	}
	name := StoredName(o.Repo, f.Name)
	final := filepath.Join(o.Dir, name)
	part := final + ".part"

	var have int64
	if st, err := os.Stat(part); err == nil {
		have = st.Size()
		if have > f.Size {
			have = 0
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, HFBase+"/"+o.Repo+"/resolve/main/"+url.PathEscape(f.Name), nil)
	if err != nil {
		return StoredModel{}, err
	}
	req.Header.Set("User-Agent", "visionary-av")
	if o.Token != "" {
		req.Header.Set("Authorization", "Bearer "+o.Token)
	}
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, err := hfClient().Do(req)
	if err != nil {
		return StoredModel{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		have = 0 // server ignored the range: start over
	case http.StatusPartialContent:
	case http.StatusUnauthorized, http.StatusForbidden:
		return StoredModel{}, errors.New("Hugging Face denied access: accept the model's terms on huggingface.co and set a token (visionary ai local hf set-token)")
	default:
		return StoredModel{}, fmt.Errorf("download failed: %s", resp.Status)
	}
	flags := os.O_CREATE | os.O_WRONLY
	if have == 0 {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_APPEND
	}
	out, err := os.OpenFile(part, flags, 0o644)
	if err != nil {
		return StoredModel{}, err
	}
	h := sha256.New()
	if have > 0 { // hash what we already have
		if old, err := os.Open(part); err == nil {
			_, _ = io.Copy(h, io.LimitReader(old, have))
			old.Close()
		}
	}
	done := have
	buf := make([]byte, 256<<10)
	var last time.Time
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return StoredModel{}, werr
			}
			h.Write(buf[:n])
			done += int64(n)
			if o.Progress != nil && time.Since(last) > 200*time.Millisecond {
				last = time.Now()
				o.Progress(done, f.Size)
			}
			if done > f.Size+1<<20 { // more than advertised
				out.Close()
				_ = os.Remove(part)
				return StoredModel{}, errors.New("download is larger than the hub reported; discarded")
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			return StoredModel{}, fmt.Errorf("download interrupted (run the same command to resume): %w", rerr)
		}
	}
	if err := out.Close(); err != nil {
		return StoredModel{}, err
	}
	if o.Progress != nil {
		o.Progress(done, f.Size)
	}
	if f.Size > 0 && done != f.Size {
		return StoredModel{}, fmt.Errorf("download incomplete (%d of %d bytes); run the same command to resume", done, f.Size)
	}
	if f.SHA256 != "" && hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		_ = os.Remove(part)
		return StoredModel{}, errors.New("checksum does not match the hub's SHA-256; file discarded")
	}
	params, err := GGUFParams(part)
	if err != nil {
		_ = os.Remove(part)
		return StoredModel{}, fmt.Errorf("not a valid GGUF file: %w", err)
	}
	if err := CheckParams(float64(params)/1e9, o.MaxParamsB, f.Name); err != nil {
		_ = os.Remove(part)
		return StoredModel{}, err
	}
	if err := os.Rename(part, final); err != nil {
		return StoredModel{}, err
	}
	sm := StoredModel{Name: name, Path: final, SizeMB: int(f.Size >> 20), ParamsB: float64(params) / 1e9,
		Source: "huggingface:" + o.Repo + "/" + f.Name, SHA256: hex.EncodeToString(h.Sum(nil)), Quant: f.Quant}
	return sm, writeMeta(sm)
}

func orDefault(b float64) float64 {
	if b <= 0 {
		return 3
	}
	return b
}
