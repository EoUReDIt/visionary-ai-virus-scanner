package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseHFRef(t *testing.T) {
	good := map[string]HFRef{
		"owner/repo":                        {"owner/repo", ""},
		"owner/repo:Q4_K_M":                 {"owner/repo", "Q4_K_M"},
		"owner/repo/m-Q4_K_M.gguf":          {"owner/repo", "m-Q4_K_M.gguf"},
		"https://huggingface.co/owner/repo": {"owner/repo", ""},
		"https://huggingface.co/owner/repo/resolve/main/a.gguf": {"owner/repo", "a.gguf"},
	}
	for in, want := range good {
		got, err := ParseHFRef(in)
		if err != nil || got != want {
			t.Errorf("%s -> %+v, %v (want %+v)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "justone", "../x/y", "http://evil.example/owner/repo", "https://huggingface.co.evil.test/a/b", "a/b/c/d"} {
		if _, err := ParseHFRef(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestPickFile(t *testing.T) {
	files := []HFFile{{Name: "m-Q8_0.gguf", Quant: "Q8_0"}, {Name: "m-Q4_K_M.gguf", Quant: "Q4_K_M"}, {Name: "m-Q2_K-00001-of-00002.gguf", Sharded: true}}
	if f, _ := PickFile(files, ""); f.Quant != "Q4_K_M" {
		t.Errorf("default pick %v", f)
	}
	if f, _ := PickFile(files, "q8_0"); f.Name != "m-Q8_0.gguf" {
		t.Errorf("quant pick %v", f)
	}
	if _, err := PickFile(files, "Q2_K"); err == nil {
		t.Error("sharded file must not be selectable")
	}
	if _, err := PickFile([]HFFile{{Name: "x", Sharded: true}}, ""); err == nil {
		t.Error("only shards should error")
	}
}

// hub serves one repository with one GGUF and honours Range.
func hub(t *testing.T, content []byte, sum string, hits *int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("filter") != "gguf" {
			t.Error("search must filter on gguf")
		}
		fmt.Fprint(w, `[{"id":"acme/tiny-GGUF","downloads":5,"likes":1,"gated":false,"gguf":{"total":1500000000}},{"id":"../bad","downloads":1}]`)
	})
	mux.HandleFunc("/api/models/acme/tiny-GGUF/tree/main", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"type":"file","path":"README.md","size":10},{"type":"file","path":"tiny-Q4_K_M.gguf","size":%d,"lfs":{"oid":"%s","size":%d}}]`, len(content), sum, len(content))
	})
	mux.HandleFunc("/acme/tiny-GGUF/resolve/main/tiny-Q4_K_M.gguf", func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			*hits++
		}
		start := 0
		if rg := r.Header.Get("Range"); strings.HasPrefix(rg, "bytes=") {
			start, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rg, "bytes="), "-"))
			w.WriteHeader(http.StatusPartialContent)
		}
		_, _ = w.Write(content[start:])
	})
	srv := httptest.NewServer(mux)
	old := HFBase
	HFBase = srv.URL
	t.Cleanup(func() { HFBase = old; srv.Close() })
	return srv
}

func sumOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestHFSearchAndFiles(t *testing.T) {
	hub(t, []byte("x"), "00", nil)
	models, err := HFSearch(context.Background(), "", "tiny", 5)
	if err != nil || len(models) != 1 || models[0].ID != "acme/tiny-GGUF" || models[0].ParamsB != 1.5 {
		t.Fatalf("search: %+v %v", models, err)
	}
	files, err := HFFiles(context.Background(), "", "acme/tiny-GGUF")
	if err != nil || len(files) != 1 || files[0].Quant != "Q4_K_M" {
		t.Fatalf("files: %+v %v", files, err)
	}
	if _, err := HFFiles(context.Background(), "", "../etc"); err == nil {
		t.Error("bad repo accepted")
	}
}

func TestHFDownloadVerifyAndResume(t *testing.T) {
	gg := writeGGUF(t, [][]uint64{{1000, 1000}}) // 1M params
	content, _ := os.ReadFile(gg)
	hub(t, content, sumOf(content), nil)
	dir := t.TempDir()
	opt := HFDownloadOptions{Repo: "acme/tiny-GGUF", Dir: dir, MaxParamsB: 3}

	// A partial file from an interrupted run is resumed, not restarted.
	part := filepath.Join(dir, StoredName("acme/tiny-GGUF", "tiny-Q4_K_M.gguf")+".part")
	if err := os.WriteFile(part, content[:20], 0o644); err != nil {
		t.Fatal(err)
	}
	var last int64
	opt.Progress = func(d, total int64) { last = d }
	m, err := HFDownload(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if last != int64(len(content)) || m.ParamsB <= 0 || !strings.HasPrefix(m.Source, "huggingface:acme/tiny-GGUF") {
		t.Fatalf("model %+v progress %d", m, last)
	}
	if _, err := os.Stat(part); !os.IsNotExist(err) {
		t.Error(".part file left behind")
	}
	list, _ := ListStore(dir)
	if len(list) != 1 || list[0].Name != m.Name {
		t.Fatalf("store %+v", list)
	}
	if err := RemoveStored(dir, m.Name); err != nil {
		t.Fatal(err)
	}
	if list, _ = ListStore(dir); len(list) != 0 {
		t.Error("model not removed")
	}
}

func TestHFDownloadRejects(t *testing.T) {
	gg := writeGGUF(t, [][]uint64{{100000, 100000}}) // 10B params
	content, _ := os.ReadFile(gg)
	hub(t, content, sumOf(content), nil)
	dir := t.TempDir()
	// Over the parameter ceiling: deleted after the real tensor count.
	_, err := HFDownload(context.Background(), HFDownloadOptions{Repo: "acme/tiny-GGUF", Dir: dir, MaxParamsB: 3, MaxGB: 1})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("over-limit model accepted: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("files left after rejection: %v", ents)
	}
	// Checksum mismatch.
	hub(t, content, strings.Repeat("0", 64), nil)
	if _, err := HFDownload(context.Background(), HFDownloadOptions{Repo: "acme/tiny-GGUF", Dir: dir, MaxParamsB: 3000}); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("bad checksum accepted: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("files left after checksum failure: %v", ents)
	}
	// Size guard stops before downloading.
	hits := 0
	hub(t, content, sumOf(content), &hits)
	_, err = HFDownload(context.Background(), HFDownloadOptions{Repo: "acme/tiny-GGUF", Dir: dir, MaxGB: 1e-9, MaxParamsB: 3000})
	if err == nil || hits != 0 {
		t.Fatalf("size guard: err=%v hits=%d", err, hits)
	}
}

func TestRedirectOnlyToHuggingFace(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed a redirect off-site") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/x", http.StatusFound)
	}))
	defer srv.Close()
	old := HFBase
	HFBase = srv.URL
	defer func() { HFBase = old }()
	var out any
	if err := hfGet(context.Background(), "tok", "/api/models/a/b", &out); err == nil || !strings.Contains(err.Error(), "not a Hugging Face host") {
		t.Fatalf("redirect off-site not refused: %v", err)
	}
}

func TestImportStore(t *testing.T) {
	src := writeGGUF(t, [][]uint64{{1000, 1000}})
	dir := t.TempDir()
	m, err := ImportGGUF(src, dir, 3)
	if err != nil || m.Source != "imported" || m.SHA256 == "" {
		t.Fatalf("import: %+v %v", m, err)
	}
	if _, err := ImportGGUF(src, dir, 3); err == nil {
		t.Error("duplicate import accepted")
	}
	big := writeGGUF(t, [][]uint64{{100000, 100000}})
	if _, err := ImportGGUF(big, dir, 3); err == nil {
		t.Error("10B model imported")
	}
	notGGUF := filepath.Join(t.TempDir(), "x.gguf")
	_ = os.WriteFile(notGGUF, []byte("not a model at all"), 0o644)
	if _, err := ImportGGUF(notGGUF, dir, 3); err == nil {
		t.Error("garbage imported")
	}
	if got, err := FindStored(dir, "m"); err != nil || got.Name != "m.gguf" {
		t.Errorf("prefix lookup: %+v %v", got, err)
	}
	if sanitizeName("../we ird?.gguf") != "we_ird_.gguf" {
		t.Errorf("sanitize: %s", sanitizeName("../we ird?.gguf"))
	}
	if err := RemoveStored(dir, "../../etc/passwd"); err == nil {
		t.Error("path traversal not rejected")
	}
}
