package defs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/rules"
)

func TestBuiltinRulesInSync(t *testing.T) {
	plain, err := os.ReadFile("builtin.yar")
	if err != nil {
		t.Fatal(err)
	}
	if BuiltinRules() != string(plain) {
		t.Fatal("builtin.yar.gz is stale: run `go generate ./internal/defs`")
	}
	set := rules.Parse(string(plain), "builtin")
	if len(set.Skipped) != 0 {
		t.Fatalf("built-in rules must all compile: %v", set.Skipped)
	}
}

func TestImportFormats(t *testing.T) {
	t.Setenv("VISIONARY_HOME", t.TempDir())
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hash := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	hexOf := func(s string) string { return fmtHex(hash(s)) }

	// ClamAV .hsb, plain list with comments, and a MalwareBazaar-style CSV.
	if _, err := Import(write("a.hsb", []byte(hexOf("one")+":3:Win.Trojan.One\n")), "", "auto", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(write("b.txt", []byte("# list\n"+hexOf("two")+"\nnot a hash\n")), "", "auto", "", ""); err != nil {
		t.Fatal(err)
	}
	csv := `"2026-01-01","` + hexOf("three") + `","d41d8cd98f00b204e9800998ecf8427e","da39a3ee5e6b4b0d3255bfef95601890afd80709","rep","x.exe","exe","application/x-dosexec","AgentTesla","n/a"` + "\n"
	if _, err := Import(write("c.csv", []byte(csv)), "", "auto", "", ""); err != nil {
		t.Fatal(err)
	}
	// A ClamAV CVD container: 512-byte header then a gzipped tar.
	var tb bytes.Buffer
	gz := gzip.NewWriter(&tb)
	tw := tar.NewWriter(gz)
	body := []byte(hexOf("four") + ":4:Win.Cvd.Four\n")
	_ = tw.WriteHeader(&tar.Header{Name: "main.hsb", Size: int64(len(body)), Mode: 0o644})
	_, _ = tw.Write(body)
	ndb := []byte("Sig:0:*:deadbeef\n")
	_ = tw.WriteHeader(&tar.Header{Name: "main.ndb", Size: int64(len(ndb)), Mode: 0o644})
	_, _ = tw.Write(ndb)
	tw.Close()
	gz.Close()
	header := append([]byte("ClamAV-VDB:01 Jan 2026:1:1:1:1:x:y:z"), make([]byte, 512)...)[:512]
	src, err := Import(write("main.cvd", append(header, tb.Bytes()...)), "", "auto", "", "")
	if err != nil || src.Count != 1 || src.Skipped != 1 {
		t.Fatalf("cvd import: %+v %v", src, err)
	}
	if _, err := Import(write("x.certs", []byte("00:AB:CD:EF:12:34,Leaked Corp\n")), "", "auto", "", ""); err != nil {
		t.Fatal(err)
	}

	db, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	for word, want := range map[string]string{"one": "Win.Trojan.One", "two": "b", "three": "MalwareBazaar.AgentTesla", "four": "Win.Cvd.Four"} {
		name, _, ok := db.LookupHash(hash(word))
		if !ok || name != want {
			t.Errorf("lookup %s = %q, %v; want %q", word, name, ok, want)
		}
	}
	if _, _, ok := db.LookupHash(hash("absent")); ok {
		t.Error("unexpected hit")
	}
	if name, ok := db.LookupCert("abcdef1234"); !ok || name != "x: Leaked Corp" {
		t.Errorf("cert lookup = %q, %v", name, ok)
	}
	if st := db.Stats(); st.Hashes != 4 || st.Sources != 5 {
		t.Errorf("stats = %+v", st)
	}
	if err := Remove("a"); err != nil {
		t.Fatal(err)
	}
	if db, _ = Open(); db.Manifest.Revision != 6 {
		t.Errorf("revision = %d, want 6", db.Manifest.Revision)
	}
	if _, _, ok := db.LookupHash(hash("one")); ok {
		t.Error("removed source still matches")
	}
}

func TestChannelURLPolicy(t *testing.T) {
	for url, ok := range map[string]bool{"https://example.com/a": true, "file:///tmp/a": true,
		"http://example.com/a": false, "http://127.0.0.1:8080/a": true, "ftp://example.com/a": false} {
		if err := ValidateChannelURL(url); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", url, err, ok)
		}
	}
	_ = config.Dir
}

func fmtHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
