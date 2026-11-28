// Package defs is the definitions store: hash sets, pattern rules and a
// code-signing certificate blocklist. Definitions arrive by import (a file
// you have) or by channel (a URL polled on a schedule); both end up as named
// sources that can be listed and removed independently.
package defs

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/rules"
)

// The built-in rules ship gzip-compressed: signature strings in plain text
// inside the executable would make other scanners (and this one) flag it.
//
//go:generate sh -c "gzip -kn9f builtin.yar"
//go:embed builtin.yar.gz
var builtinGz []byte

// BuiltinRules returns the source of the rules shipped with the app.
func BuiltinRules() string {
	zr, err := gzip.NewReader(bytes.NewReader(builtinGz))
	if err != nil {
		return ""
	}
	b, _ := io.ReadAll(zr)
	return string(b)
}

type Source struct {
	Name       string    `json:"name"`
	Kind       string    `json:"kind"` // hashes | yara | certs
	Origin     string    `json:"origin"`
	Count      int       `json:"count"`
	Skipped    int       `json:"skipped,omitempty"`
	ImportedAt time.Time `json:"imported_at"`
	Channel    string    `json:"channel,omitempty"`
}

type Manifest struct {
	Revision int      `json:"revision"`
	Sources  []Source `json:"sources"`
}

func dir(parts ...string) string {
	return config.Path(append([]string{"defs"}, parts...)...)
}

// ManifestModTime lets a long-running process skip re-reading the manifest
// until the file has actually changed.
func ManifestModTime() time.Time {
	if st, err := os.Stat(dir("manifest.json")); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

func LoadManifest() Manifest {
	var m Manifest
	if b, err := os.ReadFile(dir("manifest.json")); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func saveManifest(m Manifest) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	return config.WriteAtomic(dir("manifest.json"), b, 0o644)
}

// ---- hash sets ----

// hashSet is a sorted, packed array of fixed-size digests: a million SHA-256
// entries cost 32 MB and one binary search per lookup.
type hashSet struct {
	Size    int
	Keys    []byte
	NameIdx []uint32
}

type hashFile struct {
	Sets  []hashSet // one per digest size present
	Names []string
}

func (h *hashSet) lookup(d []byte) (uint32, bool) {
	n := len(h.Keys) / h.Size
	i := sort.Search(n, func(i int) bool {
		return bytes.Compare(h.Keys[i*h.Size:(i+1)*h.Size], d) >= 0
	})
	if i < n && bytes.Equal(h.Keys[i*h.Size:(i+1)*h.Size], d) {
		return h.NameIdx[i], true
	}
	return 0, false
}

type hashBuilder struct {
	entries map[int][]hashEntry
	names   []string
	nameIdx map[string]uint32
}

type hashEntry struct {
	key  []byte
	name uint32
}

func newHashBuilder() *hashBuilder {
	return &hashBuilder{entries: map[int][]hashEntry{}, nameIdx: map[string]uint32{}}
}

func (b *hashBuilder) add(digest []byte, name string) {
	idx, ok := b.nameIdx[name]
	if !ok {
		idx = uint32(len(b.names))
		b.names = append(b.names, name)
		b.nameIdx[name] = idx
	}
	b.entries[len(digest)] = append(b.entries[len(digest)], hashEntry{digest, idx})
}

func (b *hashBuilder) count() int {
	n := 0
	for _, e := range b.entries {
		n += len(e)
	}
	return n
}

func (b *hashBuilder) build() hashFile {
	hf := hashFile{Names: b.names}
	for _, size := range []int{16, 20, 32} {
		es := b.entries[size]
		if len(es) == 0 {
			continue
		}
		sort.Slice(es, func(i, j int) bool { return bytes.Compare(es[i].key, es[j].key) < 0 })
		hs := hashSet{Size: size, Keys: make([]byte, 0, len(es)*size), NameIdx: make([]uint32, 0, len(es))}
		for i, e := range es {
			if i > 0 && bytes.Equal(es[i-1].key, e.key) {
				continue
			}
			hs.Keys = append(hs.Keys, e.key...)
			hs.NameIdx = append(hs.NameIdx, e.name)
		}
		hf.Sets = append(hf.Sets, hs)
	}
	return hf
}

// ---- loaded database ----

type DB struct {
	Manifest Manifest
	hashes   map[string]*hashFile // by source name
	Rules    *rules.Set
	certs    map[string]string // normalised serial/thumbprint -> "source: name"
}

// Open loads every source. Built-in rules are always present.
func Open() (*DB, error) {
	db := &DB{Manifest: LoadManifest(), hashes: map[string]*hashFile{}, certs: map[string]string{}}
	db.Rules = rules.Parse(BuiltinRules(), "builtin")
	var firstErr error
	for _, s := range db.Manifest.Sources {
		var err error
		switch s.Kind {
		case "hashes":
			var hf hashFile
			var f *os.File
			if f, err = os.Open(dir("hashes", s.Name+".vdb")); err == nil {
				err = gob.NewDecoder(bufio.NewReaderSize(f, 1<<20)).Decode(&hf)
				f.Close()
			}
			if err == nil {
				db.hashes[s.Name] = &hf
			}
		case "yara":
			var b []byte
			if b, err = os.ReadFile(dir("rules", s.Name+".yar")); err == nil {
				db.Rules.Merge(rules.Parse(string(b), s.Name))
			}
		case "certs":
			var b []byte
			if b, err = os.ReadFile(dir("certs", s.Name+".txt")); err == nil {
				for id, name := range parseCerts(bytes.NewReader(b)) {
					db.certs[id] = s.Name + ": " + name
				}
			}
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("definitions source %q: %w", s.Name, err)
		}
	}
	return db, firstErr
}

// LookupHash checks any of the digests against every hash source.
func (db *DB) LookupHash(digests ...[]byte) (name, source string, ok bool) {
	for src, hf := range db.hashes {
		for i := range hf.Sets {
			for _, d := range digests {
				if len(d) != hf.Sets[i].Size {
					continue
				}
				if idx, hit := hf.Sets[i].lookup(d); hit {
					return hf.Names[idx], src, true
				}
			}
		}
	}
	return "", "", false
}

// LookupCert checks a certificate serial number or thumbprint (hex).
func (db *DB) LookupCert(id string) (string, bool) {
	n, ok := db.certs[NormalizeCertID(id)]
	return n, ok
}

func (db *DB) HasCerts() bool { return len(db.certs) > 0 }

type Stats struct {
	Revision     int `json:"revision"`
	Hashes       int `json:"hashes"`
	Rules        int `json:"rules"`
	RulesSkipped int `json:"rules_skipped"`
	Certs        int `json:"certs"`
	Sources      int `json:"sources"`
}

func (db *DB) Stats() Stats {
	st := Stats{Revision: db.Manifest.Revision, Rules: len(db.Rules.Rules),
		RulesSkipped: len(db.Rules.Skipped), Certs: len(db.certs), Sources: len(db.Manifest.Sources)}
	for _, hf := range db.hashes {
		for _, s := range hf.Sets {
			st.Hashes += len(s.NameIdx)
		}
	}
	return st
}

// ---- parsing ----

var sep = regexp.MustCompile(`[\s,;:|"']+`)

func isHex(s string) bool {
	if len(s) != 32 && len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// parseHashes accepts ClamAV .hdb/.hsb ("hash:size:name"), plain digest lists
// and CSV exports: the first MD5/SHA-1/SHA-256 on each line is the entry.
func parseHashes(r io.Reader, defaultName string, b *hashBuilder) (skipped int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || strings.HasPrefix(line, "//") {
			continue
		}
		name := defaultName
		if f := strings.Split(line, ":"); len(f) >= 3 && isHex(f[0]) && f[2] != "" {
			name = f[2] // ClamAV
		} else if f := strings.Split(line, `","`); len(f) >= 9 {
			if sig := strings.Trim(f[8], `" `); sig != "" && sig != "n/a" {
				name = "MalwareBazaar." + sig
			}
		}
		found := false
		for _, tok := range sep.Split(line, 12) {
			if isHex(tok) {
				d, _ := hex.DecodeString(tok)
				b.add(d, name)
				found = true
				break
			}
		}
		if !found {
			skipped++
		}
	}
	return skipped
}

// NormalizeCertID lower-cases and strips separators and leading zero bytes so
// serials print the same whatever tool produced them.
func NormalizeCertID(s string) string {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "", "0x", "").Replace(s))
	for len(s) > 2 && strings.HasPrefix(s, "00") {
		s = s[2:]
	}
	return s
}

func parseCerts(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		id, name, _ := strings.Cut(line, ",")
		id = NormalizeCertID(strings.Trim(id, `" `))
		if _, err := hex.DecodeString(id); err != nil || len(id) < 8 {
			continue
		}
		name = strings.Trim(name, `" `)
		if name == "" {
			name = "blocked certificate"
		}
		out[id] = name
	}
	return out
}

var nameRe = regexp.MustCompile(`[^a-z0-9._-]+`)

func cleanName(s string) string {
	s = nameRe.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.Trim(s, "-.")
	if s == "" {
		s = "source"
	}
	return s
}

func detectKind(path, hint string, head []byte) string {
	ext := strings.ToLower(filepath.Ext(hint))
	if ext == "" {
		ext = strings.ToLower(filepath.Ext(path))
	}
	switch ext {
	case ".yar", ".yara", ".rule", ".rules":
		return "yara"
	case ".certs":
		return "certs"
	case ".cvd", ".cld":
		return "cvd"
	}
	if bytes.HasPrefix(head, []byte("ClamAV-VDB:")) {
		return "cvd"
	}
	if bytes.Contains(head, []byte("condition:")) && bytes.Contains(head, []byte("rule ")) {
		return "yara"
	}
	return "hashes"
}

// Import adds (or replaces) a source from a local file. kind may be "auto".
// hint is the original file name when path is a temporary download.
func Import(path, name, kind, hint, channel string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return Source{}, err
	}
	defer f.Close()
	head := make([]byte, 64*1024)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Source{}, err
	}
	if hint == "" {
		hint = filepath.Base(path)
	}
	if kind == "" || kind == "auto" {
		kind = detectKind(path, hint, head)
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(hint), filepath.Ext(hint))
	}
	src := Source{Name: cleanName(name), Origin: hint, ImportedAt: time.Now(), Channel: channel}

	switch kind {
	case "yara":
		b, err := io.ReadAll(io.LimitReader(f, 64<<20))
		if err != nil {
			return src, err
		}
		set := rules.Parse(string(b), src.Name)
		if len(set.Rules) == 0 {
			reason := "no rules found"
			if len(set.Skipped) > 0 {
				reason = "no usable rules; first problem: " + set.Skipped[0]
			}
			return src, errors.New(reason)
		}
		src.Kind, src.Count, src.Skipped = "yara", len(set.Rules), len(set.Skipped)
		if err := config.WriteAtomic(dir("rules", src.Name+".yar"), b, 0o644); err != nil {
			return src, err
		}
	case "certs":
		b, err := io.ReadAll(io.LimitReader(f, 16<<20))
		if err != nil {
			return src, err
		}
		m := parseCerts(bytes.NewReader(b))
		if len(m) == 0 {
			return src, errors.New("no certificate serials or thumbprints found (expected: hex[,name] per line)")
		}
		src.Kind, src.Count = "certs", len(m)
		if err := config.WriteAtomic(dir("certs", src.Name+".txt"), b, 0o644); err != nil {
			return src, err
		}
	case "hashes", "cvd":
		hb := newHashBuilder()
		if kind == "cvd" {
			src.Skipped, err = parseCVD(f, src.Name, hb)
			if err != nil {
				return src, err
			}
		} else {
			src.Skipped = parseHashes(f, src.Name, hb)
		}
		if hb.count() == 0 {
			return src, errors.New("no MD5/SHA-1/SHA-256 hashes found")
		}
		hf := hb.build()
		for _, s := range hf.Sets {
			src.Count += len(s.NameIdx)
		}
		src.Kind = "hashes"
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(hf); err != nil {
			return src, err
		}
		if err := config.WriteAtomic(dir("hashes", src.Name+".vdb"), buf.Bytes(), 0o644); err != nil {
			return src, err
		}
	default:
		return src, fmt.Errorf("unknown definitions kind %q (use hashes, yara, certs or cvd)", kind)
	}

	m := LoadManifest()
	replaced := false
	for i := range m.Sources {
		if m.Sources[i].Name == src.Name {
			if m.Sources[i].Kind != src.Kind {
				removeFiles(m.Sources[i])
			}
			m.Sources[i] = src
			replaced = true
		}
	}
	if !replaced {
		m.Sources = append(m.Sources, src)
	}
	m.Revision++
	return src, saveManifest(m)
}

// parseCVD reads a ClamAV .cvd/.cld container and imports its hash
// databases. Body and logical signatures (.ndb/.ldb) need ClamAV's own
// matcher and are counted as skipped.
func parseCVD(f io.Reader, name string, hb *hashBuilder) (skipped int, err error) {
	br := bufio.NewReaderSize(f, 1<<20)
	header := make([]byte, 512)
	if _, err := io.ReadFull(br, header); err != nil || !bytes.HasPrefix(header, []byte("ClamAV-VDB:")) {
		return 0, errors.New("not a ClamAV CVD/CLD file")
	}
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return skipped, nil
		}
		if err != nil {
			return skipped, err
		}
		switch strings.ToLower(filepath.Ext(h.Name)) {
		case ".hdb", ".hsb", ".hdu", ".hsu":
			skipped += parseHashes(tr, name, hb)
		case ".ndb", ".ldb", ".mdb", ".msb", ".ndu", ".ldu", ".mdu", ".msu":
			sc := bufio.NewScanner(tr)
			sc.Buffer(make([]byte, 64*1024), 4<<20)
			for sc.Scan() {
				skipped++
			}
		}
	}
}

func removeFiles(s Source) {
	switch s.Kind {
	case "hashes":
		_ = os.Remove(dir("hashes", s.Name+".vdb"))
	case "yara":
		_ = os.Remove(dir("rules", s.Name+".yar"))
	case "certs":
		_ = os.Remove(dir("certs", s.Name+".txt"))
	}
}

func Remove(name string) error {
	m := LoadManifest()
	for i, s := range m.Sources {
		if s.Name == name {
			removeFiles(s)
			m.Sources = append(m.Sources[:i], m.Sources[i+1:]...)
			m.Revision++
			return saveManifest(m)
		}
	}
	return fmt.Errorf("no definitions source named %q", name)
}
