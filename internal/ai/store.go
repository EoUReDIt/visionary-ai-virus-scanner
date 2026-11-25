package ai

import (
	"crypto/sha256"
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
)

// StoredModel is a GGUF file in Visionary's model store (either downloaded
// from Hugging Face or brought by the user).
type StoredModel struct {
	Name    string  `json:"name"`
	Path    string  `json:"path"`
	SizeMB  int     `json:"size_mb"`
	ParamsB float64 `json:"params_b"`
	Source  string  `json:"source"` // huggingface:<repo>/<file> | imported
	SHA256  string  `json:"sha256,omitempty"`
	Quant   string  `json:"quant,omitempty"`
}

var storeNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,250}\.gguf$`)

func metaPath(gguf string) string { return strings.TrimSuffix(gguf, ".gguf") + ".meta.json" }

func writeMeta(m StoredModel) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(metaPath(m.Path), b, 0o644)
}

// ListStore returns the models in dir. Metadata written at download or import
// time is trusted only for provenance; size is read from the file itself.
func ListStore(dir string) ([]StoredModel, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []StoredModel
	for _, e := range ents {
		if e.IsDir() || !storeNameRe.MatchString(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		m := StoredModel{Name: e.Name(), Path: p, Source: "unknown"}
		if st, err := os.Stat(p); err == nil {
			m.SizeMB = int(st.Size() >> 20)
		}
		if b, err := os.ReadFile(metaPath(p)); err == nil {
			var meta StoredModel
			if json.Unmarshal(b, &meta) == nil {
				m.Source, m.SHA256, m.Quant, m.ParamsB = meta.Source, meta.SHA256, meta.Quant, meta.ParamsB
			}
		}
		if m.ParamsB == 0 {
			if n, err := GGUFParams(p); err == nil {
				m.ParamsB = float64(n) / 1e9
				_ = writeMeta(m)
			}
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ImportGGUF brings a user's own GGUF into the store (a copy, so the original
// can move). The file must be a real GGUF and under the parameter ceiling.
func ImportGGUF(src, dir string, maxB float64) (StoredModel, error) {
	st, err := os.Stat(src)
	if err != nil {
		return StoredModel{}, err
	}
	if st.IsDir() {
		return StoredModel{}, errors.New("expected a .gguf file, not a folder")
	}
	n, err := GGUFParams(src)
	if err != nil {
		return StoredModel{}, fmt.Errorf("%s is not a usable GGUF file: %w", filepath.Base(src), err)
	}
	if err := CheckParams(float64(n)/1e9, maxB, filepath.Base(src)); err != nil {
		return StoredModel{}, err
	}
	name := sanitizeName(filepath.Base(src))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return StoredModel{}, err
	}
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		return StoredModel{}, fmt.Errorf("%s is already in the store (remove it first)", name)
	}
	in, err := os.Open(src)
	if err != nil {
		return StoredModel{}, err
	}
	defer in.Close()
	tmp := dst + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return StoredModel{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return StoredModel{}, err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return StoredModel{}, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return StoredModel{}, err
	}
	m := StoredModel{Name: name, Path: dst, SizeMB: int(st.Size() >> 20), ParamsB: float64(n) / 1e9,
		Source: "imported", SHA256: hex.EncodeToString(h.Sum(nil))}
	return m, writeMeta(m)
}

func sanitizeName(base string) string {
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == '+':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := strings.TrimLeft(b.String(), "._-+")
	if !strings.HasSuffix(strings.ToLower(s), ".gguf") {
		s += ".gguf"
	}
	if s == ".gguf" {
		s = "model.gguf"
	}
	return s
}

// FindStored resolves a model name (or unambiguous prefix) in the store.
func FindStored(dir, name string) (StoredModel, error) {
	models, err := ListStore(dir)
	if err != nil {
		return StoredModel{}, err
	}
	var hits []StoredModel
	for _, m := range models {
		if m.Name == name || m.Name == name+".gguf" {
			return m, nil
		}
		if strings.HasPrefix(m.Name, name) {
			hits = append(hits, m)
		}
	}
	if len(hits) == 1 {
		return hits[0], nil
	}
	if len(hits) > 1 {
		return StoredModel{}, fmt.Errorf("%q matches %d models; use the full name", name, len(hits))
	}
	return StoredModel{}, fmt.Errorf("no model %q in the store (visionary ai local models)", name)
}

// RemoveStored deletes a model and its metadata.
func RemoveStored(dir, name string) error {
	m, err := FindStored(dir, name)
	if err != nil {
		return err
	}
	if filepath.Dir(m.Path) != filepath.Clean(dir) {
		return errors.New("refusing to delete outside the model store")
	}
	_ = os.Remove(metaPath(m.Path))
	return os.Remove(m.Path)
}
