package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
)

// QItem describes one quarantined file.
type QItem struct {
	ID       string    `json:"id"`
	Original string    `json:"original"`
	SHA256   string    `json:"sha256"`
	Threat   string    `json:"threat"`
	Score    int       `json:"score"`
	Size     int64     `json:"size"`
	Time     time.Time `json:"time"`
	Findings []Finding `json:"findings,omitempty"`
}

const xorKey = 0xA5

func qdir() string { return filepath.Dir(config.Path("quarantine", "x")) }

func xor(b []byte) {
	for i := range b {
		b[i] ^= xorKey
	}
}

// Quarantine moves a file into the vault. The stored copy is XOR-encoded so
// it cannot be executed (and other scanners do not trip over it).
func Quarantine(path string, res *Result) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	id := hex.EncodeToString(rnd)
	item := QItem{ID: id, Original: path, SHA256: res.SHA256, Threat: res.Threat, Score: res.Score,
		Size: int64(len(data)), Time: time.Now(), Findings: res.Findings}
	xor(data)
	if err := os.WriteFile(filepath.Join(qdir(), id+".vq"), data, 0o600); err != nil {
		return "", err
	}
	meta, _ := json.MarshalIndent(item, "", "  ")
	if err := os.WriteFile(filepath.Join(qdir(), id+".json"), meta, 0o600); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		// The file is in use: keep the vault copy out of the list and say so.
		os.Remove(filepath.Join(qdir(), id+".vq"))
		os.Remove(filepath.Join(qdir(), id+".json"))
		return "", fmt.Errorf("could not remove the original (in use?): %w", err)
	}
	return id, nil
}

func QuarantineList() []QItem {
	var out []QItem
	metas, _ := filepath.Glob(filepath.Join(qdir(), "*.json"))
	for _, m := range metas {
		var it QItem
		if b, err := os.ReadFile(m); err == nil && json.Unmarshal(b, &it) == nil {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

func qfind(id string) (QItem, error) {
	if id == "" || strings.ContainsAny(id, `/\.`) {
		return QItem{}, errors.New("invalid quarantine id")
	}
	var it QItem
	b, err := os.ReadFile(filepath.Join(qdir(), id+".json"))
	if err != nil {
		return it, fmt.Errorf("no quarantined item %q", id)
	}
	return it, json.Unmarshal(b, &it)
}

// QuarantineRestore puts a file back (to dest, or its original location).
func QuarantineRestore(id, dest string) (QItem, error) {
	it, err := qfind(id)
	if err != nil {
		return it, err
	}
	data, err := os.ReadFile(filepath.Join(qdir(), id+".vq"))
	if err != nil {
		return it, err
	}
	xor(data)
	if dest == "" {
		dest = it.Original
	}
	if _, err := os.Stat(dest); err == nil {
		return it, fmt.Errorf("%s already exists", dest)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return it, err
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return it, err
	}
	it.Original = dest
	return it, QuarantineDelete(id)
}

func QuarantineDelete(id string) error {
	if _, err := qfind(id); err != nil {
		return err
	}
	os.Remove(filepath.Join(qdir(), id+".json"))
	return os.Remove(filepath.Join(qdir(), id+".vq"))
}
