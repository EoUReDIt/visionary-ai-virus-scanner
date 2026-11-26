// Package behavior learns what normal looks like on this machine and scores
// departures from it. It models three things:
//
//   - which programs run, and from where
//   - who starts whom (parent -> child edges)
//   - how fast files change in the user's folders
//
// During the learning window everything observed becomes the baseline. After
// it, a process start is scored by how unfamiliar it is; a few patterns that
// are abnormal on any machine (a document reader spawning a shell, a hidden
// encoded PowerShell) score from day one. An anomaly is not a conviction: it
// sends the executable through the scan engine with the anomaly attached as
// evidence, so signatures, Defender and the AI layer get the final say.
package behavior

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
)

type ExeProfile struct {
	Count    int            `json:"count"`
	First    time.Time      `json:"first"`
	Last     time.Time      `json:"last"`
	Parents  map[string]int `json:"parents,omitempty"`
	Children map[string]int `json:"children,omitempty"`
}

type RateModel struct {
	Mean float64 `json:"mean"`
	Var  float64 `json:"var"`
	N    int     `json:"n"`
}

type Baseline struct {
	Started  time.Time              `json:"started"`
	Events   int                    `json:"events"`
	Exes     map[string]*ExeProfile `json:"exes"`
	FileRate RateModel              `json:"file_rate"`
}

type Anomaly struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"` // process | file-burst
	Score   int       `json:"score"`
	PID     int       `json:"pid,omitempty"`
	Exe     string    `json:"exe,omitempty"`
	Parent  string    `json:"parent,omitempty"`
	Cmdline string    `json:"cmdline,omitempty"`
	Reasons []string  `json:"reasons"`
}

func baselinePath() string { return config.Path("behavior", "baseline.json") }

func Load() *Baseline {
	b := &Baseline{Started: time.Now(), Exes: map[string]*ExeProfile{}}
	if raw, err := os.ReadFile(baselinePath()); err == nil {
		_ = json.Unmarshal(raw, b)
	}
	if b.Exes == nil {
		b.Exes = map[string]*ExeProfile{}
	}
	return b
}

func Reset() error {
	err := os.Remove(baselinePath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

type Monitor struct {
	mu     sync.Mutex
	base   *Baseline
	known  map[int]string // pid -> exe key, to spot new processes
	primed bool
	dirty  bool
}

func NewMonitor() *Monitor {
	return &Monitor{base: Load(), known: map[int]string{}}
}

func (m *Monitor) Save() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dirty {
		return
	}
	if len(m.base.Exes) > 20000 {
		// Forget one-off executables first.
		for k, p := range m.base.Exes {
			if p.Count <= 1 {
				delete(m.base.Exes, k)
			}
		}
	}
	raw, _ := json.Marshal(m.base)
	if config.WriteAtomic(baselinePath(), raw, 0o644) == nil {
		m.dirty = false
	}
}

type Summary struct {
	Started     time.Time `json:"started"`
	Events      int       `json:"events"`
	Executables int       `json:"executables"`
	Edges       int       `json:"parent_child_edges"`
	FileRate    float64   `json:"typical_file_changes_per_10s"`
}

func (m *Monitor) Summary() Summary { return Summarize(m.base) }

func Summarize(b *Baseline) Summary {
	s := Summary{Started: b.Started, Events: b.Events, Executables: len(b.Exes),
		FileRate: math.Round(b.FileRate.Mean*10) / 10}
	for _, p := range b.Exes {
		s.Edges += len(p.Parents)
	}
	return s
}

var userDir = regexp.MustCompile(`^(c:\\users\\|/home/)[^\\/]+`)

// exeKey normalises a path so the baseline is not tied to one user name.
func exeKey(path string) string {
	k := strings.ToLower(path)
	return userDir.ReplaceAllString(k, "${1}*")
}

func baseName(path string) string {
	n := strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/")))
	return strings.TrimSuffix(n, ".exe")
}

// Programs that open untrusted content. A shell under one of these is the
// classic shape of an exploit or a malicious attachment.
var contentApps = map[string]bool{"winword": true, "excel": true, "powerpnt": true, "outlook": true,
	"onenote": true, "acrord32": true, "acrobat": true, "chrome": true, "msedge": true, "firefox": true,
	"brave": true, "opera": true, "discord": true, "teams": true, "ms-teams": true, "slack": true,
	"telegram": true, "whatsapp": true, "vlc": true, "notepad": true, "winrar": true, "7zfm": true}

type cmdIndicator struct {
	re    *regexp.Regexp
	score int
	why   string
}

func riskyLocation(key string) (int, string) {
	k := strings.ReplaceAll(key, `\`, "/")
	switch {
	case strings.Contains(k, "/appdata/local/temp/"), strings.Contains(k, "/windows/temp/"), strings.HasPrefix(k, "/tmp/"),
		strings.HasPrefix(k, "/dev/shm/"):
		return 25, "runs from a temp folder"
	case strings.Contains(k, "/downloads/"):
		return 20, "runs from Downloads"
	case strings.Contains(k, "/users/public/"), strings.Contains(k, "/programdata/") && strings.Count(k, "/") <= 3:
		return 20, "runs from a world-writable folder"
	case strings.Contains(k, "/appdata/roaming/"):
		return 10, "runs from roaming app data"
	}
	return 0, ""
}

// Observe scores one process start against the baseline and then folds it
// in. While learning, only the universal rules can raise an anomaly.
func (m *Monitor) Observe(p plat.Proc, parent *plat.Proc, learning bool, threshold int) *Anomaly {
	if p.Exe == "" && p.Name == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exe := p.Exe
	if exe == "" {
		exe = p.Name
	}
	key, name := exeKey(exe), baseName(exe)
	parentName := ""
	if parent != nil {
		if parent.Exe != "" {
			parentName = baseName(parent.Exe)
		} else {
			parentName = baseName(parent.Name)
		}
	}
	prof := m.base.Exes[key]

	score := 0
	var reasons []string
	add := func(s int, why string) {
		if s > 0 {
			score += s
			reasons = append(reasons, why)
		}
	}
	// Universal rules.
	if contentApps[parentName] && shells[name] {
		add(45, fmt.Sprintf("%s started %s", parentName, name))
	}
	for _, ind := range cmdIndicators {
		if ind.re.MatchString(p.Cmdline) {
			add(ind.score, ind.why)
		}
	}
	// Learned rules.
	if !learning {
		if prof == nil {
			add(25, "program has never run on this computer")
			add(riskyLocation(key))
		} else if prof.Count < 3 {
			add(10, "program has rarely run before")
		}
		if prof != nil && parentName != "" && prof.Parents[parentName] == 0 {
			add(20, fmt.Sprintf("never started by %s before", parentName))
		}
		if parentName != "" && shells[name] {
			if pp := m.base.Exes[exeKey(parentExe(parent))]; pp != nil && pp.Count >= 5 && pp.Children[name] == 0 {
				add(20, fmt.Sprintf("%s has never launched %s", parentName, name))
			}
		}
	} else if prof == nil {
		// Still flag the obvious while learning, without needing history.
		if s, why := riskyLocation(key); s >= 20 && (contentApps[parentName] || len(reasons) > 0) {
			add(s, why)
		}
	}
	if score > 100 {
		score = 100
	}

	var an *Anomaly
	if score >= threshold {
		an = &Anomaly{Time: time.Now(), Kind: "process", Score: score, PID: p.PID, Exe: exe,
			Parent: parentName, Cmdline: truncate(p.Cmdline, 400), Reasons: reasons}
	}
	// Anomalous starts are not learned, so repeating an attack does not
	// teach the baseline that it is normal.
	if an == nil {
		now := time.Now()
		if prof == nil {
			prof = &ExeProfile{First: now, Parents: map[string]int{}, Children: map[string]int{}}
			m.base.Exes[key] = prof
		}
		prof.Count++
		prof.Last = now
		if parentName != "" {
			if prof.Parents == nil {
				prof.Parents = map[string]int{}
			}
			prof.Parents[parentName]++
			if pp := m.base.Exes[exeKey(parentExe(parent))]; pp != nil {
				if pp.Children == nil {
					pp.Children = map[string]int{}
				}
				pp.Children[name]++
			}
		}
		m.base.Events++
		m.dirty = true
	}
	return an
}

func parentExe(p *plat.Proc) string {
	if p == nil {
		return ""
	}
	if p.Exe != "" {
		return p.Exe
	}
	return p.Name
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Poll lists processes and returns anomalies for the ones that appeared
// since the previous call. The first call only primes the process table.
func (m *Monitor) Poll(learning bool, threshold int) (anomalies []Anomaly, started []plat.Proc) {
	procs, err := plat.ListProcesses()
	if err != nil {
		return nil, nil
	}
	byPID := make(map[int]*plat.Proc, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = &procs[i]
	}
	m.mu.Lock()
	primed := m.primed
	m.primed = true
	old := m.known
	m.known = make(map[int]string, len(procs))
	for _, p := range procs {
		m.known[p.PID] = p.Exe
	}
	m.mu.Unlock()
	for i := range procs {
		p := procs[i]
		if prev, seen := old[p.PID]; seen && prev == p.Exe {
			continue
		}
		if !primed {
			// Whatever is already running when the guard starts is recorded
			// as baseline, not judged.
			m.Observe(p, byPID[p.PPID], true, 1000)
			continue
		}
		started = append(started, p)
		if an := m.Observe(p, byPID[p.PPID], learning, threshold); an != nil {
			anomalies = append(anomalies, *an)
		}
	}
	return anomalies, started
}

// ObserveFileRate feeds one 10-second count of file changes in the user's
// folders. A burst far outside the learned rate is how mass encryption or
// mass deletion looks from the outside.
func (m *Monitor) ObserveFileRate(count int, learning bool) *Anomaly {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := &m.base.FileRate
	x := float64(count)
	sd := math.Sqrt(r.Var)
	limit := math.Max(r.Mean+6*sd, 150)
	if !learning && r.N >= 30 && x > limit {
		return &Anomaly{Time: time.Now(), Kind: "file-burst", Score: 60, Reasons: []string{
			fmt.Sprintf("%d files changed in 10 seconds (typical: %.0f)", count, r.Mean),
			"possible mass encryption, deletion or a runaway script"}}
	}
	// Exponentially weighted mean and variance.
	const alpha = 0.05
	if r.N == 0 {
		r.Mean = x
	} else {
		d := x - r.Mean
		r.Mean += alpha * d
		r.Var = (1 - alpha) * (r.Var + alpha*d*d)
	}
	r.N++
	m.dirty = true
	return nil
}
