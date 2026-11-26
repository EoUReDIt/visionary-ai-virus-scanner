// Package engine is the detection pipeline. Every front end (CLI, real-time
// guard, dashboard) calls the same ScanFile, so the layers always cooperate
// in the same order:
//
//	allowlist -> cache -> hash definitions -> pattern rules -> static
//	heuristics -> signature/certificate -> [gray zone only] Microsoft
//	Defender second opinion -> reputation -> local AI -> cloud AI -> action
//
// Cheap, certain layers run first; the expensive ones only see what the cheap
// ones could not settle.
package engine

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
)

const (
	Clean      = "clean"
	Suspicious = "suspicious"
	Malicious  = "malicious"
	Skipped    = "skipped"
	Failed     = "error"

	MaliciousAt  = 80
	SuspiciousAt = 40
	heuristicCap = 75
	cacheVersion = 1
)

type Finding struct {
	Layer  string `json:"layer"`
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Detail string `json:"detail,omitempty"`
}

// AIVerdict is what an AI provider concluded from a Report.
type AIVerdict struct {
	Verdict           string   `json:"verdict"` // malicious | suspicious | benign | unknown
	Confidence        float64  `json:"confidence"`
	Category          string   `json:"category,omitempty"`           // trojan | ransomware | infostealer | dropper | lolbin | pup | dual-use-tool | benign | unknown
	RecommendedAction string   `json:"recommended_action,omitempty"` // quarantine | review | monitor | allow
	Summary           string   `json:"summary,omitempty"`
	Reasons           []string `json:"reasons"`
	Provider          string   `json:"provider"`
	Model             string   `json:"model"`
	Cached            bool     `json:"cached,omitempty"`
}

// ProcessContext captures runtime lineage when a scan is triggered by a
// process start or behavioural anomaly (critical for LOLBin / fileless triage).
type ProcessContext struct {
	PID     int    `json:"pid,omitempty"`
	Parent  string `json:"parent,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

// AIStats tracks live AI triage outcomes during this session.
type AIStats struct {
	Triaged   int64 `json:"triaged"`
	Convicted int64 `json:"convicted"`
	Cleared   int64 `json:"cleared"`
	CacheHits int64 `json:"cache_hits"`
	Errors    int64 `json:"errors"`
}

type Result struct {
	Path       string     `json:"path"`
	Size       int64      `json:"size"`
	SHA256     string     `json:"sha256,omitempty"`
	MD5        string     `json:"md5,omitempty"`
	SHA1       string     `json:"sha1,omitempty"`
	Verdict    string     `json:"verdict"`
	Score      int        `json:"score"`
	Threat     string     `json:"threat,omitempty"`
	Findings   []Finding  `json:"findings,omitempty"`
	Features   Features   `json:"features"`
	AI         *AIVerdict `json:"ai,omitempty"`
	Trusted    bool       `json:"signature_trusted,omitempty"`
	Action     string     `json:"action,omitempty"`
	Error      string     `json:"error,omitempty"`
	Cached     bool       `json:"cached,omitempty"`
	DurationMs int64      `json:"duration_ms"`
	heurFactor float64
	scoreCap   int
}

func (r *Result) add(f Finding) {
	for _, old := range r.Findings {
		if old.Layer == f.Layer && old.Name == f.Name && old.Detail == f.Detail {
			return
		}
	}
	r.Findings = append(r.Findings, f)
}

// compute turns findings into a score. Hash, certificate, rule, Defender and
// reputation hits are "hard" evidence and stand on their own. Heuristics add
// up but are capped below the conviction threshold: a guess never carries
// the weight of a known sample, it only earns a closer look.
func (r *Result) compute() {
	hard, heur, beh := 0, 0, 0
	threat := ""
	for _, f := range r.Findings {
		switch f.Layer {
		case "heuristic", "archive":
			heur += f.Score
		case "behavior":
			beh += f.Score
		default:
			if f.Score > hard {
				hard, threat = f.Score, f.Name
			}
		}
	}
	if heur > heuristicCap {
		heur = heuristicCap
	}
	// A trusted Authenticode signature discounts static heuristics (e.g. packed
	// dev/game tools), but NEVER discounts live behavioural anomalies — that way
	// fileless LOLBin abuse of signed Windows tools (powershell, mshta, cmd)
	// still reaches the gray zone and AI triage.
	if r.Trusted {
		heur = heur * 3 / 10
	}
	if r.heurFactor > 0 {
		heur = int(float64(heur) * r.heurFactor)
	}
	soft := heur + beh
	if soft > heuristicCap {
		soft = heuristicCap
	}
	score := max(hard, soft)
	if hard > 0 && soft > 0 {
		score = min(100, hard+soft/4)
		// Heuristics can strengthen a conviction but not create one: a rule
		// its author scored as "suspicious" stays in the gray zone.
		if hard < MaliciousAt && score >= MaliciousAt {
			score = MaliciousAt - 1
		}
	}
	if r.scoreCap > 0 && hard < MaliciousAt && score > r.scoreCap {
		score = r.scoreCap
	}
	r.Score = score
	switch {
	case score >= MaliciousAt:
		r.Verdict = Malicious
	case score >= SuspiciousAt:
		r.Verdict = Suspicious
	default:
		r.Verdict = Clean
	}
	if threat == "" && r.Verdict != Clean {
		best := Finding{}
		for _, f := range r.Findings {
			if f.Score > best.Score {
				best = f
			}
		}
		threat = "Heuristic." + best.Name
	}
	if r.Verdict == Clean {
		threat = ""
	}
	r.Threat = threat
}

// Report is the evidence handed to the AI layer.
type Report struct {
	FileName string          `json:"file_name"`
	Location string          `json:"location"`
	Size     int64           `json:"size"`
	SHA256   string          `json:"sha256"`
	Score    int             `json:"engine_score"`
	Findings []Finding       `json:"engine_findings"`
	Features Features        `json:"features"`
	Process  *ProcessContext `json:"process_context,omitempty"`
}

// SecondOpinion is Microsoft Defender as seen by the engine.
type SecondOpinion interface {
	ScanFile(path string) (threat string, found bool, err error)
	ScanBuffer(data []byte, name string) (found bool, err error)
	VerifyTrust(path string) (trusted bool, err error)
}

// Reputation is a hash-only cloud lookup.
type Reputation interface {
	Lookup(ctx context.Context, sha256 string) (malicious, total int, label string, found bool, err error)
}

type Engine struct {
	Cfg      *config.Config
	DB       *defs.DB
	Defender SecondOpinion
	Rep      Reputation
	AI       func(ctx context.Context, rep *Report) (*AIVerdict, error)
	GameMode func() bool

	cacheMu   sync.Mutex
	cache     map[string]cacheEntry
	dirty     bool
	aiCacheMu sync.Mutex
	aiCache   map[string]*AIVerdict
	aiUsed    atomic.Int32
	aiTriaged atomic.Int64
	aiConvict atomic.Int64
	aiCleared atomic.Int64
	aiHits    atomic.Int64
	aiErrors  atomic.Int64
	selfExe   string
}

type cacheEntry struct {
	Size int64
	Mod  int64
	Rev  int
}

type Options struct {
	Escalate   bool // let gray-zone files reach Defender / reputation / AI
	Quarantine bool // move malicious files to quarantine
	NoCache    bool
	Describe   bool            // collect descriptive features even for clean files
	Context    []Finding       // extra evidence (e.g. behaviour anomalies) for this file
	Process    *ProcessContext // optional live process context for LOLBin triage
}

func New(cfg *config.Config, db *defs.DB) *Engine {
	e := &Engine{Cfg: cfg, DB: db, cache: map[string]cacheEntry{}, aiCache: map[string]*AIVerdict{}}
	e.selfExe, _ = os.Executable()
	if cfg.Scan.UseCache {
		if f, err := os.Open(cachePath()); err == nil {
			var c struct {
				Version int
				Entries map[string]cacheEntry
			}
			if gob.NewDecoder(f).Decode(&c) == nil && c.Version == cacheVersion && c.Entries != nil {
				e.cache = c.Entries
			}
			f.Close()
		}
	}
	return e
}

func cachePath() string { return config.Path("cache", "scan.gob") }

// ClearCache removes the persisted scan cache.
func ClearCache() error {
	err := os.Remove(cachePath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Flush persists the clean-file cache.
func (e *Engine) Flush() {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if !e.dirty || !e.Cfg.Scan.UseCache {
		return
	}
	if len(e.cache) > 500000 {
		e.cache = map[string]cacheEntry{}
	}
	f, err := os.Create(cachePath() + ".tmp")
	if err != nil {
		return
	}
	err = gob.NewEncoder(f).Encode(struct {
		Version int
		Entries map[string]cacheEntry
	}{cacheVersion, e.cache})
	f.Close()
	if err == nil {
		_ = os.Rename(cachePath()+".tmp", cachePath())
		e.dirty = false
	}
}

// ResetBudget starts a new AI budget (call once per scan job).
func (e *Engine) ResetBudget() { e.aiUsed.Store(0) }

// AIStats returns a snapshot of session AI triage counts.
func (e *Engine) AIStats() AIStats {
	return AIStats{
		Triaged:   e.aiTriaged.Load(),
		Convicted: e.aiConvict.Load(),
		Cleared:   e.aiCleared.Load(),
		CacheHits: e.aiHits.Load(),
		Errors:    e.aiErrors.Load(),
	}
}

func (e *Engine) maxBytes() int64 {
	mb := e.Cfg.Scan.MaxFileSizeMB
	if mb <= 0 {
		mb = 64
	}
	return int64(mb) << 20
}

func pathKey(p string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}

func (e *Engine) allowed(path, sha string) bool {
	for _, h := range e.Cfg.Allow.Hashes {
		if sha != "" && strings.EqualFold(h, sha) {
			return true
		}
	}
	if sha == "" {
		for _, p := range e.Cfg.Allow.Paths {
			if p != "" && strings.HasPrefix(pathKey(path), pathKey(p)) {
				return true
			}
		}
	}
	return false
}

// ownFile is true for the scanner's own data (definitions, quarantine) and
// executable, which by nature contain the patterns the rules look for.
func (e *Engine) ownFile(path string) bool {
	k := pathKey(path)
	return strings.HasPrefix(k, pathKey(config.Dir())+string(filepath.Separator)) || k == pathKey(e.selfExe)
}

// ScanFile runs the full pipeline on one file.
func (e *Engine) ScanFile(ctx context.Context, path string, opt Options) *Result {
	start := time.Now()
	res := &Result{Path: path, Verdict: Clean}
	defer func() { res.DurationMs = time.Since(start).Milliseconds() }()

	st, err := os.Lstat(path)
	if err != nil {
		res.Verdict, res.Error = Failed, err.Error()
		return res
	}
	if !st.Mode().IsRegular() || e.ownFile(path) || e.allowed(path, "") {
		res.Verdict = Skipped
		return res
	}
	res.Size = st.Size()
	if res.Size == 0 {
		return res
	}
	rev := e.DB.Manifest.Revision
	key := pathKey(path)
	if e.Cfg.Scan.UseCache && !opt.NoCache && len(opt.Context) == 0 {
		e.cacheMu.Lock()
		c, ok := e.cache[key]
		e.cacheMu.Unlock()
		if ok && c.Size == res.Size && c.Mod == st.ModTime().UnixNano() && c.Rev == rev {
			res.Cached = true
			return res
		}
	}

	f, err := os.Open(path)
	if err != nil {
		res.Verdict, res.Error = Failed, err.Error()
		return res
	}
	hm, h1, h2 := md5.New(), sha1.New(), sha256.New()
	hashes := io.MultiWriter(hm, h1, h2)
	limit := e.maxBytes()
	data, err := io.ReadAll(io.TeeReader(io.LimitReader(f, limit), hashes))
	if err == nil && res.Size > limit {
		// Large files are still hashed in full; content layers see the head.
		_, err = io.Copy(hashes, f)
		res.add(Finding{"archive", "partial-content-scan", 0,
			fmt.Sprintf("only the first %d MB were content-scanned", limit>>20)})
	}
	f.Close()
	if err != nil {
		res.Verdict, res.Error = Failed, err.Error()
		return res
	}
	sum := func(h hash.Hash) []byte { return h.Sum(nil) }
	dm, d1, d2 := sum(hm), sum(h1), sum(h2)
	res.MD5, res.SHA1, res.SHA256 = hex.EncodeToString(dm), hex.EncodeToString(d1), hex.EncodeToString(d2)

	if e.allowed(path, res.SHA256) {
		res.Verdict, res.Action = Skipped, "allowlisted"
		return res
	}
	if name, src, ok := e.DB.LookupHash(dm, d1, d2); ok {
		res.add(Finding{"hash", name, 100, "known sample (definitions: " + src + ")"})
	}

	e.analyze(data, filepath.Base(path), res, 0, true)
	for _, c := range opt.Context {
		res.add(c)
	}

	// Signature layer: blocklisted certificates convict, a chain Windows
	// trusts discounts heuristics (it never excuses a hash or rule hit).
	for _, s := range res.Features.Signers {
		for _, id := range []string{s.Serial, s.Thumbprint, s.SHA256} {
			if name, ok := e.DB.LookupCert(id); ok {
				res.add(Finding{"cert", "BlockedCertificate", 90,
					fmt.Sprintf("signed with a blocklisted certificate (%s) — %s", s.Subject, name)})
			}
		}
	}
	res.compute()
	// String extraction is the slowest step and only matters as evidence
	// for a person or a model, so it runs only when there is something to
	// explain.
	if res.Score > 0 || opt.Describe {
		res.Features.Strings = interestingStrings(data, 40)
	}
	if res.Score > 0 && res.Features.PE != nil && res.Features.PE.HasSignature && e.Defender != nil {
		if ok, err := e.Defender.VerifyTrust(path); err == nil && ok {
			res.Trusted = true
			res.compute()
		}
	}

	shouldEscalate := res.Verdict == Suspicious
	if !shouldEscalate && e.Cfg.AI.Sensitivity == "proactive" && !res.Trusted && res.Score >= 25 && isRiskyLocation(locationClass(path)) {
		shouldEscalate = true
	}
	if opt.Escalate && shouldEscalate && ctx.Err() == nil {
		e.escalate(ctx, path, data, res, opt.Process, opt.NoCache)
	}

	switch res.Verdict {
	case Clean:
		if e.Cfg.Scan.UseCache && len(opt.Context) == 0 {
			e.cacheMu.Lock()
			e.cache[key] = cacheEntry{res.Size, st.ModTime().UnixNano(), rev}
			e.dirty = true
			e.cacheMu.Unlock()
		}
	case Malicious:
		if opt.Quarantine {
			if protectedPath(path) {
				res.Action = "not quarantined: operating-system path, review manually"
			} else if id, err := Quarantine(path, res); err != nil {
				res.Action = "quarantine failed: " + err.Error()
			} else {
				res.Action = "quarantined as " + id
			}
		}
	}
	return res
}

// analyze runs the content layers on a buffer (a file or an archive member).
func (e *Engine) analyze(data []byte, name string, res *Result, depth int, top bool) {
	typ := detectType(data, name)
	if top {
		res.Features.Type = typ
		res.Features.Entropy = entropy(data)
	}
	for _, m := range e.DB.Rules.Scan(data) {
		detail := m.Description
		if m.Source != "builtin" {
			detail = strings.TrimSpace(detail + " [" + m.Source + "]")
		}
		res.add(Finding{"rule", m.Rule, m.Score, detail})
	}
	for _, f := range nameHeuristics(name, typ) {
		res.add(f)
	}
	switch typ {
	case "pe":
		info, fs := analyzePE(data)
		for _, f := range fs {
			res.add(f)
		}
		if top {
			res.Features.PE = info
			res.Features.Signers = signers(data)
		}
	case "script", "text", "lnk":
		if len(data) <= 8<<20 {
			for _, f := range analyzeScript(data) {
				res.add(f)
			}
		}
		if top {
			text := decodeText(data)
			if len(text) > 3000 {
				text = text[:3000]
			}
			res.Features.Snippet = text
		}
	case "zip":
		if e.Cfg.Scan.ScanArchives && depth < zipMaxDepth {
			e.scanZip(data, depth, res)
		}
	}
}

// escalate asks the slower layers about a gray-zone file, stopping as soon
// as one of them settles it.
func (e *Engine) escalate(ctx context.Context, path string, data []byte, res *Result, proc *ProcessContext, noCache bool) {
	gaming := e.GameMode != nil && e.GameMode()

	if e.Defender != nil && e.Cfg.Windows.DefenderSecondOpinion {
		found, name := false, ""
		if t := res.Features.Type; (t == "script" || t == "text") && len(data) < 4<<20 {
			found, _ = e.Defender.ScanBuffer(data, filepath.Base(path))
			name = "AMSI"
		}
		if !found && !gaming {
			name, found, _ = e.Defender.ScanFile(path)
		}
		if found {
			res.add(Finding{"defender", "Defender:" + name, 95, "Microsoft Defender also flags this file"})
			res.compute()
			return
		}
	}

	if e.Rep != nil && e.Cfg.Reputation.VirusTotal && !gaming {
		if mal, total, label, found, err := e.Rep.Lookup(ctx, res.SHA256); err == nil && found {
			switch {
			case mal >= 5:
				if label == "" {
					label = "Reputation.Malicious"
				}
				res.add(Finding{"reputation", label, 90, fmt.Sprintf("%d of %d engines on VirusTotal flag this hash", mal, total)})
			case mal > 0:
				res.add(Finding{"heuristic", "reputation:low-detections", 20,
					fmt.Sprintf("%d of %d engines on VirusTotal flag this hash", mal, total)})
			case total >= 40:
				res.heurFactor = 0.5
				res.add(Finding{"reputation", "known-clean", 0, fmt.Sprintf("0 of %d engines on VirusTotal flag this hash", total)})
			}
			res.compute()
			if res.Verdict != Suspicious {
				return
			}
		}
	}

	if e.AI == nil || gaming {
		return
	}

	// Check the in-memory SHA-256 AI verdict cache when there is no unique
	// runtime command-line context attached and caching is allowed.
	cacheKey := res.SHA256
	if noCache || (proc != nil && (proc.Cmdline != "" || proc.Parent != "")) {
		cacheKey = ""
	}
	var v *AIVerdict
	if cacheKey != "" {
		e.aiCacheMu.Lock()
		if cached, ok := e.aiCache[cacheKey]; ok {
			cp := *cached
			cp.Cached = true
			v = &cp
		}
		e.aiCacheMu.Unlock()
	}
	if v != nil {
		e.aiHits.Add(1)
	} else {
		budget := e.Cfg.Scan.AIBudget
		if budget <= 0 {
			budget = 20
		}
		if int(e.aiUsed.Add(1)) > budget {
			res.add(Finding{"ai", "ai-budget-exhausted", 0, "AI review skipped: per-scan budget reached"})
			return
		}
		rep := e.BuildReport(path, res)
		rep.Process = proc
		var err error
		v, err = e.AI(ctx, rep)
		if err != nil {
			e.aiErrors.Add(1)
			res.add(Finding{"ai", "ai-unavailable", 0, err.Error()})
			return
		}
		e.aiTriaged.Add(1)
		if cacheKey != "" {
			e.aiCacheMu.Lock()
			if e.aiCache == nil || len(e.aiCache) > 2048 {
				e.aiCache = map[string]*AIVerdict{}
			}
			cp := *v
			e.aiCache[cacheKey] = &cp
			e.aiCacheMu.Unlock()
		}
	}

	res.AI = v
	thr := e.Cfg.AI.ConfidenceThreshold
	if thr < 0.5 || thr > 0.99 {
		thr = 0.80
	}
	why := strings.Join(v.Reasons, "; ")
	if why == "" && v.Summary != "" {
		why = v.Summary
	}
	switch {
	case v.Verdict == "malicious" && v.Confidence >= thr:
		e.aiConvict.Add(1)
		name := "AI.Malicious"
		if v.Category != "" && v.Category != "unknown" && v.Category != "benign" {
			name = "AI." + strings.ToUpper(v.Category[:1]) + v.Category[1:]
		}
		res.add(Finding{"ai", name, MaliciousAt, fmt.Sprintf("%s (%s, confidence %.0f%%)", why, v.Model, v.Confidence*100)})
	case v.Verdict == "benign" && v.Confidence >= thr:
		// The model may clear a heuristic guess, never hard evidence.
		e.aiCleared.Add(1)
		res.scoreCap = SuspiciousAt - 5
		res.add(Finding{"ai", "ai-cleared", 0, fmt.Sprintf("%s (%s, confidence %.0f%%)", why, v.Model, v.Confidence*100)})
	default:
		res.add(Finding{"ai", "ai-inconclusive", 0, fmt.Sprintf("%s: %s (%s, confidence %.0f%%)", v.Verdict, why, v.Model, v.Confidence*100)})
	}
	res.compute()
}

func isRiskyLocation(loc string) bool {
	switch loc {
	case "downloads folder", "temp folder", "startup folder", "desktop":
		return true
	}
	return false
}

func (e *Engine) BuildReport(path string, res *Result) *Report {
	return &Report{FileName: filepath.Base(path), Location: locationClass(path), Size: res.Size,
		SHA256: res.SHA256, Score: res.Score, Findings: res.Findings, Features: res.Features}
}

// locationClass describes where a file lives without leaking the user name.
func locationClass(path string) string {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, c := range []struct{ needle, class string }{
		{"/downloads/", "downloads folder"}, {"/appdata/local/temp/", "temp folder"}, {"/temp/", "temp folder"},
		{"/tmp/", "temp folder"}, {"/startup/", "startup folder"}, {"/desktop/", "desktop"},
		{"/node_modules/", "npm dependency"}, {"/site-packages/", "python dependency"},
		{"/steamapps/", "steam library"}, {"/windows/system32/", "system directory"},
		{"/program files", "program files"}, {"/appdata/roaming/", "roaming app data"},
	} {
		if strings.Contains(p, c.needle) {
			return c.class
		}
	}
	return "other"
}

func protectedPath(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	if root := strings.ToLower(filepath.ToSlash(os.Getenv("SystemRoot"))); root != "" && strings.HasPrefix(p, root+"/") {
		return true
	}
	for _, pre := range []string{"/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/boot/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Summary is the outcome of a multi-file scan.
type Summary struct {
	Files       int       `json:"files"`
	Clean       int       `json:"clean"`
	Suspicious  int       `json:"suspicious"`
	Malicious   int       `json:"malicious"`
	Errors      int       `json:"errors"`
	Skipped     int       `json:"skipped"`
	Cached      int       `json:"cached"`
	Quarantined int       `json:"quarantined"`
	Bytes       int64     `json:"bytes"`
	Seconds     float64   `json:"seconds"`
	Cancelled   bool      `json:"cancelled,omitempty"`
	Detections  []*Result `json:"detections"`
}

// ExitCode follows the convention CI tools expect: 0 clean, 1 malicious,
// 2 suspicious, 3 errors only.
func (s *Summary) ExitCode() int {
	switch {
	case s.Malicious > 0:
		return 1
	case s.Suspicious > 0:
		return 2
	case s.Errors > 0 && s.Files == s.Errors:
		return 3
	}
	return 0
}

// ScanPaths walks files and directories with a worker pool. progress is
// called once per file, serialised.
func (e *Engine) ScanPaths(ctx context.Context, paths []string, opt Options, progress func(*Result)) *Summary {
	start := time.Now()
	e.ResetBudget()
	sum := &Summary{Detections: []*Result{}}
	workers := e.Cfg.Scan.Workers
	if workers <= 0 {
		workers = max(1, runtime.NumCPU()/2)
	}
	if e.GameMode != nil && e.GameMode() {
		workers = 1
	}
	files := make(chan string, 256)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range files {
				r := e.ScanFile(ctx, p, opt)
				mu.Lock()
				sum.Files++
				sum.Bytes += r.Size
				switch r.Verdict {
				case Clean:
					sum.Clean++
				case Suspicious:
					sum.Suspicious++
					sum.Detections = append(sum.Detections, r)
				case Malicious:
					sum.Malicious++
					sum.Detections = append(sum.Detections, r)
					if strings.HasPrefix(r.Action, "quarantined") {
						sum.Quarantined++
					}
				case Skipped:
					sum.Skipped++
				case Failed:
					sum.Errors++
				}
				if r.Cached {
					sum.Cached++
				}
				if progress != nil {
					progress(r)
				}
				mu.Unlock()
			}
		}()
	}
	seen := map[string]bool{}
	send := func(p string) bool {
		k := pathKey(p)
		if seen[k] {
			return true
		}
		seen[k] = true
		select {
		case files <- p:
			return true
		case <-ctx.Done():
			return false
		}
	}
walk:
	for _, root := range paths {
		st, err := os.Stat(root)
		if err != nil {
			mu.Lock()
			sum.Files++
			sum.Errors++
			if progress != nil {
				progress(&Result{Path: root, Verdict: Failed, Error: err.Error()})
			}
			mu.Unlock()
			continue
		}
		if !st.IsDir() {
			if !send(root) {
				break walk
			}
			continue
		}
		stop := false
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				stop = true
				return filepath.SkipAll
			}
			if d.IsDir() {
				if p != root && (config.Excluded(p+"/", e.Cfg.Scan.Excludes) || pathKey(p) == pathKey(config.Dir())) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || config.Excluded(p, e.Cfg.Scan.Excludes) {
				return nil
			}
			if !send(p) {
				stop = true
				return filepath.SkipAll
			}
			return nil
		})
		if stop {
			break
		}
	}
	close(files)
	wg.Wait()
	e.Flush()
	sum.Cancelled = ctx.Err() != nil
	sum.Seconds = float64(time.Since(start).Milliseconds()) / 1000
	sort.Slice(sum.Detections, func(i, j int) bool { return sum.Detections[i].Score > sum.Detections[j].Score })
	return sum
}
