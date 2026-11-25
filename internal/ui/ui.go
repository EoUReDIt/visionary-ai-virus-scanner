// Package ui serves the dashboard: one embedded page and a small JSON API on
// 127.0.0.1. Every endpoint is a thin wrapper around a function in package
// app that the command line also calls.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/ai"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/secure"
)

//go:embed index.html
var indexHTML []byte

// job is the single scan the dashboard can run at a time.
type job struct {
	mu         sync.Mutex
	Running    bool             `json:"running"`
	Kind       string           `json:"kind"`
	Files      int              `json:"files"`
	Current    string           `json:"current"`
	Detections []*engine.Result `json:"detections"`
	Summary    *engine.Summary  `json:"summary,omitempty"`
	Error      string           `json:"error,omitempty"`
	cancel     context.CancelFunc
}

type server struct {
	a     *app.App
	token string
	host  string
	job   job
	dl    download
	ctx   context.Context
}

// download is the one model download the dashboard runs at a time.
type download struct {
	mu      sync.Mutex
	Running bool   `json:"running"`
	Ref     string `json:"ref"`
	Done    int64  `json:"done"`
	Total   int64  `json:"total"`
	Error   string `json:"error,omitempty"`
	Result  string `json:"result,omitempty"`
	cancel  context.CancelFunc
}

func (d *download) snapshot() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]any{"running": d.Running, "ref": d.Ref, "done": d.Done, "total": d.Total, "error": d.Error, "result": d.Result}
}

// Serve runs the dashboard until ctx is cancelled.
func Serve(ctx context.Context, a *app.App, port int, open, guard bool) error {
	if port == 0 {
		port = a.Config().UI.Port
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		// The preferred port is taken (perhaps another dashboard): any free one.
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			return err
		}
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	s := &server{a: a, token: hex.EncodeToString(raw), host: ln.Addr().String(), ctx: ctx}
	url := fmt.Sprintf("http://%s/#t=%s", s.host, s.token)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	for path, h := range map[string]func(*http.Request) (any, error){
		"/api/status":     s.status,
		"/api/scan":       s.scan,
		"/api/job":        s.jobState,
		"/api/job/cancel": s.jobCancel,
		"/api/protection": s.protection,
		"/api/events":     s.events,
		"/api/quarantine": s.quarantine,
		"/api/defs":       s.defs,
		"/api/ai":         s.ai,
		"/api/settings":   s.settings,
		"/api/windows":    s.windows,
		"/api/preboot":    s.preboot,
	} {
		mux.HandleFunc(path, s.api(h))
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	if guard && !app.GuardAlive() {
		go func() { _ = a.RunGuard(ctx, nil) }()
	}
	// Full-screen detection has to happen in the user's session; this
	// process is in it, a service is not.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.Reload()
				a.GameMode()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()

	fmt.Println("Visionary dashboard:", url)
	fmt.Println("(the link carries a one-time access token; Ctrl+C to stop)")
	if open {
		_ = plat.OpenBrowser(url)
	}
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hostOK rejects requests that reached the server under another name, which
// is what a DNS-rebinding page would do.
func (s *server) hostOK(r *http.Request) bool {
	_, port, _ := net.SplitHostPort(s.host)
	return r.Host == s.host || r.Host == "localhost:"+port
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || !s.hostOK(r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

// api wraps a handler with the access checks and JSON plumbing. The token
// travels in a header a cross-site page cannot set, so no other web page on
// the machine can drive the antivirus.
func (s *server) api(h func(*http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		tok := r.Header.Get("X-Visionary-Token")
		if !s.hostOK(r) || subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "access token missing or wrong: reopen the dashboard with `visionary ui`"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		out, err := h(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			out = map[string]string{"error": err.Error()}
		}
		if out == nil {
			out = map[string]bool{"ok": true}
		}
		_ = json.NewEncoder(w).Encode(out)
	}
}

type req struct {
	Action     string   `json:"action"`
	Kind       string   `json:"kind"`
	Paths      []string `json:"paths"`
	Path       string   `json:"path"`
	Deep       bool     `json:"deep"`
	Quarantine bool     `json:"quarantine"`
	For        string   `json:"for"`
	Password   string   `json:"password"`
	ID         string   `json:"id"`
	Allow      bool     `json:"allow"`
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Key        string   `json:"key"`
	Value      string   `json:"value"`
	All        bool     `json:"all"`
	Days       int      `json:"days"`
	Hours      int      `json:"hours"`
}

func body(r *http.Request) (req, error) {
	var q req
	if r.Method != http.MethodPost {
		return q, errors.New("POST required")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		return q, errors.New("bad request body")
	}
	return q, nil
}

func (s *server) status(r *http.Request) (any, error) {
	s.a.Reload()
	return s.a.Status(r.URL.Query().Get("windows") == "1"), nil
}

func (s *server) scan(r *http.Request) (any, error) {
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	j := &s.job
	j.mu.Lock()
	if j.Running {
		j.mu.Unlock()
		return nil, errors.New("a scan is already running")
	}
	if q.Kind == "targeted" && len(q.Paths) == 0 {
		j.mu.Unlock()
		return nil, errors.New("enter a file or folder to scan")
	}
	ctx, cancel := context.WithCancel(s.ctx)
	j.Running, j.Kind, j.Files, j.Current, j.Detections, j.Summary, j.Error = true, q.Kind, 0, "", nil, nil, ""
	j.cancel = cancel
	j.mu.Unlock()

	progress := func(res *engine.Result) {
		j.mu.Lock()
		j.Files++
		j.Current = res.Path
		if res.Verdict == engine.Malicious || res.Verdict == engine.Suspicious {
			slim := *res
			slim.Features.Snippet = ""
			j.Detections = append(j.Detections, &slim)
		}
		j.mu.Unlock()
	}
	go func() {
		defer cancel()
		opts := app.ScanOptions{Deep: q.Deep, Quarantine: q.Quarantine}
		var sum *engine.Summary
		var err error
		switch q.Kind {
		case "quick":
			sum = s.a.QuickScan(ctx, opts, progress)
		case "boot":
			sum = s.a.BootScan(ctx, false, progress)
		case "targeted":
			sum, err = s.a.TargetedScan(ctx, q.Paths, opts, progress)
		default:
			err = errors.New("unknown scan kind")
		}
		j.mu.Lock()
		j.Running, j.Current = false, ""
		if sum != nil {
			slim := *sum
			slim.Detections = nil // already streamed
			j.Summary = &slim
		}
		if err != nil {
			j.Error = err.Error()
		}
		j.mu.Unlock()
	}()
	return nil, nil
}

func (s *server) jobState(*http.Request) (any, error) {
	j := &s.job
	j.mu.Lock()
	defer j.mu.Unlock()
	return map[string]any{"running": j.Running, "kind": j.Kind, "files": j.Files, "current": j.Current,
		"detections": j.Detections, "summary": j.Summary, "error": j.Error}, nil
}

func (s *server) jobCancel(*http.Request) (any, error) {
	s.job.mu.Lock()
	defer s.job.mu.Unlock()
	if s.job.cancel != nil {
		s.job.cancel()
	}
	return nil, nil
}

func (s *server) protection(r *http.Request) (any, error) {
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	switch q.Action {
	case "enable":
		return nil, s.a.Enable()
	case "disable":
		mode, d := "permanent", time.Duration(0)
		switch q.For {
		case "restart":
			mode = "restart"
		case "permanent":
		default:
			if d, err = time.ParseDuration(q.For); err != nil {
				return nil, errors.New("choose how long to disable protection")
			}
			mode = "timed"
		}
		return nil, s.a.Disable(mode, d, q.Password)
	}
	return nil, errors.New("unknown action")
}

func (s *server) events(r *http.Request) (any, error) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 1000 {
		n = 200
	}
	evs := s.a.Events(n)
	if evs == nil {
		evs = []app.Event{}
	}
	return evs, nil
}

func (s *server) quarantine(r *http.Request) (any, error) {
	if r.Method == http.MethodGet {
		items := engine.QuarantineList()
		if items == nil {
			items = []engine.QItem{}
		}
		return items, nil
	}
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	switch q.Action {
	case "restore":
		_, err := s.a.Restore(q.ID, "", q.Allow)
		return nil, err
	case "delete":
		return nil, engine.QuarantineDelete(q.ID)
	}
	return nil, errors.New("unknown action")
}

func (s *server) defs(r *http.Request) (any, error) {
	if r.Method == http.MethodGet {
		s.a.Reload()
		return map[string]any{"sources": s.a.DefSources(), "channels": s.a.Config().Channels,
			"presets": defs.Presets, "stats": s.a.Status(false).Defs}, nil
	}
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	switch q.Action {
	case "import":
		if q.Path == "" {
			return nil, errors.New("enter the path of a definitions file")
		}
		return s.a.ImportDefs(q.Path, q.Name, q.Kind)
	case "remove":
		return nil, s.a.RemoveDefs(q.Name)
	case "channel-add":
		if err := s.a.ChannelAdd(q.Name, q.URL, q.Kind, q.Hours, nil); err != nil {
			return nil, err
		}
		return s.a.ChannelUpdate(strings.ToLower(q.Name), true)
	case "channel-remove":
		return nil, s.a.ChannelRemove(q.Name)
	case "channel-update":
		return s.a.ChannelUpdate(q.Name, true)
	}
	return nil, errors.New("unknown action")
}

func (s *server) ai(r *http.Request) (any, error) {
	cfg := s.a.Config()
	if r.Method == http.MethodGet {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		models, err := s.a.LocalModels(ctx)
		runtime := "running"
		if err != nil {
			runtime = "not reachable"
		}
		if models == nil {
			models = []ai.LocalModel{}
		}
		stored, _ := s.a.StoredModels()
		if stored == nil {
			stored = []ai.StoredModel{}
		}
		return map[string]any{"mode": cfg.AI.Mode, "local": cfg.AI.Local, "cloud": cfg.AI.Cloud,
			"cloud_key_set": secure.Secret("anthropic") != "", "vt_key_set": secure.Secret("virustotal") != "",
			"recommended": ai.RecommendedFor(cfg.AI.Local.MaxParamsB), "models": models, "ollama": runtime,
			"stored": stored, "download": s.dl.snapshot(), "hf_token_set": secure.Secret("huggingface") != ""}, nil
	}
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	switch q.Action {
	case "mode":
		return nil, s.a.SetAIMode(q.Value)
	case "use":
		p, err := s.a.UseLocalModel(ctx, q.Name)
		return map[string]any{"params_b": p}, err
	case "pull":
		p, err := s.a.PullLocalModel(s.ctx, q.Name, nil)
		return map[string]any{"params_b": p}, err
	case "gguf":
		p, err := s.a.UseGGUF(q.Path, q.Value)
		return map[string]any{"params_b": p}, err
	case "load":
		return nil, s.a.LoadLocalModel(ctx, true)
	case "hf-search":
		return s.a.HFSearch(ctx, q.Value)
	case "hf-files":
		return s.a.HFFiles(ctx, q.Name)
	case "hf-get":
		return nil, s.startDownload(q.Name, q.Value)
	case "hf-cancel":
		s.dl.mu.Lock()
		if s.dl.cancel != nil {
			s.dl.cancel()
		}
		s.dl.mu.Unlock()
		return nil, nil
	case "hf-token":
		return nil, s.a.SetSecret("huggingface", q.Key)
	case "import":
		m, err := s.a.ImportModel(q.Path, true)
		return map[string]any{"params_b": m.ParamsB, "name": m.Name}, err
	case "use-stored":
		m, err := s.a.UseStoredModel(q.Name)
		return map[string]any{"params_b": m.ParamsB}, err
	case "remove-stored":
		return nil, s.a.RemoveStoredModel(q.Name)
	case "set-key":
		if strings.TrimSpace(q.Key) == "" {
			return nil, errors.New("paste an API key")
		}
		return nil, s.a.SetSecret("anthropic", q.Key)
	case "clear-key":
		return nil, s.a.SetSecret("anthropic", "")
	case "vt-key":
		return nil, s.a.SetSecret("virustotal", q.Key)
	case "test":
		res := s.a.TestAI(ctx)
		if len(res) == 0 {
			return nil, errors.New("no AI provider is configured yet")
		}
		return res, nil
	case "explain":
		res, text, model, err := s.a.Explain(ctx, q.Path)
		if err != nil {
			return nil, err
		}
		res.Features.Snippet = ""
		return map[string]any{"result": res, "explanation": text, "model": model}, nil
	}
	return nil, errors.New("unknown action")
}

func (s *server) settings(r *http.Request) (any, error) {
	if r.Method == http.MethodGet {
		s.a.Reload()
		return map[string]any{"config": s.a.Config(), "user": secure.CurrentUser()}, nil
	}
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	switch q.Action {
	case "set":
		return nil, s.a.Set(q.Key, q.Value)
	case "profile":
		return nil, s.a.SetProfile(q.Value)
	case "gamemode":
		return nil, s.a.SetGameMode(q.Value)
	case "reset":
		return nil, s.a.ResetSettings(q.Password, q.All)
	case "learn":
		return nil, s.a.LearnStart(q.Days)
	case "stop-learning":
		return nil, s.a.LearnStop()
	case "behavior-reset":
		return nil, s.a.BehaviorReset()
	case "exclude-add":
		return nil, s.a.Exclude(q.Value, true)
	case "exclude-remove":
		return nil, s.a.Exclude(q.Value, false)
	case "allow-remove":
		return nil, s.a.Allow(q.Value, false)
	}
	return nil, errors.New("unknown action")
}

func (s *server) windows(r *http.Request) (any, error) {
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	switch q.Action {
	case "coexist":
		return nil, s.a.Coexist()
	case "passive-on", "passive-off":
		msg, err := s.a.DefenderPassive(q.Action == "passive-on")
		return map[string]string{"message": msg}, err
	case "offline-scan":
		return nil, s.a.DefenderOfflineScan()
	}
	return nil, errors.New("unknown action")
}

func (s *server) preboot(r *http.Request) (any, error) {
	q, err := body(r)
	if err != nil {
		return nil, err
	}
	switch q.Action {
	case "schedule":
		return nil, s.a.ScheduleBootScan()
	case "cancel":
		return nil, s.a.CancelBootScan()
	}
	return nil, errors.New("unknown action")
}

// startDownload runs a Hugging Face download in the background; the page polls
// GET /api/ai for progress.
func (s *server) startDownload(ref, quant string) error {
	if strings.TrimSpace(ref) == "" {
		return errors.New("enter a Hugging Face repository such as unsloth/Qwen3-1.7B-GGUF")
	}
	s.dl.mu.Lock()
	if s.dl.Running {
		s.dl.mu.Unlock()
		return errors.New("a download is already running")
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.dl.Running, s.dl.Ref, s.dl.Done, s.dl.Total, s.dl.Error, s.dl.Result, s.dl.cancel = true, ref, 0, 0, "", "", cancel
	s.dl.mu.Unlock()
	go func() {
		defer cancel()
		m, err := s.a.HFGet(ctx, ref, quant, true, func(done, total int64) {
			s.dl.mu.Lock()
			s.dl.Done, s.dl.Total = done, total
			s.dl.mu.Unlock()
		})
		s.dl.mu.Lock()
		defer s.dl.mu.Unlock()
		s.dl.Running = false
		if err != nil {
			s.dl.Error = err.Error()
			return
		}
		s.dl.Result = fmt.Sprintf("%s ready (%.2fB parameters)", m.Name, m.ParamsB)
	}()
	return nil
}
