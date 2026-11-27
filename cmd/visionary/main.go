// Command visionary is the whole product: every feature is a subcommand
// here first, and the dashboard (`visionary ui`) drives the same code.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/ai"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/defs"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/edition"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/plat"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/risk"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/secure"
)

const usage = `Visionary — antivirus with local and cloud AI

  visionary status                         protection, definitions, AI, Windows Security
  visionary scan quick                     running programs, autoruns, temp, downloads
  visionary scan <path>...                 targeted scan of files or folders
  visionary scan boot                      boot-critical locations (drivers, services, autoruns)
  visionary guard                          real-time protection in this terminal
  visionary ui                             open the dashboard

  visionary protection status|enable
  visionary protection disable --for 15m|1h|restart|permanent
  visionary gamemode on|off|auto
  visionary profile balanced|gamer|dev|lite

  visionary defs import <file> [--name N] [--kind hashes|yara|certs|cvd]
  visionary defs list|stats|remove <name>
  visionary defs channel presets|list|add <name> [url]|remove <name>|update [name]

  visionary ai status|test|recommend
  visionary ai mode off|local|cloud|hybrid
  visionary ai sensitivity conservative|balanced|proactive
  visionary ai local list|pull <model>|use <model>|gguf <file>|load|unload
  visionary ai cloud provider gemini|claude|openai|set-key|clear-key|model <id>|endpoint <url>
  visionary ai explain <file>
  visionary reputation provider [virustotal|otx|both]
  visionary reputation set-key|clear-key [virustotal|otx] | sync-otx
  visionary risk sync|guidance|search <query>|provider [nvd|custom]|set-key|clear-key

  visionary quarantine list|restore <id> [--allow] [--to path]|delete <id>
  visionary allow list|add <path-or-sha256>|remove <item>
  visionary exclude list|add <pattern>|remove <pattern>
  visionary behavior status|learn [--days N]|stop-learning|reset
  visionary windows status|coexist|passive on|off|offline-scan
  visionary preboot schedule [--reboot]|status|cancel
  visionary service install|uninstall|start|stop|status
  visionary settings show|set <key> <value>|reset [--all]
  visionary events [-n 30]
  visionary version

Scan flags: --deep (ask Defender / reputation / AI about gray-zone files),
--quarantine, --no-cache, --json.   Most commands accept --json.
Exit codes: 0 clean, 1 malicious found, 2 suspicious found, 3 error.
`

var (
	color   bool
	jsonOut bool
)

func paint(code, s string) string {
	if !color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func red(s string) string    { return paint("31;1", s) }
func yellow(s string) string { return paint("33", s) }
func green(s string) string  { return paint("32", s) }
func dim(s string) string    { return paint("2", s) }
func bold(s string) string   { return paint("1", s) }

func fail(err error) {
	fmt.Fprintln(os.Stderr, red("error: ")+err.Error())
	os.Exit(3)
}

func check(err error) {
	if err != nil {
		fail(err)
	}
}

func emit(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// parse lets flags appear before or after positional arguments.
func parse(fs *flag.FlagSet, argv []string) []string {
	fs.BoolVar(&jsonOut, "json", false, "machine-readable output")
	var pos []string
	for len(argv) > 0 {
		_ = fs.Parse(argv)
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		argv = rest[1:]
	}
	return pos
}

func arg(pos []string, i int) string {
	if i < len(pos) {
		return pos[i]
	}
	return ""
}

func need(pos []string, i int, what string) string {
	if v := arg(pos, i); v != "" {
		return v
	}
	fail(errors.New("missing " + what))
	return ""
}

func ok(format string, args ...any) { fmt.Println(green("✓ ") + fmt.Sprintf(format, args...)) }

func interruptible() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx
}

func main() {
	color = term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == "" && plat.EnableANSI()
	argv := os.Args[1:]

	a, err := app.Open()
	check(err)
	if runningAsService() || (len(argv) >= 2 && argv[0] == "service" && argv[1] == "run") {
		check(runService(a))
		return
	}
	// VisionaryUI.exe is this program linked without a console window: the
	// Start-menu shortcut and Windows sign-in tray launcher.
	if exe, _ := os.Executable(); strings.HasPrefix(strings.ToLower(filepath.Base(exe)), "visionaryui") &&
		(len(argv) == 0 || (len(argv) == 1 && argv[0] == "--tray")) {
		openBrowser := len(argv) == 0
		if err := serveUI(interruptible(), a, 0, openBrowser, true); err != nil {
			a.Log("system", "warn", "Dashboard could not start: "+err.Error(), nil)
		}
		return
	}
	// If double-clicked directly in Windows Explorer with no arguments, open the
	// lightweight web dashboard so the user sees the app immediately (all editions).
	if len(argv) == 0 && plat.LaunchedFromExplorer() {
		if err := serveUI(interruptible(), a, 0, true, true); err != nil {
			fmt.Fprintln(os.Stderr, red("error: ")+err.Error())
			fmt.Print("\nPress Enter to close...")
			_, _ = fmt.Scanln()
		}
		return
	}
	if len(argv) == 0 || argv[0] == "help" || argv[0] == "-h" || argv[0] == "--help" {
		fmt.Print(usage)
		return
	}
	cmd, rest := argv[0], argv[1:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Print(usage) }

	switch cmd {
	case "version":
		fmt.Println("visionary", config.Version, "("+edition.Name+" edition)")
	case "status":
		parse(fs, rest)
		cmdStatus(a)
	case "scan":
		cmdScan(a, fs, rest)
	case "guard":
		parse(fs, rest)
		if app.GuardAlive() {
			fail(errors.New("a guard is already running (service or another terminal)"))
		}
		fmt.Println(bold("Visionary real-time protection") + dim("  — Ctrl+C to stop"))
		check(a.RunGuard(interruptible(), func(s string) {
			fmt.Println(dim(time.Now().Format("15:04:05")), s)
		}))
	case "ui":
		port := fs.Int("port", 0, "port to listen on")
		noOpen := fs.Bool("no-open", false, "do not open a browser window")
		trayOnly := fs.Bool("tray", false, "start minimized to the system tray")
		noGuard := fs.Bool("no-guard", false, "do not run real-time protection inside the dashboard process")
		parse(fs, rest)
		check(serveUI(interruptible(), a, *port, !*noOpen && !*trayOnly, !*noGuard))
	case "protection":
		cmdProtection(a, fs, rest)
	case "gamemode":
		pos := parse(fs, rest)
		check(a.SetGameMode(need(pos, 0, "on, off or auto")))
		ok("game mode: %s", pos[0])
	case "profile":
		pos := parse(fs, rest)
		if arg(pos, 0) == "" {
			fmt.Println(a.Config().Profile)
			return
		}
		check(a.SetProfile(pos[0]))
		ok("profile: %s", pos[0])
	case "defs":
		cmdDefs(a, fs, rest)
	case "ai":
		cmdAI(a, fs, rest)
	case "reputation":
		maxFiles := fs.Int("limit", 50, "maximum files to hash-check (for scan)")
		pos := parse(fs, rest)
		target := strings.ToLower(strings.TrimSpace(arg(pos, 1)))
		switch arg(pos, 0) {
		case "provider":
			if target == "" {
				fmt.Println(a.ActiveReputationProvider())
				return
			}
			check(a.Set("reputation.provider", target))
			ok("threat exchange provider: %s", a.ActiveReputationProvider())
		case "set-key":
			if target == "" {
				if a.ActiveReputationProvider() == "otx" {
					target = "otx"
				} else {
					target = "virustotal"
				}
			}
			if target != "virustotal" && target != "otx" {
				fail(errors.New("provider for set-key must be virustotal or otx"))
			}
			label := "VirusTotal"
			if target == "otx" {
				label = "AlienVault OTX"
			}
			key, err := secure.PromptPassword(label + " API key: ")
			check(err)
			check(a.SetSecret(target, key))
			ok("%s key stored (encrypted); Threat Exchange hash lookups enabled", label)
		case "clear-key":
			if target == "" {
				if a.ActiveReputationProvider() == "otx" {
					target = "otx"
				} else {
					target = "virustotal"
				}
			}
			if target != "virustotal" && target != "otx" {
				fail(errors.New("provider for clear-key must be virustotal or otx"))
			}
			check(a.SetSecret(target, ""))
			ok("%s key removed", target)
		case "sync-otx":
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			n, err := a.SyncOTXFeed(ctx)
			check(err)
			ok("synced %d new SHA-256 indicators from AlienVault OTX into local definitions", n)
		case "scan":
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			rep, err := a.BatchHashScan(ctx, arg(pos, 1), *maxFiles)
			check(err)
			if jsonOut {
				emit(rep)
				return
			}
			ok("hash scan (%s): %d files (%d unique · %d cached · %d live) — %d malicious, %d suspicious, %d clean, %d unknown",
				rep.Provider, rep.Files, rep.UniqueHash, rep.CacheHits, rep.LiveQueries,
				rep.Malicious, rep.Suspicious, rep.Clean, rep.Unknown)
			for _, it := range rep.Items {
				if it.Verdict == "malicious" || it.Verdict == "suspicious" {
					fmt.Printf("  [%s] %s — %s (%s)\n", strings.ToUpper(it.Verdict), it.Path, it.Label, it.Detail)
				}
			}
		default:
			fail(errors.New("usage: visionary reputation provider [virustotal|otx|both] | set-key [virustotal|otx] | clear-key [virustotal|otx] | sync-otx | scan [path]"))
		}
	case "risk":
		cmdRisk(a, fs, rest)
	case "quarantine":
		cmdQuarantine(a, fs, rest)
	case "allow", "exclude":
		cmdLists(a, cmd, fs, rest)
	case "behavior", "behaviour":
		cmdBehavior(a, fs, rest)
	case "windows":
		cmdWindows(a, fs, rest)
	case "preboot":
		cmdPreboot(a, fs, rest)
	case "service":
		pos := parse(fs, rest)
		msg, err := serviceCommand(need(pos, 0, "install, uninstall, start, stop or status"))
		check(err)
		ok("service %s", msg)
	case "path":
		pos := parse(fs, rest)
		switch arg(pos, 0) {
		case "add":
			_ = plat.EnsureSharedDataDir(config.Dir())
			check(plat.UpdateSystemPath(need(pos, 1, "directory"), true))
			ok("added %s to machine PATH", pos[1])
		case "remove":
			check(plat.UpdateSystemPath(need(pos, 1, "directory"), false))
			ok("removed %s from machine PATH", pos[1])
		default:
			fail(errors.New("usage: visionary path add|remove <dir>"))
		}
	case "settings":
		cmdSettings(a, fs, rest)
	case "events":
		n := fs.Int("n", 30, "how many events")
		parse(fs, rest)
		evs := a.Events(*n)
		if jsonOut {
			emit(evs)
			return
		}
		for i := len(evs) - 1; i >= 0; i-- {
			e := evs[i]
			sev := dim(e.Severity)
			if e.Severity == "high" {
				sev = red(e.Severity)
			} else if e.Severity == "warn" {
				sev = yellow(e.Severity)
			}
			fmt.Printf("%s  %-5s %-11s %s\n", dim(e.Time.Local().Format("01-02 15:04:05")), sev, e.Type, e.Message)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Print(usage)
		os.Exit(3)
	}
}

func onOff(b bool) string {
	if b {
		return green("on")
	}
	return red("off")
}

func cmdStatus(a *app.App) {
	s := a.Status(true)
	if jsonOut {
		emit(s)
		return
	}
	row := func(k, v string) { fmt.Printf("  %-22s %s\n", k, v) }
	fmt.Println(bold("Visionary " + s.Version + " (" + s.Edition + " edition)"))
	prot := onOff(s.Protection) + dim("  ("+s.ProtReason+")")
	row("Real-time protection", prot)
	guard := green("running")
	if !s.GuardAlive {
		guard = yellow("not running") + dim("  (visionary guard, or visionary service install)")
	}
	row("Guard", guard)
	row("Profile", s.Profile+map[bool]string{true: "  · game mode active"}[s.GameMode])
	row("Definitions", fmt.Sprintf("%d hashes, %d rules, %d certificates in %d sources, %d channels",
		s.Defs.Hashes, s.Defs.Rules, s.Defs.Certs, s.Defs.Sources, s.Channels))
	aiLine := s.AIMode
	if s.LocalModel != "" {
		aiLine += "  · local: " + s.LocalModel
	}
	if s.CloudModel != "" {
		aiLine += "  · cloud: " + s.CloudModel
	}
	row("AI", aiLine)
	var repParts []string
	if s.VTKey && (s.RepProvider == "virustotal" || s.RepProvider == "both") {
		repParts = append(repParts, "VirusTotal")
	}
	if s.OTXKey && (s.RepProvider == "otx" || s.RepProvider == "both") {
		repParts = append(repParts, "AlienVault OTX")
	}
	repLine := dim("off")
	if len(repParts) > 0 {
		repLine = strings.Join(repParts, " + ") + " hash lookups"
	}
	row("Threat Exchange", repLine)
	riskLine := s.RiskPosture
	if s.RiskKEVs > 0 {
		riskLine = yellow(fmt.Sprintf("%s · %d KEV advisories · %d priority targets", s.RiskPosture, s.RiskKEVs, s.RiskTargets))
	} else if s.RiskTargets > 0 {
		riskLine = fmt.Sprintf("%s · %d priority targets", s.RiskPosture, s.RiskTargets)
	}
	row("Risk Exchange", riskLine)
	beh := fmt.Sprintf("%d programs known", s.Behavior.Executables)
	if s.Learning {
		beh += yellow("  · learning")
	}
	row("Behaviour model", beh)
	row("Quarantine", fmt.Sprintf("%d items", s.Quarantine))
	if s.BootScan {
		row("Boot scan", yellow("scheduled for next restart"))
	}
	if w := s.Windows; w != nil && w.Available {
		row("Microsoft Defender", fmt.Sprintf("%s mode, real-time %s", w.RunningMode, map[bool]string{true: "on", false: "off"}[w.RealTime]))
		row("Visionary's role", w.Role)
		for _, n := range w.Notes {
			fmt.Println("  " + dim("note: "+n))
		}
	}
	for _, w := range s.Warnings {
		fmt.Println("  " + yellow("warning: ") + w)
	}
}

func printResult(r *engine.Result) {
	label := yellow("SUSPICIOUS")
	if r.Verdict == engine.Malicious {
		label = red("MALICIOUS ")
	}
	fmt.Printf("%s %s\n", label, r.Path)
	fmt.Printf("           %s  score %d  sha256 %s\n", bold(r.Threat), r.Score, dim(r.SHA256))
	for _, f := range r.Findings {
		score := ""
		if f.Score > 0 {
			score = fmt.Sprintf(" +%d", f.Score)
		}
		fmt.Printf("           %s %s%s %s\n", dim("["+f.Layer+"]"), f.Name, dim(score), dim(f.Detail))
	}
	if r.Action != "" {
		fmt.Printf("           → %s\n", r.Action)
	}
}

func cmdScan(a *app.App, fs *flag.FlagSet, rest []string) {
	deep := fs.Bool("deep", false, "escalate gray-zone files to Defender / reputation / AI")
	quarantine := fs.Bool("quarantine", false, "quarantine malicious files")
	noCache := fs.Bool("no-cache", false, "ignore the clean-file cache")
	once := fs.Bool("once", false, "boot scan: remove the boot task afterwards")
	pos := parse(fs, rest)
	if len(pos) == 0 {
		fail(errors.New("usage: visionary scan quick | boot | <path>..."))
	}
	opts := app.ScanOptions{Deep: *deep, Quarantine: *quarantine, NoCache: *noCache}
	ctx := interruptible()
	tty := color && !jsonOut
	count := 0
	progress := func(r *engine.Result) {
		count++
		if jsonOut {
			return
		}
		if r.Verdict == engine.Malicious || r.Verdict == engine.Suspicious {
			if tty {
				fmt.Print("\r\x1b[K")
			}
			printResult(r)
		} else if tty && count%25 == 0 {
			p := r.Path
			if len(p) > 70 {
				p = "…" + p[len(p)-69:]
			}
			fmt.Printf("\r\x1b[K%s %s", dim(fmt.Sprintf("%6d", count)), dim(p))
		}
	}
	var sum *engine.Summary
	switch pos[0] {
	case "quick":
		sum = a.QuickScan(ctx, opts, progress)
	case "boot":
		sum = a.BootScan(ctx, *once, progress)
	default:
		var err error
		sum, err = a.TargetedScan(ctx, pos, opts, progress)
		check(err)
	}
	if jsonOut {
		emit(sum)
		os.Exit(sum.ExitCode())
	}
	if tty {
		fmt.Print("\r\x1b[K")
	}
	state := green("no threats found")
	if sum.Malicious > 0 {
		state = red(fmt.Sprintf("%d malicious", sum.Malicious))
		if sum.Suspicious > 0 {
			state += ", " + yellow(fmt.Sprintf("%d suspicious", sum.Suspicious))
		}
	} else if sum.Suspicious > 0 {
		state = yellow(fmt.Sprintf("%d suspicious", sum.Suspicious))
	}
	extra := ""
	if sum.Cached > 0 {
		extra += fmt.Sprintf(", %d unchanged since last scan", sum.Cached)
	}
	if sum.Errors > 0 {
		extra += fmt.Sprintf(", %d unreadable", sum.Errors)
	}
	if sum.Quarantined > 0 {
		extra += fmt.Sprintf(", %d quarantined", sum.Quarantined)
	}
	if sum.Cancelled {
		extra += ", " + yellow("cancelled")
	}
	fmt.Printf("%s — %d files, %.1f MB in %.1fs%s\n", state, sum.Files, float64(sum.Bytes)/(1<<20), sum.Seconds, extra)
	if sum.Suspicious > 0 && !*deep {
		fmt.Println(dim("tip: --deep asks Microsoft Defender, reputation and AI about suspicious files; `visionary ai explain <file>` explains one"))
	}
	os.Exit(sum.ExitCode())
}

func parseFor(s string) (mode string, d time.Duration, err error) {
	switch s {
	case "restart", "until-restart":
		return "restart", 0, nil
	case "permanent", "forever", "":
		return "permanent", 0, nil
	}
	d, err = time.ParseDuration(s)
	if err != nil {
		return "", 0, errors.New("--for takes a duration (15m, 1h, 8h), restart or permanent")
	}
	return "timed", d, nil
}

func cmdProtection(a *app.App, fs *flag.FlagSet, rest []string) {
	forFlag := fs.String("for", "", "15m, 1h, restart or permanent")
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "", "status":
		on, why := a.ProtectionActive()
		if jsonOut {
			emit(map[string]any{"enabled": on, "reason": why})
			return
		}
		fmt.Printf("real-time protection: %s (%s)\n", onOff(on), why)
	case "enable":
		check(a.Enable())
		ok("real-time protection enabled")
	case "disable":
		if *forFlag == "" {
			fail(errors.New("say how long: --for 15m | 1h | restart | permanent  (each has a way back on)"))
		}
		mode, d, err := parseFor(*forFlag)
		check(err)
		pw := ""
		if a.Config().Security.RequirePasswordToDisable {
			pw, err = secure.PromptPassword("Computer password for " + secure.CurrentUser() + ": ")
			check(err)
		}
		check(a.Disable(mode, d, pw))
		_, why := a.ProtectionActive()
		fmt.Println(yellow("! ") + "real-time protection " + why + dim("  — re-enable any time: visionary protection enable"))
	default:
		fail(errors.New("usage: visionary protection status|enable|disable --for <duration|restart|permanent>"))
	}
}

func cmdDefs(a *app.App, fs *flag.FlagSet, rest []string) {
	name := fs.String("name", "", "source name")
	kind := fs.String("kind", "auto", "hashes, yara, certs or cvd")
	every := fs.Int("every", 0, "channel poll interval in hours")
	force := fs.Bool("force", false, "update channels even if not due")
	var headers multiFlag
	fs.Var(&headers, "header", `extra request header for a channel, e.g. "Auth-Key: abc" (repeatable)`)
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "import":
		src, err := a.ImportDefs(need(pos, 1, "a definitions file"), *name, *kind)
		check(err)
		if jsonOut {
			emit(src)
			return
		}
		ok("imported %d %s definitions as %q", src.Count, src.Kind, src.Name)
		if src.Skipped > 0 {
			fmt.Println(dim(fmt.Sprintf("  %d entries were not usable (unsupported rule features or signature types)", src.Skipped)))
		}
	case "list", "":
		srcs := a.DefSources()
		if jsonOut {
			emit(srcs)
			return
		}
		fmt.Printf("%-28s %-7s %10s  %s\n", "SOURCE", "KIND", "ENTRIES", "IMPORTED")
		fmt.Printf("%-28s %-7s %10d  %s\n", "builtin", "yara", builtinCount(a), "shipped with the app")
		for _, s := range srcs {
			from := s.ImportedAt.Local().Format("2006-01-02 15:04")
			if s.Channel != "" {
				from += "  (channel " + s.Channel + ")"
			}
			fmt.Printf("%-28s %-7s %10d  %s\n", s.Name, s.Kind, s.Count, from)
		}
	case "stats":
		emit(a.Status(false).Defs)
	case "remove":
		check(a.RemoveDefs(need(pos, 1, "a source name")))
		ok("removed %s", pos[1])
	case "channel", "channels":
		switch arg(pos, 1) {
		case "presets":
			for _, p := range defs.Presets {
				fmt.Printf("%-26s every %dh  %s\n%s\n", bold(p.Name), p.Hours, p.About, dim("  "+p.URL))
			}
		case "add":
			check(a.ChannelAdd(need(pos, 2, "a channel name (or preset)"), arg(pos, 3), *kind, *every, headers))
			ok("subscribed to %s — fetching now", pos[2])
			res, err := a.ChannelUpdate(strings.ToLower(pos[2]), true)
			check(err)
			for _, r := range res {
				fmt.Printf("  %s: %s\n", r.Name, r.Status)
			}
		case "remove":
			check(a.ChannelRemove(need(pos, 2, "a channel name")))
			ok("unsubscribed from %s", pos[2])
		case "update":
			res, err := a.ChannelUpdate(arg(pos, 2), *force || arg(pos, 2) == "")
			check(err)
			if jsonOut {
				emit(res)
				return
			}
			if len(res) == 0 {
				fmt.Println("no channels subscribed (visionary defs channel presets)")
			}
			for _, r := range res {
				fmt.Printf("%-26s %s\n", r.Name, r.Status)
			}
		case "list", "":
			chs := a.Config().Channels
			if jsonOut {
				emit(chs)
				return
			}
			if len(chs) == 0 {
				fmt.Println("no channels subscribed (visionary defs channel presets)")
			}
			for _, c := range chs {
				last := "never checked"
				if !c.LastChecked.IsZero() {
					last = c.LastChecked.Local().Format("01-02 15:04") + "  " + c.LastStatus
				}
				fmt.Printf("%-26s every %dh  %s\n%s\n", bold(c.Name), c.IntervalHours, last, dim("  "+c.URL))
			}
		default:
			fail(errors.New("usage: visionary defs channel presets|list|add <name> [url]|remove <name>|update [name]"))
		}
	default:
		fail(errors.New("usage: visionary defs import|list|stats|remove|channel ..."))
	}
}

func builtinCount(a *app.App) int {
	n := 0
	for _, r := range a.Engine().DB.Rules.Rules {
		if r.Source == "builtin" {
			n++
		}
	}
	return n
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdAI(a *app.App, fs *flag.FlagSet, rest []string) {
	server := fs.String("server", "", "path to llama-server(.exe) for GGUF models")
	noUse := fs.Bool("no-use", false, "download or import without selecting the model")
	quant := fs.String("quant", "", "quantisation or file name to download (e.g. Q4_K_M)")
	pos := parse(fs, rest)
	ctx := interruptible()
	cfg := a.Config()
	switch arg(pos, 0) {
	case "", "status":
		prov := a.ActiveCloudProvider()
		st := map[string]any{"mode": cfg.AI.Mode, "sensitivity": cfg.AI.Sensitivity, "local": cfg.AI.Local,
			"cloud_provider": prov, "cloud": cfg.AI.Cloud, "cloud_key_set": a.HasCloudKey(),
			"ai_stats": a.Engine().AIStats()}
		if jsonOut {
			emit(st)
			return
		}
		sens := cfg.AI.Sensitivity
		if sens == "" {
			sens = "balanced"
		}
		fmt.Printf("mode        %s  (sensitivity: %s)\n", bold(cfg.AI.Mode), sens)
		fmt.Printf("local       %s via %s at %s (limit %.1fB parameters)\n", cfg.AI.Local.Model, cfg.AI.Local.Provider,
			cfg.AI.Local.Endpoint, cfg.AI.Local.MaxParamsB)
		key := red("no API key")
		if a.HasCloudKey() {
			key = green("API key set")
		}
		share := "feature reports only"
		if cfg.AI.Cloud.ShareSnippets {
			share = "feature reports + script excerpts"
		}
		fmt.Printf("cloud       %s / %s, %s, sends %s\n", prov, cfg.AI.Cloud.Model, key, share)
		fmt.Println(dim("hybrid = local model first, cloud only when the local model is unsure"))
	case "mode":
		check(a.SetAIMode(need(pos, 1, "off, local, cloud or hybrid")))
		ok("AI mode: %s", pos[1])
	case "sensitivity":
		check(a.Set("ai.sensitivity", need(pos, 1, "conservative, balanced or proactive")))
		ok("AI sensitivity: %s", pos[1])
	case "recommend":
		fmt.Printf("Local models under the %.1fB-parameter limit (pull with: visionary ai local pull <model>)\n", cfg.AI.Local.MaxParamsB)
		for _, m := range ai.RecommendedFor(cfg.AI.Local.MaxParamsB) {
			fmt.Printf("  %-22s %-6s %s\n", bold(m.Model), m.Params, m.About)
		}
	case "test":
		res := a.TestAI(ctx)
		if jsonOut {
			emit(res)
			return
		}
		if len(res) == 0 {
			fail(errors.New("no AI provider is configured (visionary ai mode ...)"))
		}
		for _, r := range res {
			if r.OK {
				ok("%s %s answered in %.1fs: %s (%.0f%%) — %s", r.Provider, r.Model, r.Seconds,
					r.Verdict.Verdict, r.Verdict.Confidence*100, strings.Join(r.Verdict.Reasons, "; "))
			} else {
				fmt.Println(red("✗ ")+r.Provider, r.Model+":", r.Error)
			}
		}
	case "local":
		switch arg(pos, 1) {
		case "list", "":
			models, err := a.LocalModels(ctx)
			check(err)
			if jsonOut {
				emit(models)
				return
			}
			if len(models) == 0 {
				fmt.Println("no models installed (visionary ai recommend)")
			}
			for _, m := range models {
				note := ""
				if m.ParamsB > cfg.AI.Local.MaxParamsB {
					note = yellow("  over the limit")
				}
				if m.Loaded {
					note += green("  loaded")
				}
				if m.Name == cfg.AI.Local.Model {
					note += bold("  ← in use")
				}
				fmt.Printf("  %-28s %-7s %6d MB%s\n", m.Name, m.Params, m.SizeMB, note)
			}
		case "pull":
			model := need(pos, 2, "a model name (visionary ai recommend)")
			params, err := a.PullLocalModel(ctx, model, func(s string) {
				if color {
					fmt.Printf("\r\x1b[K%s", dim(s))
				}
			})
			if color {
				fmt.Print("\r\x1b[K")
			}
			check(err)
			ok("%s ready (%.2fB parameters) and selected", model, params)
		case "use":
			params, err := a.UseLocalModel(ctx, need(pos, 2, "a model name"))
			check(err)
			ok("using %s (%.2fB parameters)", pos[2], params)
		case "gguf":
			params, err := a.UseGGUF(need(pos, 2, "a .gguf file"), *server)
			check(err)
			ok("using %s (%.2fB parameters) through llama-server", pos[2], params)
			if a.Config().AI.Local.ServerPath == "" {
				fmt.Println(dim("  start llama-server yourself on port 8089, or pass --server <path to llama-server> so Visionary starts it"))
			}
		case "load", "unload":
			check(a.LoadLocalModel(ctx, pos[1] == "load"))
			ok("model %sed", pos[1])
		case "models":
			ms, err := a.StoredModels()
			check(err)
			if jsonOut {
				emit(ms)
				return
			}
			if len(ms) == 0 {
				fmt.Println("model store is empty (visionary ai local hf get <repo> | visionary ai local import <file.gguf>)")
			}
			for _, m := range ms {
				note := ""
				if m.Path == cfg.AI.Local.ModelPath {
					note = bold("  ← in use")
				}
				if m.ParamsB > cfg.AI.Local.MaxParamsB {
					note += yellow("  over the limit")
				}
				fmt.Printf("  %-52s %5.2fB %6d MB  %s%s\n", m.Name, m.ParamsB, m.SizeMB, dim(m.Source), note)
			}
			fmt.Println(dim("store: " + app.ModelDir()))
		case "import":
			m, err := a.ImportModel(need(pos, 2, "a .gguf file"), !*noUse)
			check(err)
			ok("imported %s (%.2fB parameters, sha256 %s…)", m.Name, m.ParamsB, m.SHA256[:12])
			if !*noUse {
				fmt.Println(dim("  selected; llama-server must be available (--server <path>) to run it"))
			}
		case "remove":
			check(a.RemoveStoredModel(need(pos, 2, "a model name (visionary ai local models)")))
			ok("removed %s", pos[2])
		case "hf":
			hfCommand(ctx, a, pos, fs, *noUse, *quant, jsonOut)
		default:
			fail(errors.New("usage: visionary ai local list|pull <model>|use <model>|gguf <file>|models|import <file>|remove <name>|hf search|files|get|set-token|load|unload"))
		}
	case "cloud":
		prov := a.ActiveCloudProvider()
		switch arg(pos, 1) {
		case "provider":
			p := need(pos, 2, "gemini, claude or openai")
			check(a.Set("ai.cloud.provider", p))
			ok("cloud provider: %s (model: %s)", p, a.Config().AI.Cloud.Model)
		case "set-key":
			if p := arg(pos, 2); p != "" {
				check(a.Set("ai.cloud.provider", p))
				prov = a.ActiveCloudProvider()
			}
			key, err := secure.PromptPassword(strings.ToUpper(prov[:1]) + prov[1:] + " API key: ")
			check(err)
			if strings.TrimSpace(key) == "" {
				fail(errors.New("empty key"))
			}
			check(a.SetSecret(ai.CloudSecretName(prov), key))
			ok("%s API key stored (encrypted); AI mode is now %s", prov, a.Config().AI.Mode)
		case "clear-key":
			if p := arg(pos, 2); p != "" {
				prov = p
			}
			check(a.SetSecret(ai.CloudSecretName(prov), ""))
			ok("%s API key removed; AI mode is now %s", prov, a.Config().AI.Mode)
		case "model":
			check(a.Set("ai.cloud.model", need(pos, 2, "a model id")))
			ok("cloud model: %s", pos[2])
		case "endpoint":
			check(a.Set("ai.cloud.endpoint", arg(pos, 2)))
			ok("cloud endpoint updated")
		default:
			fail(errors.New("usage: visionary ai cloud provider gemini|claude|openai | set-key [provider] | clear-key [provider] | model <id> | endpoint <url>"))
		}
	case "explain":
		res, text, model, err := a.Explain(ctx, need(pos, 1, "a file"))
		check(err)
		if jsonOut {
			emit(map[string]any{"result": res, "explanation": text, "model": model})
			return
		}
		if res.Verdict == engine.Clean {
			fmt.Printf("%s %s (score %d)\n", green("CLEAN     "), res.Path, res.Score)
		} else {
			printResult(res)
		}
		fmt.Println()
		fmt.Println(text)
		fmt.Println(dim("— " + model))
	default:
		fail(errors.New("usage: visionary ai status|mode|recommend|test|local ...|cloud ...|explain <file>"))
	}
}

func cmdQuarantine(a *app.App, fs *flag.FlagSet, rest []string) {
	allow := fs.Bool("allow", false, "also allowlist the file so it is not taken again")
	to := fs.String("to", "", "restore to this path instead of the original")
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "list", "":
		items := engine.QuarantineList()
		if jsonOut {
			emit(items)
			return
		}
		if len(items) == 0 {
			fmt.Println("quarantine is empty")
		}
		for _, it := range items {
			fmt.Printf("%s  %s  %s\n              %s\n", bold(it.ID), it.Time.Local().Format("2006-01-02 15:04"), red(it.Threat), it.Original)
		}
	case "restore":
		it, err := a.Restore(need(pos, 1, "a quarantine id"), *to, *allow)
		check(err)
		ok("restored to %s", it.Original)
	case "delete":
		check(engine.QuarantineDelete(need(pos, 1, "a quarantine id")))
		ok("deleted %s", pos[1])
	default:
		fail(errors.New("usage: visionary quarantine list|restore <id> [--allow] [--to path]|delete <id>"))
	}
}

func cmdLists(a *app.App, which string, fs *flag.FlagSet, rest []string) {
	pos := parse(fs, rest)
	cfg := a.Config()
	switch arg(pos, 0) {
	case "list", "":
		if which == "allow" {
			if jsonOut {
				emit(cfg.Allow)
				return
			}
			for _, h := range cfg.Allow.Hashes {
				fmt.Println("sha256 ", h)
			}
			for _, p := range cfg.Allow.Paths {
				fmt.Println("path   ", p)
			}
			return
		}
		all := map[string]any{"scan": cfg.Scan.Excludes, "realtime": cfg.Realtime.Excludes,
			"profile_" + cfg.Profile: config.ProfileExcludes(cfg.Profile)}
		if jsonOut {
			emit(all)
			return
		}
		for _, p := range cfg.Scan.Excludes {
			fmt.Println(p)
		}
		for _, p := range config.ProfileExcludes(cfg.Profile) {
			fmt.Println(p, dim(" (real-time only, from the "+cfg.Profile+" profile)"))
		}
	case "add", "remove":
		item := need(pos, 1, "an item")
		if which == "allow" {
			check(a.Allow(item, pos[0] == "add"))
		} else {
			check(a.Exclude(item, pos[0] == "add"))
		}
		ok("%s list updated", which)
	default:
		fail(fmt.Errorf("usage: visionary %s list|add <item>|remove <item>", which))
	}
}

func cmdBehavior(a *app.App, fs *flag.FlagSet, rest []string) {
	days := fs.Int("days", 0, "learning period in days")
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "", "status":
		s := a.Status(false)
		var anomalies []app.Event
		for _, e := range a.Events(500) {
			if e.Type == "anomaly" {
				anomalies = append(anomalies, e)
			}
		}
		if jsonOut {
			emit(map[string]any{"enabled": a.Config().Behavior.Enabled, "learning": s.Learning,
				"learning_until": a.Config().Behavior.LearningUntil, "baseline": s.Behavior, "anomalies": anomalies})
			return
		}
		fmt.Printf("behaviour monitoring: %s\n", onOff(a.Config().Behavior.Enabled))
		if s.Learning {
			fmt.Printf("learning until %s — everything seen now is treated as normal\n",
				a.Config().Behavior.LearningUntil.Local().Format("2006-01-02 15:04"))
		}
		fmt.Printf("baseline: %d programs, %d parent→child pairs, %d process starts observed, ~%.0f file changes / 10s\n",
			s.Behavior.Executables, s.Behavior.Edges, s.Behavior.Events, s.Behavior.FileRate)
		fmt.Printf("recent anomalies: %d\n", len(anomalies))
		for i, e := range anomalies {
			if i >= 10 {
				break
			}
			fmt.Printf("  %s  %s\n", dim(e.Time.Local().Format("01-02 15:04")), e.Message)
		}
	case "learn":
		check(a.LearnStart(*days))
		ok("learning until %s", a.Config().Behavior.LearningUntil.Local().Format("2006-01-02 15:04"))
	case "stop-learning":
		check(a.LearnStop())
		ok("learning stopped; unfamiliar activity is now scored")
	case "reset":
		check(a.BehaviorReset())
		ok("behaviour baseline cleared")
	default:
		fail(errors.New("usage: visionary behavior status|learn [--days N]|stop-learning|reset"))
	}
}

func cmdWindows(a *app.App, fs *flag.FlagSet, rest []string) {
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "", "status":
		s := a.WindowsStatus()
		if jsonOut {
			emit(s)
			return
		}
		if !s.Available {
			fmt.Println("Windows Security is not available on this system")
		} else {
			fmt.Printf("Microsoft Defender: %s mode, real-time %s, tamper protection %s, definitions %s\n",
				bold(s.RunningMode), onOff(s.RealTime), onOff(s.TamperProtected), s.SignatureDate)
			for _, p := range s.Products {
				fmt.Printf("  registered: %s (enabled: %v, up to date: %v)\n", p.Name, p.Enabled, p.UpToDate)
			}
		}
		fmt.Println("Visionary's role:", s.Role)
		for _, n := range s.Notes {
			fmt.Println(dim("note: " + n))
		}
	case "coexist":
		check(a.Coexist())
		ok("Defender now skips Visionary's data folder, and Visionary asks Defender for second opinions")
	case "passive":
		msg, err := a.DefenderPassive(need(pos, 1, "on or off") == "on")
		check(err)
		fmt.Println(msg)
	case "offline-scan":
		check(a.DefenderOfflineScan())
		ok("Microsoft Defender Offline scan requested — Windows will restart into the recovery environment")
	default:
		fail(errors.New("usage: visionary windows status|coexist|passive on|off|offline-scan"))
	}
}

func cmdPreboot(a *app.App, fs *flag.FlagSet, rest []string) {
	reboot := fs.Bool("reboot", false, "restart now")
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "schedule":
		check(a.ScheduleBootScan())
		ok("boot-time scan scheduled: it runs as SYSTEM at the next startup, before login")
		fmt.Println(dim("  for a scan from outside Windows (rootkits): visionary windows offline-scan"))
		if *reboot {
			check(plat.Reboot())
			fmt.Println("restarting in 10 seconds…")
		}
	case "", "status":
		pending := app.BootScanPending()
		if jsonOut {
			emit(map[string]any{"scheduled": pending, "task_registered": plat.BootTaskScheduled()})
			return
		}
		if pending {
			fmt.Println("a boot-time scan is scheduled for the next restart")
		} else {
			fmt.Println("no boot-time scan scheduled; reports from past runs are in " + config.Path("reports", ""))
		}
	case "cancel":
		check(a.CancelBootScan())
		ok("boot-time scan cancelled")
	default:
		fail(errors.New("usage: visionary preboot schedule [--reboot]|status|cancel"))
	}
}

func cmdSettings(a *app.App, fs *flag.FlagSet, rest []string) {
	all := fs.Bool("all", false, "also clear API keys, behaviour baseline and event log")
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "", "show":
		emit(a.Config())
		if !jsonOut {
			keys := []string{"realtime.auto_quarantine", "scan.max_file_size_mb", "scan.workers", "scan.scan_archives",
				"scan.use_cache", "scan.ai_budget", "behavior.enabled", "behavior.threshold",
				"security.require_password_to_disable", "windows.defender_second_opinion",
				"reputation.provider", "reputation.virustotal", "reputation.otx",
				"risk.enabled", "risk.provider", "risk.endpoint", "risk.kev_only", "risk.min_severity", "risk.auto_prioritize",
				"ai.sensitivity", "ai.confidence_threshold", "ai.cloud.provider", "ai.cloud.endpoint",
				"ai.cloud.share_snippets", "ai.cloud.model", "ai.cloud.effort", "ai.local.endpoint", "ai.local.provider",
				"ai.local.server_path", "ai.local.max_params_b", "ai.local.cpu_only", "ai.local.threads",
				"ai.local.keep_alive", "realtime.workers", "realtime.settle_ms", "behavior.poll_ms", "ui.port"}
			sort.Strings(keys)
			fmt.Println(dim("\nsettable with `visionary settings set <key> <value>`:\n  " + strings.Join(keys, "\n  ")))
		}
	case "set":
		check(a.Set(need(pos, 1, "a setting name"), need(pos, 2, "a value")))
		ok("%s = %s", pos[1], pos[2])
	case "reset":
		fmt.Println("This restores default settings and clears cached scan results.")
		if *all {
			fmt.Println("It also removes API keys, the behaviour baseline and the event log.")
		}
		fmt.Println("Definitions and quarantined files are kept.")
		pw, err := secure.PromptPassword("Computer password for " + secure.CurrentUser() + ": ")
		check(err)
		check(a.ResetSettings(pw, *all))
		ok("settings reset")
	default:
		fail(errors.New("usage: visionary settings show|set <key> <value>|reset [--all]"))
	}
}

// hfCommand implements `visionary ai local hf ...`.
func hfCommand(ctx context.Context, a *app.App, pos []string, fs *flag.FlagSet, noUse bool, quant string, jsonOut bool) {
	switch arg(pos, 2) {
	case "search":
		models, err := a.HFSearch(ctx, strings.Join(pos[3:], " "))
		check(err)
		if jsonOut {
			emit(models)
			return
		}
		limit := a.Config().AI.Local.MaxParamsB
		for _, m := range models {
			note := ""
			if m.ParamsB > 0 {
				note = fmt.Sprintf("%.1fB", m.ParamsB)
				if m.ParamsB > limit {
					note += yellow(" over the limit")
				}
			}
			if m.Gated {
				note += dim(" gated")
			}
			fmt.Printf("  %-55s %8d downloads  %s\n", bold(m.ID), m.Downloads, note)
		}
		if len(models) == 0 {
			fmt.Println("no GGUF repositories found")
		}
		fmt.Println(dim("next: visionary ai local hf files <repo>   then   visionary ai local hf get <repo> [--quant Q4_K_M]"))
	case "files":
		files, err := a.HFFiles(ctx, need(pos, 3, "a repository (owner/name)"))
		check(err)
		if jsonOut {
			emit(files)
			return
		}
		for _, f := range files {
			note := ""
			if f.Sharded {
				note = yellow("  split file: not supported")
			}
			fmt.Printf("  %-56s %-8s %6d MB%s\n", f.Name, f.Quant, f.SizeMB, note)
		}
	case "get":
		ref := need(pos, 3, "a repository, e.g. unsloth/Qwen3-1.7B-GGUF")
		last := time.Time{}
		m, err := a.HFGet(ctx, ref, quant, !noUse, func(done, total int64) {
			if color && (time.Since(last) > 250*time.Millisecond || done == total) {
				last = time.Now()
				pct := 0
				if total > 0 {
					pct = int(done * 100 / total)
				}
				fmt.Printf("\r\x1b[K%s", dim(fmt.Sprintf("downloading %d%%  %d / %d MB", pct, done>>20, total>>20)))
			}
		})
		if color {
			fmt.Print("\r\x1b[K")
		}
		check(err)
		ok("%s ready (%.2fB parameters, checksum verified)", m.Name, m.ParamsB)
		if !noUse {
			fmt.Println(dim("  selected; llama-server must be available (visionary ai local gguf --server <path>) to run it"))
		}
	case "set-token":
		tok, err := secure.PromptPassword("Hugging Face read token (empty to clear): ")
		check(err)
		check(a.SetSecret("huggingface", tok))
		ok("token saved (used only for gated models)")
	default:
		fail(errors.New("usage: visionary ai local hf search <text>|files <repo>|get <repo[:quant]> [--quant Q] [--no-use]|set-token"))
	}
}

func cmdRisk(a *app.App, fs *flag.FlagSet, rest []string) {
	kev := fs.Bool("kev", false, "only CISA Known Exploited Vulnerabilities")
	sev := fs.String("severity", "", "CVSS v3 severity: CRITICAL, HIGH, MEDIUM, or LOW")
	limit := fs.Int("limit", 15, "maximum CVEs to return")
	pos := parse(fs, rest)
	switch arg(pos, 0) {
	case "", "status", "guidance":
		g := a.RiskGuidance()
		if jsonOut {
			emit(g)
			return
		}
		row("Provider", a.ActiveRiskProvider())
		row("Scan posture", g.Posture)
		row("Guidance", g.Reason)
		for _, t := range g.PriorityTargets {
			fmt.Printf("  %-34s  %-8s  %s\n", t.Product, t.Severity, strings.Join(t.CVEs, ", "))
		}
	case "sync":
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		st, g, err := a.SyncRiskExchange(ctx)
		check(err)
		if jsonOut {
			emit(map[string]any{"state": st, "guidance": g})
			return
		}
		ok("synced %d advisories (%d KEV) from %s — scan posture: %s", len(st.Advisories), g.KEVCount, st.Provider, g.Posture)
		fmt.Println("  " + dim(g.Reason))
	case "search":
		q := strings.Join(pos[1:], " ")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		advs, total, err := a.SearchRiskExchange(ctx, risk.SearchOptions{
			Query:    q,
			Severity: *sev,
			KEVOnly:  *kev,
			Limit:    *limit,
		})
		check(err)
		if jsonOut {
			emit(map[string]any{"total": total, "advisories": advs})
			return
		}
		ok("%d matching CVEs (showing %d)", total, len(advs))
		for _, c := range advs {
			tag := c.Severity
			if c.KEV {
				tag += " · KEV"
			}
			fmt.Printf("  %-16s  CVSS %-4.1f  %-16s  %s\n", c.ID, c.CVSS, tag, c.Summary)
		}
	case "provider":
		p := arg(pos, 1)
		if p == "" {
			fmt.Println(a.ActiveRiskProvider())
			return
		}
		check(a.Set("risk.provider", p))
		ok("risk exchange provider: %s", a.ActiveRiskProvider())
	case "set-key":
		key, err := secure.PromptPassword("NIST NVD API key (optional — lifts free limit from 5 to 50 req/30s): ")
		check(err)
		check(a.SetSecret("nvd", key))
		ok("NIST NVD API key stored (encrypted)")
	case "clear-key":
		check(a.SetSecret("nvd", ""))
		ok("NIST NVD API key removed (using keyless free tier: 5 req/30s)")
	default:
		fail(errors.New("usage: visionary risk status|sync|guidance|search <query> [--kev] [--severity CRITICAL|HIGH]|provider [nvd|custom]|set-key|clear-key"))
	}
}
