package app

import (
	"context"
	"path/filepath"
	"strings"
	"time"
)

// rescanBackoff stops one busy file (a log, a database, a download in
// progress) from being rehashed every few seconds. Each time a path is
// scanned again while it keeps changing, the wait before the next scan grows:
// base, 3x base, then 12x base (5s, 15s, 60s by default). A path that has been
// quiet for a while starts over, so a fresh change to an old file is seen
// promptly.
type rescanBackoff struct {
	base  time.Duration
	state map[string]backoffState
}

type backoffState struct {
	last  time.Time // when the path was last handed to a worker
	level int
}

var backoffSteps = [...]int{1, 3, 12}

func newRescanBackoff(base time.Duration) *rescanBackoff {
	if base <= 0 {
		base = 5 * time.Second
	}
	return &rescanBackoff{base: base, state: map[string]backoffState{}}
}

func (b *rescanBackoff) wait(level int) time.Duration {
	if level >= len(backoffSteps) {
		level = len(backoffSteps) - 1
	}
	return b.base * time.Duration(backoffSteps[level])
}

// allow reports whether path may be scanned at now. When it is allowed the
// scan is recorded and the next wait grows.
func (b *rescanBackoff) allow(path string, now time.Time) bool {
	st, ok := b.state[path]
	if !ok {
		b.state[path] = backoffState{last: now}
		return true
	}
	quiet := b.wait(len(backoffSteps)-1) * 2
	if now.Sub(st.last) >= quiet {
		b.state[path] = backoffState{last: now}
		return true
	}
	if now.Sub(st.last) < b.wait(st.level) {
		return false
	}
	st.last = now
	if st.level < len(backoffSteps) {
		st.level++
	}
	b.state[path] = st
	return true
}

// prune forgets paths that have been quiet long enough to start over.
func (b *rescanBackoff) prune(now time.Time) {
	quiet := b.wait(len(backoffSteps)-1) * 2
	for p, st := range b.state {
		if now.Sub(st.last) >= quiet {
			delete(b.state, p)
		}
	}
}

// skippedExt reports whether path ends in one of the skip extensions.
// The list is lower case with the leading dot.
func skippedExt(path string, exts []string) bool {
	if len(exts) == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false
	}
	for _, e := range exts {
		if e == ext {
			return true
		}
	}
	return false
}

// throttle sleeps after a scan that took busy, so the worker uses about
// percent of one core over time. percent <= 0 or >= 100 disables it. The
// pause is capped so a single huge file cannot park the worker.
func throttle(ctx context.Context, busy time.Duration, percent int) {
	if percent <= 0 || percent >= 100 || busy <= 0 {
		return
	}
	d := busy * time.Duration(100-percent) / time.Duration(percent)
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
