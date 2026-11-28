package app

import (
	"os"
	"testing"
	"time"
)

func TestQuitRequestOnlyAppliesToRunningProcesses(t *testing.T) {
	t.Setenv("VISIONARY_HOME", t.TempDir())
	a, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if QuitRequested() {
		t.Fatal("no request yet, but QuitRequested is true")
	}
	if err := a.Quit(""); err != nil {
		t.Fatal(err)
	}
	// The file is newer than the process start only if written after it.
	now := time.Now().Add(time.Second)
	_ = os.Chtimes(quitPath(), now, now)
	if !QuitRequested() {
		t.Fatal("quit request not seen")
	}
	// A stale request from before this process started must not count.
	old := startedAt.Add(-time.Hour)
	_ = os.Chtimes(quitPath(), old, old)
	if QuitRequested() {
		t.Fatal("stale quit request was honoured")
	}
}
