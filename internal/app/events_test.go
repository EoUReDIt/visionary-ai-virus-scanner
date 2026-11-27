package app

import (
	"fmt"
	"strings"
	"testing"
)

func TestEventsTailRead(t *testing.T) {
	t.Setenv("VISIONARY_HOME", t.TempDir())
	a, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	// Write > 300 KiB of events so App.Events exercises the 256 KiB tail-seek path.
	pad := strings.Repeat("x", 600)
	const total = 550
	for i := 1; i <= total; i++ {
		a.Log("scan", "info", fmt.Sprintf("event-%04d %s", i, pad), nil)
	}

	got := a.Events(30)
	if len(got) != 30 {
		t.Fatalf("expected 30 events, got %d", len(got))
	}
	if !strings.HasPrefix(got[0].Message, fmt.Sprintf("event-%04d ", total)) {
		t.Fatalf("newest event mismatch: got %q", got[0].Message[:20])
	}
	if !strings.HasPrefix(got[29].Message, fmt.Sprintf("event-%04d ", total-29)) {
		t.Fatalf("30th event mismatch: got %q", got[29].Message[:20])
	}
}
