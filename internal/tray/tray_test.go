package tray

import (
	"strings"
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
)

func TestComputeStates(t *testing.T) {
	cases := []struct {
		name      string
		status    *app.Status
		wantState State
		wantSub   string
	}{
		{
			name:      "active protected",
			status:    &app.Status{Edition: "core", Protection: true, GuardAlive: true},
			wantState: StateActive,
			wantSub:   "Protected",
		},
		{
			name:      "active game mode",
			status:    &app.Status{Edition: "core", Protection: true, GuardAlive: true, GameMode: true},
			wantState: StateActive,
			wantSub:   "Game Mode",
		},
		{
			name:      "paused timed",
			status:    &app.Status{Edition: "safe", Protection: false, ProtReason: "disabled until 15:30:00"},
			wantState: StatePaused,
			wantSub:   "Paused",
		},
		{
			name:      "paused until restart",
			status:    &app.Status{Edition: "core", Protection: false, ProtReason: "disabled until restart"},
			wantState: StatePaused,
			wantSub:   "Paused",
		},
		{
			name:      "warning permanent disable",
			status:    &app.Status{Edition: "core", Protection: false, ProtReason: "disabled until re-enabled by the user"},
			wantState: StateWarning,
			wantSub:   "Protection Off",
		},
		{
			name:      "warning guard offline",
			status:    &app.Status{Edition: "core", Protection: true, GuardAlive: false},
			wantState: StateWarning,
			wantSub:   "Guard Offline",
		},
		{
			name:      "warning quarantined threats",
			status:    &app.Status{Edition: "core", Protection: true, GuardAlive: true, Quarantine: 2},
			wantState: StateWarning,
			wantSub:   "2 Threats Quarantined",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Compute(tc.status)
			if got.State != tc.wantState {
				t.Fatalf("Compute() state = %q, want %q (label=%q)", got.State, tc.wantState, got.Label)
			}
			if !strings.Contains(got.Label, tc.wantSub) {
				t.Fatalf("Compute() label = %q, want substring %q", got.Label, tc.wantSub)
			}
			if len(got.Tooltip) > 124 {
				t.Fatalf("tooltip exceeds Win32 limit: %d chars", len(got.Tooltip))
			}
		})
	}
}
