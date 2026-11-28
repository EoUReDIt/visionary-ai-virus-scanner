package app

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/config"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/secure"
)

// startedAt is when this process began; a quit request only applies to
// processes that were already running when it was made, so a stale request
// never stops a later start.
var startedAt = time.Now()

func quitPath() string { return config.Path("quit.request") }

// Quit asks every running Visionary process on this computer to exit: the
// Windows service, the dashboard and tray, and any terminal guard. The request
// is a shared file each of them checks, so it works across user sessions and
// without administrator rights. Starting Visionary again, or the service
// starting at the next boot, runs protection as normal.
//
// Quitting is the same as turning protection off, so it asks for the computer
// password whenever disabling does.
func (a *App) Quit(password string) error {
	if a.Config().Security.RequirePasswordToDisable {
		if err := secure.VerifyPassword(password); err != nil {
			return fmt.Errorf("computer password required to quit: %w", err)
		}
	}
	if err := config.WriteAtomic(quitPath(), []byte(time.Now().Format(time.RFC3339Nano)), 0o644); err != nil {
		return errors.New("cannot write the quit request: " + err.Error())
	}
	a.Log("protection", "info", "Visionary quit requested: real-time protection and its helpers are stopping", nil)
	return nil
}

// QuitRequested is true when a quit request was made after this process started.
func QuitRequested() bool {
	st, err := os.Stat(quitPath())
	return err == nil && st.ModTime().After(startedAt)
}
