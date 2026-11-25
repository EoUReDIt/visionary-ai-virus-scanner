//go:build !windows

package main

import (
	"errors"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
)

func runningAsService() bool { return false }

func runService(*app.App) error { return errors.New("the service only exists on Windows") }

func serviceCommand(string) (string, error) {
	return "", errors.New("the background service only exists on Windows; use `visionary guard` here")
}
