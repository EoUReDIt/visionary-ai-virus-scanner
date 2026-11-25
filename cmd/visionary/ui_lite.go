//go:build lite

package main

import (
	"context"
	"errors"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
)

// The Lite edition ships without the dashboard (its embedded page and local
// web server): everything is a command.
func serveUI(context.Context, *app.App, int, bool, bool) error {
	return errors.New("the dashboard is not part of the Lite edition: use the visionary commands (visionary help), or install the full edition")
}
