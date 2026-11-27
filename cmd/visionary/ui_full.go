package main

import (
	"context"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/ui"
)

func serveUI(ctx context.Context, a *app.App, port int, open, guard bool) error {
	return ui.Serve(ctx, a, port, open, guard)
}
