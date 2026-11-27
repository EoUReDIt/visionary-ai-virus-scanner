//go:build !windows

package tray

import "context"

// Controller is a no-op tray handle on non-Windows platforms.
type Controller struct{}

// Start is a no-op on non-Windows platforms.
func Start(context.Context, Callbacks) *Controller { return &Controller{} }

// Refresh is a no-op on non-Windows platforms.
func (*Controller) Refresh() {}

// Close is a no-op on non-Windows platforms.
func (*Controller) Close() {}
