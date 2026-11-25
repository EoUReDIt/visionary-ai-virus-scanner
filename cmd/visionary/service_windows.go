//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/app"
)

const serviceName = "VisionaryAV"

func runningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type guardService struct{ a *app.App }

func (g *guardService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = g.a.RunGuard(ctx, nil)
		close(done)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
			}
			return false, 0
		}
	}
	cancel()
	return false, 0
}

func runService(a *app.App) error { return svc.Run(serviceName, &guardService{a}) }

// serviceCommand manages the auto-start service that keeps real-time
// protection running from boot, before and between user sessions.
func serviceCommand(action string) (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("cannot reach the service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	if action == "install" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		if s, err := m.OpenService(serviceName); err == nil {
			s.Close()
			return "", errors.New("the service is already installed")
		}
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: "Visionary Real-Time Protection",
			Description: "Scans new files and newly started programs, and watches for abnormal activity.",
			StartType:   mgr.StartAutomatic,
		}, "service", "run")
		if err != nil {
			return "", err
		}
		defer s.Close()
		_ = s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		}, 86400)
		if err := s.Start(); err != nil {
			return "installed (start it with: visionary service start)", nil
		}
		return "installed and started", nil
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		return "", errors.New("the service is not installed (visionary service install)")
	}
	defer s.Close()
	stop := func() {
		if st, err := s.Control(svc.Stop); err == nil {
			for i := 0; i < 40 && st.State != svc.Stopped; i++ {
				time.Sleep(250 * time.Millisecond)
				st, _ = s.Query()
			}
		}
	}
	switch action {
	case "uninstall":
		stop()
		return "removed", s.Delete()
	case "start":
		return "started", s.Start()
	case "stop":
		stop()
		return "stopped", nil
	case "status":
		st, err := s.Query()
		if err != nil {
			return "", err
		}
		names := map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting",
			svc.StopPending: "stopping", svc.Running: "running", svc.Paused: "paused"}
		return names[st.State], nil
	}
	return "", errors.New("usage: visionary service install|uninstall|start|stop|status")
}
