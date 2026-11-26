//go:build safe && !lite

package config

import (
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/edition"
)

func TestSafeEditionIdentity(t *testing.T) {
	if !edition.Safe || edition.Lite || edition.Name != "safe" {
		t.Fatalf("unexpected safe edition flags: Safe=%v Lite=%v Name=%q", edition.Safe, edition.Lite, edition.Name)
	}
}
