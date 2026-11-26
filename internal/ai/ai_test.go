package ai

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/EoUReDIt/visionary-ai-virus-scanner/internal/engine"
)

func TestParseVerdict(t *testing.T) {
	for raw, want := range map[string]engine.AIVerdict{
		`{"verdict":"malicious","confidence":0.91,"reasons":["a","b"]}`:                                {Verdict: "malicious", Confidence: 0.91},
		"Sure!\n```json\n{\"verdict\": \"Benign\", \"confidence\": \"85%\", \"reasons\": \"ok\"}\n```": {Verdict: "benign", Confidence: 0.85},
		`{"verdict":"clean","confidence":90}`:                                                          {Verdict: "benign", Confidence: 0.9},
	} {
		got, err := ParseVerdict(raw)
		if err != nil || got.Verdict != want.Verdict || got.Confidence != want.Confidence {
			t.Errorf("%q -> %+v, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"no json here", `{"verdict":"maybe"}`, `{"verdict":`} {
		if _, err := ParseVerdict(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

type fake struct {
	name, reply string
	err         error
	calls       int
	lastUser    string
}

func (f *fake) Name() string  { return f.name }
func (f *fake) Model() string { return f.name + "-model" }
func (f *fake) Complete(_ context.Context, _, user string, _ bool) (string, error) {
	f.calls++
	f.lastUser = user
	return f.reply, f.err
}

func TestHybridPolicy(t *testing.T) {
	rep := &engine.Report{FileName: "a.ps1", Features: engine.Features{Snippet: "SECRET-SCRIPT-BODY"}}
	sure := `{"verdict":"malicious","confidence":0.95,"reasons":["x"]}`
	unsure := `{"verdict":"suspicious","confidence":0.4,"reasons":["x"]}`
	benign := `{"verdict":"benign","confidence":0.9,"reasons":["x"]}`

	// A confident local answer never reaches the cloud.
	local, cloud := &fake{name: "local", reply: sure}, &fake{name: "cloud", reply: benign}
	v, err := (&Triage{Local: local, Cloud: cloud}).Assess(context.Background(), rep)
	if err != nil || v.Provider != "local" || cloud.calls != 0 {
		t.Errorf("confident local: %+v %v cloud calls %d", v, err, cloud.calls)
	}
	// An unsure local answer escalates, and the snippet stays on the machine.
	local = &fake{name: "local", reply: unsure}
	v, err = (&Triage{Local: local, Cloud: cloud}).Assess(context.Background(), rep)
	if err != nil || v.Provider != "cloud" || v.Verdict != "benign" {
		t.Errorf("escalation: %+v %v", v, err)
	}
	if !contains(local.lastUser, "SECRET-SCRIPT-BODY") || contains(cloud.lastUser, "SECRET-SCRIPT-BODY") {
		t.Error("snippet privacy: local should see it, cloud should not")
	}
	// Cloud failure falls back to what the local model said.
	down := &fake{name: "cloud", err: errors.New("offline")}
	v, err = (&Triage{Local: local, Cloud: down}).Assess(context.Background(), rep)
	if err != nil || v.Provider != "local" {
		t.Errorf("fallback: %+v %v", v, err)
	}
	if _, err := (&Triage{}).Assess(context.Background(), rep); err == nil {
		t.Error("no providers should be an error")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func writeGGUF(t *testing.T, dims [][]uint64) string {
	t.Helper()
	var b []byte
	le := binary.LittleEndian
	str := func(s string) { b = le.AppendUint64(b, uint64(len(s))); b = append(b, s...) }
	b = append(b, "GGUF"...)
	b = le.AppendUint32(b, 3)
	b = le.AppendUint64(b, uint64(len(dims)))
	b = le.AppendUint64(b, 2)
	str("general.name")
	b = le.AppendUint32(b, 8)
	str("tiny")
	str("tokenizer.tokens")
	b = le.AppendUint32(b, 9)
	b = le.AppendUint32(b, 8)
	b = le.AppendUint64(b, 2)
	str("a")
	str("b")
	for _, d := range dims {
		str("t")
		b = le.AppendUint32(b, uint32(len(d)))
		for _, x := range d {
			b = le.AppendUint64(b, x)
		}
		b = le.AppendUint32(b, 0)
		b = le.AppendUint64(b, 0)
	}
	p := filepath.Join(t.TempDir(), "m.gguf")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParameterLimit(t *testing.T) {
	small := writeGGUF(t, [][]uint64{{50000, 1024}, {1024, 1024}, {1024}})
	n, err := GGUFParams(small)
	if err != nil || n != 50000*1024+1024*1024+1024 {
		t.Fatalf("params = %d, %v", n, err)
	}
	if err := CheckGGUF(small, 3.0); err != nil {
		t.Errorf("small model rejected: %v", err)
	}
	big := writeGGUF(t, [][]uint64{{100000, 4096}, {100000, 4096}, {100000, 4096}, {100000, 4096},
		{100000, 4096}, {100000, 4096}, {100000, 4096}, {100000, 4096}})
	if err := CheckGGUF(big, 3.0); err == nil {
		t.Error("3.28B model accepted under a 3B limit")
	}
	if ParseParamSize("1.7B") != 1.7 || math.Abs(ParseParamSize("494.03M")-0.49403) > 1e-9 {
		t.Error("ParseParamSize")
	}
}

func TestRichVerdictParsing(t *testing.T) {
	raw := `{"verdict":"malicious","confidence":0.93,"category":"lolbin","recommended_action":"quarantine","summary":"Word spawned encoded PowerShell downloading a remote stage.","reasons":["Office parent spawned PowerShell","Base64 payload with IEX"]}`
	v, err := ParseVerdict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.Category != "lolbin" || v.RecommendedAction != "quarantine" || v.Summary == "" || len(v.Reasons) != 2 {
		t.Fatalf("unexpected rich verdict: %+v", v)
	}
}

