package rules

import (
	"bytes"
	"context"
	"testing"
	"time"
)

const src = `
import "pe"
// a comment with rule words: rule X { condition: true }
rule Text_And_Hex : tag1 {
  meta:
    description = "text and hex"
    score = 90
  strings:
    $a = "evil-marker" nocase
    $h = { DE AD ?? EF [1-3] 42 ( 01 | 02 03 ) }
    $w = "wide" wide
  condition:
    $a and $h and not $w
}
rule Of_Them { strings: $s1 = "one" $s2 = "two" $s3 = "three" condition: 2 of ($s*) }
rule At_Start { strings: $mz = "MZ" condition: $mz at 0 and filesize < 1KB and uint16(0) == 0x5A4D }
rule Regex { meta: severity = "low" strings: $r = /https?:\/\/[a-z]+\.example\/[0-9]{3}/ nocase condition: $r }
rule Fullword { strings: $f = "cat" fullword condition: $f }
rule Uses_Module { condition: pe.number_of_sections > 3 }
rule Uses_Loop { strings: $a = "x" condition: for any i in (1..#a) : ( @a[i] < 10 ) }
`

func TestParseAndScan(t *testing.T) {
	set := Parse(src, "test")
	if len(set.Rules) != 5 {
		t.Fatalf("compiled %d rules, want 5 (skipped: %v)", len(set.Rules), set.Skipped)
	}
	if len(set.Skipped) != 2 {
		t.Fatalf("skipped %v, want the module and loop rules", set.Skipped)
	}
	cases := []struct {
		data string
		want []string
	}{
		{"xx EVIL-MARKER \xde\xad\x00\xef\x99\x99\x42\x02\x03", []string{"Text_And_Hex"}},
		{"evil-marker \xde\xad\x00\xef\x99\x42\x01 w\x00i\x00d\x00e\x00", nil},
		{"evil-marker \xde\xad\x00\xef\x42\x01", nil}, // jump needs at least one byte
		{"one and three", []string{"Of_Them"}},
		{"only one", nil},
		{"MZ header", []string{"At_Start"}},
		{" MZ not at start", nil},
		{"see HTTPS://abc.example/123 now", []string{"Regex"}},
		{"a cat sat", []string{"Fullword"}},
		{"concatenate", nil},
	}
	for _, c := range cases {
		got := set.Scan([]byte(c.data))
		if len(got) != len(c.want) {
			t.Errorf("%q: matched %v, want %v", c.data, got, c.want)
			continue
		}
		for i := range got {
			if got[i].Rule != c.want[i] {
				t.Errorf("%q: matched %s, want %s", c.data, got[i].Rule, c.want[i])
			}
		}
	}
	for _, r := range set.Rules {
		if r.Name == "Text_And_Hex" && r.Score != 90 || r.Name == "Regex" && r.Score != 30 {
			t.Errorf("%s score = %d", r.Name, r.Score)
		}
	}
}

func TestScanContextCancelledReturnsNil(t *testing.T) {
	set := Parse(`rule Always_Not { strings: $a = "nope" condition: not $a }`, "test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := set.ScanContext(ctx, []byte("anything")); len(got) != 0 {
		t.Fatalf("cancelled ScanContext matched %v, want nil", got)
	}
}

func TestHexJumpBacktrackingBounded(t *testing.T) {
	// Pathological pattern with 3 wide jumps that previously backtracked O(4096^3).
	set := Parse(`
rule MultiJump {
  strings:
    $h = { AA [0-4096] AA [0-4096] AA [0-4096] BB }
  condition:
    $h
}`, "test")
	buf := bytes.Repeat([]byte{0xAA}, 8192)
	start := time.Now()
	if got := set.ScanContext(context.Background(), buf); len(got) != 0 {
		t.Fatalf("expected no match, got %v", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pathological hex jump took %v, expected bounded completion", elapsed)
	}
	// Verify valid match still succeeds.
	buf[len(buf)-1] = 0xBB
	if got := set.ScanContext(context.Background(), buf); len(got) != 1 || got[0].Rule != "MultiJump" {
		t.Fatalf("expected MultiJump match, got %v", got)
	}
}

func TestNocaseASCIIAvoidsFullLowerCopy(t *testing.T) {
	set := Parse(`rule NocaseASCII { strings: $a = "PowerShell" nocase fullword condition: $a }`, "test")
	buf := append(bytes.Repeat([]byte("padding "), 4096), []byte("run pOwErShElL now")...)
	v := &view{raw: buf}
	if off := set.Rules[0].patterns[0].find(context.Background(), v, 0); off < 0 {
		t.Fatalf("expected nocase match")
	}
	if v.low != nil {
		t.Fatalf("expected ASCII nocase search not to allocate view.low copy")
	}
}
