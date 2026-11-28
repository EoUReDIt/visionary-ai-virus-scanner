package risk

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestKeywordsMatchWholeWordsOnly(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"a flaw in the parser library", false}, // "rar" inside "library"
		{"digital signature check", false},      // "git" inside "digital"
		{"winrar before 6.23", true},
		{"cpe microsoft_edge_chromium", true},
		{"git for windows", true},
	}
	kws := []string{"rar", "git", "winrar", "microsoft_edge"}
	for _, c := range cases {
		if got := containsAnyWord(c.text, kws); got != c.want {
			t.Errorf("containsAnyWord(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

func TestGuidanceIgnoresSubstringMatches(t *testing.T) {
	st := State{Advisories: []Advisory{{ID: "CVE-2024-0001", Severity: "CRITICAL",
		Summary: "Improper parameter validation in a graphics library"}}}
	g := ComputeGuidance(st)
	if g.RecommendArchives {
		t.Error("archive inspection recommended because 'rar' appears inside 'library'/'parameter'")
	}
	if len(g.PriorityTargets) != 0 {
		t.Errorf("unexpected targets: %+v", g.PriorityTargets)
	}
}

func TestTruncateRunesKeepsUTF8(t *testing.T) {
	s := strings.Repeat("é", 200) // 400 bytes, 2 bytes per rune
	out := truncateRunes(s, 260)
	if !utf8.ValidString(out) || len(out) > 262 {
		t.Fatalf("bad truncation: valid=%v len=%d", utf8.ValidString(out), len(out))
	}
	if truncateRunes("short", 260) != "short" {
		t.Fatal("short text changed")
	}
}

func TestValidatePublicIPRejectsReservedRanges(t *testing.T) {
	for _, ip := range []string{"0.1.2.3", "192.0.0.8", "240.0.0.1", "255.255.255.255", "10.0.0.1", "127.0.0.1"} {
		if _, err := ValidatePublicIP(ip); err == nil {
			t.Errorf("%s accepted", ip)
		}
	}
	if _, err := ValidatePublicIP("8.8.8.8"); err != nil {
		t.Errorf("public IP rejected: %v", err)
	}
}
