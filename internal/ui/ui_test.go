package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/colorprofile"
)

func TestPlainStyleReturnsTextUnchanged(t *testing.T) {
	for _, p := range []colorprofile.Profile{colorprofile.NoTTY, colorprofile.Ascii} {
		s := Style{Profile: p}
		for _, f := range []func(string) string{s.Bold, s.Faint, s.Bad, s.Soon, s.Good, s.Note} {
			if got := f("text"); got != "text" {
				t.Errorf("profile %v returned %q, want %q", p, got, "text")
			}
		}
	}
}

func TestStyledStyleAddsEscapes(t *testing.T) {
	s := Style{Profile: colorprofile.TrueColor}
	if got := s.Bad("expired"); !strings.Contains(got, "\x1b[") || !strings.Contains(got, "expired") {
		t.Errorf("Bad() = %q, want the word wrapped in escape codes", got)
	}
	if got := s.Bad(""); got != "" {
		t.Errorf("Bad(\"\") = %q, want empty, so padding stays plain", got)
	}
}

func TestClean(t *testing.T) {
	if got := Clean("ok\x1b[31mred\x07\n\u009b"); got != "ok[31mred" {
		t.Errorf("Clean() = %q, want control characters removed", got)
	}
}
