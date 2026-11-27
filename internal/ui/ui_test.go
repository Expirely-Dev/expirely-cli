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
	if got := Clean("evil\u202egpj.com\u200b"); got != "evilgpj.com" {
		t.Errorf("Clean() = %q, want the bidi override and zero-width space removed", got)
	}
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		width int
		want  string
	}{
		{name: "fits", text: "one two", width: 80, want: "one two"},
		{name: "breaks at a space", text: "one two three", width: 7, want: "one two\nthree"},
		{name: "exactly the width stays", text: "abc def", width: 7, want: "abc def"},
		{name: "a long word stays whole", text: "see https://example.com/a/long/path now", width: 10, want: "see\nhttps://example.com/a/long/path\nnow"},
		{name: "empty", text: "", width: 80, want: ""},
		{name: "runs of spaces collapse", text: "one   two", width: 80, want: "one two"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Wrap(tt.text, tt.width); got != tt.want {
				t.Errorf("Wrap(%q, %d) = %q, want %q", tt.text, tt.width, got, tt.want)
			}
		})
	}
}
