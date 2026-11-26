// Package ui styles what expirely shows a person at a terminal. A Style that
// is not Styled returns text unchanged, so every layout is written once and
// styling only wraps words in escape codes: a styled render with its escape
// codes removed is the plain render, byte for byte. Text from outside
// expirely goes through Clean before it is styled, so it cannot carry escape
// codes of its own.
package ui

import (
	"io"
	"strings"
	"unicode"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
)

// Style is how a stream shows text. The zero Style is plain.
type Style struct {
	Profile colorprofile.Profile
}

// Styled reports whether s adds escape codes at all. A terminal without
// color, such as one with NO_COLOR set or TERM=dumb, gets plain text rather
// than bold and faint alone.
func (s Style) Styled() bool { return s.Profile > colorprofile.Ascii }

// Writer returns w with every escape code reduced to what the profile can
// show: colors become the nearest the terminal has, or nothing under
// NO_COLOR.
func (s Style) Writer(w io.Writer) io.Writer {
	return &colorprofile.Writer{Forward: w, Profile: s.Profile}
}

var (
	bold   = lipgloss.NewStyle().Bold(true)
	faint  = lipgloss.NewStyle().Faint(true)
	red    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	yellow = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	green  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	warn   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
)

func (s Style) apply(st lipgloss.Style, text string) string {
	if !s.Styled() || text == "" {
		return text
	}
	return st.Render(text)
}

// Bold emphasizes text expirely wrote.
func (s Style) Bold(text string) string { return s.apply(bold, text) }

// Faint shows text as secondary, such as a date next to a count of days.
func (s Style) Faint(text string) string { return s.apply(faint, text) }

// Bad marks an outcome that needs action now, such as an expired
// certificate.
func (s Style) Bad(text string) string { return s.apply(red, text) }

// Soon marks an outcome that needs action before long, such as a
// certificate expiring within the warning window.
func (s Style) Soon(text string) string { return s.apply(yellow, text) }

// Good marks an outcome that needs nothing.
func (s Style) Good(text string) string { return s.apply(green, text) }

// Note marks a remark a person should read, such as a trust problem.
func (s Style) Note(text string) string { return s.apply(warn, text) }

// Clean removes control characters from text that came from outside
// expirely, such as a certificate field or an error from a peer, so it
// cannot move the cursor, recolor the terminal or change its title.
func Clean(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, text)
}
