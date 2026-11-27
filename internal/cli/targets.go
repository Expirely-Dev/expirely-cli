package cli

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/expirely-dev/expirely-cli/internal/target"
)

// fileList collects repeated --file flags.
type fileList []string

func (f *fileList) String() string { return strings.Join(*f, ",") }

func (f *fileList) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// collectTargets parses the targets in args and in each file, in that
// order, and drops repeats while keeping the first occurrence. A file named
// "-" is read from stdin. In a file, blank lines and lines starting with #
// are skipped.
func collectTargets(args, files []string, stdin io.Reader) ([]target.Target, *Error) {
	var targets []target.Target
	seen := make(map[target.Target]bool)
	add := func(input, where string) *Error {
		t, err := target.Parse(input)
		if err != nil {
			return failf(CodeInvalidTarget, "%s%v", where, err)
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
		return nil
	}

	for _, arg := range args {
		if e := add(arg, ""); e != nil {
			return nil, e
		}
	}

	for _, name := range files {
		if e := readTargetFile(name, stdin, add); e != nil {
			return nil, e
		}
	}
	return targets, nil
}

func readTargetFile(name string, stdin io.Reader, add func(input, where string) *Error) *Error {
	r := stdin
	label := "stdin"
	if name != "-" {
		f, err := os.Open(name) //nolint:gosec // G304: reading the file the user named is the purpose of --file.
		if err != nil {
			return failf(CodeFileUnreadable, "%v", err)
		}
		defer func() { _ = f.Close() }()
		r = f
		label = name
	}

	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if e := add(text, label+":"+strconv.Itoa(line)+": "); e != nil {
			return e
		}
	}
	if err := sc.Err(); err != nil {
		return failf(CodeFileUnreadable, "read %s: %v", label, err)
	}
	return nil
}

func fileNames(files []string) []string {
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f
		if f == "-" {
			names[i] = "stdin"
		}
	}
	return names
}
