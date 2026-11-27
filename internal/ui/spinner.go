package ui

import (
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var frames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	// spinnerDelay keeps a scan that finishes quickly from flashing a
	// spinner for a frame.
	spinnerDelay    = 150 * time.Millisecond
	spinnerInterval = 80 * time.Millisecond
	clearLine       = "\r\x1b[2K"
)

// Spinner shows a label on one line of a terminal, such as "Scanning N
// targets" with a count of finished targets, and erases that line when it
// stops. It draws nothing until spinnerDelay has passed.
type Spinner struct {
	w     io.Writer
	label string
	total int
	done  atomic.Int64
	stop  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

// StartSpinner starts a spinner for total targets on w, which must be a
// terminal; a caller that has no terminal does not start one. Stop must be
// called to end it.
func StartSpinner(w io.Writer, total int) *Spinner {
	return start(&Spinner{w: w, total: total})
}

// StartWaiting starts a spinner on w that shows label, after Clean, with
// no count, for work whose size is not known until it ends. Stop must be
// called to end it.
func StartWaiting(w io.Writer, label string) *Spinner {
	return start(&Spinner{w: w, label: Clean(label)})
}

func start(s *Spinner) *Spinner {
	s.stop = make(chan struct{})
	s.wg.Go(s.run)
	return s
}

// Done records that one more target finished. It is safe to call from any
// goroutine.
func (s *Spinner) Done() { s.done.Add(1) }

// Stop erases the spinner's line, if it drew one, and returns once the
// spinner has stopped writing. Calling it again does nothing.
func (s *Spinner) Stop() {
	s.once.Do(func() {
		close(s.stop)
		s.wg.Wait()
	})
}

func (s *Spinner) run() {
	delay := time.NewTimer(spinnerDelay)
	defer delay.Stop()
	select {
	case <-s.stop:
		return
	case <-delay.C:
	}

	tick := time.NewTicker(spinnerInterval)
	defer tick.Stop()
	for frame := 0; ; frame++ {
		_, _ = io.WriteString(s.w, clearLine+s.line(frame))
		select {
		case <-s.stop:
			_, _ = io.WriteString(s.w, clearLine)
			return
		case <-tick.C:
		}
	}
}

func (s *Spinner) line(frame int) string {
	if s.label != "" {
		return frames[frame%len(frames)] + " " + s.label
	}
	text := frames[frame%len(frames)] + " Scanning " + strconv.Itoa(s.total) + " target"
	if s.total == 1 {
		return text
	}
	return text + "s  " + strconv.FormatInt(s.done.Load(), 10) + "/" + strconv.Itoa(s.total)
}
