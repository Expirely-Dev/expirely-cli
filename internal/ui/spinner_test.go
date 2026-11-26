package ui

import (
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestSpinnerDrawsNothingForAQuickScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out lockedBuffer
		s := StartSpinner(&out, 3)
		time.Sleep(spinnerDelay - time.Millisecond)
		s.Stop()

		if got := out.String(); got != "" {
			t.Errorf("output = %q, want nothing before the delay", got)
		}
	})
}

func TestSpinnerCountsAndErasesItsLine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out lockedBuffer
		s := StartSpinner(&out, 3)
		time.Sleep(spinnerDelay)
		synctest.Wait()
		s.Done()
		s.Done()
		time.Sleep(spinnerInterval)
		synctest.Wait()
		s.Stop()
		s.Stop()

		got := out.String()
		if !strings.Contains(got, "⠋ Scanning 3 targets  0/3") {
			t.Errorf("output = %q, want the first frame with 0/3", got)
		}
		if !strings.Contains(got, "⠙ Scanning 3 targets  2/3") {
			t.Errorf("output = %q, want the next frame with 2/3", got)
		}
		if !strings.HasSuffix(got, clearLine) {
			t.Errorf("output = %q, want it to end by erasing the line", got)
		}
	})
}

func TestSpinnerOneTargetHasNoCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out lockedBuffer
		s := StartSpinner(&out, 1)
		time.Sleep(spinnerDelay)
		synctest.Wait()
		s.Stop()

		if got := out.String(); !strings.Contains(got, "⠋ Scanning 1 target"+clearLine) {
			t.Errorf("output = %q, want a singular label with no count", got)
		}
	})
}
