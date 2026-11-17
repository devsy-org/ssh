package ssh

import (
	"bytes"
	"io"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

type testChannel struct {
	bytes.Buffer
	stderr bytes.Buffer
}

func (c *testChannel) Close() error      { return nil }
func (c *testChannel) CloseWrite() error { return nil }
func (c *testChannel) SendRequest(string, bool, []byte) (bool, error) {
	return true, nil
}
func (c *testChannel) Stderr() io.ReadWriter { return &c.stderr }

func TestOpenChannelSetLifecycle(t *testing.T) {
	t.Parallel()

	set := &openChannelSet{}
	if got := set.any(); got != nil {
		t.Fatalf("empty set returned channel %v", got)
	}

	first := &testChannel{}
	second := &testChannel{}
	set.add(first)
	set.add(second)
	if got := set.any(); got != gossh.Channel(first) {
		t.Fatalf("any() = %v, want first channel", got)
	}

	set.remove(first)
	if got := set.any(); got != gossh.Channel(second) {
		t.Fatalf("any() after removal = %v, want second channel", got)
	}

	// Removing an absent channel is intentionally idempotent.
	set.remove(first)
	set.remove(second)
	if got := set.any(); got != nil {
		t.Fatalf("empty set after removals returned %v", got)
	}
}

func TestOpenChannelSetConcurrentAccess(t *testing.T) {
	t.Parallel()

	set := &openChannelSet{}
	channels := make([]*testChannel, 64)
	for i := range channels {
		channels[i] = &testChannel{}
	}

	var wg sync.WaitGroup
	for _, ch := range channels {
		ch := ch
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				set.add(ch)
				_ = set.any()
				set.remove(ch)
			}
		}()
	}
	wg.Wait()

	// Each goroutine removes its own final registration. Duplicate transient
	// registrations are removed one-at-a-time during the loop; no operation may
	// race or panic under -race.
	for _, ch := range channels {
		for {
			set.mu.Lock()
			found := false
			for _, existing := range set.chans {
				if existing == ch {
					found = true
					break
				}
			}
			set.mu.Unlock()
			if !found {
				break
			}
			set.remove(ch)
		}
	}
	if got := set.any(); got != nil {
		t.Fatalf("set not empty after concurrent lifecycle test: %v", got)
	}
}
