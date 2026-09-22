package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// TestRun_ShutsDownOnSIGTERM checks that run returns cleanly once its
// context is cancelled, rather than blocking forever.
func TestRun_ShutsDownOnSIGTERM(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- run("127.0.0.1:2379")
	}()

	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal self: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after SIGTERM")
	}
}
