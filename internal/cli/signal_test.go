package cli

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestInterruptContextCancelsOnSIGTERM(t *testing.T) {
	ctx, stop := interruptContext()
	defer stop()
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Skipf("cannot signal self: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context not cancelled by SIGTERM")
	}
}
